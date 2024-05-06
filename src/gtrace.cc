#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include "elf_parser.h"
#include <unordered_map>
#include <vector>
#include <sys/prctl.h>
#include <sys/auxv.h>
#include <libelf.h>
#include <gelf.h>
#include <getopt.h>
#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>
extern "C"
{
  #include "syscall_nums.h"
  #include "utils.h"
}

static void read_cu_list(Dwarf_Debug dbg);
static void print_die_data(Dwarf_Debug dbg, Dwarf_Die print_me,int level);
static void get_die_and_siblings(Dwarf_Debug dbg, Dwarf_Die in_die,int in_level);
bool timestamps = false;
int agr = -1;
class breakpoint {
    public:
        std::intptr_t addr;
        uint8_t orig_data;
        bool enabled = false;
        std::string *name;
        std::vector<std::pair<std::string, std::string>> *args;
        bool is_return;
        bool is_lib_func;
	breakpoint(std::intptr_t addr, std::string name, bool is_return, bool is_lib_func) {
	    this->addr = addr;
	    this->orig_data = 0;
	    this->name = new std::string(name);
	    this->args = new std::vector<std::pair<std::string, std::string>>();
	    this->is_return = is_return;
	    this->is_lib_func = is_lib_func;
	};
	~breakpoint() {
	    //delete this->name;
	    //delete this->args;
	};
};
std::unordered_map<std::intptr_t, breakpoint*> breakpoints_map;
ssize_t format_timeval(struct timeval *tv, char *buf, size_t sz);

void fatal(char *err_str, ...) {
    va_list args;
    va_start(args, err_str);
    vfprintf(stderr, err_str, args);
    va_end(args);
    exit(EXIT_FAILURE);
}

uint64_t get_entrypoint(pid_t child_pid) {

    char fn[512];
    snprintf(fn, 512, "/proc/%d/auxv", child_pid);
    int fd = open(fn, O_RDONLY);                                        
    int ret = 0;                                                          
    if (fd == -1) {                                                       
        fatal("couldn't read %s: %s", fn, strerror(errno));
    }                                                                     
                                                                          
    while (1) {                                                           
        Elf64_auxv_t aux_entry = {};                                      
        if( read(fd, &aux_entry, sizeof(aux_entry)) == 0)
            fatal("FINISHED READING AUXV\n");
        if(aux_entry.a_type == AT_ENTRY) {
	    close(fd);
            return aux_entry.a_un.a_val;
	}
    }                                                                     
}
void get_registers(pid_t &child_pid, struct user_regs_struct *regs) {
    if(ptrace(PTRACE_GETREGS, child_pid, nullptr, regs) == -1) {
	fatal("Error: Pid %d PTRACE_GETREGS %s\n", child_pid, strerror(errno));
    };
}
uint64_t get_program_counter(pid_t &child_pid) {
    user_regs_struct regs;
    get_registers(child_pid, &regs);
    return (uint64_t)regs.rip;
}

void set_program_counter(pid_t &child_pid, uint64_t &pc) {
    user_regs_struct regs;
    get_registers(child_pid, &regs);

    #ifdef __x86_64__
        regs.rip = pc;
    #else
        regs.eip = pc;
    #endif
    ptrace(PTRACE_SETREGS, child_pid, nullptr, &regs);
}



void disable_breakpoint(pid_t &child_pid, breakpoint *bp) {
    auto data = ptrace(PTRACE_PEEKTEXT, child_pid, bp->addr, nullptr);

    //overwrite the low byte with the original data and write it back to memory.
    auto restored_data = ((data & ~0xff) | bp->orig_data);
    long ret = ptrace(PTRACE_POKEDATA, child_pid, bp->addr, restored_data);
    if(ret == -1) {
	fatal("Error: PTRACE_POKEDATA Failed to disable breakpoint 0x%lx %s\n", bp->addr, strerror(errno));
    }
}
void enable_breakpoint(pid_t &child_pid, breakpoint *bp) {
    uint64_t pc = get_program_counter(child_pid);
    auto data = ptrace(PTRACE_PEEKDATA, child_pid, bp->addr, NULL);
    bp->orig_data = static_cast<uint8_t>(data & 0xff); //save bottom byte
    
    //set bottom byte to 0xcc
    uint64_t int3 = 0xcc;
    uint64_t data_with_int3 = ((data & ~0xff) | int3);
    data = ptrace(PTRACE_POKEDATA, child_pid, bp->addr, data_with_int3);
    if(data == -1) {
	fatal("Error: PTRACE_POKEDATA Failed to enable breakpoint %s 0x%lx %s\n", bp->name->c_str(), bp->addr, strerror(errno));
    }
}

void wait_for_signal(pid_t &child_pid) {
    int wait_status = 0;
    auto options = 0;
    auto i = waitpid(child_pid, &wait_status, options);
    if(WIFEXITED(wait_status) || (WIFSIGNALED(wait_status) && WTERMSIG(wait_status) == SIGKILL)) {
      fflush(stdout);
      fatal("[+] process %d terminated\n", child_pid);
      return;
    }
}

void set_breakpoint(pid_t &child_pid, std::intptr_t &addr, std::string &name, bool is_return, bool is_lib_func) {

    breakpoint *bp = new breakpoint(addr, name, is_return, is_lib_func);
    enable_breakpoint(child_pid, bp);
    breakpoints_map.emplace(addr, bp);
}

void dump_reg_buffer(FILE *outfile, long reg, char *reg_str, pid_t pid, uint64_t depth) {
    char buf[4096];
    output_data(outfile, "Register $%s = 0x%llx", reg_str, reg);
    output_data(outfile, "\n");
    for(int tmp = 0; tmp < depth; tmp++) {
        output_data(outfile, "\t");
    }
    if(mem_read(pid, reg, (uint64_t*)&buf, agr) != -1) {
	bool print_string = false;
	for(int i = 0; i < agr || !print_string; i++) {
	    if(i == 0 && print_string == false) {
	    } else if(i % 16 == 0) {
		print_string = !print_string;
		if(print_string) {
		    i -= 16;
		} else {
		    output_data(outfile, "\n");
                    for(int tmp = 0; tmp < depth; tmp++) {
                        output_data(outfile, "\t");
                    }
		}
	    }
	    unsigned char byte = buf[i];
	    if(print_string) {
		if(byte < 32 || byte > 126) {
	            output_data(outfile, ". ");
		} else {
	            output_data(outfile, "%c ", byte);
		}
	    } else {
	        output_data(outfile, "%02x ", byte);
	    }
	}
    }
    output_data(outfile, "\n");
    for(int tmp = 0; tmp < depth; tmp++) {
        output_data(outfile, "\t");
    }
}

void output_with_dwarf(std::vector<std::pair<std::string, std::string>> *args, int index, long reg, FILE *outfile, pid_t pid, uint64_t depth) {
    std::pair<std::string, std::string> arg = args->at(index);
    std::string type_name = arg.second;
    if(index != 0) {
        output_data(outfile, ", ");
    }
    //if(type == 0x86) {
    if(!type_name.compare(std::string("ptr_char"))) {
        char str[4096];
	mem_read(pid, reg, (uint64_t*)&str, 4096);
    	output_data(outfile, "%s = %s", arg.first.c_str(), str);
    } else if (!type_name.compare(std::string("char"))) {
    	output_data(outfile, "%s = 0x%c", arg.first.c_str(), reg);
    } else {
	if(agr != -1) {
	    dump_reg_buffer(outfile, reg, (char*)arg.first.c_str(), pid, depth);
	} else {
    	    output_data(outfile, "%s = 0x%llx", arg.first.c_str(), reg);
	}
    }
}

void output_reg_data(FILE *outfile, struct user_regs_struct *regs, pid_t pid, uint64_t depth) {
    if(agr == -1) {
        output_data(outfile, "Registers ($rdi = 0x%llx, $rsi = 0x%llx, $rdx = 0x%llx, $r10 = 0x%llx, $r8 = 0x%llx, $r9 = 0x%llx)", regs->rdi, regs->rsi, regs->rdx, regs->r10, regs->r8, regs->r9);
    }
    else {
	dump_reg_buffer(outfile, regs->rdi, "rdi", pid, depth);
	dump_reg_buffer(outfile, regs->rsi, "rsi", pid, depth);
	dump_reg_buffer(outfile, regs->rdx, "rdx", pid, depth);
	dump_reg_buffer(outfile, regs->r10, "r10", pid, depth);
	dump_reg_buffer(outfile, regs->r8, "r8", pid, depth);
	dump_reg_buffer(outfile, regs->r9, "r9", pid, depth);
    }
}
void step_over_breakpoint(pid_t &child_pid, FILE* outfile) {
    auto possible_breakpoint_location = get_program_counter(child_pid) - 1;
    char time_str[32];
    struct timeval tv;
    struct user_regs_struct regs;
    static uint64_t depth = 0;


    if (breakpoints_map.count(possible_breakpoint_location)) {
        get_registers(child_pid, &regs);
        breakpoint *bp = breakpoints_map.at(possible_breakpoint_location);
        format_timeval(&tv, time_str, sizeof(time_str));
        if(bp->is_return) {
            depth--;
        }
        for(int i = 0; i < depth; i++) {
            output_data(outfile, "\t");
        }
        if(bp->is_return) {
            output_data(outfile, "return: %s : return value = 0x%llx", bp->name->c_str(), regs.rax);
        } else if(bp->is_lib_func) {
	    if(timestamps)
            	output_data(outfile, "%s ", time_str);
            output_data(outfile, "library call is ");
            output_data(outfile, "%s ", bp->name->c_str());
	    output_reg_data(outfile, &regs, child_pid, depth);
      	    long sp = ptrace(PTRACE_PEEKUSER, child_pid, 8*RSP, 0);
      	    long ret_addr = ptrace(PTRACE_PEEKTEXT, child_pid, sp, 0);
      	    set_breakpoint(child_pid, ret_addr, *bp->name, true, false);
	    depth++;
        } else {
	    if(timestamps)
            	output_data(outfile, "%s ", time_str);
            output_data(outfile, "Static call is ");
            output_data(outfile, "%s ", bp->name->c_str());
	    get_registers(child_pid, &regs);
	    if(bp->args->empty()) {
	        output_reg_data(outfile, &regs, child_pid, depth);
	    } else {
	        output_data(outfile, "Arguements (");
		if(bp->args->size() >= 1) {
	            output_with_dwarf(bp->args, 0, regs.rdi, outfile, child_pid, depth);
		}
		if(bp->args->size() >= 2) {
	            output_with_dwarf(bp->args, 1, regs.rsi, outfile, child_pid, depth);
		}
		if(bp->args->size() >= 3) {
	            output_with_dwarf(bp->args, 2, regs.rdx, outfile, child_pid, depth);
		}
		if(bp->args->size() >= 4) {
	            output_with_dwarf(bp->args, 3, regs.r10, outfile, child_pid, depth);
		}
		if(bp->args->size() >= 5) {
	            output_with_dwarf(bp->args, 4, regs.r8, outfile, child_pid, depth);
		}
		if(bp->args->size() >= 6) {
	            output_with_dwarf(bp->args, 5, regs.r9, outfile, child_pid, depth);
		}
		output_data(outfile, ")");
	    }
      	    long sp = ptrace(PTRACE_PEEKUSER, child_pid, 8*RSP, 0);
      	    long ret_addr = ptrace(PTRACE_PEEKTEXT, child_pid, sp, 0);
	    if(bp->name->compare("_start")) {
      	        set_breakpoint(child_pid, ret_addr, *bp->name, true, false);
	    }
	    depth++;
	}
        auto previous_instruction_address = possible_breakpoint_location;
        set_program_counter(child_pid, previous_instruction_address);
        disable_breakpoint(child_pid, bp);
        ptrace(PTRACE_SINGLESTEP, child_pid, nullptr, nullptr);
        wait_for_signal(child_pid);
	if(!bp->is_return) {
            enable_breakpoint(child_pid, bp);
	}
    } else {
        for(int i = 0; i < depth; i++) {
            output_data(outfile, "\t");
        }
        struct syscall_data data;
        format_timeval(&tv, time_str, sizeof(time_str));
	ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
	long syscall = regs.orig_rax;
	data = syscall_table[syscall];
	if(timestamps)
            output_data(outfile, "%s ", time_str);
	output_data(outfile, "system call is %s ", data.name);
	if(data.func_ptr != NULL) {
	    data.func_ptr(child_pid, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9, outfile);
	} else {
	    output_data(outfile, "Registers ($rdi = 0x%llx, $rsi = 0x%llx, $rdx = 0x%llx, $r10 = 0x%llx, $r8 = 0x%llx, $r9 = 0x%llx)", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
	}
	ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
	wait_for_signal(child_pid);
    }
    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
    output_data(outfile, "\n");
}

void usage() {
    printf("gtrace -flags (program to run) (program args)\n");
    printf("gtrace requires at least one arguement specifying a program to trace\n");
    printf("--timestamps provides timesatmps in trace output\n");
    printf("--outfile filename outputs data to the file specified by filename instead of stdout\n");
    printf("--help prints out options for how to run gtrace\n");
    printf("--aggressive takes an integer and prints out that many bytes from each register when getting function arguements\n");
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {   
    pid_t child_pid;
    long orig_eax;
    if(argc < 2) {
	usage();
    }
    static struct option longopts[] = {
        { "timestamps",	no_argument,		NULL, 		't' },
    	{ "outfile",	required_argument,	NULL, 	       	'f' },
    	{ "aggressive",	required_argument,	NULL, 	       	'a' },
    	{ "help",	no_argument,		NULL, 	       	'h' },
    	{ NULL, 	0,			NULL, 		0 }
    };

    int ch = 0;
    FILE *outfile = stdout;
    while ((ch = getopt_long(argc, argv, "to:a:h", longopts, NULL)) != -1) {
    	switch (ch) {
    	case 't':
    		timestamps = true;
    		break;
    	case 'o':
		if((outfile = fopen(optarg, "w+")) == NULL)
		    fatal("Failed to open outfile %s\n", optarg);
    		break;
    	case 'h':
		usage();
    		break;
    	case 'a':
		agr = strtol(optarg, NULL, 10);
		if(agr <= 0 || agr > 4096)
		    fatal("Number of bytes to aggressivley find is valid for numbers 1-4096\n");
		if(agr % 8 != 0)
		    fatal("Number of bytes to aggressivley find must be multiple of 8\n");
		break;
    	default:
		break;
    	}
    }
    argc -= optind;
    argv += optind;
    child_pid = fork();
    if(child_pid == -1) {
	fatal("Failed to fork child process\n");
    }
    else if(child_pid == 0) {
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
		fatal("FAILED TO SET TRACEME");
        ptrace(PTRACE_SETOPTIONS, 0, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC);
	if(*argv == NULL) {
	    fatal("Program to trace must be specified\n");
	}
	prctl(PR_SET_PDEATHSIG, SIGHUP);
	if(execvp(argv[0], argv) == -1) {
	    fatal("Failed to exec %s for reason %s\n", argv[0], strerror(errno));
	}
    }
    std::string program((std::string)"/proc/" + std::to_string(child_pid) + "/exe");
    wait_for_signal(child_pid);
    elf_parser::Elf_parser elf_parser(program);
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)elf_parser.get_memory_map();
    std::vector<elf_parser::segment_t> segs = elf_parser.get_segments();
    std::vector<elf_parser::symbol_t> symbols = elf_parser.get_symbols();

    uint64_t entry = get_entrypoint(child_pid);
    uint64_t slide = entry - ehdr->e_entry;
    std::vector<elf_parser::relocation_t> relocs = elf_parser.get_relocations();

    for(elf_parser::relocation_t &rel: relocs) {
	if(rel.relocation_symbol_name.empty() || rel.relocation_type.compare(std::string("R_X86_64_JUMP_SLOT"))) {
	    continue;
	}
	std::intptr_t plt_addr = rel.relocation_plt_address + static_cast<std::intptr_t>(slide);
        set_breakpoint(child_pid, plt_addr, rel.relocation_symbol_name, false, true);
    }
    for(auto &sym: symbols) {
	if(sym.symbol_value != 0 && !sym.symbol_type.compare(std::string("FUNC"))) {
	    std::intptr_t sym_addr = sym.symbol_value + static_cast<std::intptr_t>(slide);
            set_breakpoint(child_pid, sym_addr, sym.symbol_name, false, false);
	}
    }

    Dwarf_Debug dbg = 0;
    int fd = -1;
    const char *filepath = NULL;
    int res = DW_DLV_ERROR;
    Dwarf_Error error;
    Dwarf_Handler errhand = 0;
    Dwarf_Ptr errarg = 0;
    filepath = *argv;
    fd = open(filepath,O_RDONLY);
    if(fd < 0) {
	fatal("Failure attempting to open %s\n",filepath);
    }
    res = dwarf_init(fd,DW_DLC_READ,errhand,errarg, &dbg,&error);
    if(res == DW_DLV_OK) {
	read_cu_list(dbg);
	res = dwarf_finish(dbg,&error);
	if(res != DW_DLV_OK) {
	    printf("dwarf_finish failed!\n");
	}
    }
    close(fd);

    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
    while(1) { 
      wait_for_signal(child_pid);
      step_over_breakpoint(child_pid, outfile);
    }
    return 0;
}

ssize_t format_timeval(struct timeval *tv, char *buf, size_t sz)
{
  ssize_t written = -1;
  struct tm *gm = gmtime(&tv->tv_sec);

  if (gm)
  {
    written = (ssize_t)strftime(buf, sz, "%Y-%m-%dT%H:%M:%S", gm);
    if ((written > 0) && ((size_t)written < sz))
    {
      int w = snprintf(buf+written, sz-(size_t)written, ".%06dZ", tv->tv_usec);
      written = (w > 0) ? written + w : -1;
    }
  }
  return written;
}

static void 
read_cu_list(Dwarf_Debug dbg)
{
	Dwarf_Unsigned cu_header_length = 0;
	Dwarf_Half version_stamp = 0;
	Dwarf_Unsigned abbrev_offset = 0;
	Dwarf_Half address_size = 0;
	Dwarf_Unsigned next_cu_header = 0;
	Dwarf_Error error;
	int cu_number = 0;

	for(;;++cu_number) {
		Dwarf_Die no_die = 0;
		Dwarf_Die cu_die = 0;
		int res = DW_DLV_ERROR;
		res = dwarf_next_cu_header(dbg,&cu_header_length,
				&version_stamp, &abbrev_offset, &address_size,
				&next_cu_header, &error);

		if(res == DW_DLV_ERROR) {
			fatal("Error in dwarf_next_cu_header\n");
		}
		if(res == DW_DLV_NO_ENTRY) {
			/* Done. */
			return;
		}
		/* The CU will have a single sibling, a cu_die. */
		res = dwarf_siblingof(dbg,no_die,&cu_die,&error);
		if(res == DW_DLV_ERROR) {
			fatal("Error in dwarf_siblingof on CU die \n");
		}
		if(res == DW_DLV_NO_ENTRY) {
			/* Impossible case. */
			fatal("no entry! in dwarf_siblingof on CU die \n");
		}

		get_die_and_siblings(dbg,cu_die,0);

		dwarf_dealloc(dbg,cu_die,DW_DLA_DIE);

	}
}

static void
get_die_and_siblings(Dwarf_Debug dbg, Dwarf_Die in_die,int in_level)
{
	int res = DW_DLV_ERROR;
	Dwarf_Die cur_die=in_die;
	Dwarf_Die sib_die=in_die;
	Dwarf_Die child = 0;
	Dwarf_Die sibling = 0;
	Dwarf_Error error;

	/* Who am I? */
	print_die_data(dbg,in_die,in_level);

	///* First son, if any */
	res = dwarf_child(cur_die,&child,&error);


        ///* traverse tree depth first */
	if(res == DW_DLV_OK)
	{ get_die_and_siblings(dbg, child, in_level+1); /* recur on the first son */
		sib_die = child;
		while(res == DW_DLV_OK) {
                        cur_die = sib_die;
			res = dwarf_siblingof_b(dbg, cur_die, 1, &sib_die, &error);
			get_die_and_siblings(dbg, sib_die, in_level+1); /* recur others */
		};
	}

	return;
}

breakpoint* get_breakpoint_with_dwarf(char *name, int tag) {
    for (auto const& element : breakpoints_map)
    {
        if(!strcmp(element.second->name->c_str(), name)) {
    	    return element.second;
        }
    }
    return nullptr;
}
static void
print_die_data(Dwarf_Debug dbg, Dwarf_Die print_me,int level)
{
	char *name = 0;
	char *type_name = 0;
	Dwarf_Error error = 0;
	Dwarf_Half tag = 0;
	const char *tagname = 0;
	Dwarf_Line* line;

	Dwarf_Bool bAttr;
	Dwarf_Attribute attr;
	int res = 0;
	Dwarf_Unsigned in_line;
	Dwarf_Unsigned in_file = 0;
	Dwarf_Off offset;
	Dwarf_Die typedie;

	Dwarf_Locdesc * loc_list;
	Dwarf_Signed num_loc;

	Dwarf_Off  ptr_address = 0;
	static breakpoint *brk = nullptr;

	int has_line_data = !dwarf_hasattr( print_me, DW_AT_decl_line, &bAttr, &error) && bAttr;
	if(has_line_data){

		/* Here we know that we have debug information for line numbers
		   in this compilation unit. Let's keep working */

		/* Using short-circuiting to ensure all steps are done in order; if a chain finishes, we know we have stored our values */
		int got_name = !dwarf_diename(print_me,&name,&error); 
		int got_line = !dwarf_attr(print_me, DW_AT_decl_line, &attr, &error) && !dwarf_formudata(attr, &in_line, &error);
		int got_file = !dwarf_attr(print_me, DW_AT_decl_file, &attr, &error) && !dwarf_formudata(attr, &in_file, &error);
		int got_loclist = !dwarf_hasattr(print_me, DW_AT_location, &bAttr, &error) && !dwarf_attr(print_me, DW_AT_location, &attr, &error)
			&& !dwarf_loclist(attr, &loc_list, &num_loc, &error);

		int got_tag_name = !dwarf_tag(print_me,&tag,&error) && dwarf_get_TAG_name(tag,&tagname);

		if(got_name && got_line && got_file){
			/* Location lists are structs; see ftp://ftp.sgi.com/sgi/dwarf/libdwarf.h */
			if(tag == DW_TAG_formal_parameter){
			    std::string type_namecpp;
		            dwarf_attr(print_me, DW_AT_type, &attr, &error);
		            dwarf_global_formref(attr, &offset, &error);
		            dwarf_offdie_b(dbg, offset, 1, &typedie, &error);
		            dwarf_diename(typedie,&type_name,&error); 
			    if(type_name != NULL) {
			        type_namecpp = std::string(type_name);
			    } else {
		                //DWARF marks pointers purely as pointers aand you need to reference another DIE Object
		                //to get the type the pointer points to.
		                dwarf_attr(typedie, DW_AT_type, &attr, &error);
		                dwarf_global_formref(attr, &offset, &error);
		                dwarf_offdie_b(dbg, offset, 1, &typedie, &error);
		                dwarf_diename(typedie,&type_name,&error); 
				type_namecpp = std::string("ptr_") + std::string(type_name);
		            }
				//printf("<%llu:%llu> tag: %d %s  name: %s loc: %lld type %lld\n",in_file, in_line,tag,tagname,name,loc_list[0].ld_s[0].lr_number, offset);
				auto arg_data = std::pair<std::string,std::string>(std::string(name), type_namecpp);
				bool add = true;
				for(std::pair<std::string,std::string> &iter : *brk->args) {
				    if(!strcmp(iter.first.c_str(), name)) {
					add = false;
					break;
				    }
				}
				if(add)
				    brk->args->push_back(arg_data);
                                //breakpoint brk = update_breakpoint_with_dwarf(char *name, int tag);
			} else if (tag == DW_TAG_subprogram) {
					//printf("<%llu:%llu> tag: %d %s  name: %s obj_pointer: 0x%llx \n",in_file, in_line,tag,tagname,name, 0x0);
                                        brk = get_breakpoint_with_dwarf(name, tag);

			}

		}

	}
	dwarf_dealloc(dbg,name,DW_DLA_STRING);
}
