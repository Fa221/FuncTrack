#define _POSIX_SOURCE 1
#define _DEFAULT_SOURCE 1
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/vfs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "pretty_print.h"
#include <utime.h>
#include <dirent.h>
#include <sys/times.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <time.h>
#include <sys/timex.h>
#include <linux/capability.h>
//#include <ustat.h>
#include <sys/types.h>
#include <linux/kexec.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sched.h>
#include <sys/mount.h>
#include <asm/ldt.h>
#include<sys/reboot.h>
#include <limits.h>
#include <linux/limits.h>
#include <linux/aio_abi.h>
#include <dirent.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/epoll.h>
#include <mqueue.h>
#include <sys/stat.h>
#include <poll.h>
#include <linux/futex.h>
#include <signal.h>
#include <ucontext.h>
#include <stdlib.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sendfile.h>
#include <sys/ipc.h>
#include <sys/shm.h>
//#include <linux/time.h>
#include "utils.h"


static void print_statfs_struct(FILE *outfile, struct statfs *s);
static void print_sockaddr(FILE *outfile, struct sockaddr *sock);


SYSCALL_PRINT_FUNC(close) {
    output_data(outfile, "fd = %ld", arg1);
}

SYSCALL_PRINT_FUNC(mmap) {
    output_data(outfile, "addr = 0x%lx length = %lu prot = %ld flags = %ld fd = %ld offset = %lu", arg1, arg2, arg3, arg4, arg5, arg6);
}

SYSCALL_PRINT_FUNC(mprotect) {
    output_data(outfile, "addr = 0x%lx len = %lu prot = %ld", arg1, arg2, arg3);
}

SYSCALL_PRINT_FUNC(munmap) {
    output_data(outfile, "addr = 0x%lx length = %lu", arg1, arg2);
}
SYSCALL_PRINT_FUNC(brk) {
    output_data(outfile,"addr = 0x%lx", arg1);
}

SYSCALL_PRINT_FUNC(access) {
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile,"pathname = %s mode = %ld", filepath, arg2);
}

SYSCALL_PRINT_FUNC(read) {
    output_data(outfile,"fd = %ld buf = 0x%lx count = %ld", arg1, arg2, arg3);
}

SYSCALL_PRINT_FUNC(write) {
    output_data(outfile,"fd = %ld buf = 0x%lx count = %ld", arg1, arg2, arg3);
}

SYSCALL_PRINT_FUNC(open) {
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile,"pathname = %s flags = %ld mode = %ld", filepath, arg2, arg3);
}

SYSCALL_PRINT_FUNC(stat) {
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile,"pathname = %s statbuf = 0x%lx", filepath, arg2);
}

SYSCALL_PRINT_FUNC(fstat) {
    output_data(outfile,"fd = %ld statbuf = 0x%lx", arg1, arg2);
}

SYSCALL_PRINT_FUNC(lstat) {
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile,"pathname = %s statbuf = 0x%lx", filepath, arg2);
}


SYSCALL_PRINT_FUNC(poll) {
    output_data(outfile,"nfds = %lu timeout = %lu\n", arg1, arg2);

    for (unsigned int i = 0; i < arg1; i++) {
        struct pollfd pfd;
        mem_read(pid, arg3 + i * sizeof(struct pollfd), (uint64_t*)&pfd, sizeof(pfd));
        output_data(outfile,"fd[%u] = %d events = %hd revents = %hd\n", i, pfd.fd, pfd.events, pfd.revents);
    }
}

SYSCALL_PRINT_FUNC(lseek) {
    const char* whence_str;
    int fd = arg1;             // File descriptor
    off_t offset = arg2;       // Offset
    int whence = arg3;         // Whence value

    switch (whence) {
        case SEEK_SET: whence_str = "SEEK_SET"; break;
        case SEEK_CUR: whence_str = "SEEK_CUR"; break;
        case SEEK_END: whence_str = "SEEK_END"; break;
        default: whence_str = "UNKNOWN"; break;
    }

    output_data(outfile,"fd = %d offset = %lld whence = %s", fd, (long long)offset, whence_str);
}


SYSCALL_PRINT_FUNC(rt_sigaction) {
    struct sigaction act_buf;

    output_data(outfile,"signum = %ld sigsetsize = %lu", arg1, arg2);

    if (arg3) {
        mem_read(pid, arg3, (uint64_t*)&act_buf, sizeof(act_buf));
        output_data(outfile,"\nnew action:\n");
        output_data(outfile,"sa_handler = %p ", act_buf.sa_handler);
        //output_data(outfile,"sa_sigaction = %p ", act_buf.sa_sigaction);
        output_data(outfile,"sa_flags = %d ", act_buf.sa_flags);
    }
    if (arg4) {
        mem_read(pid, arg4, (uint64_t*)&act_buf, sizeof(act_buf));
        output_data(outfile,"\nold action:\n");
        output_data(outfile,"sa_handler = %p ", act_buf.sa_handler);
        //output_data(outfile,"sa_sigaction = %p ", act_buf.sa_sigaction);
        output_data(outfile,"sa_flags = %d ", act_buf.sa_flags);
    }
}

// Function to print a sigset_t in a human-readable format
void print_signal_set(sigset_t *set, FILE *outfile) {
    int first = 1;

    output_data(outfile,"{");
    for (int sig = 1; sig < NSIG; sig++) {
        if (sigismember(set, sig)) {
            if (!first) {
                output_data(outfile,", ");
            }
            output_data(outfile,"%d", sig);
            first = 0;
        }
    }
    output_data(outfile,"}");
}

SYSCALL_PRINT_FUNC(rt_sigprocmask) {
    const char* how_str;
    sigset_t set_buf;

    int how = arg1;             // The "how" parameter
    size_t sigsetsize = arg2;   // The "sigsetsize" parameter
    uint64_t set = arg3;        // The "set" parameter
    uint64_t oldset = arg4;     // The "oldset" parameter

    switch (how) {
        case SIG_BLOCK: how_str = "SIG_BLOCK"; break;
        case SIG_UNBLOCK: how_str = "SIG_UNBLOCK"; break;
        case SIG_SETMASK: how_str = "SIG_SETMASK"; break;
        default: how_str = "UNKNOWN"; break;
    }

    output_data(outfile,"how = %s sigsetsize = %zu", how_str, sigsetsize);

    if (set) {
        mem_read(pid, set, (uint64_t*)&set_buf, sigsetsize);
        output_data(outfile,"\nnew set = ");
        print_signal_set(&set_buf, outfile);
    }

    if (oldset) {
        mem_read(pid, oldset, (uint64_t*)&set_buf, sigsetsize);
        output_data(outfile,"\nold set = ");
        print_signal_set(&set_buf, outfile);
    }
}

SYSCALL_PRINT_FUNC(rt_sigreturn) {
    stack_t altstack;
    sigset_t sigmask;

    // Retrieve the alternate signal stack information
    if (sigaltstack(NULL, &altstack) == 0) {
        output_data(outfile,"Alternate signal stack:\n");
        output_data(outfile,"ss_sp = 0x%lx, ss_size = %zu, ss_flags = 0x%lx\n",
               (unsigned long)altstack.ss_sp, altstack.ss_size, (unsigned long)altstack.ss_flags);
    }

    // Retrieve the current signal mask
    if (sigprocmask(SIG_BLOCK, NULL, &sigmask) == 0) {
        output_data(outfile,"Current signal mask:\n");
        // Print the signal numbers in the mask
        for (int sig = 1; sig < NSIG; sig++) {
            if (sigismember(&sigmask, sig)) {
                output_data(outfile,"%d ", sig);
            }
        }
        output_data(outfile,"\n");
    }
}

SYSCALL_PRINT_FUNC(ioctl) {
    int fd = (int)arg1;         // File descriptor
    unsigned long request = (unsigned long)arg2;  // IOCTL request
    unsigned long argp = arg3;  // Argument for IOCTL

    output_data(outfile,"ioctl: fd = %d, request = 0x%lx, argp = 0x%lx\n", fd, request, argp);


    // Print the command code and device type (assuming request format is 32-bit)
    int command_code = (int)(request & 0xFF);
    int device_type = (int)((request >> 8) & 0xFF);
    output_data(outfile,"  Command Code: %d, Device Type: %d\n", command_code, device_type);
}

SYSCALL_PRINT_FUNC(pread64) {
    int fd = (int)arg1;          // File descriptor
    void* buf = (void*)arg2;     // Buffer address
    size_t count = (size_t)arg3; // Number of bytes to read
    off_t offset = (off_t)arg4;  // Offset within the file

    output_data(outfile,"pread64: fd = %d, buf = 0x%lx, count = %zu, offset = %lld\n", fd, (unsigned long)buf, count, (long long)offset);
}

SYSCALL_PRINT_FUNC(pwrite64) {
    int fd = (int)arg1;          // File descriptor
    const void* buf = (const void*)arg2; // Buffer address
    size_t count = (size_t)arg3; // Number of bytes to write
    off_t offset = (off_t)arg4;  // Offset within the file

    output_data(outfile,"pwrite64: fd = %d, buf = 0x%lx, count = %zu, offset = %lld\n", fd, (unsigned long)buf, count, (long long)offset);
}

SYSCALL_PRINT_FUNC(readv) {
    int fd = (int)arg1;                // File descriptor
    struct iovec* iov = (struct iovec*)arg2; // Array of struct iovec
    int iovcnt = (int)arg3;            // Number of struct iovec elements

    output_data(outfile,"readv: fd = %d, iov = 0x%lx, iovcnt = %d\n", fd, (unsigned long)iov, iovcnt);

    // Print the details of each struct iovec
    for (int i = 0; i < iovcnt; i++) {
        output_data(outfile,"  iovec[%d]: iov_base = 0x%lx, iov_len = %zu\n", i, (unsigned long)iov[i].iov_base, iov[i].iov_len);
    }
}


SYSCALL_PRINT_FUNC(writev) {
    int fd = (int)arg1;                // File descriptor
    struct iovec* iov = (struct iovec*)arg2; // Array of struct iovec
    int iovcnt = (int)arg3;            // Number of struct iovec elements

    output_data(outfile,"writev: fd = %d, iov = 0x%lx, iovcnt = %d\n", fd, (unsigned long)iov, iovcnt);

    // Print the details of each struct iovec
    for (int i = 0; i < iovcnt; i++) {
        output_data(outfile,"  iovec[%d]: iov_base = 0x%lx, iov_len = %zu\n", i, (unsigned long)iov[i].iov_base, iov[i].iov_len);
    }
}

SYSCALL_PRINT_FUNC(pipe) {
    int* pipefd = (int*)arg1;  // Pointer to an integer array for the pipe file descriptors

    output_data(outfile,"pipe: pipefd = 0x%lx\n", (unsigned long)pipefd);

    if (pipefd) {
        output_data(outfile,"  pipefd[0] (read end) = %d, pipefd[1] (write end) = %d\n", pipefd[0], pipefd[1]);
    }
}

SYSCALL_PRINT_FUNC(select) {
    int nfds = (int)arg1 + 1;        // Number of file descriptors to check
    fd_set* readfds = (fd_set*)arg2; // Read file descriptor set
    fd_set* writefds = (fd_set*)arg3; // Write file descriptor set
    fd_set* exceptfds = (fd_set*)arg4; // Exception file descriptor set
    struct timeval* timeout = (struct timeval*)arg5; // Timeout

    output_data(outfile,"select: nfds = %d, timeout = { tv_sec = %ld, tv_usec = %ld }\n", nfds, timeout ? timeout->tv_sec : 0, timeout ? timeout->tv_usec : 0);

    // Print the read file descriptor set
    if (readfds) {
        output_data(outfile,"  Read FDs: ");
        for (int i = 0; i < nfds; i++) {
            if (FD_ISSET(i, readfds)) {
                output_data(outfile,"%d ", i);
            }
        }
        output_data(outfile,"\n");
    }

    // Print the write file descriptor set
    if (writefds) {
        output_data(outfile,"  Write FDs: ");
        for (int i = 0; i < nfds; i++) {
            if (FD_ISSET(i, writefds)) {
                output_data(outfile,"%d ", i);
            }
        }
        output_data(outfile,"\n");
    }

    // Print the exception file descriptor set
    if (exceptfds) {
        output_data(outfile,"  Exception FDs: ");
        for (int i = 0; i < nfds; i++) {
            if (FD_ISSET(i, exceptfds)) {
                output_data(outfile,"%d ", i);
            }
        }
        output_data(outfile,"\n");
    }
}

SYSCALL_PRINT_FUNC(sched_yield) {
    output_data(outfile,"sched_yield: Yielding CPU to other tasks.\n");
}

SYSCALL_PRINT_FUNC(mremap) {
    uint64_t old_addr, old_size, new_addr, new_size;

    // Read the arguments using mem_read
    if (mem_read(pid, arg1, &old_addr, sizeof(uint64_t)) == 0 &&
        mem_read(pid, arg2, &old_size, sizeof(uint64_t)) == 0 &&
        mem_read(pid, arg3, &new_addr, sizeof(uint64_t)) == 0 &&
        mem_read(pid, arg4, &new_size, sizeof(uint64_t)) == 0) {

        output_data(outfile,"mremap: old_addr = 0x%lx, old_size = %lu, new_addr = 0x%lx, new_size = %lu\n",
               old_addr, old_size, new_addr, new_size);
    } else {
        output_data(outfile,"mremap: Failed to read syscall arguments.\n");
    }
}

SYSCALL_PRINT_FUNC(msync) {
    void *addr;
    size_t length;
    int flags;

    // Read memory address, length, and flags from the target process
    if (mem_read(pid, arg1, (uint64_t*)&addr, sizeof(addr)) != 0 ||
        mem_read(pid, arg2, (uint64_t*)&length, sizeof(length)) != 0 ||
        mem_read(pid, arg3, (uint64_t*)&flags, sizeof(flags)) != 0) {
        output_data(outfile,"Failed to read syscall arguments from target process.\n");
        return;
    }

    output_data(outfile,"msync: addr = %p, length = %zu", addr, length);

    // Check and print the synchronization flags
    if (flags & _SC_FSYNC) {
        output_data(outfile,", _SC_ASYNC");
    }
    if (flags & _SC_FSYNC) {
        output_data(outfile,", _SC_SYNC");
    }
    output_data(outfile,"\n");
}
SYSCALL_PRINT_FUNC(mincore) {
    void *start;
    size_t length;
    unsigned char *vec;

    // Read memory address, length, and vector from the target process
    if (mem_read(pid, arg1, (uint64_t*)&start, sizeof(start)) != 0 ||
        mem_read(pid, arg2, (uint64_t*)&length, sizeof(length)) != 0 ||
        mem_read(pid, arg3, (uint64_t*)&vec, sizeof(vec)) != 0) {
        output_data(outfile,"Failed to read syscall arguments from the target process.\n");
        return;
    }

    output_data(outfile,"mincore: start = %p, length = %zu\n", start, length);

    // Print the vector indicating which pages are in memory
    output_data(outfile,"mincore: vector = [");
    for (size_t i = 0; i < length; i++) {
        if (i > 0) {
            output_data(outfile,", ");
        }
        output_data(outfile,"%c", vec[i] & 1 ? '*' : ' ');
    }
    output_data(outfile,"]\n");
}
SYSCALL_PRINT_FUNC(madvise) {
    void *addr;
    size_t length;
    int advice;

    // Read memory address, length, and advice from the target process
    if (mem_read(pid, arg1, (uint64_t*)&addr, sizeof(addr)) != 0 ||
        mem_read(pid, arg2, (uint64_t*)&length, sizeof(length)) != 0 ||
        mem_read(pid, arg3, (uint64_t*)&advice, sizeof(advice)) != 0) {
        output_data(outfile,"Failed to read syscall arguments from the target process.\n");
        return;
    }

    output_data(outfile,"madvise: addr = %p, length = %zu, advice = ", addr, length);

    switch (advice) {
        case MADV_NORMAL:
            output_data(outfile,"MADV_NORMAL\n");
            break;
        case MADV_RANDOM:
            output_data(outfile,"MADV_RANDOM\n");
            break;
        case MADV_SEQUENTIAL:
            output_data(outfile,"MADV_SEQUENTIAL\n");
            break;
        case MADV_WILLNEED:
            output_data(outfile,"MADV_WILLNEED\n");
            break;
        case MADV_DONTNEED:
            output_data(outfile,"MADV_DONTNEED\n");
            break;
        default:
            output_data(outfile,"UNKNOWN (%d)\n", advice);
    }
}

SYSCALL_PRINT_FUNC(shmget) {
    key_t key;
    size_t size;
    int shmflg;

    // Read the key, size, and shmflg arguments from the target process
    if (mem_read(pid, arg1, (uint64_t*)&key, sizeof(key)) != 0 ||
        mem_read(pid, arg2, (uint64_t*)&size, sizeof(size)) != 0 ||
        mem_read(pid, arg3, (uint64_t*)&shmflg, sizeof(shmflg)) != 0) {
        output_data(outfile,"Failed to read syscall arguments from the target process.\n");
        return;
    }

    output_data(outfile,"shmget: key = %d, size = %zu, shmflg = 0%o\n", key, size, shmflg);
}

SYSCALL_PRINT_FUNC(shmat) {
    int shmid;
    void *shmaddr;
    int shmflg;

    // Read the shmid, shmaddr, and shmflg arguments from the target process
    if (mem_read(pid, arg1, (uint64_t*)&shmid, sizeof(shmid)) != 0 ||
        mem_read(pid, arg2, (uint64_t*)&shmaddr, sizeof(shmaddr)) != 0 ||
        mem_read(pid, arg3, (uint64_t*)&shmflg, sizeof(shmflg)) != 0) {
        output_data(outfile,"Failed to read syscall arguments from the target process.\n");
        return;
    }

    output_data(outfile,"shmat: shmid = %d, shmaddr = %p, shmflg = 0%o\n", shmid, shmaddr, shmflg);
}

SYSCALL_PRINT_FUNC(shmctl) {
    int shmid;
    int cmd;
    struct shmid_ds buf;

    // Read the shmid, cmd, and buf arguments from the target process
    if (mem_read(pid, arg1, (uint64_t*)&shmid, sizeof(shmid)) != 0 ||
        mem_read(pid, arg2, (uint64_t*)&cmd, sizeof(cmd)) != 0 ||
        mem_read(pid, arg3, (uint64_t*)&buf, sizeof(buf)) != 0) {
        output_data(outfile,"Failed to read syscall arguments from the target process.\n");
        return;
    }

    output_data(outfile,"shmctl: shmid = %d, cmd = %d\n", shmid, cmd);

    // Print information based on the cmd value
    switch (cmd) {
        case IPC_STAT:
            output_data(outfile,"IPC_STAT:\n");
            output_data(outfile,"  shm_perm.uid = %d\n", buf.shm_perm.uid);
            output_data(outfile,"  shm_perm.gid = %d\n", buf.shm_perm.gid);
            output_data(outfile,"  shm_perm.cuid = %d\n", buf.shm_perm.cuid);
            output_data(outfile,"  shm_perm.cgid = %d\n", buf.shm_perm.cgid);
            output_data(outfile,"  shm_perm.mode = 0%o\n", buf.shm_perm.mode);
            output_data(outfile,"  shm_perm.key = %d\n", buf.shm_perm.__key);
            output_data(outfile,"  shm_segsz = %zu bytes\n", buf.shm_segsz);
            output_data(outfile,"  shm_atime = %ld\n", buf.shm_atime);
            output_data(outfile,"  shm_dtime = %ld\n", buf.shm_dtime);
            output_data(outfile,"  shm_ctime = %ld\n", buf.shm_ctime);
            output_data(outfile,"  shm_cpid = %d\n", buf.shm_cpid);
            output_data(outfile,"  shm_lpid = %d\n", buf.shm_lpid);
            output_data(outfile,"  shm_nattch = %lu\n", (unsigned long)buf.shm_nattch);
            break;

        case IPC_SET:
            output_data(outfile,"IPC_SET (Not displaying details)\n");
            break;

        case IPC_RMID:
            output_data(outfile,"IPC_RMID (Removing shared memory segment)\n");
            break;

        default:
            output_data(outfile,"Unknown cmd value: %d\n", cmd);
            break;
    }
}

SYSCALL_PRINT_FUNC(dup) {
    int old_fd = arg1;
    int new_fd = arg2;  // The return value of dup is the new file descriptor

    output_data(outfile,"dup: old_fd = %d, new_fd = %d\n", old_fd, new_fd);
}

SYSCALL_PRINT_FUNC(dup2) {
    int old_fd = arg1;
    int new_fd = arg2;

    output_data(outfile,"dup2: old_fd = %d, new_fd = %d\n", old_fd, new_fd);
}

SYSCALL_PRINT_FUNC(pause) {
    output_data(outfile,"pause: Process is waiting for a signal\n");
}

SYSCALL_PRINT_FUNC(nanosleep) {
    struct timespec req, rem;

    mem_read(pid, arg1, (uint64_t*)&req, sizeof(req));

    output_data(outfile,"nanosleep: Requested sleep time: %ld seconds %ld nanoseconds\n", req.tv_sec, req.tv_nsec);

    // Check if the syscall was interrupted based on the arg2 parameter.
    if (arg2 != 0) {
        mem_read(pid, arg2, (uint64_t*)&rem, sizeof(rem));
        output_data(outfile,"nanosleep: Sleep was interrupted. Remaining time: %ld seconds %ld nanoseconds\n", rem.tv_sec, rem.tv_nsec);
    } else {
        output_data(outfile,"nanosleep: Sleep completed successfully\n");
    }
}

SYSCALL_PRINT_FUNC(getitimer) {
    struct itimerval itimer;

    mem_read(pid, arg1, (uint64_t*)&itimer, sizeof(itimer));

    output_data(outfile,"getitimer: which = %ld, value = {%ld, %ld}, it_interval = {%ld, %ld}\n",
           (long)arg1, itimer.it_value.tv_sec, itimer.it_value.tv_usec,
           itimer.it_interval.tv_sec, itimer.it_interval.tv_usec);
}

SYSCALL_PRINT_FUNC(alarm) {
    long seconds;
    if (mem_read(pid, (uint64_t)arg1, (uint64_t*)&seconds, sizeof(seconds)) == 0) {
        output_data(outfile,"alarm: seconds = %ld\n", seconds);
    } else {
        output_data(outfile,"Failed to read alarm value from process memory.\n");
    }
}

SYSCALL_PRINT_FUNC(setitimer) {
    int which = arg1;
    struct itimerval new_value;

    if (mem_read(pid, (uint64_t)arg2, (uint64_t*)&new_value, sizeof(new_value)) == 0) {
        output_data(outfile,"setitimer: which = %d\n", which);

        output_data(outfile,"it_interval: tv_sec = %ld, tv_usec = %ld\n", new_value.it_interval.tv_sec, new_value.it_interval.tv_usec);
        output_data(outfile,"it_value: tv_sec = %ld, tv_usec = %ld\n", new_value.it_value.tv_sec, new_value.it_value.tv_usec);
    } else {
        output_data(outfile,"Failed to read setitimer values from process memory.\n");
    }
}

SYSCALL_PRINT_FUNC(getpid) {
    pid_t process_id = getpid();
    output_data(outfile,"PID: %d\n", process_id);
}


SYSCALL_PRINT_FUNC(sendfile) {
    int out_fd = (int)arg1;    // The file descriptor to send to
    int in_fd = (int)arg2;     // The file descriptor to send from
    off_t *offset = (off_t *)arg3;  // Pointer to the file offset
    size_t count = (size_t)arg4;   // Number of bytes to send

    // Perform the sendfile syscall and get the return value
    ssize_t retval = sendfile(out_fd, in_fd, offset, count);

    // Print the syscall information
    output_data(outfile,"sendfile: out_fd = %d, in_fd = %d, offset = %lld, count = %zu\n",
           out_fd, in_fd, (long long)*offset, count);

    // Print the return value
    output_data(outfile,"sendfile: retval = %zd\n", retval);
}

SYSCALL_PRINT_FUNC(socket) {
    int domain = arg1;    // The first argument is the socket domain
    int type = arg2;      // The second argument is the socket type
    int protocol = arg3;  // The third argument is the protocol

    output_data(outfile,"domain = %d, type = %d, protocol = %d\n", domain, type, protocol);
}

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

SYSCALL_PRINT_FUNC(connect) {
    int sockfd = arg1; // The first argument is the socket file descriptor
    struct sockaddr addr;
    socklen_t addrlen;

    // Read the sockaddr structure
    mem_read(pid, arg2, (uint64_t*)&addr, sizeof(addr));

    // Read the length of the sockaddr structure
    mem_read(pid, arg3, (uint64_t*)&addrlen, sizeof(addrlen));

    // Now you can print the sockfd, sockaddr, and addrlen
    output_data(outfile,"sockfd = %d\n", sockfd);

    // Print the contents of the sockaddr structure
    output_data(outfile,"addr = ");
    print_sockaddr(outfile, &addr);

    // Print the length of the sockaddr structure
    output_data(outfile,"addrlen = %zu\n", (size_t)addrlen);
}

SYSCALL_PRINT_FUNC(accept) {
    int sockfd = arg1;  // The socket file descriptor
    struct sockaddr *addr = (struct sockaddr *)arg2;  // The address of the client
    socklen_t *addrlen = (socklen_t *)arg3;  // The size of the address structure
    output_data(outfile,"accept: sockfd = %d\n", sockfd);
    if (addr && addrlen) {
        // Print the client's address information
        print_sockaddr(outfile, addr);

        // Print the size of the address structure
        output_data(outfile,"addrlen = %u\n", *addrlen);
    } else {
        output_data(outfile,"Invalid address or addrlen pointers\n");
    }
}

SYSCALL_PRINT_FUNC(sendto) {
    int sockfd = arg1;  // The socket file descriptor
    size_t len = arg3;  // The length of the data
    int flags = arg4;  // Flags for sendto
    const struct sockaddr *dest_addr = (const struct sockaddr *)arg5;  // The destination address
    socklen_t addrlen = arg6;  // The size of the destination address

    // Perform the sendto syscall

    // Check for errors and handle as needed

    // Print the result
    output_data(outfile,"sendto: sockfd = %d, len = %zu, flags = %d\n", sockfd, len, flags);

    // Check if dest_addr is a valid pointer and addrlen is non-zero
    if (dest_addr && addrlen > 0) {
        // Print the destination address information
        output_data(outfile,"Destination Address:\n");
        print_sockaddr(outfile, dest_addr);

        // Print the size of the destination address
        output_data(outfile,"addrlen = %u\n", addrlen);
    } else {
        output_data(outfile,"Invalid destination address or addrlen\n");
    }
}

SYSCALL_PRINT_FUNC(recvfrom) {
    int sockfd = arg1;  // The socket file descriptor
    size_t len = arg3;  // The length of the data
    int flags = arg4;   // Flags for recvfrom
    struct sockaddr_storage src_addr;  // The source address (can be IPv4 or IPv6)
    socklen_t addrlen = sizeof(src_addr);  // The size of the source address

    // Perform the recvfrom syscall

    // Check for errors and handle as needed

    // Print the result
    output_data(outfile,"recvfrom: sockfd = %d, len = %zu, flags = %d\n", sockfd, len, flags);

    // Check if addrlen is non-zero
    if (addrlen > 0) {
        // Print the source address information
        output_data(outfile,"Source Address:\n");
        print_sockaddr(outfile, (const struct sockaddr *)&src_addr);

        // Print the size of the source address
        output_data(outfile,"addrlen = %u\n", addrlen);
    } else {
        output_data(outfile,"Invalid addrlen\n");
    }
}

SYSCALL_PRINT_FUNC(sendmsg) {
    int sockfd = arg1;  // The socket file descriptor
    struct msghdr msg;  // The message header structure
    size_t len = arg3;  // The length of the data

    mem_read(pid, arg2, (uint64_t*)&msg, sizeof(msg));

    output_data(outfile,"sendmsg: sockfd = %d, len = %zu\n", sockfd, len);

    output_data(outfile,"Message Header:\n");
    output_data(outfile,"msg_name = %p, msg_namelen = %u\n", msg.msg_name, msg.msg_namelen);
    output_data(outfile,"msg_iov = %p, msg_iovlen = %zu\n", msg.msg_iov, msg.msg_iovlen);
    output_data(outfile,"msg_control = %p, msg_controllen = %zu\n", msg.msg_control, msg.msg_controllen);
    output_data(outfile,"msg_flags = %d\n", msg.msg_flags);
    if (msg.msg_control && msg.msg_controllen > 0) {
        output_data(outfile,"Ancillary Data (msg_control):\n");
    }
}

SYSCALL_PRINT_FUNC(recvmsg) {
    int sockfd = arg1;  // The socket file descriptor
    struct msghdr msg;  // The message header structure
    size_t len = arg3;  // The length of the data received

    // Use mem_read to read the msg structure from the process's memory
    mem_read(pid, arg2, (uint64_t*)&msg, sizeof(msg));

    // Print the result
    output_data(outfile,"recvmsg: sockfd = %d, len = %zu\n", sockfd, len);

    // Print the message header fields
    output_data(outfile,"Message Header:\n");
    output_data(outfile,"msg_name = %p, msg_namelen = %u\n", msg.msg_name, msg.msg_namelen);
    output_data(outfile,"msg_iov = %p, msg_iovlen = %zu\n", msg.msg_iov, msg.msg_iovlen);
    output_data(outfile,"msg_control = %p, msg_controllen = %zu\n", msg.msg_control, msg.msg_controllen);
    output_data(outfile,"msg_flags = %d\n", msg.msg_flags);

    // Handle msg_control (ancillary data) if it's available
    if (msg.msg_control && msg.msg_controllen > 0) {
        // Process and print the ancillary data
        output_data(outfile,"Ancillary Data (msg_control):\n");
        // Implement code to parse and print ancillary data here if needed.
    }

    // Print the received data if available
    if (msg.msg_iovlen > 0 && msg.msg_iov[0].iov_base) {
        char* received_data = (char*)malloc(len);
        mem_read(pid, (uint64_t)msg.msg_iov[0].iov_base, (uint64_t*)received_data, len);
        output_data(outfile,"Received Data:\n");
        output_data(outfile,"%.*s\n", (int)len, received_data);
        free(received_data);
    }
}

SYSCALL_PRINT_FUNC(shutdown) {
    int sockfd;
    int how;
    mem_read(pid, arg1, (uint64_t*)&sockfd, sizeof(sockfd));
    mem_read(pid, arg2, (uint64_t*)&how, sizeof(how));

    output_data(outfile,"sockfd = %d, how = ", sockfd);

    if (how == SHUT_RD) {
        output_data(outfile,"SHUT_RD\n");
    } else if (how == SHUT_WR) {
        output_data(outfile,"SHUT_WR\n");
    } else if (how == SHUT_RDWR) {
        output_data(outfile,"SHUT_RDWR\n");
    } else {
        output_data(outfile,"Unknown (%d)\n", how);
    }
}

SYSCALL_PRINT_FUNC(bind) {
    int sockfd;
    struct sockaddr *addr;
    socklen_t addrlen;

    mem_read(pid, arg1, (uint64_t*)&sockfd, sizeof(sockfd));
    mem_read(pid, arg2, (uint64_t*)&addr, sizeof(addr));
    mem_read(pid, arg3, (uint64_t*)&addrlen, sizeof(addrlen));

    output_data(outfile,"sockfd = %d, ", sockfd);

    if (addr != NULL) {
        output_data(outfile,"address = ");
        print_sockaddr(outfile, addr);
        output_data(outfile,", addrlen = %u\n", addrlen);
    } else {
        output_data(outfile,"NULL address, addrlen = %u\n", addrlen);
    }
}
SYSCALL_PRINT_FUNC(listen) {
    output_data(outfile, "sockfd = %lu backlog = %lu ", arg1, arg2);
}
SYSCALL_PRINT_FUNC(getsockname) {
    socklen_t addrlen = 0;
    mem_read(pid, arg3, (uint64_t*)&addrlen, sizeof(addrlen));
    struct sockaddr *sock = malloc(addrlen);
    mem_read(pid, arg2, (uint64_t*)sock, addrlen);
    output_data(outfile, "sockfd = %lu ", arg1);
    output_data(outfile, "addr = ");
    print_sockaddr(outfile, sock);
    output_data(outfile, "addrlen = %lu ", arg3);
    free(sock);
}

SYSCALL_PRINT_FUNC(socketpair) {
    int sv[2];
    mem_read(pid, arg4, (uint64_t*)&sv, sizeof(sv));
    output_data(outfile, "domain = %lu type = %lu protocol = %lu sv[0] = %d sv[1] = %d ", arg1, arg2, arg3, sv[0], sv[1]);
}
SYSCALL_PRINT_FUNC(setsockopt) {
    uint8_t *buf = malloc(arg5);
    mem_read(pid, arg4, (uint64_t*)buf, arg5);
    output_data(outfile, "sockfd = %lu level = %lu optname = %lu optval = 0x", arg1, arg2, arg3);
    for(int i = 0; i < arg5; i++)
	output_data(outfile, "%hhX", buf[i]);
    output_data(outfile, " optlen = %lu ", arg5);
    free(buf);
}
SYSCALL_PRINT_FUNC(getsockopt) {
    uint64_t oplen_buf = 0;
    mem_read(pid, arg5, (uint64_t*)&oplen_buf, sizeof(oplen_buf));
    socklen_t *optlen = (socklen_t*)&oplen_buf;
    uint8_t *buf = malloc(*optlen);
    mem_read(pid, arg4, (uint64_t*)buf, *optlen);
    output_data(outfile, "sockfd = %lu level = %lu optname = %lu optval = 0x", arg1, arg2, arg3);
    for(int i = 0; i < *optlen; i++)
	output_data(outfile, "%hhX", buf[i]);
    output_data(outfile, " optlen = %u ", *optlen);
    free(buf);
}
SYSCALL_PRINT_FUNC(msgsnd) {
    uint8_t *buf = malloc(arg3);
    mem_read(pid, arg2, (uint64_t*)buf, arg3);
    output_data(outfile, "msgid = %lu msgp = ", arg1);
    for(int i = 0; i < arg5; i++)
	output_data(outfile, "%hhX", buf[i]);
    output_data(outfile, " msgz = %lu msgflag = %lu ", arg3, arg4);
    free(buf);
}
SYSCALL_PRINT_FUNC(msgrcv) {
    uint8_t *buf = malloc(arg3);
    mem_read(pid, arg2, (uint64_t*)buf, arg3);
    output_data(outfile, "msgid = %lu msgp = ", arg1);
    for(int i = 0; i < arg5; i++)
	output_data(outfile, "%hhX", buf[i]);
    output_data(outfile, " msgz = %lu msgtyp = %lu msgflag = %lu ", arg3, arg4, arg5);
    free(buf);
}
SYSCALL_PRINT_FUNC(msgget) {
    output_data(outfile, "key = %lu msgflag = %lu ", arg1, arg2);
}
SYSCALL_PRINT_FUNC(fcntl) {
    output_data(outfile, "fd = %lu cmd = %lu ", arg1, arg2);
}
SYSCALL_PRINT_FUNC(flock) {
    output_data(outfile, "fd = %lu operation = %lu ", arg1, arg2);
}
SYSCALL_PRINT_FUNC(fsync) {
    output_data(outfile, "fd = %lu ", arg1);
}
SYSCALL_PRINT_FUNC(truncate) {
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "path = %s length = %lu ", filepath, arg2);
}
SYSCALL_PRINT_FUNC(ftruncate) {
    output_data(outfile, "fd = %lu length = %lu ", arg1, arg2);
}
SYSCALL_PRINT_FUNC(getdents) {
    struct dirent d;
    mem_read(pid, arg2, (uint64_t*)&d, sizeof(d));
    output_data(outfile, "fd = %lu ", arg1);
    output_data(outfile, "dipr = {.d_ino + %lu .d_off = %lu .d_reclen = %u .d_name = %s .d_type = %d} ", d.d_ino, d.d_off, d.d_reclen, d.d_name, d.d_type);
    output_data(outfile, "count = %lu ", arg3);
}
SYSCALL_PRINT_FUNC(getcwd) {
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "buf = %s size = %lu ", filepath, arg2);
}
SYSCALL_PRINT_FUNC(chdir) {
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "path = %s ", filepath);
}
SYSCALL_PRINT_FUNC(rename) {
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "oldpath = %s ", filepath);
    mem_read(pid, arg2, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "newpath = %s ", filepath);
}
SYSCALL_PRINT_FUNC(mkdir) {
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "pathname = %s mode = %lu ", filepath, arg2);
}
SYSCALL_PRINT_FUNC(rmdir) {
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "pathname = %s ", filepath);
}
SYSCALL_PRINT_FUNC(symlink) {
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "target = %s ", filepath);
    mem_read(pid, arg2, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "linkpath = %s ", filepath);
}
SYSCALL_PRINT_FUNC(readlink) {
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "pathname = %s buf = ", filepath);
    uint8_t *buf = malloc(arg3);
    mem_read(pid, arg2, (uint64_t*)buf, arg3);
    for(int i = 0; i < arg5; i++)
	output_data(outfile, "%hhX", buf[i]);
    output_data(outfile, " bufize = %lu ", arg3);
    free(buf);
}
SYSCALL_PRINT_FUNC(fchmod) {
    output_data(outfile, "fd = %lu mode = %lu ", arg1, arg2);
}
SYSCALL_PRINT_FUNC(chown) {
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "pathname = %s owner = %lu group = %lu ", filepath, arg2, arg3);
}
SYSCALL_PRINT_FUNC(fchown) {
    output_data(outfile, "fd = %lu owner = %lu group = %lu ", arg1, arg2, arg3);
}

SYSCALL_PRINT_FUNC(times){
    //output_data(outfile, "buf = 0x%lx", arg1);
    struct tms tms_buf;
    mem_read(pid, arg1, (uint64_t*)&tms_buf, sizeof(tms_buf));
    output_data(outfile, "tm_struct = { .tms_utime = %ld .tms_stime = %ld .tms_cutime = %ld .tms_cstime = %ld }", tms_buf.tms_utime, tms_buf.tms_stime, tms_buf.tms_cutime, tms_buf.tms_cstime);
}
SYSCALL_PRINT_FUNC(ptrace){
    output_data(outfile, "request = %ld pid = %ld addr = 0x%lx data = 0x%lx", arg1, arg2, arg3, arg4);
}
SYSCALL_PRINT_FUNC(getuid){
    output_data(outfile, "uid = %ld", arg1);
}
SYSCALL_PRINT_FUNC(syslog){
    char format[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&format, sizeof(format));
    output_data(outfile, " priority = %lu format = %s ", arg1, format);
}
SYSCALL_PRINT_FUNC(getgid){
    output_data(outfile, "gid = %ld", arg1);
}
SYSCALL_PRINT_FUNC(setuid){
    output_data(outfile, "uid = %ld", arg1);
}
SYSCALL_PRINT_FUNC(setgid){
    output_data(outfile, "gid = %ld", arg1);
}
SYSCALL_PRINT_FUNC(geteuid){
    output_data(outfile, "euid = %ld", arg1);
}
SYSCALL_PRINT_FUNC(getegid){
    output_data(outfile, "egid = %ld", arg1);
}
SYSCALL_PRINT_FUNC(setpgid){
    output_data(outfile, "pid = %ld pgid = %ld", arg1, arg2);
}
SYSCALL_PRINT_FUNC(getppid){
    output_data(outfile, "ppid = %ld", arg1);
}
SYSCALL_PRINT_FUNC(getpgrp){
    output_data(outfile, "pid = %ld", arg1);
}
SYSCALL_PRINT_FUNC(setsid){
    output_data(outfile, "pid = %ld", arg1);
}
SYSCALL_PRINT_FUNC(setreuid){
    output_data(outfile, "ruid = %ld euid = %ld", arg1, arg2);
}
SYSCALL_PRINT_FUNC(setregid){
    output_data(outfile, "rgid = %ld egid = %ld", arg1, arg2);
}
// Not sure if this will print accurately
SYSCALL_PRINT_FUNC(getgroups){
    int groups[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&groups, PATH_MAX);
    output_data(outfile, "size = %ld GIDs=", arg1);
    for (int i = 0; i <= arg1; i++) {
        output_data(outfile, "%d ", (int)groups[i]);
    }
    //@ Will Fix this list printing later
}
// Not sure if this will print accurately
SYSCALL_PRINT_FUNC(setgroups){
    int groups[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&groups, PATH_MAX);
    output_data(outfile, "size = %ld GIDs=", arg1);
    for (int i = 0; i <= arg1; i++) {
        output_data(outfile, "%d ", (int)groups[i]);
    }
    //@ Will Fix this list printing later
}
//
SYSCALL_PRINT_FUNC(setresuid){
    output_data(outfile, "ruid = %ld euid = %ld suid = %ld", arg1, arg2, arg3);
}
SYSCALL_PRINT_FUNC(getresuid){
    output_data(outfile, "ruid = %ld euid = %ld suid = %ld", arg1, arg2, arg3);
}
SYSCALL_PRINT_FUNC(setresgid){
    output_data(outfile, "rgid = %ld egid = %ld sgid = %ld", arg1, arg2, arg3);
}
SYSCALL_PRINT_FUNC(getresgid){
    output_data(outfile, "rgid = %ld egid = %ld sgid = %ld", arg1, arg2, arg3);
}
SYSCALL_PRINT_FUNC(getpgid){
    output_data(outfile, "pid = %ld", arg1);
}
SYSCALL_PRINT_FUNC(setfsuid){
    output_data(outfile, "uid = %ld", arg1);
}
SYSCALL_PRINT_FUNC(setfsgid){
    output_data(outfile, "gid = %ld", arg1);
}
SYSCALL_PRINT_FUNC(getsid){
    output_data(outfile, "pid = %ld", arg1);
}
SYSCALL_PRINT_FUNC(capget){
    //output_data(outfile, "header = 0x%lx data = 0x%lx", arg1, arg2);
    struct __user_cap_header_struct header_buf;
    mem_read(pid, arg1, (uint64_t*)&header_buf, sizeof(header_buf));
    struct __user_cap_data_struct data_buf;
    mem_read(pid, arg2, (uint64_t*)&data_buf, sizeof(data_buf));
    output_data(outfile, "__user_cap_header = {.version = %d .pid = %d} __user_cap_data = {.effective = %d .permitted = %d .inheritable = %d}", header_buf.version, header_buf.pid, data_buf.effective, data_buf.permitted, data_buf.inheritable);
}
SYSCALL_PRINT_FUNC(capset){
    //output_data(outfile, "header = 0x%lx data = 0x%lx", arg1, arg2);
    struct __user_cap_header_struct header_buf;
    mem_read(pid, arg1, (uint64_t*)&header_buf, sizeof(header_buf));
    struct __user_cap_data_struct data_buf;
    mem_read(pid, arg2, (uint64_t*)&data_buf, sizeof(data_buf));
    output_data(outfile, "__user_cap_header = {.version = %d .pid = %d} __user_cap_data = {.effective = %d .permitted = %d .inheritable = %d}", header_buf.version, header_buf.pid, data_buf.effective, data_buf.permitted, data_buf.inheritable);
}
SYSCALL_PRINT_FUNC(rt_sigpending){
    output_data(outfile, "set = 0x%lx", arg1);
    // Opaque struct, can't print
    //struct sigset_t set_buf;
    //mem_read(pid, arg1, (uint64_t*)&set_buf, sizeof(set_buf));
    //output_data(outfile, "sigset_t contents:\n");
    //for(int i = 0; i <= arg2; i++) {
    //    output_data(outfile, "sig[i]: %lu\n", set_buf.__val[i]);
    //}

}
SYSCALL_PRINT_FUNC(rt_sigtimedwait){
    // Opaque struct, can't print
    // struct sigset_t set_buf;
    // mem_read(pid, arg1, (uint64_t*)&set_buf, sizeof(set_buf));
    // output_data(outfile, "sigset_t contents:\n");
    // for(int i = 0; i <= arg2; i++) {
    //     output_data(outfile, "sig[i]: %lu\n", set_buf.__val[i]);
    // }
    // struct siginfo_t info_buf;
    // mem_read(pid, arg2, (uint64_t*)&info_buf, sizeof(info_buf));
    // output_data(outfile, "siginfo_t contents:\n");
    // output_data(outfile, "si_signo: %d\n", info_buf.si_signo);
    // output_data(outfile, "si_errno: %d\n", info_buf.si_errno);
    // output_data(outfile, "si_code: %d\n", info_buf.si_code);
    // output_data(outfile, "si_pid: %d\n", info_buf.si_pid);
    // output_data(outfile, "si_uid: %d\n", info_buf.si_uid);
    // output_data(outfile, "si_status: %d\n", info_buf.si_status);
    // output_data(outfile, "si_utime: %ld\n", info_buf.si_utime);
    // output_data(outfile, "si_stime: %ld\n", info_buf.si_stime);
    // output_data(outfile, "si_int: %d\n", info_buf.si_int);
    // output_data(outfile, "si_overrun: %d\n", info_buf.si_overrun);
    // output_data(outfile, "si_timerid: %d\n", info_buf.si_timerid);
    // output_data(outfile, "si_band: %ld\n", info_buf.si_band);
    // output_data(outfile, "si_fd: %d\n", info_buf.si_fd);
    // output_data(outfile, "si_addr_lsb: %d\n", info_buf.si_addr_lsb);
    // output_data(outfile, "si_pkey: %d\n", info_buf.si_pkey);
    struct timespec timespec_buf;
    mem_read(pid, arg3, (uint64_t*)&timespec_buf, sizeof(arg4));
    output_data(outfile, "sigset_it = 0x%lx  siginfo_t = 0x%lx timespec = {.tv_sec =  %ld .tv_nsec = %ld}", arg1, arg2, timespec_buf.tv_sec, timespec_buf.tv_nsec);

}
SYSCALL_PRINT_FUNC(rt_sigqueueinfo){
    output_data(outfile, "pid = %ld sig = %ld siginfo_t = 0x%lx", arg1, arg2, arg3);
    // Opaque struct, can't print
    // struct siginfo_t info_buf;
    // mem_read(pid, arg3, (uint64_t*)&info_buf, sizeof(info_buf));
    // output_data(outfile, "siginfo_t contents:\n");
    // output_data(outfile, "si_signo: %d\n", info_buf.si_signo);
    // output_data(outfile, "si_errno: %d\n", info_buf.si_errno);
    // output_data(outfile, "si_code: %d\n", info_buf.si_code);
    // output_data(outfile, "si_pid: %d\n", info_buf.si_pid);
    // output_data(outfile, "si_uid: %d\n", info_buf.si_uid);
    // output_data(outfile, "si_status: %d\n", info_buf.si_status);
    // output_data(outfile, "si_utime: %ld\n", info_buf.si_utime);
    // output_data(outfile, "si_stime: %ld\n", info_buf.si_stime);
    // output_data(outfile, "si_int: %d\n", info_buf.si_int);
    // output_data(outfile, "si_overrun: %d\n", info_buf.si_overrun);
    // output_data(outfile, "si_timerid: %d\n", info_buf.si_timerid);
    // output_data(outfile, "si_band: %ld\n", info_buf.si_band);
    // output_data(outfile, "si_fd: %d\n", info_buf.si_fd);
    // output_data(outfile, "si_addr_lsb: %d\n", info_buf.si_addr_lsb);
    // output_data(outfile, "si_pkey: %d\n", info_buf.si_pkey);

}
SYSCALL_PRINT_FUNC(rt_sigsuspend){
    output_data(outfile, "set = 0x%lx", arg1);
    // Opaque struct, can't print
    // struct sigset_t set_buf;
    // mem_read(pid, arg1, (uint64_t*)&set_buf, sizeof(set_buf));
    // output_data(outfile, "sigset_t contents:\n");
    // for(int i = 0; i <= arg2; i++) {
    //     output_data(outfile, "sig[i]: %lu\n", set_buf.__val[i]);
    // }
}
SYSCALL_PRINT_FUNC(sigaltstack){
    output_data(outfile, "ss = 0x%lx old_ss = 0x%lx", arg1, arg2);
    // Opaque struct, can't print
    // struct stack_t ss_buf;
    // mem_read(pid, arg1, (uint64_t*)&ss_buf, sizeof(ss_buf));
    // output_data(outfile, "stack_t contents:\n");
    // output_data(outfile, "ss_size: %zu\n", ss_buf.ss_size);
    // struct stack_t old_ss_buf;
    // mem_read(pid, arg2, (uint64_t*)&old_ss_buf, sizeof(old_ss_buf));
    // output_data(outfile, "stack_t contents:\n");
    // output_data(outfile, "ss_flags: %d\n", old_ss_buf.ss_flags);
    // output_data(outfile, "ss_size: %zu\n", old_ss_buf.ss_size);

}
SYSCALL_PRINT_FUNC(utime){
    char filepath[PATH_MAX];
    struct utimbuf ut_buf;
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    mem_read(pid, arg2, (uint64_t*)&ut_buf, sizeof(ut_buf));
    output_data(outfile, "pathname = %s  utime = {.actime = %ld .modtime = %ld} ", filepath, ut_buf.actime, ut_buf.modtime);
}
SYSCALL_PRINT_FUNC(mknod){
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "pathname = %s mode = %ld dev = %ld", filepath, arg2, arg3);
}
SYSCALL_PRINT_FUNC(uselib){
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "library = %s", filepath);
}
SYSCALL_PRINT_FUNC(personality){
    output_data(outfile, "personality = %ld", arg1);
}
SYSCALL_PRINT_FUNC(ustat){
    //DEPRECATED from glibc 2.26 onwards so ustat.h doesn't exist
    output_data(outfile, "dev = %ld ubuf = 0x%lx", arg1, arg2);
    //output_data(outfile, "device id = %ld", arg1);
    //struct ustat ustat_buf;
    //mem_read(pid, arg2, (uint64_t*)&ustat_buf, sizeof(ustat_buf));
    //output_data(outfile, "ustat contents:\n");
    //output_data(outfile, "f_tfree: %ld\n", ustat_buf.f_tfree);
    //output_data(outfile, "f_tinode: %ld\n", ustat_buf.f_tinode);

}
SYSCALL_PRINT_FUNC(statfs) {
    char filepath[PATH_MAX];
    struct statfs stat_buf;
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    mem_read(pid, arg2, (uint64_t*)&stat_buf, sizeof(stat_buf));
    output_data(outfile, "pathname = %s ", filepath);
    print_statfs_struct(outfile, &stat_buf);
}

SYSCALL_PRINT_FUNC(fstatfs) {
    struct statfs stat_buf;
    mem_read(pid, arg2, (uint64_t*)&stat_buf, sizeof(stat_buf));
    output_data(outfile, "fd = %lu ", arg1);
    print_statfs_struct(outfile, &stat_buf);
}

SYSCALL_PRINT_FUNC(sysfs){
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "pathname = %s", filepath);
}
SYSCALL_PRINT_FUNC(getpriority){
    output_data(outfile, "which = %ld who = %ld", arg1, arg2);
}
SYSCALL_PRINT_FUNC(setpriority){
    output_data(outfile, "which = %ld who = %ld priority = %ld", arg1, arg2, arg3);
}
SYSCALL_PRINT_FUNC(sched_setparam){
    struct sched_param sparam_buf;
    mem_read(pid, arg2, (uint64_t*)&sparam_buf, sizeof(sparam_buf));
    output_data(outfile, "pid = %ld, sched_param:{sched_priority: %d}", arg1, sparam_buf.sched_priority);

}
SYSCALL_PRINT_FUNC(sched_getparam){
    struct sched_param sparam_buf;
    mem_read(pid, arg2, (uint64_t*)&sparam_buf, sizeof(sparam_buf));
    output_data(outfile, "pid = %ld, sched_param:{sched_priority: %d}", arg1, sparam_buf.sched_priority);
}
SYSCALL_PRINT_FUNC(sched_setscheduler){
    struct sched_param sparam_buf;
    mem_read(pid, arg3, (uint64_t*)&sparam_buf, sizeof(sparam_buf));
    output_data(outfile, "pid = %ld policy = %ld sched_param = {.sched_priority = %d}", arg1, arg2, sparam_buf.sched_priority);
}
SYSCALL_PRINT_FUNC(sched_getscheduler){
    output_data(outfile, "pid = %ld", arg1);
}
SYSCALL_PRINT_FUNC(sched_get_priority_max){
    output_data(outfile, "policy = %ld", arg1);
}
SYSCALL_PRINT_FUNC(sched_get_priority_min){
    output_data(outfile, "policy = %ld", arg1);
}
SYSCALL_PRINT_FUNC(sched_rr_get_interval){
    struct timespec timespec_buf;
    mem_read(pid, arg2, (uint64_t*)&timespec_buf, sizeof(timespec_buf));
    output_data(outfile, "pid = %ld timespec = {.tv_sec: %ld .tv_nsec = %ld}", arg1, timespec_buf.tv_sec, timespec_buf.tv_nsec);

}
SYSCALL_PRINT_FUNC(mlock){
    output_data(outfile, "addr = 0x%lx len = %lu", arg1, arg2);
}
SYSCALL_PRINT_FUNC(munlock){
    output_data(outfile, "addr = 0x%lx len = %lu", arg1, arg2);
}
// 150-200
SYSCALL_PRINT_FUNC(mlockall){
    output_data(outfile, "flags = %ld", arg1);
}
SYSCALL_PRINT_FUNC(munlockall){
    output_data(outfile, "void function");
}
SYSCALL_PRINT_FUNC(vhangup){
    output_data(outfile, "void function");
}
SYSCALL_PRINT_FUNC(modify_ldt){
    struct user_desc ud_buf;
    mem_read(pid, arg2, (uint64_t*)&ud_buf, sizeof(ud_buf));
    output_data(outfile, "func = %ld bytecount = %ld user_desc = {.entry_number = %d .base_addr = 0x%x .limit = %d .seg_32bit = %d .contents = %d .read_exec_only = %d .limit_in_pages = %d .seg_not_present = %d .useable = %d}", arg1, arg3, ud_buf.entry_number, ud_buf.base_addr, ud_buf.limit, ud_buf.seg_32bit, ud_buf.contents, ud_buf.read_exec_only, ud_buf.limit_in_pages, ud_buf.seg_not_present, ud_buf.useable);
}
SYSCALL_PRINT_FUNC(pivot_root){
    output_data(outfile, "new_root = %lu put_old = %lu", arg1, arg2); // Docs say both should be %s
}
SYSCALL_PRINT_FUNC(prctl){
    output_data(outfile, "option = %ld arg2 = 0x%lx arg3 = 0x%lx arg4 = 0x%lx arg5 = 0x%lx", arg1, arg2, arg3, arg4, arg5);
}
SYSCALL_PRINT_FUNC(arch_prctl){
    output_data(outfile, "code = %lu addr = 0x%lx", arg1, arg2); // Docs say code should be %d
}
SYSCALL_PRINT_FUNC(adjtimex){
    struct timex timex_buf;
    mem_read(pid, arg1, (uint64_t*)&timex_buf, sizeof(timex_buf));
    output_data(outfile, "timex= { .modes=%d .offset=%ld .freq=%ld .maxerror=%ld .esterror=%ld .status=%d .constant=%ld .precision=%ld .tolerance=%ld .time = { .tv_sec=%ld .tv_usec=%ld}}\n", timex_buf.modes, timex_buf.offset, timex_buf.freq, timex_buf.maxerror, timex_buf.esterror, timex_buf.status, timex_buf.constant, timex_buf.precision, timex_buf.tolerance, timex_buf.time.tv_sec, timex_buf.time.tv_usec);
    //output_data(outfile, "tick: %ld\n", timex_buf.time.tick);
    //output_data(outfile, "ppsfreq: %ld\n",timex_buf.time.ppsfreq);
    //output_data(outfile, "jitter: %ld\n", timex_buf.time.jitter);
    //output_data(outfile, "shift: %d\n", timex_buf.time.shift);
    //output_data(outfile, "stabil: %ld\n", timex_buf.time.stabil);
    //output_data(outfile, "jitcnt: %ld\n", timex_buf.time.jitcnt);
    //output_data(outfile, "calcnt: %ld\n", timex_buf.time.calcnt);
    //output_data(outfile, "errcnt: %ld\n", timex_buf.time.errcnt);
    //output_data(outfile, "stbcnt: %ld\n", timex_buf.time.stbcnt);
    //output_data(outfile, "tai: %d\n", timex_buf.time.tai);

}
SYSCALL_PRINT_FUNC(setrlimit){
    struct rlimit rlim_buf;
    mem_read(pid, arg2, (uint64_t*)&rlim_buf, sizeof(rlim_buf));
    output_data(outfile, "resource = %ld, rlimit = { .rlim_cur = %ld .rlim_max = %ld}", arg1, rlim_buf.rlim_cur, rlim_buf.rlim_max);
}
SYSCALL_PRINT_FUNC(chroot){
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "pathname = %s", filepath);
}
SYSCALL_PRINT_FUNC(sync){
    output_data(outfile, "void function");
}
SYSCALL_PRINT_FUNC(acct){
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "pathname = %s", filepath);
}
SYSCALL_PRINT_FUNC(settimeofday){
    struct timeval tv_buf;
    //mem_read(pid, arg1, (uint64_t*)&tv_buf, sizeof(tv_buf));;
    //  The use of the timezone structure is obsolete  https://man7.org/linux/man-pages/man2/gettimeofday.2.html
    //struct timezone tz_buf; 
    //mem_read(pid, arg2, (uint64_t*)&tz_buf, sizeof(tz_buf));
    //output_data(outfile, "timval = {.tv_sec = %ld .tv_usec = %ld} timezone = {.tz_minuteswest = %d .tz_dsttime = %d}", tv_buf.tv_sec, tv_buf.tv_usec, tz_buf.tz_minuteswest, tz_buf.tz_dsttime);
    output_data(outfile, "timval = {.tv_sec = %ld .tv_usec = %ld}", tv_buf.tv_sec, tv_buf.tv_usec);

}
SYSCALL_PRINT_FUNC(mount){
    char source[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&source, PATH_MAX);
    char target[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&target, PATH_MAX);
    char fs[PATH_MAX];
    mem_read(pid, arg3, (uint64_t*)&fs, PATH_MAX);
    output_data(outfile, "source = %s target = %s filesystemtype = %s mountflags = %ld data = 0x%lx", source, target, fs, arg4, arg5);
}
SYSCALL_PRINT_FUNC(swapon){
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "pathname = %s swapflags = %ld", filepath, arg2);
}
SYSCALL_PRINT_FUNC(swapoff){
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    output_data(outfile, "pathname = %s", filepath);
}
SYSCALL_PRINT_FUNC(reboot){
    output_data(outfile, "int=%lu", arg1);
}
SYSCALL_PRINT_FUNC(sethostname){
    char name[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&name, PATH_MAX);
    output_data(outfile, "name = %s len = %ld", name, arg2);
}
SYSCALL_PRINT_FUNC(setdomainname){
    char name[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&name, PATH_MAX);
    output_data(outfile, "name = %s len = %ld", name, arg2);
}
SYSCALL_PRINT_FUNC(iopl){
    output_data(outfile, "level = %ld", arg1);
}
SYSCALL_PRINT_FUNC(ioperm){
    output_data(outfile, "from = %ld num = %ld turn_on = %ld", arg1, arg2, arg3);
}
SYSCALL_PRINT_FUNC(init_module){
    char params[PATH_MAX];
    mem_read(pid, arg3, (uint64_t*)&params, PATH_MAX);
    output_data(outfile, "module_image = 0x%lx len = %lu params = %s", arg1, arg2, params);
}
SYSCALL_PRINT_FUNC(delete_module){
    char name[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&name, PATH_MAX);
    output_data(outfile, "name = %s flags = %ld", name, arg2);
}
SYSCALL_PRINT_FUNC(quotactl){
    char special[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&special, PATH_MAX);
    output_data(outfile, "cmd = %ld special = %s id = %ld addr = 0x%lx", arg1, special, arg3, arg4);
}
SYSCALL_PRINT_FUNC(gettid){
 output_data(outfile, "void function");
}
SYSCALL_PRINT_FUNC(readahead){
    output_data(outfile, "fd = %ld offset = %ld count = %ld", arg1, arg2, arg3);
}
SYSCALL_PRINT_FUNC(setxattr){
    char pathname[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&pathname, PATH_MAX);
    char name[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&name, PATH_MAX);
    output_data(outfile, "pathname = %s name = %s value = 0x%lx size = %ld flags = %ld", pathname, name, arg3, arg4, arg5);
}
SYSCALL_PRINT_FUNC(lsetxattr){
    char pathname[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&pathname, PATH_MAX);
    char name[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&name, PATH_MAX);
    output_data(outfile, "pathname = %s name = %s value = 0x%lx size = %ld flags = %ld", pathname, name, arg3, arg4, arg5);
}
SYSCALL_PRINT_FUNC(fsetxattr){
    char pathname[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&pathname, PATH_MAX);
    char name[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&name, PATH_MAX);
    output_data(outfile, "pathname = %s name = %s value = 0x%lx size = %ld flags = %ld", pathname, name, arg3, arg4, arg5);
}
SYSCALL_PRINT_FUNC(getxattr){
    char pathname[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&pathname, PATH_MAX);
    char name[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&name, PATH_MAX);
    output_data(outfile, "pathname = %s name = %s value = 0x%lx size = %ld flags = %ld", pathname, name, arg3, arg4, arg5);
}
SYSCALL_PRINT_FUNC(lgetxattr){
    char pathname[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&pathname, PATH_MAX);
    char name[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&name, PATH_MAX);
    output_data(outfile, "pathname = %s name = %s value = 0x%lx size = %ld flags = %ld", pathname, name, arg3, arg4, arg5);
}
SYSCALL_PRINT_FUNC(fgetxattr){
    char pathname[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&pathname, PATH_MAX);
    char name[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&name, PATH_MAX);
    output_data(outfile, "pathname = %s name = %s value = 0x%lx size = %ld flags = %ld", pathname, name, arg3, arg4, arg5);
}
SYSCALL_PRINT_FUNC(listxattr){
    //output_data(outfile, "pathname = %s list = 0x%lx size = %ld", arg1, arg2, arg3);
    char pathname[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&pathname, PATH_MAX);
    output_data(outfile, "pathname = %s", pathname);
    // @ Will come in to read in the list and print the strings
}
SYSCALL_PRINT_FUNC(llistxattr){
    //output_data(outfile, "pathname = %s list = 0x%lx size = %ld", arg1, arg2, arg3);
    char pathname[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&pathname, PATH_MAX);
    output_data(outfile, "pathname = %s", pathname);
    // @ Will come in to read in the list and print the strings
}
SYSCALL_PRINT_FUNC(flistxattr){
    char fd[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&fd, PATH_MAX);
    output_data(outfile, "fd = %s", fd);
    // @ Will come in to read in the list and print the strings
}
SYSCALL_PRINT_FUNC(removexattr){
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    char name[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&name, PATH_MAX);
    output_data(outfile, "pathname = %s name = %s", filepath, name);
}
SYSCALL_PRINT_FUNC(lremovexattr){
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    char name[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&name, PATH_MAX);
    output_data(outfile, "pathname = %s name = %s", filepath, name);
}
SYSCALL_PRINT_FUNC(fremovexattr){
    char filepath[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filepath, PATH_MAX);
    char name[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&name, PATH_MAX);
    output_data(outfile, "pathname = %s name = %s", filepath, name);
}
SYSCALL_PRINT_FUNC(tkill){
    output_data(outfile, "tid = %ld sig = %ld", arg1, arg2);
}

SYSCALL_PRINT_FUNC(time){
    // Opaque type?
    //struct time_t time_buf;
    //mem_read(pid, arg1, (uint64_t*)&time_buf, sizeof(time_buf));
    //output_data(outfile, "time = {.tm_sec = %ld }", time_buf.tm_sec);
    output_data(outfile, "secondsp = 0x%lx", arg1);
}
SYSCALL_PRINT_FUNC(futex){
    struct timespec timespec_buf;
    mem_read(pid, arg4, (uint64_t*)&timespec_buf, sizeof(timespec_buf));
    output_data(outfile, "uaddr = 0x%lx op = %ld val = %ld timeout = {.tv_sec = %ld .tv_nsec = %ld} uaddr2 = 0x%lx val3 = %ld", arg1, arg2, arg3, timespec_buf.tv_sec, timespec_buf.tv_nsec, arg5, arg6);
}
SYSCALL_PRINT_FUNC(sched_setaffinity){
    // Opaque Struct, can't print
    //struct cpu_set_t cpuset_buf;
    //mem_read(pid, arg3, (uint64_t*)&cpuset_buf, arg2);
    //output_data(outfile, "pid = %ld cpusetsize = %ld mask = 0x%lx", arg1, arg2, cpuset_buf.__bits);
    output_data(outfile, "pid = %ld cpusetsize = %ld mask = 0x%lx", arg1, arg2, arg3);
}
SYSCALL_PRINT_FUNC(sched_getaffinity){
    // Opaque Struct, can't print
    //struct cpu_set_t cpuset_buf;
    //mem_read(pid, arg3, (uint64_t*)&cpuset_buf, arg2);
    //output_data(outfile, "pid = %ld cpusetsize = %ld mask = 0x%lx", arg1, arg2, cpuset_buf.__bits);
    output_data(outfile, "pid = %ld cpusetsize = %ld mask = 0x%lx", arg1, arg2, arg3);
}
SYSCALL_PRINT_FUNC(set_thread_area){
    struct user_desc ud_buf;
    mem_read(pid, arg2, (uint64_t*)&ud_buf, sizeof(ud_buf));
    output_data(outfile, "user_desc = {.entry_number = %d .base_addr = 0x%x .limit = %d .seg_32bit = %d .contents = %d .read_exec_only = %d .limit_in_pages = %d .seg_not_present = %d .useable = %d}", ud_buf.entry_number, ud_buf.base_addr, ud_buf.limit, ud_buf.seg_32bit, ud_buf.contents, ud_buf.read_exec_only, ud_buf.limit_in_pages, ud_buf.seg_not_present, ud_buf.useable);
}
SYSCALL_PRINT_FUNC(io_setup){
    // https://oxnz.github.io/2016/10/13/linux-aio/
    unsigned long ctx;
    mem_read(pid, arg2, (uint64_t*)&ctx, sizeof(ctx));
    output_data(outfile, "nr_events = %lu ctx = %lu", arg1, ctx);
}
SYSCALL_PRINT_FUNC(io_destroy){
    output_data(outfile, "ctx = %lu", arg1);
}
SYSCALL_PRINT_FUNC(io_getevents){
    // https://oxnz.github.io/2016/10/13/linux-aio/
    struct io_event event_buf;
    mem_read(pid, arg4, (uint64_t*)&event_buf, sizeof(event_buf));
    struct timespec timespec_buf;
    mem_read(pid, arg5, (uint64_t*)&timespec_buf, sizeof(timespec_buf));
    output_data(outfile, "ctx = %lu min_nr = %lu nr = %lu events = {.data = %llu .obj = %llu .res = %lld .res2 = %lld } timeout = {.tv_sec = %ld .tv_nsec = %ld}", arg1, arg2, arg3, event_buf.data, event_buf.obj, event_buf.res, event_buf.res2, timespec_buf.tv_sec, timespec_buf.tv_nsec);
}
SYSCALL_PRINT_FUNC(io_submit){
    struct iocb iocb_buf;
    mem_read(pid, arg3, (uint64_t*)&iocb_buf, sizeof(iocb_buf));
    output_data(outfile, "ctx = %lu nr = %lu iocb = {.aio_lio_opcode = %hu .aio_reqprio = %hd .aio_fildes = %u .aio_buf = %llu .aio_nbytes = %llu .aio_offset = %lld}", arg1, arg2, iocb_buf.aio_lio_opcode, iocb_buf.aio_reqprio, iocb_buf.aio_fildes, iocb_buf.aio_buf, iocb_buf.aio_nbytes, iocb_buf.aio_offset);

}
SYSCALL_PRINT_FUNC(io_cancel){
    struct iocb iocb_buf;
    mem_read(pid, arg2, (uint64_t*)&iocb_buf, sizeof(iocb_buf));
    struct io_event event_buf;
    mem_read(pid, arg3, (uint64_t*)&event_buf, sizeof(event_buf));
    output_data(outfile, "ctx = %lu iocb = {.aio_lio_opcode = %hu .aio_reqprio = %hd .aio_fildes = %u .aio_buf = %llu .aio_nbytes = %llu .aio_offset = %lld} io_event =  {.data = %llu .obj = %llu .res = %lld .res2 = %lld }", arg1, iocb_buf.aio_lio_opcode, iocb_buf.aio_reqprio, iocb_buf.aio_fildes, iocb_buf.aio_buf, iocb_buf.aio_nbytes, iocb_buf.aio_offset, event_buf.data, event_buf.obj, event_buf.res, event_buf.res2);

}
SYSCALL_PRINT_FUNC(get_thread_area){
    struct user_desc ud_buf;
    mem_read(pid, arg2, (uint64_t*)&ud_buf, sizeof(ud_buf));
    output_data(outfile, "user_desc = {.entry_number = %d .base_addr = 0x%x .limit = %d .seg_32bit = %d .contents = %d .read_exec_only = %d .limit_in_pages = %d .seg_not_present = %d .useable = %d}", ud_buf.entry_number, ud_buf.base_addr, ud_buf.limit, ud_buf.seg_32bit, ud_buf.contents, ud_buf.read_exec_only, ud_buf.limit_in_pages, ud_buf.seg_not_present, ud_buf.useable);
}
SYSCALL_PRINT_FUNC(epoll_create){
    output_data(outfile, "size = %ld", arg1);
}
SYSCALL_PRINT_FUNC(remap_file_pages){
    output_data(outfile, "addr = 0x%lx size = %ld prot = %ld pgoff = %ld flags = %ld", arg1, arg2, arg3, arg4, arg5);
}
SYSCALL_PRINT_FUNC(getdents64){
    // Struct isn't actually defined in any headers
    // https://linux.die.net/man/2/getdents64
    output_data(outfile, "fd = %ld dirent =0x%lx", arg1, arg2);
}
SYSCALL_PRINT_FUNC(set_tid_address){
    output_data(outfile, "tidptr = 0x%lx", arg1);
}
SYSCALL_PRINT_FUNC(restart_syscall){
    output_data(outfile, "void function");
}
SYSCALL_PRINT_FUNC(semtimedop){
    struct sembuf sembuf_buf;
    mem_read(pid, arg2, (uint64_t*)&sembuf_buf, sizeof(sembuf_buf));
    struct timespec timespec_buf;
    mem_read(pid, arg4, (uint64_t*)&timespec_buf, sizeof(timespec_buf));
    output_data(outfile, "semid = %ld sops = {.sem_num = %hu .sem_op = %hu .sem_flg = %hu} nsops = %ld timeout = {.tv_sec = %ld .tv_nsec = %ld}", arg1, sembuf_buf.sem_num, sembuf_buf.sem_op, sembuf_buf.sem_flg, arg3, timespec_buf.tv_sec, timespec_buf.tv_nsec);
}
SYSCALL_PRINT_FUNC(fadvise64){
    output_data(outfile, "fd = %ld offset = %ld len = %ld advice = %ld", arg1, arg2, arg3, arg4);
}
SYSCALL_PRINT_FUNC(timer_create){
    struct sigevent sigevent_buf;
    mem_read(pid, arg2, (uint64_t*)&sigevent_buf, sizeof(sigevent_buf));
    struct sigevent sevp_buf;
    mem_read(pid, arg3, (uint64_t*)&sevp_buf, sizeof(sevp_buf));
    //timer_t should be considered opaque
    // @Will not sure how to get sigevent.sigev_value.sival_ptr
    output_data(outfile, "clockid = 0x%lx sigevent = {.sigev_notify = %d .sigev_signo = %d .sigev_value ={.sival_int = %d .sival_ptr = void} } sevp = {.sigev_notify = %d .sigev_signo = %d .sigev_value = {.sival_int = %d .sival_ptr = void} } timer = 0x%lx ", arg1, sigevent_buf.sigev_notify, sigevent_buf.sigev_signo, sigevent_buf.sigev_value.sival_int , sevp_buf.sigev_notify, sevp_buf.sigev_signo, sevp_buf.sigev_value.sival_int, arg4);

}
SYSCALL_PRINT_FUNC(timer_settime){
    //timer_t should be considered opaque
    struct itimerspec itimerspec_buf;
    mem_read(pid, arg3, (uint64_t*)&itimerspec_buf, sizeof(itimerspec_buf));
    struct itimerspec oitimerspec_buf;
    mem_read(pid, arg4, (uint64_t*)&oitimerspec_buf, sizeof(oitimerspec_buf));
    output_data(outfile, "timer_t = 0x%lx flags = %lu new_itimerspec = { .it_interval = {.tv_sec =  %ld .tv_nsec = %ld}  .it_value = {.tv_sec =  %ld .tv_nsec = %ld} } old_itimerspec = { .it_interval = {.tv_sec =  %ld .tv_nsec = %ld}  .it_value = {.tv_sec =  %ld .tv_nsec = %ld} }", arg1, arg2, itimerspec_buf.it_interval.tv_sec, itimerspec_buf.it_interval.tv_nsec, itimerspec_buf.it_value.tv_sec, itimerspec_buf.it_value.tv_nsec, oitimerspec_buf.it_interval.tv_sec, oitimerspec_buf.it_interval.tv_nsec, oitimerspec_buf.it_value.tv_sec, oitimerspec_buf.it_value.tv_nsec);
}
SYSCALL_PRINT_FUNC(timer_gettime){
    //timer_t should be considered opaque
    struct itimerspec itimerspec_buf;
    mem_read(pid, arg2, (uint64_t*)&itimerspec_buf, sizeof(itimerspec_buf));
    output_data(outfile, "timer_t = 0x%lx itimerspec = { .it_interval = {.tv_sec =  %ld .tv_nsec = %ld}  .it_value = {.tv_sec =  %ld .tv_nsec = %ld} }", arg1, itimerspec_buf.it_interval.tv_sec, itimerspec_buf.it_interval.tv_nsec, itimerspec_buf.it_value.tv_sec, itimerspec_buf.it_value.tv_nsec);
}
SYSCALL_PRINT_FUNC(timer_getoverrun){
    //timer_t should be considered opaque
    output_data(outfile, "timer_t = 0x%lx", arg1);
}
SYSCALL_PRINT_FUNC(timer_delete){
    //timer_t should be considered opaque
    output_data(outfile, "timer_t = 0x%lx", arg1);
}
SYSCALL_PRINT_FUNC(clock_settime){
    //clock_id is opaque?
    struct timespec timespec_buf;
    mem_read(pid, arg2, (uint64_t*)&timespec_buf, sizeof(timespec_buf));
    output_data(outfile, "clockid = 0x%lx timespec = {.tv_sec = %ld .tv_nsec = %ld}", arg1, timespec_buf.tv_sec, timespec_buf.tv_nsec);
}
SYSCALL_PRINT_FUNC(clock_gettime){
    //clock_id is opaque?
    struct timespec timespec_buf;
    mem_read(pid, arg2, (uint64_t*)&timespec_buf, sizeof(timespec_buf));
    output_data(outfile, "clockid = 0x%lx timespec = {.tv_sec = %ld .tv_nsec = %ld}", arg1, timespec_buf.tv_sec, timespec_buf.tv_nsec);
}
SYSCALL_PRINT_FUNC(clock_getres){
    //clock_id is opaque?
    struct timespec timespec_buf;
    mem_read(pid, arg2, (uint64_t*)&timespec_buf, sizeof(timespec_buf));
    output_data(outfile, "clockid = 0x%lx timespec = {.tv_sec = %ld .tv_nsec = %ld}", arg1, timespec_buf.tv_sec, timespec_buf.tv_nsec);
}
SYSCALL_PRINT_FUNC(clock_nanosleep){
    //clock_id is opaque?
    struct timespec timespec_buf;
    mem_read(pid, arg3, (uint64_t*)&timespec_buf, sizeof(timespec_buf));
    struct timespec timespec_buf2;
    mem_read(pid, arg4, (uint64_t*)&timespec_buf2, sizeof(timespec_buf2));
    output_data(outfile, "clockid = 0x%lx flags = %ld request = {.tv_sec = %ld .tv_nsec = %ld} remain = {.tv_sec = %ld .tv_nsec = %ld}", arg1, arg2, timespec_buf.tv_sec, timespec_buf.tv_nsec, timespec_buf2.tv_sec, timespec_buf2.tv_nsec);
}
SYSCALL_PRINT_FUNC(exit_group){
    output_data(outfile, "status = %ld", arg1);
}
SYSCALL_PRINT_FUNC(epoll_wait){
    struct epoll_event epoll_event_buf;
    mem_read(pid, arg2, (uint64_t*)&epoll_event_buf, sizeof(epoll_event_buf));
    // @Will not sure how to get ptr address
    output_data(outfile, "epfd = %ld events = {.events = %u .data = {.ptr = void}} maxevents = %ld timeout = %ld", arg1, epoll_event_buf.events, arg3, arg4);
}
SYSCALL_PRINT_FUNC(epoll_ctl){
    struct epoll_event epoll_event_buf;
    mem_read(pid, arg2, (uint64_t*)&epoll_event_buf, sizeof(epoll_event_buf));
    // @Will not sure how to get ptr address
    output_data(outfile, "epfd = %ld events = {.events = %u .data = {.ptr = void}} maxevents = %ld timeout = %ld", arg1, epoll_event_buf.events, arg3, arg4);
}
SYSCALL_PRINT_FUNC(tgkill){
    output_data(outfile, "tgid = %ld tid = %ld sig = %ld", arg1, arg2, arg3);
}
SYSCALL_PRINT_FUNC(utimes){
    char filename [PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&filename, PATH_MAX);
    struct timeval timeval_buf;
    mem_read(pid, arg2, (uint64_t*)&timeval_buf, sizeof(timeval_buf));
    output_data(outfile, "filename = %s times =[ news access time = {.tv_sec = %ld .tv_usec = %ld} ", filename, timeval_buf.tv_sec, timeval_buf.tv_usec);
}
SYSCALL_PRINT_FUNC(mbind){
    output_data(outfile, "addr = 0x%lx len = %ld mode = %ld nmask = 0x%lx maxnode = %ld flags = %ld", arg1, arg2, arg3, arg4, arg5, arg6);
}
SYSCALL_PRINT_FUNC(set_mempolicy){
    output_data(outfile, "mode = %ld nmask = 0x%lx maxnode = %ld", arg1, arg2, arg3);
}
SYSCALL_PRINT_FUNC(get_mempolicy){
    output_data(outfile, "mode = %ld nmask = 0x%lx maxnode = %ld addr= 0x%lx flags =%lu ", arg1, arg2, arg3, arg4, arg5);
}
SYSCALL_PRINT_FUNC(mq_open){
    char name[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&name, PATH_MAX);
    output_data(outfile, "name = %s flags = %ld", name, arg2);
}
SYSCALL_PRINT_FUNC(mq_unlink){
    char name[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&name, PATH_MAX);
    output_data(outfile, "name = %s", name);
}
SYSCALL_PRINT_FUNC(mq_timedsend){
    struct timespec timespec_buf;
    mem_read(pid, arg5, (uint64_t*)&timespec_buf, sizeof(timespec_buf));
    output_data(outfile, "mqdes = %ld msg_ptr = 0x%lx msg_len = %ld msg_prio = %ld abs_timeout = {.tv_sec = %ld .tv_nsec = %ld}", arg1, arg2, arg3, arg4, timespec_buf.tv_sec, timespec_buf.tv_nsec);
}
SYSCALL_PRINT_FUNC(mq_timedreceive){
    struct timespec timespec_buf;
    mem_read(pid, arg5, (uint64_t*)&timespec_buf, sizeof(timespec_buf));
    char msg[arg3];
    mem_read(pid, arg2, (uint64_t*)&msg, arg3);
    output_data(outfile, "mqdes = %ld msg_ptr = %s msg_len = %ld msg_prio = 0x%lx abs_timeout = {.tv_sec = %ld .tv_nsec = %ld}", arg1, msg, arg3, arg4, timespec_buf.tv_sec, timespec_buf.tv_nsec);
}
SYSCALL_PRINT_FUNC(mq_notify){
    struct sigevent sigevent_buf;
    mem_read(pid, arg2, (uint64_t*)&sigevent_buf, sizeof(sigevent_buf));
    output_data(outfile, "mqdes = %ld sigevent = {.sigev_notify = %d .sigev_signo = %d .sigev_value = {.sival_int = %d .sival_ptr = void} }", arg1, sigevent_buf.sigev_notify, sigevent_buf.sigev_signo, sigevent_buf.sigev_value.sival_int);
}
SYSCALL_PRINT_FUNC(mq_getsetattr){
    struct mq_attr mq_attr_buf;
    mem_read(pid, arg2, (uint64_t*)&mq_attr_buf, sizeof(mq_attr_buf));
    struct mq_attr mq_attr_buf2;
    mem_read(pid, arg3, (uint64_t*)&mq_attr_buf2, sizeof(mq_attr_buf2));
    output_data(outfile, "mqdes = %ld mqstat = {.mq_flags = %ld .mq_maxmsg = %ld .mq_msgsize = %ld .mq_curmsgs = %ld} omqstat = {.mq_flags = %ld .mq_maxmsg = %ld .mq_msgsize = %ld .mq_curmsgs = %ld}", arg1, mq_attr_buf.mq_flags, mq_attr_buf.mq_maxmsg, mq_attr_buf.mq_msgsize, mq_attr_buf.mq_curmsgs, mq_attr_buf2.mq_flags, mq_attr_buf2.mq_maxmsg, mq_attr_buf2.mq_msgsize, mq_attr_buf2.mq_curmsgs);
}
SYSCALL_PRINT_FUNC(kexec_load){
    struct kexec_segment kexec_segment_buf;
    mem_read(pid, arg3, (uint64_t*)&kexec_segment_buf, sizeof(kexec_segment_buf));  
    // @Will not sure how to print the address
    output_data(outfile, "entry = 0x%lx nr_segments = %ld segments = {.buf = void  .bufsz = %ld .mem = void .memsz = %ld}", arg1, arg2, kexec_segment_buf.bufsz, kexec_segment_buf.memsz);
}
SYSCALL_PRINT_FUNC(waitid){
    // I don't think this is correct
    output_data(outfile, "idtype = %ld id = %ld infop = 0x%lx options = %ld", arg1, arg2, arg3, arg4);
}
SYSCALL_PRINT_FUNC(add_key){
    char type[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&type, PATH_MAX);
    char description[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&description, PATH_MAX);
    output_data(outfile, "type = %s description = %s payload = 0x%lx plen = %ld", type, description, arg3, arg4);
}
SYSCALL_PRINT_FUNC(request_key){
    char type[PATH_MAX];
    mem_read(pid, arg1, (uint64_t*)&type, PATH_MAX);
    char description[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&description, PATH_MAX);
    char callout_info[PATH_MAX];
    mem_read(pid, arg3, (uint64_t*)&callout_info, PATH_MAX);
    // pretty sure arg4 is incorrect.
    output_data(outfile, "type = %s description = %s callout_info = 0x%s plen = %ld", type, description, callout_info, arg4);
}
SYSCALL_PRINT_FUNC(keyctl){
    output_data(outfile, "operation = %lu arg2 = %lu arg3 = %lu arg4 = %lu arg5 = %lu", arg1, arg2, arg3, arg4, arg5);
}
// 251
SYSCALL_PRINT_FUNC(ioprio_set){
    output_data(outfile, "which = %ld who = %ld", arg1, arg2);
}
SYSCALL_PRINT_FUNC(ioprio_get){
    output_data(outfile, "which = %ld who = %ld ioprio = %ld", arg1, arg2, arg3);
}
SYSCALL_PRINT_FUNC(inotify_init){
    output_data(outfile, "void functions");
}
SYSCALL_PRINT_FUNC(inotify_add_watch){
    char pathname[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&pathname, PATH_MAX);
    output_data(outfile, "fd = %ld pathname = %s mask = %ld", arg1, pathname, arg3);

}
SYSCALL_PRINT_FUNC(inotify_rm_watch){
    output_data(outfile, "fd = %ld wd = %ld", arg1, arg2);
}
SYSCALL_PRINT_FUNC(migrate_pages){
    output_data(outfile, "pid = %ld maxnode = %ld old_nodes = 0x%lx new_nodes = 0x%lx", arg1, arg2, arg3, arg4);
}
SYSCALL_PRINT_FUNC(openat){
    char pathname[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&pathname, PATH_MAX);
    output_data(outfile, "dfd = %ld pathname = %s flags = %ld mode = %ld", arg1, pathname, arg3, arg4);
}
SYSCALL_PRINT_FUNC(mkdirat){
    char pathname[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&pathname, PATH_MAX);
    // I think arg3 is incorrect
    output_data(outfile, "dirfd = %ld pathname = %s mode = 0x%lx", arg1, pathname, arg3);
}
SYSCALL_PRINT_FUNC(mknodat){
    char pathname[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&pathname, PATH_MAX);
    // I think arg3 and arg4 is incorrect
    output_data(outfile, "dirfd = %ld pathname = %s mode = 0x%lx dev = 0x%lx", arg1, pathname, arg3, arg4);
}
SYSCALL_PRINT_FUNC(fchownat){
    char pathname[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&pathname, PATH_MAX);
    // I think arg3 and arg4 is incorrect
    output_data(outfile, "dirfd = %ld pathname = %s owner = 0x%lx group = 0x%lx flags = 0x%lu", arg1, pathname, arg3, arg4, arg5);
}
SYSCALL_PRINT_FUNC(futimesat){
    struct timeval timeval_buf;
    mem_read(pid, arg3, (uint64_t*)&timeval_buf, sizeof(timeval_buf));
    char pathname[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&pathname, PATH_MAX);
    // I think my timeval part is incorrect
    output_data(outfile, "dirfd = %ld pathname = %s [ {.tv_sec = %ld .tv_usec = %ld} {.tv_sec =  .tv_usec = } ]", arg1, pathname, timeval_buf.tv_sec, timeval_buf.tv_usec);
}
SYSCALL_PRINT_FUNC(newfstatat){
    struct stat stat_buf;
    mem_read(pid, arg3, (uint64_t*)&stat_buf, sizeof(stat_buf));
    char pathname[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&pathname, PATH_MAX);
    //output_data(outfile, "dirfd = %ld pathname = %s statbuf = {.st_dev = %ld .st_ino = %ld .st_nlink = %ld .st_mode = %u .st_uid = %u .st_gid = %u .st_rdev = %ld .st_size = %ld .st_blksize = %ld .st_blocks = %ld .st_atim = {.tv_sec = %ld .tv_nsec = %ld} .st_mtim = {.tv_sec = %ld .tv_nsec = %ld} .st_ctim = {.tv_sec = %ld .tv_nsec = %ld} .st_ino = %ld}", arg1, pathname, stat_buf.st_dev, stat_buf.st_ino, stat_buf.st_nlink, stat_buf.st_mode, stat_buf.st_uid, stat_buf.st_gid, stat_buf.st_rdev, stat_buf.st_size, stat_buf.st_blksize, stat_buf.st_blocks, stat_buf.st_atim.tv_sec, stat_buf.st_atim.tv_nsec, stat_buf.st_mtim.tv_sec, stat_buf.st_mtim.tv_nsec, stat_buf.st_ctim.tv_sec, stat_buf.st_ctim.tv_nsec, stat_buf.st_ino);
    output_data(outfile, "dirfd = %ld pathname = %s statbuf = {.st_dev = %ld .st_ino = %ld .st_nlink = %ld .st_mode = %u .st_uid = %u .st_gid = %u .st_rdev = %ld .st_size = %ld .st_blksize = %ld .st_blocks = %ld st_atime = %ld st_mtime = %ld st_ctime %ld .st_ino = %ld}", arg1, pathname, stat_buf.st_dev, stat_buf.st_ino, stat_buf.st_nlink, stat_buf.st_mode, stat_buf.st_uid, stat_buf.st_gid, stat_buf.st_rdev, stat_buf.st_size, stat_buf.st_blksize, stat_buf.st_blocks, stat_buf.st_atime, stat_buf.st_mtime, stat_buf.st_ctime, stat_buf.st_ino);
}
SYSCALL_PRINT_FUNC(unlinkat){
    char pathname[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&pathname, PATH_MAX);
    output_data(outfile, "dirfd = %ld pathname = %s flags = %ld", arg1, pathname, arg3);
}
SYSCALL_PRINT_FUNC(renameat){
    char oldname[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&oldname, PATH_MAX);
    char newname[PATH_MAX];
    mem_read(pid, arg4, (uint64_t*)&newname, PATH_MAX);
    output_data(outfile, "olddirfd = %ld oldpath = %s newdirfd = %ld newpath = %s", arg1, oldname, arg3, newname);
}
SYSCALL_PRINT_FUNC(linkat){
    char oldname[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&oldname, PATH_MAX);
    char newname[PATH_MAX];
    mem_read(pid, arg4, (uint64_t*)&newname, PATH_MAX);
    output_data(outfile, "olddirfd = %ld oldpath = %s newdirfd = %ld newpath = %s", arg1, oldname, arg3, newname);
}
SYSCALL_PRINT_FUNC(symlinkat){
    char oldname[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&oldname, PATH_MAX);
    char newname[PATH_MAX];
    mem_read(pid, arg4, (uint64_t*)&newname, PATH_MAX);
    output_data(outfile, "oldpath = %s newdirfd = %ld newpath = %s", oldname, arg3, newname);
}
SYSCALL_PRINT_FUNC(readlinkat){
    char buf[arg4];
    mem_read(pid, arg3, (uint64_t*)&buf, arg4);
    char pathname[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&pathname, PATH_MAX);
    output_data(outfile, "dirfd = %ld pathname = %s buf = %s bufsiz = %ld", arg1, pathname, buf, arg4);

}
SYSCALL_PRINT_FUNC(fchmodat){
    char pathname[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&pathname, PATH_MAX);
    //Mode T probably isn't correct
    output_data(outfile, "dirfd = %ld pathname = %s mode_t =0x%lx flags = %lu", arg1, pathname, arg3, arg4);
}
SYSCALL_PRINT_FUNC(faccessat){
    char pathname[PATH_MAX];
    mem_read(pid, arg2, (uint64_t*)&pathname, PATH_MAX);
    //Mode T probably isn't correct
    output_data(outfile, "dirfd = %ld pathname = %s mode_t =0x%lx flags = %lu", arg1, pathname, arg3, arg4);
}
SYSCALL_PRINT_FUNC(pselect6){
// Is  it the same as pselect (no 6)?
// https://linux.die.net/man/2/pselect6 
}
SYSCALL_PRINT_FUNC(ppoll){
    struct pollfd pollfd_buf;
    mem_read(pid, arg1, (uint64_t*)&pollfd_buf, sizeof(pollfd_buf));
    struct timespec timespec_buf;
    mem_read(pid, arg4, (uint64_t*)&timespec_buf, sizeof(timespec_buf));
    //sigset_t is opaque
    //nfds may not be correct
    output_data(outfile, "fds = {.fd = %d .events = %u .revents = %u} nfds = %ld timeout = {.tv_sec = %ld .tv_nsec = %ld} sigmask = 0x%lx", pollfd_buf.fd, pollfd_buf.events, pollfd_buf.revents, arg2, timespec_buf.tv_sec, timespec_buf.tv_nsec, arg5);
}
SYSCALL_PRINT_FUNC(unshare){
    output_data(outfile, "flags = %ld", arg1);
}
SYSCALL_PRINT_FUNC(set_robust_list){
        struct robust_list_head robust_list_head_buf;
        mem_read(pid, arg1, (uint64_t*)&robust_list_head_buf, arg2);
        // @ Will need help with these lists
        //output_data(outfile, "head = {.list = 0x%lx .futex_offset = %ld .list_op_pending = %ld}", robust_list_head_buf.list, robust_list_head_buf.futex_offset, robust_list_head_buf.list_op_pending);


}
SYSCALL_PRINT_FUNC(get_robust_list){
        struct robust_list_head robust_list_head_buf;
        mem_read(pid, arg1, (uint64_t*)&robust_list_head_buf, arg2);
        // @Will need help with these lists
        //output_data(outfile, "pid = %lu head = {.list = 0x%lx .futex_offset = %ld .list_op_pending = 0x%lx}", arg1, robust_list_head_buf.list, robust_list_head_buf.futex_offset, robust_list_head_buf.list_op_pending);

}
SYSCALL_PRINT_FUNC(splice){
    output_data(outfile, "fd_in = %ld off_in = 0x%lx fd_out = %ld off_out = 0x%lx len = %ld flags = %ld", arg1, arg2, arg3, arg4, arg5, arg6);
}
SYSCALL_PRINT_FUNC(tee){
    output_data(outfile, "fd_in = %ld fd_out = %ld len = %ld flags = %lu", arg1, arg2, arg3, arg4);
}
SYSCALL_PRINT_FUNC(sync_file_range){
    output_data(outfile, "fd = %ld offset = %ld nbytes = %ld flags = %lu", arg1, arg2, arg3, arg4);
}
SYSCALL_PRINT_FUNC(vmsplice){

}
SYSCALL_PRINT_FUNC(move_pages){

}
SYSCALL_PRINT_FUNC(utimensat){

}
SYSCALL_PRINT_FUNC(epoll_pwait){

}
SYSCALL_PRINT_FUNC(signalfd){

}
SYSCALL_PRINT_FUNC(timerfd_create){

}
SYSCALL_PRINT_FUNC(eventfd){

}
SYSCALL_PRINT_FUNC(fallocate){

}
SYSCALL_PRINT_FUNC(timerfd_settime){

}
SYSCALL_PRINT_FUNC(timerfd_gettime){

}
SYSCALL_PRINT_FUNC(accept4){

}
SYSCALL_PRINT_FUNC(signalfd4){

}
SYSCALL_PRINT_FUNC(eventfd2){

}
SYSCALL_PRINT_FUNC(epoll_create1){

}
SYSCALL_PRINT_FUNC(dup3){

}
SYSCALL_PRINT_FUNC(pipe2){

}
SYSCALL_PRINT_FUNC(inotify_init1){

}
SYSCALL_PRINT_FUNC(preadv){

}
SYSCALL_PRINT_FUNC(pwritev){

}
SYSCALL_PRINT_FUNC(rt_tgsigqueueinfo){

}
SYSCALL_PRINT_FUNC(perf_event_open){

}
SYSCALL_PRINT_FUNC(recvmmsg){

}
SYSCALL_PRINT_FUNC(fanotify_init){

}
SYSCALL_PRINT_FUNC(fanotify_mark){

}
SYSCALL_PRINT_FUNC(prlimit64){

}
SYSCALL_PRINT_FUNC(name_to_handle_at){

}
SYSCALL_PRINT_FUNC(open_by_handle_at){

}
SYSCALL_PRINT_FUNC(clock_adjtime){

}
SYSCALL_PRINT_FUNC(syncfs){

}
SYSCALL_PRINT_FUNC(sendmmsg){

}
SYSCALL_PRINT_FUNC(setns){

}
SYSCALL_PRINT_FUNC(getcpu){

}
SYSCALL_PRINT_FUNC(process_vm_readv){

}
SYSCALL_PRINT_FUNC(process_vm_writev){

}
SYSCALL_PRINT_FUNC(kcmp){

}
SYSCALL_PRINT_FUNC(finit_module){

}
SYSCALL_PRINT_FUNC(sched_setattr){

}
SYSCALL_PRINT_FUNC(sched_getattr){

}
SYSCALL_PRINT_FUNC(renameat2){

}
SYSCALL_PRINT_FUNC(seccomp){

}
SYSCALL_PRINT_FUNC(getrandom){

}
SYSCALL_PRINT_FUNC(memfd_create){

}
SYSCALL_PRINT_FUNC(kexec_file_load){
    
}
SYSCALL_PRINT_FUNC(bpf){

}
SYSCALL_PRINT_FUNC(execveat){

}
SYSCALL_PRINT_FUNC(userfaultfd){

}
SYSCALL_PRINT_FUNC(membarrier){

}
SYSCALL_PRINT_FUNC(mlock2){

}
SYSCALL_PRINT_FUNC(copy_file_range){

}
SYSCALL_PRINT_FUNC(preadv2){

}
SYSCALL_PRINT_FUNC(pwritev2){

}
SYSCALL_PRINT_FUNC(pkey_mprotect){

}
SYSCALL_PRINT_FUNC(pkey_alloc){

}
SYSCALL_PRINT_FUNC(pkey_free){

}
SYSCALL_PRINT_FUNC(statx){

}
SYSCALL_PRINT_FUNC(io_pgetevents){

}
SYSCALL_PRINT_FUNC(rseq){

}
SYSCALL_PRINT_FUNC(pidfd_send_signal){

}
SYSCALL_PRINT_FUNC(io_uring_setup){

}
SYSCALL_PRINT_FUNC(io_uring_enter){

}
SYSCALL_PRINT_FUNC(io_uring_register){

}
SYSCALL_PRINT_FUNC(open_tree){

}
SYSCALL_PRINT_FUNC(move_mount){

}
SYSCALL_PRINT_FUNC(fsopen){

}
SYSCALL_PRINT_FUNC(fsconfig){

}
SYSCALL_PRINT_FUNC(fsmount){

}
SYSCALL_PRINT_FUNC(fspick){

}
SYSCALL_PRINT_FUNC(pidfd_open){

}
SYSCALL_PRINT_FUNC(clone3){

}
SYSCALL_PRINT_FUNC(close_range){

}
SYSCALL_PRINT_FUNC(openat2){

}
SYSCALL_PRINT_FUNC(pidfd_getfd){

}
SYSCALL_PRINT_FUNC(faccessat2){

}
SYSCALL_PRINT_FUNC(accessat2){

}
SYSCALL_PRINT_FUNC(process_madvise){

}
SYSCALL_PRINT_FUNC(epoll_pwait2){

}
SYSCALL_PRINT_FUNC(mount_setattr){

}
SYSCALL_PRINT_FUNC(quotactl_fd){

}
SYSCALL_PRINT_FUNC(landlock_create_ruleset){

}
SYSCALL_PRINT_FUNC(landlock_add_rule){

}
SYSCALL_PRINT_FUNC(landlock_restrict_self){

}
SYSCALL_PRINT_FUNC(memfd_secret){

}
SYSCALL_PRINT_FUNC(process_mrelease){
    
}

static void print_sockaddr(FILE* outfile, struct sockaddr *sock) {
    output_data(outfile, "{.sa_family = %d ", sock->sa_family);
    if(sock->sa_family == AF_INET) {
	struct sockaddr_in *sock4 = (struct sockaddr_in*)sock;
	output_data(outfile, ".sin_family = %d .sin_port %d .sin_addr %d }", sock4->sin_family, sock4->sin_port, sock4->sin_addr.s_addr);
    } else if(sock->sa_family == AF_INET6) {
	struct sockaddr_in6 *sock6 = (struct sockaddr_in6*)sock;
	output_data(outfile, ".sin6_family = %d .sin6_port %d .sin6_flowinfo %d .in6_addr = 0x", sock6->sin6_family, sock6->sin6_port, sock6->sin6_flowinfo);
	for(int i = 0; i < sizeof(sock6->sin6_addr.s6_addr); i++) {
		output_data(outfile, "%hhX", sock6->sin6_addr.s6_addr[i]);
	}
	output_data(outfile, " .sin6_scope_id = %u}", sock6->sin6_scope_id);
    }
}

static void print_statfs_struct(FILE *outfile, struct statfs *s) {
    output_data(outfile, "statfs = {.f_type = %lu .f_bsize = %lu .f_blocks = %lu .f_bfree = %lu .f_bavail = %lu .f_files = %lu .f_ffree = %lu .f_fsid = %lu .f_namelen = %lu .f_frsize = %lu .f_flags = %lu", s->f_type, s->f_bsize, s->f_blocks, s->f_bfree, s->f_bavail, s->f_files, s->f_ffree, s->f_fsid, s->f_namelen, s->f_frsize, s->f_flags);
}
