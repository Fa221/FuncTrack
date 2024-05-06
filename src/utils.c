#include <stdarg.h>
#include <stdio.h>
#include "utils.h"
#include <sys/ptrace.h>
void output_data(FILE *outfile, char *err_str, ...) {
    va_list args;
    va_start(args, err_str);
    vfprintf(outfile, err_str, args);
    va_end(args);
}
int mem_read(pid_t pid, uint64_t addr, uint64_t *buf, size_t len) {
    long word;
    for(int i = 0; i < len/WORD_SIZE; i++) {
        word = ptrace(PTRACE_PEEKDATA, pid, addr + i*WORD_SIZE, 0x0);
        if(word == -1) {
            return -1;
        }
        buf[i] = word;
    }
    return 0;
}
