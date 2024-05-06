#pragma once
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#define WORD_SIZE 8
void output_data(FILE*, char *str, ...);
int mem_read(pid_t, uint64_t, uint64_t*, size_t);
