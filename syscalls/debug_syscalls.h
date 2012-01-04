#ifndef DEBUG_SYSCALLS_H
#define DEBUG_SYSCALLS_H

#include "trace.h"

/* get the name of a syscall */
const char *syscall_name(long no);

const char *socketcall_name(long no);

/* get the name of a syscall */
const char *signal_name(int no);
int signal_no(const char *name);

void print_flags(int flags);
void print_call(long call, long args[], int argc);
void print_trace_call(trace_t *t);
void print_trace_return(trace_t *t);

#endif /* DEBUG_SYSCALLS_H */
