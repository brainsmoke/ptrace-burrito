
/* This file is part of ptrace-burrito
 *
 * Copyright 2010-2018 Erik Bosman <erik@minemu.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UTIL_H
#define UTIL_H

#include <sys/types.h>
#include <sys/mman.h>

#include <stdint.h>

#include "trace.h"
#include "signal_queue.h"

/* Low-level functionality, some of which need
 * platform specific implementations
 */

uint64_t get_timestamp(void);

unsigned long get_eventmsg(trace_t *t);

void get_registers(trace_t *t);
void set_registers(trace_t *t);

void write_modified_regs(trace_t *t);

void init_debug_regs(trace_t *t);
void clear_debug_regs(trace_t *t);

int debug_reg_breakpoints_enabled(trace_t *t);
int debug_reg_breakpoints_triggered(trace_t *t);

/* returns -1 if not trapped, returns breakpoint/watchpoint number if trapped */
int debug_reg_current_breakpoint(trace_t *t);


/* returns breakpoint/watchpoint number, or -1 on error,
 *
 * use prot=PROT_READ|PROT_WRITE to break on reads & writes, PROT_WRITE for writes,
 * PROT_EXEC for breakpoints
 *
 * breakpoints are cleared on exec
 *
 */
int debug_reg_set_breakpoint(trace_t *t, uintptr_t address);
int debug_reg_set_watchpoint(trace_t *t, uintptr_t address, int prot, int size);
int debug_reg_get_breakpoint(trace_t *t, int index, uintptr_t *address, int *prot, int *size);
int debug_reg_unset_breakpoint(trace_t *t, int index);


void get_siginfo(pid_t pid, siginfo_t *info);
void set_siginfo(pid_t pid, siginfo_t *info);

uintptr_t get_pc(trace_t *t);
void set_pc(trace_t *t, uintptr_t val);

uintptr_t get_sp(trace_t *t);
void set_sp(trace_t *t, uintptr_t val);

unsigned long get_syscall(trace_t *t);
void set_syscall(trace_t *t, unsigned long val);

unsigned long get_syscall_arg(trace_t *t, int number);
void set_syscall_arg(trace_t *t, int number, unsigned long val);

void get_syscall_args(trace_t *t, long *args, int argc);
void set_syscall_args(trace_t *t, long *args, int argc);


unsigned long get_func_arg(trace_t *t, int number);
unsigned long get_func_result(trace_t *t);

unsigned long get_syscall_result(trace_t *t);
void set_syscall_result(trace_t *t, unsigned long val);

void set_trap_flag(trace_t *t, int val);
int get_trap_flag(trace_t *t);

int program_counter_at_tsc(trace_t *t);
void emulate_tsc(trace_t *t, uint64_t timestamp);

/* NOTE: contents of 'return register' undefined */
void skip_syscall(trace_t *t);

void next_trap(trace_t *t, signal_queue_t *q);

/* reverts back to the state before the syscall,
 * the syscall should not have changed anything,
 * only useful during POST_CALL
 */
void reset_syscall(trace_t *t);

/*
 * The following functions do nasty stuff to the program:
 * but restore execution state afterwards
 */

/* undoes the syscall we just entered, useful only during PRE_CALL
 */
void undo_syscall(trace_t *t);

/* restarts the syscall we just entered, useful only during PRE_CALL
 */
void redo_syscall(trace_t *t, signal_queue_t *q);

/* NOTE: Can only be used just before, or just after a syscall;
 * don't call it during the other callbacks
 * injected syscalls should not modify the execution
 * environment in a way that makes continuing the syscall
 * impossible
 * any signals caught will be stored in q if not set to NULL
 */
long inject_syscall(trace_t *t, long call, long args[], int argc,
                    signal_queue_t *q);

enum { TO_USER = 0x01, FROM_USER = 0x02 };

typedef struct
{
	long value;
	void *buf;
	long size;
	int flags;
} arg_t;

/* like inject_syscall, but allows for data to be copied from/to
 * our userspace.
 */
long inject_data_syscall(trace_t *t, long call, arg_t args[], int argc,
                         signal_queue_t *q);

struct stat64; /* include sys/stat.h with _LARGEFILE64_SOURCE */
/* does an (f)stat64 inside the traced process */
long inject_stat64(trace_t *t, char *file, struct stat64 *s, signal_queue_t *q);
long inject_lstat64(trace_t *t, char *file,struct stat64 *s, signal_queue_t *q);
long inject_fstat64(trace_t *t, int fd, struct stat64 *s, signal_queue_t *q);
long inject_readlink(trace_t *t, char *path, char *buf, size_t bufsiz,
                     signal_queue_t *q);

typedef struct
{
	void *base_addr;
	size_t size;
/*	long mode, ... */

} mmap_data_t;

/* laddr may be NULL */
mmap_data_t mmap_data(trace_t *t, void *laddr, void *raddr, size_t n, /*... ,*/
                      signal_queue_t *q);

void munmap_data(trace_t *t, mmap_data_t *map, signal_queue_t *q);

/* Copies data between the traced and the tracing process
 * naming is from the perspective of the tracer, so
 * memload copies data from the tracee to the tracer.
 */
int memload(pid_t pid, void *laddr, void *raddr, size_t n);
int memloadstr(pid_t pid, void *laddr, void *raddr, size_t max_size);
int memstore(pid_t pid, void *laddr, void *raddr, size_t n);

/* creates open pipes for communication to traced processes */
void init_pipe_channels(void);

/* we shouldn't let the traced process do file operation on our pipe */
int is_pipe_channel(int fd);

/* NOTE: use these only before or after syscall */
int memload_pipe(trace_t *t, void *laddr, void *raddr, size_t n,
                 signal_queue_t *q);
int memstore_pipe(trace_t *t, void *laddr, void *raddr, size_t n,
                  signal_queue_t *q);

#endif /* UTIL_H */
