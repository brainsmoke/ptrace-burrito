#ifndef UTIL_H
#define UTIL_H

#include <sys/types.h>
#include <stdint.h>

#include "trace.h"
#include "signal_queue.h"

/* Low-level functionality, some of which needs
 * platform specific implementations
 */

uint64_t get_timestamp(void);

unsigned long get_eventmsg(trace_t *t);

void get_registers(trace_t *t);
void set_registers(trace_t *t);

void get_siginfo(pid_t pid, siginfo_t *info);
void set_siginfo(pid_t pid, siginfo_t *info);

/*
 * The following functions only read/change the registers in trace_t:
 * the caller should call set_registers() to make it definite
 */

unsigned long get_syscall(trace_t *t);
void set_syscall(trace_t *t, unsigned long val);

unsigned long get_arg(trace_t *t, int number);
void set_arg(trace_t *t, int number, unsigned long val);

void get_args(trace_t *t, long *args, int argc);
void set_args(trace_t *t, long *args, int argc);

unsigned long get_result(trace_t *t);
void set_result(trace_t *t, unsigned long val);

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
