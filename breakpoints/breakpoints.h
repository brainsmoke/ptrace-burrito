#ifndef BREAKPOINTS_H
#define BREAKPOINTS_H

#include <stdint.h>

#include "trace.h"

enum
{
	BP_COPY_CHILD = 1, /*  */
	BP_COPY_EXEC  = 2, /*  */
	BP_DISABLED   = 4, /*  */
};

enum
{
	BP_FILEOFFSET = 1,
	BP_ADDRESS    = 2,
};

void add_breakpoint_fileoff(trace_t *t, int bpid, const char *filename, intptr_t offset, int flags);
void add_watchpoint_fileoff(trace_t *t, int bpid, const char *filename, intptr_t offset, int prot, int size, int flags);

void add_breakpoint_address(trace_t *t, int bpid, intptr_t address, int flags);
void add_watchpoint_address(trace_t *t, int bpid, intptr_t address, int prot, int size, int flags);

void enable_breakpoint(trace_t *t, int bpid);
void disable_breakpoint(trace_t *t, int bpid);

void del_breakpoint(trace_t *t, int bpid);

void try_activate_breakpoints(trace_t *t);

int current_breakpoint_id(trace_t *t);

/* in plug->start() */
void update_breakpoints_on_fork(trace_t *parent, trace_t *child);

/* in plug->exec() */
void update_breakpoints_on_exec(trace_t *t);

/* in plug->post_call() */
void update_breakpoints_post_syscall(trace_t *t);

/* in plug->stop() */
void update_breakpoints_on_exit(trace_t *t);

/* wrapper calling the update functions above automatically */
tracer_plugin_t breakpoint_wrap(tracer_plugin_t *plug);

#endif
