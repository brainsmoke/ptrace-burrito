
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

#ifndef TRACE_H
#define TRACE_H

#include <sys/ptrace.h>
#include <sys/types.h>

#include "arch.h"

typedef struct breakpoint_s breakpoint_t;

#define CALL_SIGTRAP (0x85)

/* possible states */
enum { START, STOP, PRE_CALL, POST_CALL, SIGNAL, EXEC, STEP, BREAKPOINT, DETACH };

/* The per-process datastructure which maintains state during execution */

typedef struct
{
	registers_t regs, orig;
	debug_registers_t debug_regs, debug_orig;
	unsigned char state, signal, exitcode, event;
	unsigned short flags, oobflags;
	pid_t pid;
	int status;
	breakpoint_t *bp_list;
	void *data; /* free to be used by tracer plugin */

} trace_t;

/* prototype for a callback function which should tell the
 * tracer for which process to wait next.
 * this is needed for the replay phase
 */
typedef pid_t (*pidselector_t)(void *);

/* always returns -1, which, when passed on to waitpid, will
 * cause it to wait for anything
 */
pid_t any_pid(void *);

typedef void (*traphandler_t)(trace_t *, void *);
typedef void (*starthandler_t)(trace_t *, trace_t *, void *);
typedef void (*datahandler_t)(void *);

/* all callbacks */
typedef struct tracer_plugin_s
{
	pidselector_t pid_selector;
	starthandler_t start;
	traphandler_t stop, pre_call, post_call, signal, exec, step, breakpoint, detach;
	datahandler_t init, final;
	void *data; /* passed on to callback functions as argument */

} tracer_plugin_t;

/* Executes and traces a new process using the specified callbacks */
void trace(pid_t pid, tracer_plugin_t *plug);

/* tells the tracer not to continue execution of this process until
 * release_process() is called, it is the caller's responsibility
 * to make sure there are processes left to wait for (and that these
 * don't block indefinitely.)
 */
void hold_process(trace_t *t);

/* continue a held process
 */
void release_process(trace_t *t);

void steptrace_process(trace_t *t, int val);
int get_steptrace_process(trace_t *t);

void trace_syscalls(trace_t *t, int val);

void detach_process(trace_t *t);
void detach_all(void);

#endif /* TRACE_H */
