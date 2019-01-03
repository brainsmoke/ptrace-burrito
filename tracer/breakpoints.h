
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

int all_breakpoints_resolved(trace_t *t);

/* used by tracer */
void update_breakpoints(trace_t *parent, trace_t *child);
void free_breakpoints(trace_t *t);

#endif
