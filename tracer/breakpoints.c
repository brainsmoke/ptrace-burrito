
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

#include <string.h>
#include <stdlib.h>

#include "breakpoints.h"
#include "errors.h"
#include "trace.h"
#include "util.h"
#include "process.h"

/* typedef struct breakpoint_s breakpoint_t; */
           struct breakpoint_s
{
	int id, type, flags, dr_index;

	char *filename;
	intptr_t offset;

	intptr_t address;

	int size, prot;

	breakpoint_t *next;
};

static breakpoint_t *free_bp(breakpoint_t *bp)
{
	breakpoint_t *next = bp->next;
	if (bp->filename)
			free(bp->filename);
	free(bp);
	return next;
}

static void free_bp_list(breakpoint_t *l)
{
	for (; l ; l = free_bp(l));
}

static breakpoint_t *find_breakpoint(trace_t *t, int bpid)
{
	breakpoint_t *bp;
	for (bp=t->bp_list; bp; bp=bp->next)
		if (bp->id == bpid)
			return bp;
	return NULL;
}

void del_breakpoint(trace_t *t, int bpid)
{
	breakpoint_t pre = { .next = t->bp_list}, *prev;

	for (prev=&pre ; prev->next ; prev=prev->next)
		if (prev->next->id == bpid)
		{
			if (prev->next->dr_index != -1)
				debug_reg_unset_breakpoint(t, prev->next->dr_index);

			prev->next = free_bp(prev->next);
			break;
		}

	t->bp_list = pre.next;
}

static void try_resolve_bp(trace_t *t, breakpoint_t *bp)
{
	if ( bp->address == 0 )
	{
		if (bp->type == BP_FILEOFFSET)
			bp->address = find_code_address(t->pid, bp->filename, bp->offset);

		else if (bp->type != BP_ADDRESS)
			fatal_error("%s: bad breakpoint type", __func__);
	}
}

static void try_activate_bp(trace_t *t, breakpoint_t *bp)
{
	try_resolve_bp(t, bp);

	if ( (bp->address == 0) || (bp->flags & BP_DISABLED) || (bp->dr_index != -1) )
		return;

	bp->dr_index = debug_reg_set_watchpoint(t, bp->address, bp->prot, bp->size);

	if (bp->dr_index < 0)
			fatal_error("%s: too many break/watchpoints", __func__);
}

void try_activate_breakpoints(trace_t *t)
{
	breakpoint_t *bp;
	for (bp = t->bp_list; bp ; bp=bp->next)
		try_activate_bp(t, bp);
}

int all_breakpoints_resolved(trace_t *t)
{
	breakpoint_t *bp;
	for (bp = t->bp_list; bp ; bp=bp->next)
		if (!bp->address)
			return 0;

	return 1;
}

static void add_watchpoint(trace_t *t, int bpid, breakpoint_t *bp)
{
	del_breakpoint(t, bpid);
	bp->next = t->bp_list,
	t->bp_list = bp;
	try_activate_bp(t, bp);
}

void add_watchpoint_fileoff(trace_t *t, int bpid, const char *filename, intptr_t offset,
                           int prot, int size, int flags)
{
	breakpoint_t *bp = (breakpoint_t*)try_malloc(sizeof(breakpoint_t));
	*bp = (breakpoint_t)
	{
		.id = bpid,
		.type = BP_FILEOFFSET,
		.flags = flags & (BP_COPY_CHILD|BP_COPY_EXEC|BP_DISABLED),
		.dr_index = -1,
		.filename = strdup(filename),
		.offset = offset,
		.prot = prot,
		.size = size,
	};
	add_watchpoint(t, bpid, bp);
}

void add_breakpoint_fileoff(trace_t *t, int bpid, const char *filename, intptr_t offset, int flags)
{
	add_watchpoint_fileoff(t, bpid, filename, offset, PROT_EXEC, 1, flags);
}

void add_watchpoint_address(trace_t *t, int bpid, intptr_t address, int prot, int size, int flags)
{
	breakpoint_t *bp = (breakpoint_t*)try_malloc(sizeof(breakpoint_t));
	*bp = (breakpoint_t)
	{
		.id = bpid,
		.type = BP_ADDRESS,
		.flags = flags & (BP_COPY_CHILD|BP_COPY_EXEC|BP_DISABLED),
		.dr_index = -1,
		.address = address,
		.prot = prot,
		.size = size,
	};
	add_watchpoint(t, bpid, bp);
}

void add_breakpoint_address(trace_t *t, int bpid, intptr_t address, int flags)
{
	add_watchpoint_address(t, bpid, address, PROT_EXEC, 1, flags);
}

void enable_breakpoint(trace_t *t, int bpid)
{
	breakpoint_t *bp = find_breakpoint(t, bpid);
	if (bp && (bp->flags & BP_DISABLED) )
	{
		bp->flags &=~ BP_DISABLED;
		try_activate_bp(t, bp);
	}
}

void disable_breakpoint(trace_t *t, int bpid)
{
	breakpoint_t *bp = find_breakpoint(t, bpid);
	if (bp && !(bp->flags & BP_DISABLED) )
	{
		bp->flags |= BP_DISABLED;
		if (bp->dr_index != -1)
		{
			debug_reg_unset_breakpoint(t, bp->dr_index);
			bp->dr_index = -1;
		}
	}
}

int current_breakpoint_id(trace_t *t)
{
	int dr_index = debug_reg_current_breakpoint(t);
	breakpoint_t *bp;
	for (bp = t->bp_list; bp ; bp=bp->next)
		if (bp->dr_index == dr_index)
			return bp->id;

	return -1;
}

static void update_breakpoints_on_fork(trace_t *parent, trace_t *child)
{
	/* first traced process */
	if (parent == NULL)
		return;

	breakpoint_t *bp, *new_bp;
	for (bp = parent->bp_list; bp ; bp = bp->next)
		if ( bp->flags & BP_COPY_CHILD )
		{
			new_bp = (breakpoint_t*)try_malloc(sizeof(breakpoint_t));
			*new_bp = *bp;
			new_bp->dr_index = -1;
			new_bp->next = NULL;

			if (new_bp->filename)
				new_bp->filename = strdup(new_bp->filename);

			add_watchpoint(child, new_bp->id, new_bp);
		}
}

static void update_breakpoints_on_exec(trace_t *t)
{
	breakpoint_t pre = { .next = t->bp_list}, *prev = &pre;

	while (prev->next)
	{
		if (prev->next->flags & BP_COPY_EXEC)
		{
			prev->next->dr_index = -1; /* drX are cleared on exec */
			if (prev->next->type == BP_FILEOFFSET)
				prev->next->address = 0;

			try_activate_bp(t, prev->next);
			prev = prev->next;
		}
		else
			prev->next = free_bp(prev->next);
	}

	t->bp_list = pre.next;
}

static void update_breakpoints_post_syscall(trace_t *t)
{
	/*
	 * TODO: deal with unmaps / remaps
	 */
	if ( (get_syscall(t) == ARCH_MMAP_SYSCALL) || !(get_syscall_arg(t, 3) & MAP_ANONYMOUS) )
		try_activate_breakpoints(t);
}

void free_breakpoints(trace_t *t)
{
	free_bp_list(t->bp_list);
	t->bp_list = NULL;
}

void update_breakpoints(trace_t *t, trace_t *parent)
{
	switch (t->state)
	{
		case START:     update_breakpoints_on_fork(parent, t); break;
		case EXEC:      update_breakpoints_on_exec(t);         break;
		case POST_CALL: update_breakpoints_post_syscall(t);    break;
		default:                                               break;
	}
}

