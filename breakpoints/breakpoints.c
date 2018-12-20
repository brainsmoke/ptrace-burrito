
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <inttypes.h>

#include "breakpoints.h"
#include "errors.h"
#include "trace.h"
#include "util.h"
#include "maps.h"

typedef struct breakpoint_s breakpoint_t;
        struct breakpoint_s
{
	int id, type, flags, dr_index;

	char *filename;
	intptr_t offset;

	intptr_t address;

	int size, prot;

	breakpoint_t *next;
};

typedef struct breakpoint_ctx_s breakpoint_ctx_t;
        struct breakpoint_ctx_s
{
	pid_t pid;
	breakpoint_t *bp;

	breakpoint_ctx_t *next;
};

static breakpoint_ctx_t *list = NULL;
static breakpoint_ctx_t *last_ctx = NULL;

static breakpoint_ctx_t *find_bp_ctx(pid_t pid)
{
	if (last_ctx && last_ctx->pid == pid)
		return last_ctx;

	breakpoint_ctx_t *l = list;
	for (l=list; l; l=l->next)
	{
		if (l->pid == pid)
		{
			last_ctx = l;
			return l;
		}
	}
	breakpoint_ctx_t *old_head=list;
	list = try_malloc(sizeof(breakpoint_ctx_t));
	*list = (breakpoint_ctx_t)
	{
		.next=old_head,
		.pid = pid,
		.bp = NULL,
	};
	last_ctx = list;
	return list;
}

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

static void del_bp_ctx(pid_t pid)
{
	last_ctx = NULL;
	breakpoint_ctx_t pre = { .next = list }, *l;

	for (l=&pre; l->next; l=l->next)
	{
		if (l->next->pid == pid)
		{
			breakpoint_ctx_t *d = l->next;
			l->next = l->next->next;
			free_bp_list(d->bp);
			free(d);
			break;
		}
	}

	list = pre.next;
}

static breakpoint_t *find_breakpoint(breakpoint_ctx_t *ctx, int bpid)
{
	breakpoint_t *bp;
	for (bp=ctx->bp; bp; bp=bp->next)
		if (bp->id == bpid)
			return bp;
	return NULL;
}

void del_breakpoint(trace_t *t, int bpid)
{
	breakpoint_ctx_t *ctx = find_bp_ctx(t->pid);
	breakpoint_t pre = { .next = ctx->bp}, *prev;

	for (prev=&pre ; prev->next ; prev=prev->next)
		if (prev->next->id == bpid)
		{
			if (prev->next->dr_index != -1)
				unset_watchpoint(t, prev->next->dr_index);

			prev->next = free_bp(prev->next);
			ctx->bp = pre.next;
			break;
		}
}

static void try_activate_bp(trace_t *t, breakpoint_t *bp)
{
	if ( (bp->flags & BP_DISABLED) || (bp->dr_index != -1) )
		return;

	uintptr_t address = 0;

	if (bp->type == BP_FILEOFFSET)
		address = find_code_address(t->pid, bp->filename, bp->offset);
	else if (bp->type == BP_ADDRESS)
		address = bp->address;
	else
		fatal_error("%s: bad breakpoint type", __func__);

	if (address != 0)
	{
		bp->dr_index = set_watchpoint(t, address, bp->prot, bp->size);
		if (bp->dr_index < 0)
			fatal_error("%s: too many break/watchpoints", __func__);
	}
}

void try_activate_breakpoints(trace_t *t)
{
	breakpoint_ctx_t *ctx = find_bp_ctx(t->pid);
	breakpoint_t *bp;
	for (bp = ctx->bp; bp ; bp=bp->next)
		try_activate_bp(t, bp);
}

static void add_watchpoint(trace_t *t, int bpid, breakpoint_t *bp)
{
	del_breakpoint(t, bpid);
	breakpoint_ctx_t *ctx = find_bp_ctx(t->pid);
	bp->next = ctx->bp,
	ctx->bp = bp;
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
	breakpoint_ctx_t *ctx = find_bp_ctx(t->pid);
	breakpoint_t *bp = find_breakpoint(ctx, bpid);
	if (bp && (bp->flags & BP_DISABLED) )
	{
		bp->flags &=~ BP_DISABLED;
		try_activate_bp(t, bp);
	}
}

void disable_breakpoint(trace_t *t, int bpid)
{
	breakpoint_ctx_t *ctx = find_bp_ctx(t->pid);
	breakpoint_t *bp = find_breakpoint(ctx, bpid);
	if (bp && !(bp->flags & BP_DISABLED) )
	{
		bp->flags &= BP_DISABLED;
		if (bp->dr_index != -1)
			unset_watchpoint(t, bp->dr_index);
	}
}

void copy_breakpoints_on_fork(trace_t *parent, trace_t *child)
{
	breakpoint_ctx_t *src_ctx = find_bp_ctx(parent->pid);

	breakpoint_t *bp, *new_bp;
	for (bp = src_ctx->bp; bp ; bp = bp->next)
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

void clear_breakpoints_on_exec(trace_t *t)
{
	breakpoint_ctx_t *ctx = find_bp_ctx(t->pid);
	breakpoint_t pre = { .next = ctx->bp}, *prev = &pre;

	while (prev->next)
		if ( !(prev->next->flags & BP_COPY_CHILD) )
		{
			if (prev->next->dr_index != -1)
				unset_watchpoint(t, prev->next->dr_index);

			prev->next = free_bp(prev->next);
		}
		else
			prev=prev->next;

	ctx->bp = pre.next;
}

void update_breakpoints_post_syscall(trace_t *t)
{
	if ( (t->syscall == ARCH_MMAP_SYSCALL) || !(get_arg(t, 3) & MAP_ANONYMOUS) )
		try_activate_breakpoints(t);
}

static pid_t wrap_pid_selector(void *data)
{
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	return plug->pid_selector(plug->data);
}

static void wrap_pre_call(trace_t *t, void *data)
{
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	if (plug->pre_call) plug->pre_call(t, plug->data);
}

static void wrap_post_call(trace_t *t, void *data)
{
	update_breakpoints_post_syscall(t);
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	if (plug->post_call) plug->post_call(t, plug->data);
}

static void wrap_signal(trace_t *t, void *data)
{
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	if (plug->signal) plug->signal(t, plug->data);
}

static void wrap_start(trace_t *t, trace_t *parent, void *data)
{
	copy_breakpoints_on_fork(parent, t);
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	if (plug->start) plug->start(t, parent, plug->data);
}

static void wrap_stop(trace_t *t, void *data)
{
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	if (plug->stop) plug->stop(t, plug->data);
	del_bp_ctx(t->pid);
}

static void wrap_step(trace_t *t, void *data)
{
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	if (plug->step) plug->step(t, plug->data);
}

static void wrap_exec(trace_t *t, void *data)
{
	clear_breakpoints_on_exec(t);
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	if (plug->step) plug->exec(t, plug->data);
}

static void wrap_breakpoint(trace_t *t, void *data)
{
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	if (plug->breakpoint) plug->breakpoint(t, plug->data);
}

tracer_plugin_t breakpoint_wrap(tracer_plugin_t *plug)
{
	tracer_plugin_t wrap = (tracer_plugin_t)
	{
		.pre_call = wrap_pre_call,
		.post_call = wrap_post_call,
		.signal = wrap_signal,
		.start = wrap_start,
		.stop = wrap_stop,
		.step = wrap_step,
		.exec = wrap_exec,
		.breakpoint = wrap_breakpoint,
		.pid_selector = wrap_pid_selector,
		.data = (void *)plug,
	};

	return wrap;
}

