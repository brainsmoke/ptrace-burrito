
#include "trace.h"

#include <linux/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "errors.h"
#include "trace.h"
#include "trace_map.h"
#include "util.h"

pid_t any_pid(void *data)
{
	return -1;
}

enum
{
	HOLD      = 0x01,
	HELD      = 0x02,
	STEPTRACE = 0x04,
};

static trace_t *new_trace(pid_t pid)
{
	trace_t *t = try_malloc(sizeof(trace_t));
	*t = (trace_t)
	{
		.pid = pid,
		.state = START,
		.flags = 0,
		.signal = 0,
		.deadbeef = { 0xDE, 0xAD, 0xBE, 0xAF },
	};

	waitpid(pid, &t->status, __WALL);
	if ( WIFEXITED(t->status) || WIFSIGNALED(t->status) )
		abort();

	if (ptrace(PTRACE_SETOPTIONS, pid, -1,
	           PTRACE_O_TRACEFORK |
	           PTRACE_O_TRACEVFORK |
	           PTRACE_O_TRACECLONE |
	           PTRACE_O_TRACEEXEC |
	           PTRACE_O_TRACEEXIT |
	           PTRACE_O_TRACESYSGOOD) != 0)
		fatal_error("setting PTRACE_SETOPTIONS failed");

	return t;
}

static void try_continue_process(trace_t *t)
{
	if (t->flags & HOLD)
		t->flags |= HELD;
	else
	{
		if (ptrace(PTRACE_SYSCALL, t->pid, 0, t->signal) != 0)
			fatal_error("ptrace failed: %s", strerror(errno));

		t->flags &=~ HELD;
	}
}

void hold_process(trace_t *t)
{
	t->flags |= HOLD;
}

void release_process(trace_t *t)
{
	t->flags &=~ HOLD;
	if (t->flags & HELD)
		try_continue_process(t);
}

void steptrace_process(trace_t *t, int val)
{
	registers_t orig;

	if (val)
		t->flags |= STEPTRACE;
	else
		t->flags &=~ STEPTRACE;

	set_trap_flag(t, val?1:0);
	orig = t->regs;
	get_registers(t);
	set_trap_flag(t, val?1:0);
	set_registers(t);
	t->regs = orig;
}

int get_steptrace_process(trace_t *t)
{
	return (t->flags & STEPTRACE) ? 1:0;
}

static void get_process_info(trace_t *t)
{
	get_registers(t);
	/* the trap flag sometimes gets unset after a syscall
	 * this fixes that
	 */
	if ( get_steptrace_process(t) ^ get_trap_flag(t) )
	{
		set_trap_flag(t, get_steptrace_process(t));
		set_registers(t);
	}
}

static void handle_event(trace_t *t, trace_t *parent, tracer_plugin_t *plug)
{
	switch (t->state)
	{
		case START:
			t->syscall = get_syscall(t);
			if ( plug->start )
				plug->start(t, parent, plug->data);
			break;
		case STOP:
			t->exitcode = get_eventmsg(t);
			if ( plug->stop )
				plug->stop(t, plug->data);
			break;
		case EXEC:
			if ( plug->exec )
				plug->exec(t, plug->data);
			break;
		case STEP:
			if ( plug->step )
				plug->step(t, plug->data);
			break;
		case SIGNAL:
			if ( plug->signal )
				plug->signal(t, plug->data);
			break;
		case PRE_CALL:
			t->syscall = get_syscall(t);
			if ( plug->pre_call )
				plug->pre_call(t, plug->data);
			break;
		case POST_CALL:
			if ( plug->post_call )
				plug->post_call(t, plug->data);
			break;
	}
}

void trace(pid_t pid, tracer_plugin_t *plug)
{
	int status, event, is_step;
	trace_map_t *map = create_trace_map();
	trace_t *t = new_trace(pid), *parent = NULL;
	put_trace(map, t);

	if (plug->init)
		plug->init(plug->data);

	for(;;)
	{
		get_process_info(t);
		if (parent)
			get_process_info(parent);

		handle_event(t, parent, plug);

		try_continue_process(t);
		if (parent)
		{
			try_continue_process(parent);
			parent = NULL;
		}

		if (t->state == STOP)
		{
			waitpid(t->pid, NULL, __WALL);
			del_trace(map, t->pid);
			if ( trace_map_count(map) == 0 )
				break;
		}

		pid = plug->pid_selector(plug->data);
		pid = waitpid(pid, &status, __WALL);

		if (pid < 0)
			fatal_error("waitpid: %s", strerror(errno));

		if ( WIFEXITED(status) || WIFSIGNALED(status) || !WIFSTOPPED(status) )
			fatal_error("unexpected behaviour: process in unexpected state");

		t = get_trace(map, pid);
		t->status = status;
		t->signal = (status>>8) & 0xff;
		event = (status>>16) & 0xff;
		is_step = !event && t->signal == SIGTRAP;

		if ( ( t->signal == SIGTRAP ) || ( t->signal == CALL_SIGTRAP ) )
			t->signal = 0;

		if (is_step)
			t->state = STEP;
		else if (event == PTRACE_EVENT_EXIT)
			t->state = STOP;
		else if (event == PTRACE_EVENT_EXEC)
			t->state = EXEC;
		else if (event)
		{
			parent = t;
			t = new_trace((pid_t)get_eventmsg(t));
			put_trace(map, t);
		}
		else if ( t->signal )
			t->state = SIGNAL;
		else if ( ( t->state == PRE_CALL ) || ( t->state == EXEC ) )
			t->state = POST_CALL;
		else
			t->state = PRE_CALL;
	}

	if (plug->final)
		plug->final(plug->data);

	free_trace_map(map);
}

