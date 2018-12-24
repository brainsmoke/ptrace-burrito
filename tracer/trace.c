
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

static trace_map_t *trace_map = NULL;

pid_t any_pid(void *data)
{
	return -1;
}

enum
{
	HOLD      = 0x01,
	HELD      = 0x02,
	STEPTRACE = 0x04,
	RELEASE   = 0x08,
	NOSYSCALL = 0x10,
};

static trace_t *new_trace(pid_t pid)
{
	trace_t *t = try_malloc(sizeof(trace_t));

	*t = (trace_t) { .pid = pid, };

	init_debug_regs(t);

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

void steptrace_process(trace_t *t, int val)
{
	if (val)
		t->flags |= STEPTRACE;
	else
		t->flags &=~ STEPTRACE;

	set_trap_flag(t, val?1:0);
}

void detach_process(trace_t *t)
{
	t->oobflags |= RELEASE;
	errno = 0;
	long ret = ptrace(PTRACE_INTERRUPT, t->pid, 0, 0);
	if ( ret && errno != EIO )
		fatal_error("ptrace failed: %s", strerror(errno));
}

void detach_all(void)
{
	size_t size, i;
	trace_t **list = trace_list(trace_map, &size);
	for (i=0; i<size; i++)
		detach_process(list[i]);
	free(list);
}

/* Don't leave any breakpoints / trap flags in the patient.
 *
 * Failsafe in case of a fatal_error(); depend as little as
 * possible on the rest of the code still functioning.
 */
void detach_atexit(void)
{
	size_t size, i;
	if ( trace_map )
	{
		trace_t **list = trace_list(trace_map, &size);
		for (i=0; i<size; i++)
		{
			trace_t *t = list[i];
			ptrace(PTRACE_INTERRUPT, t->pid, 0, 0);

			t->status = 0;
			waitpid(t->pid, &t->status, __WALL);
			t->signal = (t->status>>8) & 0xff;
			if ( ( t->signal == SIGTRAP ) || ( t->signal == CALL_SIGTRAP ) )
				t->signal = 0;

			get_registers(t);
			steptrace_process(t, 0);
			clear_debug_regs(t);
			write_modified_regs(t);

			ptrace(PTRACE_DETACH, t->pid, 0, t->signal);
		}
		free(list);
	}
}

static void detach_cleanup(trace_t *t)
{
	steptrace_process(t, 0);
	clear_debug_regs(t);
}

void trace_syscalls(trace_t *t, int val)
{
	if (!val)
		t->flags |= NOSYSCALL;
	else
		t->flags &=~ NOSYSCALL;
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
		set_trap_flag(t, get_steptrace_process(t));
}

static void try_continue_process(trace_t *t)
{
	if (t->flags & HOLD)
		t->flags |= HELD;
	else
	{
		int cont = PTRACE_SYSCALL;

		if ( t->state == DETACH )
		{
			cont = PTRACE_DETACH;
			detach_cleanup(t);
		}
		else if ( t->flags & NOSYSCALL )
			cont = PTRACE_CONT;

		write_modified_regs(t);

		if (ptrace(cont, t->pid, 0, t->signal) != 0)
			fatal_error("ptrace failed: %s", strerror(errno));

		if ( t->state == STOP )
			waitpid(t->pid, NULL, __WALL);

		if (t->flags & HELD)
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

static void handle_event(trace_t *t, trace_t *parent, tracer_plugin_t *plug)
{
	switch (t->state)
	{
		case START:      if (plug->start)      plug->start(t, parent, plug->data);  break;
		case STOP:       if (plug->stop)       plug->stop(t, plug->data);           break;
		case EXEC:       if (plug->exec)       plug->exec(t, plug->data);           break;
		case STEP:       if (plug->step)       plug->step(t, plug->data);           break;
		case BREAKPOINT: if (plug->breakpoint) plug->breakpoint(t, plug->data);     break;
		case DETACH:     if (plug->detach)     plug->detach(t, plug->data);         break;
		case SIGNAL:     if (plug->signal)     plug->signal(t, plug->data);         break;
		case PRE_CALL:   if (plug->pre_call)   plug->pre_call(t, plug->data);       break;
		case POST_CALL:  if (plug->post_call)  plug->post_call(t, plug->data);      break;
	}
}

static trace_t *wait_for_event(pid_t pid_select)
{
	int status;
	pid_t pid;
	trace_t *t, *t_ok = NULL;

	while (!t_ok)
	{
		/* we may get a pid we don't know about yet */
		pid = waitpid(pid_select, &status, __WALL);

		if (pid < 0)
			fatal_error("waitpid: %s", strerror(errno));

		if ( WIFEXITED(status) || WIFSIGNALED(status) || !WIFSTOPPED(status) )
			fatal_error("unexpected behaviour: process in unexpected state");

		/* unknown pid will return NULL */
		t = get_trace(trace_map, pid);

		/* always return known processes */
		t_ok = t;

		if (t == NULL)
		{
			t = new_trace(pid);
			put_trace(trace_map, t);

			/* only return new processes if we explicitly wait for them */
			if ( pid == pid_select )
				t_ok = t;
		}

		/* fill in correct info regardless */
		t->status = status;
		t->signal = (status>>8) & 0xff;
		t->event = (status>>16) & 0xff;
		get_process_info(t);
	}

	return t;
}

void trace(pid_t pid, tracer_plugin_t *plug)
{
	int is_trap;
	trace_map = create_trace_map();
	trace_t *t, *parent = NULL;
	pid_t new_pid = pid;

	atexit(detach_atexit);

	if (plug->init)
		plug->init(plug->data);

	while ( new_pid || trace_map_count(trace_map) > 0 )
	{
		t = wait_for_event( new_pid ? new_pid : plug->pid_selector(plug->data) );

		is_trap = !t->event && t->signal == SIGTRAP;
		if ( ( t->signal == SIGTRAP ) || ( t->signal == CALL_SIGTRAP ) )
			t->signal = 0;

		if ( new_pid )
		{
			t->state = START;
			new_pid = 0;
		}
		else if (is_trap)
		{
			if ( debug_reg_breakpoints_triggered(t) )
				t->state = BREAKPOINT;
			else
				t->state = STEP;
		}
		else if (t->event == PTRACE_EVENT_EXIT)
		{
			t->exitcode = get_eventmsg(t);
			t->state = STOP;
		}
		else if (t->event == PTRACE_EVENT_EXEC)
		{
			t->state = EXEC;
			init_debug_regs(t);
		}
		else if (t->event == PTRACE_EVENT_STOP) /* at this point, it must've come from PTRACE_INTERRUPT */
		{
			if ( !(t->oobflags & RELEASE) )
			{
				try_continue_process(t);
				continue;
//				fatal_error("unexpected behaviour: process in unexpected stop state");
			}
			t->state = DETACH;
		}
		else if (t->event) /* clone()/fork()/vfork() */
		{
			parent = t;
			new_pid = (pid_t)get_eventmsg(parent);

			t = get_trace(trace_map, new_pid);
			if (!t)
				continue;

			t->state = START;
			new_pid = 0;
		}
		else if ( t->signal )
			t->state = SIGNAL;
		else if ( ( t->state == PRE_CALL ) || ( t->state == EXEC ) )
			t->state = POST_CALL;
		else
			t->state = PRE_CALL;

		handle_event(t, parent, plug);

		if (parent)
		{
			try_continue_process(parent);
			parent = NULL;
		}

		if ( (t->state != DETACH) && (t->oobflags & RELEASE) )
		{
			t->state = DETACH;
			handle_event(t, parent, plug);
		}

		try_continue_process(t);

		if ( (t->state == STOP) || (t->state == DETACH) )
			del_trace(trace_map, t->pid);
	}

	if (plug->final)
		plug->final(plug->data);

	trace_map_t *tmp = trace_map;
	trace_map = NULL;
	free_trace_map(tmp);
}

