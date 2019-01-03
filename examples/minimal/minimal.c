
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "trace.h"
#include "util.h"
#include "process.h"
#include "symbols.h"
#include "breakpoints.h"
#include "debug_syscalls.h"

int step = 0;

void plug_start(trace_t *t, trace_t *parent, void *data)
{
	if (parent == 0)
	{
		/* very, very basic symbol resolver */
		uintptr_t offset;
		const char *libname = get_symbol("malloc", &offset);
		add_breakpoint_fileoff(t, 0, libname, offset, BP_COPY_EXEC|BP_COPY_CHILD);
	}
	else
		printf("%5d: CLONE parent = %d\n", t->pid, parent->pid);

	if (step) steptrace_process(t, 1);
}

void plug_stop(trace_t *t, void *data)
{
	printf("%5d: STOPPED\n", t->pid);
}

void plug_exec(trace_t *t, void *data)
{
	printf("%5d: EXEC!\n", t->pid);
}

void plug_pre_call(trace_t *t, void *data)
{
	printf("%5d: %s(...) = ...\n", t->pid, syscall_name(get_syscall(t)));
}

void plug_post_call(trace_t *t, void *data)
{
	printf("%5d: ... = %lx\n", t->pid, get_syscall_result(t));
}

void plug_signal(trace_t *t, void *data)
{
	printf("%5d: SIGNAL %d\n", t->pid, t->signal);
}

void plug_breakpoint(trace_t *t, void *data)
{
	printf("%5d: BREAKPOINT on malloc @ %lx\n", t->pid, get_pc(t));
}

void plug_step(trace_t *t, void *data)
{
	printf("%5d: step @ [%lx]\n", t->pid, get_pc(t));
}

int main(int argc, char **argv)
{
	if (strcmp(argv[1], "-step") == 0) { step = 1; argv++; }

	tracer_plugin_t plug = (tracer_plugin_t)
	{
		.start = plug_start,
		.stop = plug_stop,
		.pre_call = plug_pre_call,
		.post_call = plug_post_call,
		.signal = plug_signal,
		.exec = plug_exec,
		.breakpoint = plug_breakpoint,
		.step = plug_step,
		.pid_selector = any_pid, /* always returns -1 */
		.data = NULL,
	};

	pid_t pid = run_traceable(argv[1], &argv[1], 0, 0);
	trace(pid, &plug);
	exit(EXIT_SUCCESS);
}

