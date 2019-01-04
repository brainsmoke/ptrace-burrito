
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

int steptrace = 0;

void start(trace_t *t, trace_t *parent, void *data)
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

	if (steptrace) steptrace_process(t, 1);
}

void stop(trace_t *t, void *data)
{
	printf("%5d: STOPPED\n", t->pid);
}

void exec(trace_t *t, void *data)
{
	printf("%5d: EXEC!\n", t->pid);
}

void pre_call(trace_t *t, void *data)
{
	printf("%5d: %s(...) = ...\n", t->pid, syscall_name(get_syscall(t)));
}

void post_call(trace_t *t, void *data)
{
	printf("%5d: ... = %lx\n", t->pid, get_syscall_result(t));
}

void signal_event(trace_t *t, void *data)
{
	printf("%5d: SIGNAL %d\n", t->pid, t->signal);
}

void breakpoint(trace_t *t, void *data)
{
	printf("%5d: BREAKPOINT on malloc @ %lx\n", t->pid, get_pc(t));
}

void step(trace_t *t, void *data)
{
	printf("%5d: step @ [%lx]\n", t->pid, get_pc(t));
}

int main(int argc, char **argv)
{
	if (strcmp(argv[1], "-step") == 0) { steptrace = 1; argv++; }

	tracer_plugin_t plug = (tracer_plugin_t)
	{
		.start = start,
		.stop = stop,
		.pre_call = pre_call,
		.post_call = post_call,
		.signal = signal_event,
		.exec = exec,
		.breakpoint = breakpoint,
		.step = step,
		.pid_selector = any_pid, /* always returns -1 */
		.data = NULL,
	};

	pid_t pid = run_traceable(argv[1], &argv[1], 0, 0);
	trace(pid, &plug);
	exit(EXIT_SUCCESS);
}

