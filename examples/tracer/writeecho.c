#include <linux/unistd.h>

#include <stdlib.h>
#include <stdio.h>

#include "debug.h"
#include "trace.h"
#include "util.h"
#include "process.h"

/* Echoes all write operations to stdout
 *
 */

static void inject_writeecho(trace_t *t, void *data)
{
	registers_t regs = t->regs;
	if ( get_syscall(t) == __NR_write )
	{
		long args[] = { 1, get_arg(t, 1), get_arg(t, 2) };
		inject_syscall(t, __NR_write, args, 3, NULL); /* ignores signals */
	}
	print_registers_if_diff(&t->regs, &regs);
	fflush(stderr);
}

int main(int argc, char **argv)
{
	tracer_plugin_t plug = (tracer_plugin_t)
	{
		.pre_call = inject_writeecho,
		.post_call = inject_writeecho,
		.pid_selector = any_pid,
	};

	debug_init(stdout);

	trace(run_traceable(argv[1], &argv[1], 1, 0), &plug);

	exit(EXIT_SUCCESS);
}

