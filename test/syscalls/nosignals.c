#include <linux/unistd.h>

#include <stdlib.h>
#include <signal.h>

#include "trace.h"
#include "debug_wrap.h"
#include "util.h"
#include "process.h"

/* does not deliver signals to children */
static void no_signal(trace_t *t, void *_)
{
	if ( (t->signal == SIGSEGV) && program_counter_at_tsc(t) )
	{
		uint64_t ts = get_timestamp();
		emulate_tsc(t, ts);
		set_registers(t);
	}
	t->signal = 0;
}

int main(int argc, char **argv)
{
	tracer_plugin_t plug = (tracer_plugin_t)
	{
		.pid_selector = any_pid,
		.signal = no_signal,
	};
	tracer_plugin_t wrap = debug_wrap(&plug);
	trace(run_traceable(argv[1], &argv[1], 1, 0), &wrap);

	exit(EXIT_SUCCESS);
}

