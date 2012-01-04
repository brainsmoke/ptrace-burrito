#include <linux/unistd.h>

#include <stdlib.h>
#include <signal.h>
#include <stdio.h>

#include "trace.h"
#include "util.h"
#include "process.h"

static void fake_tsc(trace_t *t, void *_)
{
	if ( (t->signal == SIGSEGV) && program_counter_at_tsc(t) )
	{
		uint64_t ts = get_timestamp();
		emulate_tsc(t, ts);
		fprintf(stderr, "\033[1;31mTIMESTAMP\033[m %llu\n", (unsigned long long)ts);
		set_registers(t);
		t->signal = 0;
	}
}

int main(int argc, char **argv)
{
	tracer_plugin_t plug = (tracer_plugin_t)
	{
		.pid_selector = any_pid,
		.signal = fake_tsc,
	};
	trace(run_traceable(argv[1], &argv[1], 1, 1), &plug);

	exit(EXIT_SUCCESS);
}

