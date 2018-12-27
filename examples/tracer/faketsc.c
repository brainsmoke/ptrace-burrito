
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

