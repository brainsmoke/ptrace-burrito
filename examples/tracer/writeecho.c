
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
		long args[] = { 1, get_syscall_arg(t, 1), get_syscall_arg(t, 2) };
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

