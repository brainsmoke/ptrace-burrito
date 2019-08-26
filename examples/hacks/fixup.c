
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
#include <string.h>
#include <stdio.h>

#include "trace.h"
#include "util.h"
#include "process.h"
#include "maps.h"
#include "debug.h"

#define MAX_WORKAROUNDS (1024)

struct { char *name; unsigned long fault_addr, epilogue_addr, retval; } workarounds[MAX_WORKAROUNDS];
int n_workarounds = 0;

static void handle_signal(trace_t *t, void *_)
{
	if ( (t->signal == SIGSEGV) )
	{
		int i;
		uintptr_t off;
		const char *name = map_name(t->pid, get_pc(t), &off);
		print_registers(&t->regs);

		fprintf(stderr, "\033[1;31mfixup: segfault at: %s[%lx]\033[0m\n", name, off);
		for (i = 0; i<n_workarounds; i++)
			if (get_pc(t) == find_code_address(t->pid, workarounds[i].name, workarounds[i].fault_addr))
			{
				set_pc(t, find_code_address(t->pid, workarounds[i].name, workarounds[i].epilogue_addr));
				t->regs.rax = workarounds[i].retval;
				t->signal = 0;
				fprintf(stderr, "\033[1;33mfixing... returning %lu\033[0m at epiloque: %s[%lx]\n",
				                workarounds[i].retval,
				                workarounds[i].name, workarounds[i].epilogue_addr);
				break;
			}
		fflush(stderr);
	}
}

static void proc_start(trace_t *t, trace_t *parent, void *data)
{
	trace_syscalls(t, 0);
}

int main(int argc, char *argv[])
{
	char **args = &argv[1];

	debug_init(stderr);

	while (strcmp(args[0], "-justreturn") == 0 && n_workarounds < MAX_WORKAROUNDS)
	{
		workarounds[n_workarounds].name = args[1];
		workarounds[n_workarounds].fault_addr = strtoul(args[2], NULL, 16);
		workarounds[n_workarounds].epilogue_addr = strtoul(args[3], NULL, 16);
		workarounds[n_workarounds].retval = (unsigned long)strtol(args[4], NULL, 10);
		n_workarounds++;
		args+=5;
	}

	tracer_plugin_t plug = (tracer_plugin_t)
	{
		.pid_selector = any_pid,
		.start = proc_start,
		.signal = handle_signal,
	};
	trace(run_traceable(args[0], args, 0, 0), &plug);

	exit(EXIT_SUCCESS);
}

