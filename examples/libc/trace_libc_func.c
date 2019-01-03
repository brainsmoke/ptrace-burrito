
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


#define _GNU_SOURCE

#include <sys/wait.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>

#include "errors.h"
#include "debug.h"
#include "trace.h"
#include "util.h"
#include "process.h"
#include "maps.h"
#include "breakpoints.h"
#include "symbols.h"

FILE *outfile = NULL;

/* color-coding output */
static const char *hi = "\033[0;31m", *blue = "\033[0;34m", *reset = "\033[m";

typedef struct
{
	const char *filename;
	uintptr_t offset;
	const char *sym;

} fileoff_t;

fileoff_t call[MAX_BREAKPOINTS];

int n_call = 0;

enum
{
	RET = 0,
	CALL_BASE = 1,
};

static void set_breakpoints(trace_t *t)
{
	int i;
	for (i=0; i<n_call; i++)
		add_breakpoint_fileoff(t, CALL_BASE+i, call[i].filename, call[i].offset,
			                      BP_COPY_EXEC|BP_COPY_CHILD);
}

static void enable_trace(trace_t *t)
{
	steptrace_process(t, 1);

	int i;
	for (i=0; i<n_call; i++)
		disable_breakpoint(t,CALL_BASE+i);

	add_watchpoint_address(t, RET, get_sp(t), PROT_READ|PROT_WRITE, sizeof(uintptr_t), BP_COPY_CHILD);
}

static void disable_trace(trace_t *t)
{
	steptrace_process(t, 0);
	del_breakpoint(t,RET);

	int i;
	for (i=0; i<n_call; i++)
		enable_breakpoint(t,CALL_BASE+i);
}

static void plug_start(trace_t *t, trace_t *parent, void *data)
{
	if (parent == NULL)
		set_breakpoints(t);
}

static void plug_post_call(trace_t *t, void *data)
{
	if (all_breakpoints_resolved(t))
		trace_syscalls(t, 0);
}

static void plug_step(trace_t *t, void *data)
{
	uintptr_t offset;
	const char *name = map_name(t->pid, t->regs.rip, &offset);
	fprintf(outfile, "%5d %s%s%s [%" PRIxPTR "]\n", t->pid, blue, name, reset, offset);
}

static void plug_breakpoint(trace_t *t, void *data)
{
	int bpid = current_breakpoint_id(t);
	if (bpid >= CALL_BASE && bpid < CALL_BASE+n_call)
	{
		uintptr_t callee;
		memload(t->pid, (void *)&callee, (void *)get_sp(t), sizeof(uintptr_t));
		uintptr_t cs_offset;
		const char *cs_name = map_name(t->pid, callee, &cs_offset);

		fprintf(outfile, "%5d: call %s%s%s() from %s%s%s [%" PRIxPTR "]\n",
		                 t->pid, hi, call[bpid-CALL_BASE].sym, reset, blue, cs_name, reset, cs_offset);
		plug_step(t, data);
		enable_trace(t);
	}
	else if (bpid == RET)
	{
		fprintf(outfile, "%5d: return ( 0x%lx )\n",t->pid, get_syscall_result(t));
		disable_trace(t);
	}
	else
		fprintf(outfile, "%5d: %sBREAKPOINT UNKNOWN! %d%s %lx\n",t->pid, hi, bpid, reset, get_pc(t));
}

static void plug_exec(trace_t *t, void *data)
{
	trace_syscalls(t, 1);
	disable_trace(t);
	reset_maps(t->pid);
}

void sigterm(int sig)
{
	detach_all();
}

void sigusr1(int sig)
{
	fflush(outfile);
}

static void usage(char *progname)
{
	fprintf(stderr, "Usage: %s [-out <outfile>|-fd <out-filedes>] [-trace <libc-symbol]* [-pid <pid>|command args...]\n", progname);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	debug_init(stderr);
	char *progname = argv[0];
	pid_t pid = -1;

	for (argv++; *argv && **argv == '-' ; argv++)
	{
		if ( strcmp(*argv, "--") == 0 )
		{
			argv++;
			break;
		}
		else if ( strcmp(*argv, "-pid") == 0 )
		{
			argv++;

			if ( !*argv )
				usage(progname);

			pid = atoi(*argv);
		}
		else if ( strcmp(*argv, "-out") == 0 )
		{
			argv++;

			if ( !*argv )
				usage(progname);

			if (outfile != NULL)
				usage(progname);

			outfile = fopen(*argv, "w");

			if (outfile == NULL)
				usage(progname);
		}
		else if ( strcmp(*argv, "-fd") == 0 )
		{
			argv++;

			if ( !*argv )
				usage(progname);

			int fd = atoi(*argv);

			if (outfile != NULL)
				usage(progname);

			outfile = fdopen(fd, "w");

			if (outfile == NULL)
				usage(progname);
		}
		else if ( strcmp(*argv, "-trace") == 0 )
		{
			if ( !argv[1] || (n_call >= MAX_BREAKPOINTS) )
				usage(progname);

			uintptr_t offset;
			const char *libname = get_symbol(argv[1], &offset);

			if (!libname)
				usage(progname);

			call[n_call++] = (fileoff_t)
			{
				.filename = libname,
				.offset = offset,
				.sym = strdup(argv[1]),
			};

			argv+=1;
		}
		else
			usage(progname);
	}

	if (outfile == NULL)
		outfile = stdout;

	if (!isatty(fileno(outfile)))
	{
		hi = blue = reset = "";
	}

	signal(SIGTERM, sigterm);
	signal(SIGUSR1, sigusr1);

	tracer_plugin_t plug = (tracer_plugin_t)
	{
//		.pre_call = plug_pre_call,
		.post_call = plug_post_call,
//		.signal = plug_signal,
		.start = plug_start,
//		.stop = plug_stop,
		.step = plug_step,
		.exec = plug_exec,
		.pid_selector = any_pid, /* always returns -1 */
		.breakpoint = plug_breakpoint,
		.data = NULL,
	};

	if (pid == -1)
	{
		if (! *argv )
			usage(progname);
		else
			pid = run_traceable(argv[0], argv, 0, 0);
	}
	else
	{
		pid_t tracer_pid = fork();
		if ( tracer_pid < 0 )
			exit(EXIT_FAILURE);

		if ( tracer_pid > 0 )
		{
			fprintf(stderr, "[press enter to detach]\n"); fflush(stderr);
			int ch;
			while ( ( (ch = getchar()) != EOF) && (ch != '\n') );
			kill(tracer_pid, SIGTERM);
			int status;
			waitpid(tracer_pid, &status, 0);
			exit(WEXITSTATUS(status));
		}

		trace_attach(pid);
	}

	trace(pid, &plug);

	fflush(outfile);

	exit(EXIT_SUCCESS);
}

