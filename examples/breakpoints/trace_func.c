
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

FILE *outfile = NULL;

typedef struct
{
	char *filename;
	uintptr_t offset;

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
	fprintf(outfile, "%d %s [%" PRIxPTR "]\n", t->pid, name, offset);
}

static void plug_breakpoint(trace_t *t, void *data)
{
	int bpid = current_breakpoint_id(t);
	if (bpid >= CALL_BASE && bpid < CALL_BASE+n_call)
	{
		fprintf(outfile, "%5d: START TRACE\n",t->pid);
		plug_step(t, data);
		enable_trace(t);
	}
	else if (bpid == RET)
	{
		fprintf(outfile, "%5d: STOP TRACE\n",t->pid);
		disable_trace(t);
	}
	else
		fprintf(outfile, "%5d: BREAKPOINT UNKNOWN! %d %lx\n",t->pid, bpid, get_pc(t));
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
	fprintf(stderr, "Usage: %s [-out <outfile>|-fd <out-filedes>] [-trace <file> <hexoffset>]* [-pid <pid>|command args...]\n", progname);
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
			if ( !argv[1] || !argv[2] || (n_call >= MAX_BREAKPOINTS) )
				usage(progname);

			call[n_call++] = (fileoff_t)
			{
				.filename = argv[1],
				.offset = strtoll(argv[2], NULL, 16)
			};

			argv+=2;
		}
		else
			usage(progname);
	}

	if (outfile == NULL)
		outfile = stdout;

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

