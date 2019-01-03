
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
#include "debug_syscalls.h"
#include "trace.h"
#include "util.h"
#include "process.h"
#include "maps.h"
#include "breakpoints.h"

static const char *c = "\033[1;31m", *n = "\033[m";

FILE *outfile = NULL;
int verbose;

typedef struct
{
	char *filename;
	uintptr_t offset;

} fileoff_t;

fileoff_t start[MAX_BREAKPOINTS], stop[MAX_BREAKPOINTS];

int n_start = 0, n_stop = 0;

enum
{
	START_BASE = 0,
	STOP_BASE = MAX_BREAKPOINTS,
};

static void set_breakpoints(trace_t *t)
{
	int i;

	for (i=0; i<n_start; i++)
		add_breakpoint_fileoff(t, START_BASE+i, start[i].filename, start[i].offset,
			                      BP_COPY_EXEC|BP_COPY_CHILD);

	for (i=0; i<n_stop; i++)
		add_breakpoint_fileoff(t, STOP_BASE+i, stop[i].filename, stop[i].offset,
			                       BP_COPY_EXEC|BP_COPY_CHILD);
}

static void enable_trace(trace_t *t)
{
	int i;

	steptrace_process(t, 1);

	for (i=0; i<n_start; i++)
		disable_breakpoint(t,START_BASE+i);

	for (i=0; i<n_stop; i++)
		enable_breakpoint(t,STOP_BASE+i);
}

static void disable_trace(trace_t *t)
{
	int i;

	steptrace_process(t, 0);

	for (i=0; i<n_stop; i++)
		disable_breakpoint(t,STOP_BASE+i);

	for (i=0; i<n_start; i++)
		enable_breakpoint(t,START_BASE+i);
}


static void plug_pre_call(trace_t *t, void *data)
{
	if (verbose)
	{
		fprintf(stderr, "%5d  ", t->pid);
		print_trace_call(t);
		fflush(stderr);
	}
}

static void plug_post_call(trace_t *t, void *data)
{
	if (verbose)
	{
		fprintf(stderr, "%5d  ", t->pid);
		print_trace_return(t);
		fflush(stderr);
	}
}

static void plug_signal(trace_t *t, void *data)
{
	if (verbose)
	{
		fprintf(stderr, "%5d  ", t->pid);
		fprintf(stderr, "%sSIGNAL%s %s\n",c,n, signal_name(t->signal));
		fflush(stderr);
	}
}

static void plug_start(trace_t *t, trace_t *parent, void *data)
{
	if (parent == NULL)
		set_breakpoints(t);

	disable_trace(t);

	if (verbose)
	{
		fprintf(stderr, "%5d  %sSTART%s\n",t->pid,c,n);
		fflush(stderr);
	}
}

static void plug_stop(trace_t *t, void *data)
{
	if (verbose)
	{
		fprintf(stderr, "%5d  ", t->pid);
		fprintf(stderr, "%sSTOP%s pid = %u, signal = %d, exit code = %d\n",
		                c, n, t->pid, t->signal, t->exitcode);
		fflush(stderr);
	}
}

static void plug_step(trace_t *t, void *data)
{
	*tag(t->pid, t->regs.rip) += 1;
}

static void plug_breakpoint(trace_t *t, void *data)
{
	int bpid = current_breakpoint_id(t);
	if (bpid >= START_BASE && bpid < START_BASE+n_start)
	{
		fprintf(stderr, "%5d  %sSTART TRACE%s\n",t->pid,c,n);
		plug_step(t, data);
		enable_trace(t);
	}
	else if (bpid >= STOP_BASE && bpid < STOP_BASE+n_stop)
	{
		fprintf(stderr, "%5d  %sSTOP TRACE%s\n",t->pid,c,n);
		disable_trace(t);
	}
	else
		fprintf(stderr, "%5d  %sBREAKPOINT UNKNOWN!%s\n",t->pid,c,n);

	fflush(stderr);
}

static void plug_exec(trace_t *t, void *data)
{
	disable_trace(t);
	reset_maps(t->pid);
	if (verbose)
	{
		fprintf(stderr, "%5d  %sEXEC%s\n",t->pid,c,n);
		fflush(stderr);
	}
}

void sigterm(int sig)
{
	detach_all();
}

void sigusr1(int sig)
{
	print_tags(outfile);
	fflush(outfile);
}


static void usage(char *progname)
{
	fprintf(stderr, "Usage: %s [-out <outfile>|-fd <out-filedes>] [-verbose] [-pid <pid>|command args...]\n", progname);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	debug_init(stderr);
	char *progname = argv[0];
	pid_t pid = -1;

	verbose = 0;
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
		else if ( strcmp(*argv, "-stop") == 0 )
		{
			if ( !argv[1] || !argv[2] || (n_stop >= MAX_BREAKPOINTS) )
				usage(progname);

			stop[n_stop++] = (fileoff_t)
			{
				.filename = argv[1],
				.offset = strtoll(argv[2], NULL, 16)
			};

			argv+=2;
		}
		else if ( strcmp(*argv, "-start") == 0 )
		{
			if ( !argv[1] || !argv[2] || (n_start >= MAX_BREAKPOINTS) )
				usage(progname);

			start[n_start++] = (fileoff_t)
			{
				.filename = argv[1],
				.offset = strtoll(argv[2], NULL, 16)
			};

			argv+=2;
		}
		else if ( strcmp(*argv, "-verbose") == 0 )
			verbose = 1;
		else
			usage(progname);
	}

	if (outfile == NULL)
		outfile = stdout;

	signal(SIGTERM, sigterm);
	signal(SIGUSR1, sigusr1);

	tracer_plugin_t plug = (tracer_plugin_t)
	{
		.pre_call = plug_pre_call,
		.post_call = plug_post_call,
		.signal = plug_signal,
		.start = plug_start,
		.stop = plug_stop,
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

	print_tags(outfile);
	fflush(outfile);

	exit(EXIT_SUCCESS);
}

