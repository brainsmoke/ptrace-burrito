
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

#include <sys/ptrace.h>
#include <sys/wait.h>

#include <linux/ptrace.h>
#include <sys/personality.h>
#include <sys/syscall.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <sched.h>

#include "errors.h"
#include "debug.h"
#include "debug_syscalls.h"
#include "trace.h"
#include "util.h"
#include "process.h"
#include "maps.h"

static const char *c = "\033[1;31m", *n = "\033[m";

int step;
FILE *outfile = NULL;
int verbose;

static void print_pre_call(trace_t *t, void *data)
{
	if (verbose)
	{
		fprintf(stderr, "%5d  ", t->pid);
		print_trace_call(t);
		fflush(stderr);
	}
}

static void print_post_call(trace_t *t, void *data)
{
	if (verbose)
	{
		fprintf(stderr, "%5d  ", t->pid);
		print_trace_return(t);
		fflush(stderr);
	}
}

static void print_signal(trace_t *t, void *data)
{
	if (verbose)
	{
		fprintf(stderr, "%5d  ", t->pid);
		fprintf(stderr, "%sSIGNAL%s %s\n",c,n, signal_name(t->signal));
		fflush(stderr);
	}
}

static void print_start(trace_t *t, trace_t *parent, void *data)
{

	if (step)
		steptrace_process(t, 1);

	if (verbose)
	{
		fprintf(stderr, "%5d  %sSTART%s\n",t->pid,c,n);
		fflush(stderr);
	}
}

static void print_stop(trace_t *t, void *data)
{
	if (verbose)
	{
		fprintf(stderr, "%5d  ", t->pid);
		fprintf(stderr, "%sSTOP%s pid = %u, signal = %d, exit code = %d\n",
		                c, n, t->pid, t->signal, t->exitcode);
		fflush(stderr);
	}
}

static void print_step(trace_t *t, void *data)
{
	*tag(t->pid, get_pc(t)) += 1;
}

static void print_exec(trace_t *t, void *data)
{
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

	step = 1;
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
		.pre_call = print_pre_call,
		.post_call = print_post_call,
		.signal = print_signal,
		.start = print_start,
		.stop = print_stop,
		.step = print_step,
		.exec = print_exec,
		.pid_selector = any_pid, /* always returns -1 */
		.data = NULL,
	};

	if (pid == -1)
	{
		if (! *argv )
			usage(progname);
		else
			pid = run_traceable(argv[0], argv, 1, 0);
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

