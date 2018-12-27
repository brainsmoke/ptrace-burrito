
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


#include <sys/ptrace.h>
#include <sys/wait.h>

#include <linux/ptrace.h>
#include <sys/personality.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>

#include "errors.h"
#include "debug.h"
#include "debug_syscalls.h"
#include "trace.h"
#include "util.h"
#include "process.h"

static const char *c = "\033[0;31m", *n = "\033[m";

int step;

static void print_pre_call(trace_t *t, void *data)
{
	print_trace_call(t);
	if (step)
		print_trace_diff(t, (trace_t*)t->data);
	else
		print_trace(t);
	*(trace_t*)t->data = *t;
	fflush(stdout);
}

static void print_post_call(trace_t *t, void *data)
{
	print_trace_return(t);
	printf("(from %s)\n", syscall_name(get_syscall(t)));
	print_trace_diff(t, (trace_t*)t->data);
	if (step)
		*(trace_t*)t->data = *t;
	fflush(stdout);
}

static void print_signal(trace_t *t, void *data)
{
	siginfo_t info;
	memset(&info, 0, sizeof(info));

	printf("%sSIGNAL%s %s\n",c,n, signal_name(t->signal));
	get_siginfo(t->pid, &info);
	printhex(&info, sizeof(info));
	if (step)
	{
		print_trace_diff(t, (trace_t*)t->data);
		*(trace_t*)t->data = *t;
	}
	else
		print_trace(t);
	fflush(stdout);
}

static void print_start(trace_t *t, trace_t *parent, void *data)
{
	if (step)
		steptrace_process(t, 1);
	t->data = try_malloc(sizeof(trace_t));
	printf("%sSTART%s\n",c,n);
	print_trace(t);
	if (step)
		*(trace_t*)t->data = *t;
	fflush(stdout);
}

static void print_stop(trace_t *t, void *data)
{
	free(t->data);
	printf("%sSTOP%s\n",c,n);
	if (step)
		print_trace_diff(t, (trace_t*)t->data);
	else
		print_trace(t);
	fflush(stdout);
}

static void print_step(trace_t *t, void *data)
{
	printf("%sSTEP%s\n",c,n);
	print_trace_diff(t, (trace_t*)t->data);
	*(trace_t*)t->data = *t;
	fflush(stdout);
}

static void print_exec(trace_t *t, void *data)
{
	printf("%sEXEC%s\n",c,n);
	print_trace_diff(t, (trace_t*)t->data);
	*(trace_t*)t->data = *t;
	fflush(stdout);
}

static void usage(char *progname)
{
	fprintf(stderr, "Usage: %s [-step] [-pid <pid>|command args...]\n", progname);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	debug_init(stdout);
	char *progname = argv[0];
	pid_t pid = -1;

	for (argv++; *argv && **argv == '-' ; argv++)
	{
		if ( strcmp(*argv, "--") == 0 )
		{
			argv++;
			break;
		}
		else if ( strcmp(*argv, "-step") == 0 )
			step = 1;

		else if ( strcmp(*argv, "-pid") == 0 )
		{
			argv++;

			if ( !*argv )
				usage(progname);

			pid = atoi(*argv);
		}
		else
			usage(progname);
	}


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
		trace_attach(pid);

	trace(pid, &plug);

	exit(EXIT_SUCCESS);
}

