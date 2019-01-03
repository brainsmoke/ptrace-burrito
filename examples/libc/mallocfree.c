
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
#include "symbols.h"
#include "breakpoints.h"

FILE *outfile = NULL;

enum
{
	MALLOC = 0,
	FREE = 1,
	RET = 2,
};

static void set_breakpoints(trace_t *t)
{
	const char *libname;
	uintptr_t offset;

	libname = get_symbol("malloc", &offset);
	add_breakpoint_fileoff(t, MALLOC, libname, offset, BP_COPY_EXEC|BP_COPY_CHILD);

	libname = get_symbol("free", &offset);
	add_breakpoint_fileoff(t, FREE, libname, offset, BP_COPY_EXEC|BP_COPY_CHILD);
}

static void enable_trace(trace_t *t)
{
	add_watchpoint_address(t, RET, get_sp(t), PROT_READ|PROT_WRITE, sizeof(uintptr_t), BP_COPY_CHILD);
	disable_breakpoint(t,MALLOC);
	disable_breakpoint(t,FREE);
}

static void disable_trace(trace_t *t)
{
	del_breakpoint(t,RET);
	enable_breakpoint(t,MALLOC);
	enable_breakpoint(t,FREE);
}

static void plug_post_call(trace_t *t, void *data)
{
	if (all_breakpoints_resolved(t))
		trace_syscalls(t, 0);
}

static void plug_start(trace_t *t, trace_t *parent, void *data)
{
	if (parent == NULL)
	{
		set_breakpoints(t);
		fprintf(outfile, "%d start\n", t->pid);
	}
	else
		fprintf(outfile, "%d clone %d -> %d\n", t->pid, parent->pid, t->pid);
}

static void plug_exec(trace_t *t, void *data)
{
	trace_syscalls(t, 1);
	fprintf(outfile, "%d execve\n", t->pid);
}

static pid_t next = -1;
pid_t plug_pid(void *data)
{
	pid_t cur = next;
	return cur;
}

static void plug_breakpoint(trace_t *t, void *data)
{
	int bpid = current_breakpoint_id(t);
	if (bpid == MALLOC)
	{
		fprintf(outfile, "%d malloc( %lu ) = ", t->pid, get_func_arg(t, 0));
		next = t->pid;
		enable_trace(t);
	}
	else if (bpid == RET)
	{
		next = -1;
		fprintf(outfile, "0x%lx\n", get_func_result(t));
		disable_trace(t);
	}
	else if (bpid == FREE)
	{
		fprintf(outfile, "%d free( 0x%lx )\n", t->pid, get_func_arg(t, 0));
	}
	else
		fprintf(outfile, "%5d: BREAKPOINT UNKNOWN!\n",t->pid);
}

/*  */
static void plug_detach(trace_t *t, void *data)
{
	if (next == t->pid)
	{
		next = -1;
		fprintf(outfile, "<process detached during malloc>\n");
	}
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
	fprintf(stderr, "Usage: %s [-out <outfile>|-fd <out-filedes>] [-pid <pid>|command args...]\n", progname);
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
		else
			usage(progname);
	}

	if (outfile == NULL)
		outfile = stdout;

	signal(SIGTERM, sigterm);
	signal(SIGUSR1, sigusr1);

	tracer_plugin_t plug = (tracer_plugin_t)
	{
		.pid_selector = plug_pid,
		.post_call = plug_post_call,
		.start = plug_start,
		.exec = plug_exec,
		.detach = plug_detach,
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

