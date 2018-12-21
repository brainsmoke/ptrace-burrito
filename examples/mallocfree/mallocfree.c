
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
	intptr_t offset;

	libname = get_symbol("malloc", &offset);
	add_breakpoint_fileoff(t, MALLOC, libname, offset, BP_COPY_EXEC|BP_COPY_CHILD);

	libname = get_symbol("free", &offset);
	add_breakpoint_fileoff(t, FREE, libname, offset, BP_COPY_EXEC|BP_COPY_CHILD);
}

static void enable_trace(trace_t *t)
{
	disable_breakpoint(t,MALLOC);
	disable_breakpoint(t,FREE);
	add_watchpoint_address(t, RET, get_sp(t), PROT_READ|PROT_WRITE, sizeof(uintptr_t), BP_COPY_CHILD);
}

static void disable_trace(trace_t *t)
{
	del_breakpoint(t,RET);
	enable_breakpoint(t,MALLOC);
	enable_breakpoint(t,FREE);
}

static void plug_start(trace_t *t, trace_t *parent, void *data)
{
	if (parent == NULL)
		set_breakpoints(t);
}

static void plug_breakpoint(trace_t *t, void *data)
{
	int bpid = current_breakpoint_id(t);
	if (bpid == MALLOC)
	{
		printf("%d malloc( %lu ) = ", t->pid, get_func_arg(t, 0));
		enable_trace(t);
	}
	else if (bpid == RET)
	{
		printf("0x%lx\n", get_func_result(t));
		disable_trace(t);
	}
	else if (bpid == FREE)
	{
		printf("%d free( 0x%lx )\n", t->pid, get_func_arg(t, 0));
	}
	else
		fprintf(outfile, "%5d: BREAKPOINT UNKNOWN!\n",t->pid);
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
		.pid_selector = any_pid, /* always returns -1 */
		.start = plug_start,
		.breakpoint = plug_breakpoint,
		.data = NULL,
	};

	tracer_plugin_t wrap = breakpoint_wrap(&plug);

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

	trace(pid, &wrap);

	fflush(outfile);

	exit(EXIT_SUCCESS);
}

