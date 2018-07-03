
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
#include "maps.h"

//static const char *c = "\033[0;31m", *n = "\033[m";

int step;
FILE *outfile = NULL;
trace_ctx_t *ctx;

static void print_pre_call(trace_t *t, void *data)
{
	print_trace_call(t);
/*
	if (step)
		print_trace_diff(t, (trace_t*)t->data);
	else
		print_trace(t);
	*(trace_t*)t->data = *t;
	fflush(stdout);
*/
}

static void print_post_call(trace_t *t, void *data)
{
	print_trace_return(t);
/*
	printf("(from %s)\n", syscall_name(get_syscall(t)));
	print_trace_diff(t, (trace_t*)t->data);
	if (step)
		*(trace_t*)t->data = *t;
	fflush(stdout);
*/
}

static void print_signal(trace_t *t, void *data)
{
/*
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
*/
}

static void print_start(trace_t *t, trace_t *parent, void *data)
{

	if (step)
		steptrace_process(t, 1);

	if (!ctx)
		ctx=t->ctx;
/*
	t->data = try_malloc(sizeof(trace_t));
	printf("%sSTART%s\n",c,n);
	print_trace(t);
	if (step)
		*(trace_t*)t->data = *t;
	fflush(stdout);
*/
}

static void print_stop(trace_t *t, void *data)
{
/*
	free(t->data);
	printf("%sSTOP%s\n",c,n);
	if (step)
		print_trace_diff(t, (trace_t*)t->data);
	else
		print_trace(t);
	fflush(stdout);
*/
}

static void print_step(trace_t *t, void *data)
{
	*tag(t->pid, t->regs.rip) += 1;
}

static void print_exec(trace_t *t, void *data)
{
	reset_maps(t->pid);
/*
	printf("%sEXEC%s\n",c,n);
	print_trace_diff(t, (trace_t*)t->data);
	*(trace_t*)t->data = *t;
	fflush(stdout);
*/
}

void sigterm(int sig)
{
//	print_tags(outfile);
//	fflush(outfile);
	if (ctx)
		detach_all(ctx);
//	exit(EXIT_SUCCESS);
}

void sigusr1(int sig)
{
	print_tags(outfile);
	fflush(outfile);
}

static void usage(char *progname)
{
	fprintf(stderr, "Usage: %s [-out <outfile>|-fd <out-filedes>] [-pid <pid>|command args...]\n", progname);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	debug_init(stdout);
	char *progname = argv[0];
	pid_t pid = -1;

	step = 1;
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

	print_tags(outfile);
	fflush(outfile);

	exit(EXIT_SUCCESS);
}

