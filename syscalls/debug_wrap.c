
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


#include <stdio.h>
#include <signal.h>

#include "errors.h"
#include "debug.h"
#include "debug_syscalls.h"
#include "debug_wrap.h"
#include "trace.h"
#include "util.h"
//#include "syscall_info.h"
#include "signal_info.h"

static const char *hi = "\033[1;31m", *low = "\033[1;30m", *n = "\033[m";

static pid_t select_pid(void *data)
{
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	return plug->pid_selector(plug->data);
}

static void print_pre_call(trace_t *t, void *data)
{
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	if (plug->pre_call) plug->pre_call(t, plug->data);

	if (t->state != PRE_CALL)
		return;

	//const syscall_info_t *info = syscall_info(t);
	fprintf(stderr, "%5d  ", t->pid);
	//print_flags(info->action);
	print_trace_call(t);
	fflush(stderr);
}

static void print_post_call(trace_t *t, void *data)
{
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	if (plug->post_call) plug->post_call(t, plug->data);
	fprintf(stderr, "%5d  ", t->pid);
	print_trace_return(t);
	fflush(stderr);
}

static void print_signal(trace_t *t, void *data)
{
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	long sig = t->signal;
	int is_ts = (sig == SIGSEGV) && program_counter_at_tsc(t);

	if (plug->signal) plug->signal(t, plug->data);

	fprintf(stderr, "%5d  ", t->pid);
	if ( is_ts )
	{
#ifdef __x86_64__
		uint64_t ts = (((uint64_t)(t->regs.rdx&&0xffffffff))<<32)|(uint32_t)(t->regs.rax&0xffffffff);
#endif
#ifdef __i386__
		uint64_t ts = (((uint64_t)t->regs.edx)<<32)|(uint32_t)t->regs.eax;
#endif
		fprintf(stderr, "%sTIMESTAMP%s %llu\n", hi, n, (unsigned long long)ts);
	}
	else if ( t->signal )
		fprintf(stderr, "%sSIGNAL%s %s\n", hi, n, signal_name(t->signal));
	else
		fprintf(stderr, "%sSIGNAL%s %s (suppressed)\n", low, n,
		                signal_name(sig));

	fflush(stderr);
}

static void print_start(trace_t *t, trace_t *parent, void *data)
{
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	if (plug->start) plug->start(t, parent, plug->data);
	fprintf(stderr, "%5d  ", t->pid);
	fprintf(stderr, "%sSTART%s %s\n", hi, n, syscall_name(get_syscall(t)));
	fflush(stderr);
}

static void print_stop(trace_t *t, void *data)
{
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	if (plug->stop) plug->stop(t, plug->data);
	fprintf(stderr, "%5d  ", t->pid);
	fprintf(stderr, "%sSTOP%s pid = %u, signal = %d, exit code = %d\n",
	                hi, n, t->pid, t->signal, t->exitcode);
	fflush(stderr);
}

static void print_step(trace_t *t, void *data)
{
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	if (plug->step) plug->step(t, plug->data);
}

static void print_exec(trace_t *t, void *data)
{
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	if (plug->exec) plug->exec(t, plug->data);
	fprintf(stderr, "%sEXEC%s\n", hi, n);
	fflush(stderr);
}

static void print_detach(trace_t *t, void *data)
{
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	if (plug->detach) plug->detach(t, plug->data);
	fprintf(stderr, "%sDETACH%s\n", hi, n);
	fflush(stderr);
}

static void print_breakpoint(trace_t *t, void *data)
{
	tracer_plugin_t *plug = (tracer_plugin_t *)data;
	fprintf(stderr, "%5d  ", t->pid);
	fprintf(stderr, "%sBREAKPOINT%s %d\n", hi, n, debug_reg_current_breakpoint(t));
	fflush(stderr);
	if (plug->breakpoint) plug->breakpoint(t, plug->data);
}

tracer_plugin_t debug_wrap(tracer_plugin_t *plug)
{
	debug_init(stderr);

	tracer_plugin_t wrap = (tracer_plugin_t)
	{
		.pre_call = print_pre_call,
		.post_call = print_post_call,
		.signal = print_signal,
		.start = print_start,
		.stop = print_stop,
		.step = print_step,
		.exec = print_exec,
		.detach = print_detach,
		.breakpoint = print_breakpoint,
		.pid_selector = select_pid,
		.data = (void *)plug,
	};

	return wrap;
}

