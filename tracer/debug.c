
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

#define _LARGEFILE64_SOURCE 1

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>

#include <stdio.h>
#include <ctype.h>

#include "debug.h"
#include "string.h"
#include "util.h"

#include <linux/unistd.h>

static FILE *out = NULL;

static inline long min(long a, long b) { return a<b ? a:b; }
static inline long max(long a, long b) { return a>b ? a:b; }

static const char *hi = "\033[0;34m",/* *color = "\033[0;31m",*/ *reset = "\033[m";

void debug_init(FILE *outfile)
{
	out = outfile;
}

FILE *debug_out(void)
{
	return out;
}

static const char *trace_state_desc [] =
{
	[START]      = "START",
	[STOP]       = "STOP",
	[PRE_CALL]   = "PRE_CALL",
	[POST_CALL]  = "POST_CALL",
	[SIGNAL]     = "SIGNAL",
	[EXEC]       = "EXEC",
	[STEP]       = "STEP",
	[BREAKPOINT] = "BREAKPOINT",
	[DETACH]     = "DETACH",
};
#define TRACE_STATE_MAX (sizeof(trace_state_desc)/sizeof(trace_state_desc[0]))

const char *trace_state_name(int state)
{
	if ( (state < TRACE_STATE_MAX) && trace_state_desc[state] )
		return trace_state_desc[state];
	else
		return "\033[0;34m[BAD STATE]\033[m";
}


static const char *ptrace_event_desc [] =
{
	[0]                       = "<no event>",
	[PTRACE_EVENT_FORK]       = "PTRACE_EVENT_FORK",
	[PTRACE_EVENT_VFORK]      = "PTRACE_EVENT_VFORK",
	[PTRACE_EVENT_CLONE]      = "PTRACE_EVENT_CLONE",
	[PTRACE_EVENT_EXEC]       = "PTRACE_EVENT_EXEC",
	[PTRACE_EVENT_VFORK_DONE] = "PTRACE_EVENT_VFORK_DONE",
	[PTRACE_EVENT_EXIT]       = "PTRACE_EVENT_EXIT",
	[PTRACE_EVENT_SECCOMP]    = "PTRACE_EVENT_SECCOMP",
	[PTRACE_EVENT_STOP]       = "PTRACE_EVENT_STOP",

};

#define PTRACE_EVENT_NAME_MAX (sizeof(ptrace_event_desc)/sizeof(ptrace_event_desc[0]))

const char *ptrace_event_name(int event)
{
	if ( (event < PTRACE_EVENT_NAME_MAX) && ptrace_event_desc[event] )
		return ptrace_event_desc[event];
	else
		return "\033[0;34m[UNKNOWN EVENT]\033[m";
}

#ifdef __i386__

const char *registers_desc[] =
{
	"    [   ebx   ] [   ecx   ]    [   edx   ] [   esi   ]",
	"    [   edi   ] [   ebp   ]    [   eax   ] [ ds] [_ds]",
	"    [ es] [_es] [ fs] [_fs]    [ gs] [_gs] [ orig eax]",
	"    [   eip   ] [ cs] [_cs]    [  eflags ] [   esp   ]",
	"    [ ss] [_ss]",
};

const char *debug_registers_desc[] =
{
	"    [   dr0   ] [   dr1   ]    [   dr2   ] [   dr3   ]",
	"    [   ???   ] [   ???   ]    [   dr6   ] [   dr7   ]",
};

#endif

#ifdef __x86_64__
//#error structure has changed, needs to be retested

const char *registers_desc[] =
{
	"    [         r15         ]    [         r14         ]",
	"    [         r13         ]    [         r12         ]",
	"    [         rbp         ]    [         rbx         ]",
	"    [         r11         ]    [         r10         ]",
	"    [         r9          ]    [         r8          ]",
	"    [         rax         ]    [         rcx         ]",
	"    [         rdx         ]    [         rsi         ]",
	"    [         rdi         ]    [       orig_rax      ]",
	"    [         rip         ]    [          cs         ]",
	"    [        eflags       ]    [         rsp         ]",
	"    [          ss         ]    [       fs_base       ]",
	"    [        gs_base      ]    [          ds         ]",
	"    [          es         ]    [          fs         ]",
	"    [          gs         ]",
};

const char *debug_registers_desc[] =
{
	"    [         dr0         ]    [         dr1         ]",
	"    [         dr2         ]    [         dr3         ]",
	"    [         ???         ]    [         ???         ]",
	"    [         dr6         ]    [         dr7         ]",
};

#endif

/* Prints up to 16 characters in hexdump style with optional colors
 * if `ascii' is non-zero, an additional ascii representation is printed
 */
static void printhex_line(const void *data, ssize_t len, int ascii,
                          const int indices[], const char *colors[])
{
	int i, cur = -1;
	char c;

	for (i=0; i<16; i++)
	{
		if (i % 8 == 0)
			fprintf(out, "   ");

		if (i < len)
		{
			if ( indices && colors && (cur != indices[i]) )
				fprintf(out, "%s", colors[cur = indices[i]]);

			fprintf(out, " %02x", ((unsigned char *)data)[i]);
		}
		else
			fprintf(out, "   ");
	}

	if (indices && colors)
		fprintf(out, "\033[m");

	if (ascii && len > 0)
	{
		cur = -1;
		fprintf(out, "    |");

		for (i=0; i<16; i++)
		{
			if (i == len)
				break;

			if ( indices && colors && (cur != indices[i]) )
				fprintf(out, "%s", colors[cur = indices[i]]);

			c = ((unsigned char *)data)[i];
			fprintf(out, "%c", isprint(c)?c:'.');
		}

		if (indices && colors)
			fprintf(out, "\033[m");

		fprintf(out, "|");
	}

	fprintf(out, "\n");
}

static void printhex_descr(const void *data, ssize_t len, int ascii,
                           const char *descriptions[])
{
	ssize_t row;

	for (row=0; row*16<len; row++)
	{
		if ( descriptions != NULL )
			fprintf(out, "%s%s%s\n", hi, descriptions[row], reset);

		printhex_line((char*)data+row*16, min(16, len-row*16),
		              ascii, NULL, NULL);
	}
}

void printhex(const void *data, int len)
{
	printhex_descr(data, len, 1, NULL);
}

static void printhex_diff_descr(const void *data1, ssize_t len1,
                                const void *data2, ssize_t len2,
                                int grane, int ascii,
                                const char *descriptions[])
{
	ssize_t row, i;

	enum { NODIFF=0, DIFF=1 };
	int d[16], diff = 0;

	const char *color1[] = { [DIFF]="\033[1;33m", [NODIFF]="\033[0;37m" };
	const char *color2[] = { [DIFF]="\033[1;33m", [NODIFF]="\033[1;30m" };
	ssize_t minlen = min(len1, len2);
	ssize_t maxlen = max(len1, len2);

	for (row=0; row*16<maxlen; row++)
	{
		if ( descriptions != NULL )
			fprintf(out, "%s%s%s\n", hi, descriptions[row], reset);

		for (i=0; i<16; i++)
		{
			if ( (row*16+i) % grane == 0 )
			{
				if ( (minlen != maxlen && minlen-i-row*16 < grane) ||
				      bcmp( (char*)data1+row*16+i,
				            (char*)data2+row*16+i,
				            min(grane, minlen-i-row*16)) )
					diff = DIFF;
				else
					diff = NODIFF;
			}

			d[i] = diff;
		}

		printhex_line((char*)data1+row*16, min(16, len1-row*16),
		              ascii, d, color1);
		printhex_line((char*)data2+row*16, min(16, len2-row*16),
		              ascii, d, color2);
	}
}

void printhex_diff(const void *data1, ssize_t len1,
                   const void *data2, ssize_t len2, int grane)
{
	printhex_diff_descr(data1, len1, data2, len2, grane, 1, NULL);
}

void print_registers(registers_t *regs)
{
	printhex_descr(regs, sizeof(registers_t), 0, registers_desc);
}

void print_debug_registers(debug_registers_t *regs)
{
	printhex_descr(regs, sizeof(debug_registers_t), 0, debug_registers_desc);
}

void print_registers_diff(registers_t *new, registers_t *old)
{
	printhex_diff_descr(new, sizeof(registers_t),
	                    old, sizeof(registers_t), sizeof(long), 0, registers_desc);
}

void print_debug_registers_diff(debug_registers_t *new, debug_registers_t *old)
{
	printhex_diff_descr(new, sizeof(debug_registers_t),
	                    old, sizeof(debug_registers_t), sizeof(long), 0, debug_registers_desc);
}

void print_registers_if_diff(registers_t *new, registers_t *old)
{
	if ( bcmp(new, old, sizeof(registers_t)) != 0 )
		print_registers_diff(new, old);
}

void print_trace(trace_t *t)
{
	fprintf(out, "\033[1mTRACE (%d)%s\n", t->pid, reset);

	fprintf(out, "  registers:\n");
	if ( bcmp(&t->regs, &t->orig, sizeof(registers_t)) != 0 )
		print_registers_diff(&t->regs, &t->orig);
	else
		print_registers(&t->regs);

	fprintf(out, "  debug registers:\n");

	if ( bcmp(&t->debug_regs, &t->debug_orig, sizeof(debug_registers_t)) != 0 )
		print_debug_registers_diff(&t->debug_regs, &t->debug_orig);
	else
		print_debug_registers(&t->debug_regs);

	fprintf(out, "  state: %s\n", trace_state_name(t->state));
	fprintf(out, "  signal: %d\n", t->signal);
	fprintf(out, "  exitcode: %d\n", t->exitcode);
	fprintf(out, "  status: %08x\n", t->status);
	fprintf(out, "  event: %s\n", ptrace_event_name(t->event));
	fprintf(out, "  bp_list: %p\n", (void*)t->bp_list);
	fprintf(out, "  (void*)data: %p\n", t->data);
}

void print_trace_diff(trace_t *new, trace_t *old)
{
	if (new->pid == old->pid)
		fprintf(out, "\033[1mTRACE (%d)%s\n", new->pid, reset);
	else
		fprintf(out, "\033[1mTRACE (%d / %d)%s\n", new->pid, old->pid, reset);


	fprintf(out, "  registers:\n");
	if ( (bcmp(&new->regs, &new->orig, sizeof(registers_t)) != 0) ||
	     (bcmp(&old->regs, &old->orig, sizeof(registers_t)) != 0) )
	{
		fprintf(out, "    regs:\n");
		print_registers_diff(&new->regs, &old->regs);
		fprintf(out, "    orig:\n");
		print_registers_diff(&new->orig, &old->orig);
	}
	else
		print_registers_diff(&new->regs, &old->regs);

	fprintf(out, "  debug registers:\n");
	if ( (bcmp(&new->debug_regs, &new->debug_orig, sizeof(debug_registers_t)) != 0) ||
	     (bcmp(&old->debug_regs, &old->debug_orig, sizeof(debug_registers_t)) != 0) )
	{
		fprintf(out, "    regs:\n");
		print_debug_registers_diff(&new->debug_regs, &old->debug_regs);
		fprintf(out, "    orig:\n");
		print_debug_registers_diff(&new->debug_orig, &old->debug_orig);
	}
	else
		print_debug_registers_diff(&new->debug_regs, &old->debug_regs);

	if (new->state == old->state)
		fprintf(out, "  state: %s\n", trace_state_name(new->state));
	else
		fprintf(out, "  \033[1mstate: %s / %s\033[m\n", trace_state_name(new->state), trace_state_name(old->state));

	if (new->signal == old->signal)
		fprintf(out, "  signal: %d\n", new->signal);
	else
		fprintf(out, "  \033[1msignal: %d / %d\033[m\n", new->signal, old->signal);

	if (new->exitcode == old->exitcode)
		fprintf(out, "  exitcode: %d\n", new->exitcode);
	else
		fprintf(out, "  \033[1mexitcode: %d / %d\033[m\n", new->exitcode, old->exitcode);

	if (new->status == old->status)
		fprintf(out, "  status: %08x\n", new->status);
	else
		fprintf(out, "  \033[1mstatus: %08x / %08x\033[m\n", new->status, old->status);

	if (new->event == old->event)
		fprintf(out, "  event: %s\n", ptrace_event_name(new->event));
	else
		fprintf(out, "  \033[1mevent: %s / %s\033[m\n",
		        ptrace_event_name(new->event), ptrace_event_name(old->event));

	if (new->bp_list == old->bp_list)
		fprintf(out, "  bp_list: %p\n", (void*)new->bp_list);
	else
		fprintf(out, "  \033[1mbp_list: %p / %p\033[m\n", (void*)new->bp_list, (void*)old->bp_list);

	if (new->data == old->data)
		fprintf(out, "  (void*)data: %p\n", new->data);
	else
		fprintf(out, "  \033[1m(void*)data: %p / %p\033[m\n", new->data, old->data);
}

void print_trace_if_diff(trace_t *new, trace_t *old)
{
	if ( bcmp(&new->regs, &old->regs, sizeof(registers_t)) != 0 )
		print_trace_diff(new, old);
}


#ifdef __i386__

static long lastop[100000];

void print_steptrace_debug(trace_t *t, registers_t *cmp)
{
	if ( bcmp(cmp, &t->regs, sizeof(registers_t)) != 0 )
	{
		print_registers_diff(cmp, &t->regs);
		unsigned long prev_opcode_len = t->regs.eip-lastop[t->pid];
		if (prev_opcode_len > 17)
			prev_opcode_len = 32;

		char opcode[prev_opcode_len];
		memload(t->pid, opcode, (void*)lastop[t->pid], prev_opcode_len);
		printhex(opcode, prev_opcode_len);
	}
	lastop[t->pid] = t->regs.eip;
}

#endif

void print_stat(const struct stat64 *s)
{
	fprintf(out,
	"struct stat {\n"
	"    dev_t     st_dev;     [%llu %llu] /* ID of device containing file */\n"
	"    ino_t     st_ino;     [%llu] /* inode number */\n"
	"    mode_t    st_mode;    [%u] /* protection */\n"
	"    nlink_t   st_nlink;   [%lu] /* number of hard links */\n"
	"    uid_t     st_uid;     [%u] /* user ID of owner */\n"
	"    gid_t     st_gid;     [%u] /* group ID of owner */\n"
	"    dev_t     st_rdev;    [%llu %llu] /* device ID (if special file) */\n"
	"    off_t     st_size;    [%llu] /* total size, in bytes */\n"
	"    blksize_t st_blksize; [%lu] /* blocksize for filesystem I/O */\n"
	"    blkcnt_t  st_blocks;  [%llu] /* number of blocks allocated */\n"
	"    time_t    st_atime;   [%lu] /* time of last access */\n"
	"    time_t    st_mtime;   [%lu] /* time of last modification */\n"
	"    time_t    st_ctime;   [%lu] /* time of last status change */\n"
	"};\n",
	(unsigned long long)s->st_dev>>8, (unsigned long long)s->st_dev&255,
	(unsigned long long)s->st_ino, s->st_mode,
	s->st_nlink, s->st_uid, s->st_gid,
	(unsigned long long)s->st_rdev>>8, (unsigned long long)s->st_rdev&255,
	(unsigned long long)s->st_size, s->st_blksize, (unsigned long long)s->st_blocks,
	s->st_atime, s->st_mtime, s->st_ctime);
	fprintf(stderr, "%lu\n", s->st_atime);
}

