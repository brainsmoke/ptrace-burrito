#define _LARGEFILE64_SOURCE 1

#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <ctype.h>

#include "debug.h"
#include "string.h"
#include "util.h"

#include <linux/unistd.h>

static FILE *out = NULL;

void debug_init(FILE *outfile)
{
	out = outfile;
}

FILE *debug_out(void)
{
	return out;
}

#ifdef __i386__

const char *trace_desc[] =
{
	"    [   ebx   ] [   ecx   ]    [   edx   ] [   esi   ]",
	"    [   edi   ] [   ebp   ]    [   eax   ] [ ds] [_ds]",
	"    [ es] [_es] [ fs] [_fs]    [ gs] [_gs] [ orig eax]",
	"    [   eip   ] [ cs] [_cs]    [  eflags ] [   esp   ]",
	"    [ ss] [_ss] [dead beef]    st sg ex fl [   pid   ]",
	"    [  status ] [ syscall ]    [  *data  ]",
};

const char *registers_desc[] =
{
	"    [   ebx   ] [   ecx   ]    [   edx   ] [   esi   ]",
	"    [   edi   ] [   ebp   ]    [   eax   ] [ ds] [_ds]",
	"    [ es] [_es] [ fs] [_fs]    [ gs] [_gs] [ orig eax]",
	"    [   eip   ] [ cs] [_cs]    [  eflags ] [   esp   ]",
	"    [ ss] [_ss]",
};

#endif

#ifdef __x86_64__
//#error structure has changed, needs to be retested

const char *trace_desc[] =
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
	"    [          gs         ]    [dead beef] st sg ex fl",
	"    [   pid   ] [  status ]    [        syscall      ]",
	"    [        *data        ]",
};

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

#endif

static inline long min(long a, long b) { return a<b ? a:b; }
static inline long max(long a, long b) { return a>b ? a:b; }

static const char *hi = "\033[0;34m",/* *color = "\033[0;31m",*/ *reset = "\033[m";

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

void print_trace(trace_t *t)
{
	printhex_descr(t, sizeof(trace_t), 0, trace_desc);
}

void print_trace_diff(trace_t *new, trace_t *old)
{
	printhex_diff_descr(new, sizeof(trace_t),
	                    old, sizeof(trace_t), sizeof(long), 0, trace_desc);
}

void print_trace_if_diff(trace_t *new, trace_t *old)
{
	if ( bcmp(&new->regs, &old->regs, sizeof(registers_t)) != 0 )
		print_trace_diff(new, old);
}

void print_registers(registers_t *regs)
{
	printhex_descr(regs, sizeof(registers_t), 0, registers_desc);
}

void print_registers_diff(registers_t *new, registers_t *old)
{
	printhex_diff_descr(new, sizeof(registers_t),
	                    old, sizeof(registers_t), sizeof(long), 0, registers_desc);
}

void print_registers_if_diff(registers_t *new, registers_t *old)
{
	if ( bcmp(new, old, sizeof(registers_t)) != 0 )
		print_registers_diff(new, old);
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

