
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
#define _GNU_SOURCE 1

#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>

#include <sys/wait.h>

#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <linux/prctl.h>

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include "process.h"
#include "errors.h"

/* Get/set the process' ability to use the timestamp counter instruction.
 * This is be available in linux 2.6.26 on x86
 */
#ifndef PR_GET_TSC
#define PR_GET_TSC 25
#define PR_SET_TSC 26
# define PR_TSC_ENABLE      1   /* allow the use of the timestamp counter */
# define PR_TSC_SIGSEGV     2   /* throw a SIGSEGV instead of reading the TSC */
#endif

/* why doesn't POSIX define this?
 * subtle behaviour quirk: the PATH used is the path of the new environment
 */
//static int execvpe(char *filename, char *argv[], char *envp[])
//{
//	char **tmp = environ;
//	environ = envp;
//	execvp(filename, argv);
//	environ = tmp;
//	return -1;
//}

void trace_attach(pid_t pid)
{
	if ( ptrace(PTRACE_SEIZE, pid, NULL, NULL) == -1 )
		fatal_error("ptrace: %s", strerror(errno));

	if ( ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) == -1 )
		fatal_error("ptrace: %s", strerror(errno));
}

pid_t run_traceable(char *path, char *args[], int no_randomize, int notsc)
{
	return run_traceable_env(path, args, environ, no_randomize, notsc);
}

pid_t run_traceable_env(char *path, char *args[], char *envp[],
                        int no_randomize, int notsc)
{
	pid_t pid = fork();

	if (pid > 0)
		return pid;

	if (pid < 0)
		fatal_error("fork: %s", strerror(errno));

	/* turn off address space randomization */
	if ( no_randomize && ( personality(personality(0xffffffff) |
	                                   ADDR_NO_RANDOMIZE) == -1) )
	{
		perror("personality");
		exit(EXIT_FAILURE);
	}

	if ( notsc && prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0) < 0 )
		fprintf(stderr, "warning, disabling RDTSC failed\n");

	if ( ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1 )
		perror("ptrace");
	else
	{
		execvpe(args[0], args, envp);
		perror("exec");
	}
	exit(EXIT_FAILURE);
}

FILE *open_maps(pid_t pid)
{
	int maxlen = 64;
	char name[maxlen];
	int len = snprintf(name, maxlen, "/proc/%u/maps", pid);

	if ( (len >= maxlen) || (len < 0) )
		fatal_error("%s: snprintf failed where it shouldn't", __func__);

	FILE *f = fopen(name, "r");
	if (f == NULL)
		fatal_error("%s: cannot open %s", __func__, name);

	return f;
}

int parse_region(FILE *f, uintptr_t *base,
                          uintptr_t *end,
                          uintptr_t *file_offset,
                          char *filename_buf, size_t maxlen)
{
	*base = *end = *file_offset = 0;

	filename_buf[0] = '\0';

	int n = fscanf(f, "%lx-%lx %*s %lx %*s %*s", base, end, file_offset);
	if (n != 3)
		return 0;

	int c;
	while ( (c = fgetc(f)) == ' ' );
	ungetc(c, f);

	if (!fgets(filename_buf, maxlen, f))
		return 0;

	int len = strlen(filename_buf);
	if (len>0 && filename_buf[len-1] == '\n')
		filename_buf[len-1] = '\0';
	else if (fgetc(f) != '\n')
		return 0;

	return 1;
}

uintptr_t find_code_address(pid_t pid, const char *filename, uintptr_t offset)
{
	FILE *f = open_maps(pid);
	char *full_path = realpath(filename, NULL);
	if (full_path == NULL)
		fatal_error("%s: realpath() failed", __func__);

	char name[4098];
	uintptr_t base, end, file_offset;
	uintptr_t address = 0;

	while (parse_region(f, &base, &end, &file_offset, name, 4098))
		if ( strcmp(name, full_path) == 0 )
			if ( (offset >= file_offset) && (offset < file_offset+end-base) )
			{
				address = base + offset - file_offset;
				break;
			}

	free(full_path);
	fclose(f);
	return address;
}


static char *get_link(const char *path)
{
	char buf[4096];
	ssize_t len = readlink(path, buf, 4096);

	if (len < 0)
		fatal_error("readlink: %s", strerror(errno));

	char *s = try_malloc(len+1);

	memcpy(s, buf, len);
	s[len]='\0';

	return s;
}

static char *get_proc_file(pid_t pid, const char *s)
{
	int maxlen = 32+strlen(s);
	char name[maxlen];
	int len = snprintf(name, maxlen, "/proc/%u/%s", pid, s);

	if ( (len >= maxlen) || (len < 0) )
		fatal_error("%s: snprintf failed where it shouldn't", __func__);

	return get_link(name);
}


const char *get_proc_exe(pid_t pid)
{
	return get_proc_file(pid, "exe");
}

const char *get_proc_cwd(pid_t pid)
{
	return get_proc_file(pid, "cwd");
}

const char *get_proc_fd(pid_t pid, int fd)
{
	char pidname[64];
	int len = snprintf(pidname, 64, "/proc/%u/%d", pid, fd);

	if ( (len >= 64) || (len < 0) )
		fatal_error("%s: snprintf failed where it shouldn't", __func__);

	return get_link(pidname);
}


