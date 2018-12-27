
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

#ifndef ARCH_H
#define ARCH_H

#include <inttypes.h>
#include <stddef.h>
#include <sys/user.h>
#include <sys/procfs.h>
#include <linux/unistd.h>

/*
 * Architecture specific definitions:
 *
 * Currently, only i386/x86_64 is supported
 */

/*
 * - Define registers_t to be whatever ptrace(PTRACE_GETREGS, ...)
 *   returns on the target platform.
 *
 * - Define ELF_CLASS, ELF_DATA and ELF_ARCH since they arent exported
 *   by the kernel anymore
 *
 */

#if defined(__i386__) || defined(__x86_64__)

typedef struct user_regs_struct registers_t;

#define MAX_BREAKPOINTS (4)

typedef struct
{
	unsigned long hw[MAX_BREAKPOINTS];
	int mapping[MAX_BREAKPOINTS]; /* kernel bug workaround, don't leave any gaps */
	unsigned char type[MAX_BREAKPOINTS];
	unsigned char len[MAX_BREAKPOINTS];
	unsigned long status;
	unsigned long control;

} debug_registers_t;

#define DEBUGREG_OFFSET(i) (offsetof(struct user, u_debugreg) + i*sizeof(unsigned long))
#define DEBUG_STATUS_REG  (6)
#define DEBUG_CONTROL_REG (7)

#endif

#ifdef __i386__

#define ELF_CLASS       ELFCLASS32
#define ELF_DATA        ELFDATA2LSB
#define ELF_ARCH        EM_386

#define ARCH_MMAP_SYSCALL __NR_mmap2
#define ARCH_STAT_SYSCALL __NR_stat64
#define ARCH_LSTAT_SYSCALL __NR_lstat64
#define ARCH_FSTAT_SYSCALL __NR_fstat64

#endif

#ifdef __x86_64__

#define ELF_CLASS       ELFCLASS64
#define ELF_DATA        ELFDATA2LSB
#define ELF_ARCH        EM_X86_64

#define ARCH_MMAP_SYSCALL __NR_mmap
#define ARCH_STAT_SYSCALL __NR_stat
#define ARCH_LSTAT_SYSCALL __NR_lstat
#define ARCH_FSTAT_SYSCALL __NR_fstat
#endif

#ifdef __powerpc__
typedef struct { uint32_t r[32]; } registers_t;
#endif

#endif /* ARCH_H */
