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

#ifdef __i386__

typedef struct user_regs_struct registers_t;
typedef struct { int dr[8]; } debug_registers_t;
#define DEBUGREG_OFFSET (offsetof(struct user, u_debugreg))
#define MAX_BREAKPOINTS (4)

#define ELF_CLASS       ELFCLASS32
#define ELF_DATA        ELFDATA2LSB
#define ELF_ARCH        EM_386

#define ARCH_MMAP_SYSCALL __NR_mmap2
#define ARCH_STAT_SYSCALL __NR_stat64
#define ARCH_LSTAT_SYSCALL __NR_lstat64
#define ARCH_FSTAT_SYSCALL __NR_fstat64

#endif

#ifdef __x86_64__

typedef struct user_regs_struct registers_t;
typedef struct { long long int dr[8]; } debug_registers_t;
#define DEBUGREG_OFFSET (offsetof(struct user, u_debugreg))
#define MAX_BREAKPOINTS (4)

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
