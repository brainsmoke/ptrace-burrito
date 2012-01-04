#ifndef ARCH_H
#define ARCH_H

#include <inttypes.h>
#include <sys/user.h>
#include <sys/procfs.h>

/*
 * Architecture specific definitions:
 *
 * Currently, only i386 is supported
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

#define ELF_CLASS       ELFCLASS32
#define ELF_DATA        ELFDATA2LSB
#define ELF_ARCH        EM_386

#endif

#ifdef __x86_64__

typedef struct user_regs_struct registers_t;

#define ELF_CLASS       ELFCLASS64
#define ELF_DATA        ELFDATA2LSB
#define ELF_ARCH        EM_X86_64

#endif

#ifdef __powerpc__
typedef struct { uint32_t r[32]; } registers_t;
#endif

#endif /* ARCH_H */
