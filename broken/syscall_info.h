#ifndef SYSCALL_INFO_H
#define SYSCALL_INFO_H

#include "trace.h"

/* A datastructure which describes buffers used in syscall i/o */
typedef struct
{
	short type;
	char ptr;
	char len;
	long size;
} uspace_buf_t;

/* types of buffers; since a call may have more than one buffer,
 * LIST_END is used to signal the end of an array of buffers.
 */
enum
{
	LIST_END=0,
	FIXED_SIZE,
	VAR_SIZE,
	FD_SET_SIZE,
	STRUCT_ARRAY,
	IOVEC_COPY,
	NULL_TERMINATED
};

/* syscall_info_t.action */
enum
{
	FAIL        = 0x0000,
	PASS        = 0x0001,
	EMULATE     = 0x0002,

	COPY_RESULT = 0x0008,

	NEWFD       = 0x0040,
};

/* make values belonging to a syscall 'adressable' */

#define RETURN_VALUE           (1)

#define ARG_BASE               (8)
#define ARG(i)                 (ARG_BASE+(i))

#define _ARG(i)                (1UL<<ARG(i))

#define SOCK_ARG_BASE          (16)
#define SOCK_ARG(i)            (SOCK_ARG_BASE+(i))

#define _SOCK_ARG(i)            (1UL<<SOCK_ARG(i))

#define PRE_LEN                (24)
#define POST_LEN               (25)
#define MIN_LEN                (26)

#define PRE_MSG_ARG_BASE       (32)
#define PRE_MSG_NAME           (PRE_MSG_ARG_BASE+0)
#define PRE_MSG_NAME_LEN       (PRE_MSG_ARG_BASE+1)
#define PRE_MSG_IOV            (PRE_MSG_ARG_BASE+2)
#define PRE_MSG_IOVLEN         (PRE_MSG_ARG_BASE+3)
#define PRE_MSG_CONTROL        (PRE_MSG_ARG_BASE+4)
#define PRE_MSG_CONTROLLEN     (PRE_MSG_ARG_BASE+5)
#define PRE_MSG_FLAGS          (PRE_MSG_ARG_BASE+6)

#define POST_MSG_ARG_BASE      (40)
#define POST_MSG_NAME          (POST_MSG_ARG_BASE+0)
#define POST_MSG_NAME_LEN      (POST_MSG_ARG_BASE+1)
#define POST_MSG_IOV           (POST_MSG_ARG_BASE+2)
#define POST_MSG_IOVLEN        (POST_MSG_ARG_BASE+3)
#define POST_MSG_CONTROL       (POST_MSG_ARG_BASE+4)
#define POST_MSG_CONTROLLEN    (POST_MSG_ARG_BASE+5)
#define POST_MSG_FLAGS         (POST_MSG_ARG_BASE+6)

#define IOV_BASE               (1024)
#define IOV_PTR(i)             (IOV_BASE+(i))

/* Info about system calls */
typedef struct
{
	uspace_buf_t *copy, *verify;
	unsigned short action;
	char argc, sock_argc;
	unsigned int fd_args;
	char msg_ptr, len_ptr, iov_ptr, iov_cnt;
} syscall_info_t;

syscall_info_t *syscall_info(trace_t *t);

extern uspace_buf_t flock_copy[];
extern uspace_buf_t flock64_copy[];


#endif /* SYSCALL_INFO_H */
