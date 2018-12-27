
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

#include <time.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ustat.h>
#include <asm/fcntl.h>
#include <sys/statfs.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <sys/utsname.h>
#include <sys/resource.h>

#include <dirent.h>
#include <linux/unistd.h>
#include <linux/net.h>
#include <linux/kernel.h>
#include <linux/eventpoll.h>
#include <linux/socket.h>
#include <sys/socket.h>

#include "syscall_info.h"
#include "util.h"

static uspace_buf_t read_copy[] =
{
	{ .type = VAR_SIZE, .ptr = ARG(1), .len = RETURN_VALUE },
	{ .type = LIST_END }
};

static uspace_buf_t mmap_copy[] =
{
/*
	{ .type = VAR_SIZE, .ptr = RETURN_VALUE, .len = ARG(1) },
*/
	{ .type = LIST_END }
};

/*
static uspace_buf_t write_verify[] =
{
	{ .type = VAR_SIZE, .ptr = ARG(1), .len = ARG(2) },
	{ .type = LIST_END }
};
*/

static uspace_buf_t waitpid_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(1), .size = sizeof (int) },
	{ .type = LIST_END }
};

static uspace_buf_t time_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(0), .size = sizeof (time_t) },
	{ .type = LIST_END }
};

static uspace_buf_t timeb_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(0), .size = sizeof (struct timeb) },
	{ .type = LIST_END }
};

static uspace_buf_t pipe_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(0), .size = sizeof (int)*2 },
	{ .type = LIST_END }
};

static uspace_buf_t tms_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(0), .size = sizeof (struct tms) },
	{ .type = LIST_END }
};

static uspace_buf_t stat_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(1), .size = sizeof (struct stat) },
	{ .type = LIST_END }
};

static uspace_buf_t stat64_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(1), .size = sizeof (struct stat64) },
	{ .type = LIST_END }
};

static uspace_buf_t statat64_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(2), .size = sizeof (struct stat64) },
	{ .type = LIST_END }
};

static uspace_buf_t statfs_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(1), .size = sizeof (struct statfs) },
	{ .type = LIST_END }
};

static uspace_buf_t statfs64_copy[] = /* XXX */
{
	{ .type = VAR_SIZE, .ptr = ARG(2), .len = ARG(1) },
/*	{ .type = FIXED_SIZE, .ptr = ARG(2), .size = sizeof (struct statfs64) },*/
	{ .type = LIST_END }
};

static uspace_buf_t xattr_copy[] =
{
	{ .type = VAR_SIZE, .ptr = ARG(2), .len = RETURN_VALUE },
	{ .type = LIST_END }
};

static uspace_buf_t readlinkat_copy[] =
{
	{ .type = VAR_SIZE, .ptr = ARG(2), .len = RETURN_VALUE },
	{ .type = LIST_END }
};

static uspace_buf_t wait4_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(1), .size = sizeof (int) },
	{ .type = FIXED_SIZE, .ptr = ARG(3), .size = sizeof (struct rusage) },
	{ .type = LIST_END }
};

static uspace_buf_t sysinfo_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(0), .size = sizeof (struct sysinfo) },
	{ .type = LIST_END }
};

static uspace_buf_t uname_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(0), .size = sizeof (struct utsname) },
	{ .type = LIST_END }
};

static uspace_buf_t llseek_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(3), .size = sizeof (loff_t) },
	{ .type = LIST_END }
};

static uspace_buf_t select_copy[] =
{
	{ .type = FD_SET_SIZE, .ptr = ARG(1), .len = ARG(0) },
	{ .type = FD_SET_SIZE, .ptr = ARG(2), .len = ARG(0) },
	{ .type = FD_SET_SIZE, .ptr = ARG(3), .len = ARG(0) },
	{ .type = FIXED_SIZE, .ptr = ARG(4), .size = sizeof (struct timeval) },
	{ .type = LIST_END }
};

static uspace_buf_t pselect_copy[] =
{
	{ .type = FD_SET_SIZE, .ptr = ARG(1), .len = ARG(0) },
	{ .type = FD_SET_SIZE, .ptr = ARG(2), .len = ARG(0) },
	{ .type = FD_SET_SIZE, .ptr = ARG(3), .len = ARG(0) },
	{ .type = FIXED_SIZE, .ptr = ARG(4), .size = sizeof (struct timespec) },
	{ .type = LIST_END }
};

static uspace_buf_t poll_copy[] =
{
	{ .type = STRUCT_ARRAY, .ptr = ARG(0), .len = ARG(1), .size=sizeof(struct pollfd)},
	{ .type = LIST_END }
};

static uspace_buf_t ppoll_copy[] =
{
	{ .type = STRUCT_ARRAY, .ptr = ARG(0), .len = ARG(1), .size=sizeof(struct pollfd)},
	{ .type = FIXED_SIZE, .ptr = ARG(2), .size = sizeof (struct timespec) },
	{ .type = LIST_END }
};

static uspace_buf_t olduid_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(0), .size = sizeof (short) },
	{ .type = FIXED_SIZE, .ptr = ARG(1), .size = sizeof (short) },
	{ .type = FIXED_SIZE, .ptr = ARG(2), .size = sizeof (short) },
	{ .type = LIST_END }
};

static uspace_buf_t resuid32_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(0), .size = sizeof (uid_t) },
	{ .type = FIXED_SIZE, .ptr = ARG(1), .size = sizeof (uid_t) },
	{ .type = FIXED_SIZE, .ptr = ARG(2), .size = sizeof (uid_t) },
	{ .type = LIST_END }
};

static uspace_buf_t resgid32_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(0), .size = sizeof (gid_t) },
	{ .type = FIXED_SIZE, .ptr = ARG(1), .size = sizeof (gid_t) },
	{ .type = FIXED_SIZE, .ptr = ARG(2), .size = sizeof (gid_t) },
	{ .type = LIST_END }
};

static uspace_buf_t rlimit_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(1), .size = sizeof (struct rlimit) },
	{ .type = LIST_END }
};

static uspace_buf_t ustat_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(1), .size = sizeof (struct ustat) },
	{ .type = LIST_END }
};

static uspace_buf_t sigpending_copy[] = /* XXX */
{
	{ .type = FIXED_SIZE, .ptr = ARG(0), .size = 8 * sizeof (char) },
	{ .type = LIST_END }
};

static uspace_buf_t rt_sigpending_copy[] =
{
	{ .type = VAR_SIZE, .ptr = ARG(0), .len = ARG(1) },
	{ .type = LIST_END }
};

static uspace_buf_t timeofday_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(0), .size = sizeof (struct timeval) },
	{ .type = FIXED_SIZE, .ptr = ARG(1), .size = sizeof (struct timezone) },
	{ .type = LIST_END }
};

static uspace_buf_t timespec_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(1), .size = sizeof (struct timespec) },
	{ .type = LIST_END }
};

static uspace_buf_t nanosleep_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(3), .size = sizeof (struct timespec) },
	{ .type = LIST_END }
};

static uspace_buf_t oldgroups_copy[] =
{
	{ .type = STRUCT_ARRAY, .ptr = ARG(1), .len = RETURN_VALUE, .size = sizeof (short) },
	{ .type = LIST_END }
};

static uspace_buf_t groups32_copy[] =
{
	{ .type = STRUCT_ARRAY, .ptr = ARG(1), .len = RETURN_VALUE, .size = sizeof (gid_t) },
	{ .type = LIST_END }
};

/*
static uspace_buf_t sendfile_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(2), .size = sizeof (off_t) },
	{ .type = LIST_END }
};

static uspace_buf_t sendfile64_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(2), .size = sizeof (loff_t) },
	{ .type = LIST_END }
};
*/

static uspace_buf_t rusage_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(1), .size = sizeof (struct rusage) },
	{ .type = LIST_END }
};

static uspace_buf_t readdir_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(1), .size = sizeof (struct dirent) },
	{ .type = LIST_END }
};

static uspace_buf_t epoll_copy[] =
{
	{ .type = STRUCT_ARRAY, .ptr = ARG(1), .len = RETURN_VALUE, .size = sizeof (struct epoll_event) },
	{ .type = LIST_END }
};

static uspace_buf_t robust_list_copy[] =
{
	{ .type = VAR_SIZE, .ptr = ARG(1), .len = POST_LEN },
	{ .type = FIXED_SIZE, .ptr = SOCK_ARG(2), .size = sizeof(size_t) },
	{ .type = LIST_END }
};


static uspace_buf_t sockaddr_copy[] = /* XXX */
{
	{ .type = VAR_SIZE, .ptr = SOCK_ARG(1), .len = MIN_LEN },
	{ .type = FIXED_SIZE, .ptr = SOCK_ARG(2), .size = sizeof(socklen_t) },
	{ .type = LIST_END }
};

static uspace_buf_t sockpair_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = SOCK_ARG(3), .size = sizeof (int)*2 },
	{ .type = LIST_END }
};

static uspace_buf_t sockrecv_copy[] =
{
	{ .type = VAR_SIZE, .ptr = SOCK_ARG(1), .len = RETURN_VALUE },
	{ .type = LIST_END }
};

static uspace_buf_t sockrecvfrom_copy[] =
{
	{ .type = VAR_SIZE, .ptr = SOCK_ARG(1), .len = RETURN_VALUE },
	{ .type = VAR_SIZE, .ptr = SOCK_ARG(4), .len = MIN_LEN },
	{ .type = FIXED_SIZE, .ptr = SOCK_ARG(5), .size = sizeof(socklen_t) },
	{ .type = LIST_END }
};

static uspace_buf_t sockopt_copy[] = /* XXX */
{
	{ .type = VAR_SIZE, .ptr = SOCK_ARG(3), .len = MIN_LEN },
	{ .type = FIXED_SIZE, .ptr = SOCK_ARG(4), .size = sizeof(socklen_t) },
	{ .type = LIST_END }
};

static uspace_buf_t recvmsg_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = SOCK_ARG(1), .size = sizeof (struct msghdr) },
	{ .type = VAR_SIZE, .ptr = PRE_MSG_CONTROL, .len = POST_MSG_CONTROLLEN },
	{ .type = IOVEC_COPY, .len = RETURN_VALUE },
	{ .type = LIST_END },
};

static uspace_buf_t iov_copy[] =
{
	{ .type = IOVEC_COPY, .len = RETURN_VALUE },
	{ .type = LIST_END },
};

uspace_buf_t flock_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(2), .size = sizeof (struct flock) },
	{ .type = LIST_END }
};

uspace_buf_t flock64_copy[] =
{
	{ .type = FIXED_SIZE, .ptr = ARG(2), .size = sizeof (struct flock64) },
	{ .type = LIST_END }
};

static syscall_info_t unknown_call_info = { .action = FAIL };

static syscall_info_t syscall_info_array[] =
{
	[__NR_restart_syscall] = { .argc = 6, .action = EMULATE }, /* !!! */
	[__NR_exit] =    { .argc = 1, .action = PASS },
	[__NR_fork] =    { .argc = 0, .action = PASS },
	[__NR_read] =    { .argc = 3, .action = EMULATE, .copy = read_copy, .fd_args = _ARG(0) },
	[__NR_write] =   { .argc = 3, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_open] =    { .argc = 3, .action = EMULATE|NEWFD },
	[__NR_close] =   { .argc = 1, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_waitpid] = { .argc = 3, .action = EMULATE, .copy = waitpid_copy },
	[__NR_creat] = { .argc = 2, .action = EMULATE|NEWFD },
	[__NR_link] = { .argc = 2, .action = EMULATE },
	[__NR_unlink] = { .argc = 1, .action = EMULATE },
/*	[__NR_execve] = { .argc = 0 }, */
	[__NR_chdir] = { .argc = 1, .action = EMULATE },
	[__NR_time] = { .argc = 1, .action = EMULATE, .copy = time_copy },
	[__NR_mknod] = { .argc = 3, .action = EMULATE },
	[__NR_chmod] = { .argc = 2, .action = EMULATE },
	[__NR_lchown] = { .argc = 3, .action = EMULATE },
/*
	[__NR_break] = { .argc = 0 },
	[__NR_oldstat] = { .argc = 0, .action =  },
*/
	[__NR_lseek] = { .argc = 3, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_getpid] = { .argc = 0, .action = EMULATE },
/*	[__NR_mount] = { .argc = 5, .action = EMULATE },
	[__NR_umount] = { .argc = 1, .action = EMULATE },*/
	[__NR_setuid] = { .argc = 1, .action = EMULATE }, /* XXX */
	[__NR_getuid] = { .argc = 0, .action = EMULATE },
	[__NR_stime] = { .argc = 1, .action = EMULATE },
/*	[__NR_ptrace] = { .argc = 0 }, */
	[__NR_alarm] = { .argc = 1, .action = EMULATE },
/*	[__NR_oldfstat] = { .argc = 0, .action = , .fd_args = _ARG(0) }, */
	[__NR_pause] = { .argc = 0, .action = EMULATE },
	[__NR_utime] = { .argc = 2, .action = EMULATE },
/*
	[__NR_stty] = { .argc = 0 },
	[__NR_gtty] = { .argc = 0 },
*/
	[__NR_access] = { .argc = 2, .action = EMULATE },
	[__NR_nice] = { .argc = 1, .action = EMULATE }, /* XXX */
	[__NR_ftime] = { .argc = 1, .action = EMULATE, .copy = timeb_copy },
	[__NR_sync] = { .argc = 0, .action = EMULATE },
	[__NR_kill] = { .argc = 2, .action = EMULATE },
	[__NR_rename] = { .argc = 2, .action = EMULATE },
	[__NR_mkdir] = { .argc = 2, .action = EMULATE },
	[__NR_rmdir] = { .argc = 2, .action = EMULATE },
	[__NR_dup] = { .argc = 1, .action = EMULATE|NEWFD, .fd_args = _ARG(0) },
	[__NR_pipe] = { .argc = 1, .action = EMULATE|NEWFD, .copy = pipe_copy },
	[__NR_times] = { .argc = 1, .action = EMULATE, .copy = tms_copy },
/*	[__NR_prof] = { .argc = 0 }, */
	[__NR_brk] = { .argc = 1, .action = PASS },
	[__NR_setgid] = { .argc = 1, .action = EMULATE }, /* XXX */
	[__NR_getgid] = { .argc = 0, .action = EMULATE },
	[__NR_signal] = { .argc = 2, .action = PASS },
	[__NR_geteuid] = { .argc = 0, .action = EMULATE },
	[__NR_getegid] = { .argc = 0, .action = EMULATE },
/*	[__NR_acct] = { .argc = 1, .action = EMULATE }, * XXX */
/*	[__NR_umount2] = { .argc = 2, .action = EMULATE },*/
/*
	[__NR_lock] = { .argc = 0 },
	[__NR_ioctl] = { .argc = 3, .action = , .fd_args = _ARG(0) },
*/
	[__NR_fcntl] = { .argc = 3, .action = EMULATE, .fd_args = _ARG(0) /*NEWFD*/ },
/*	[__NR_mpx] = { .argc = 0 }, */
	[__NR_setpgid] = { .argc = 2, .action = EMULATE },
	[__NR_ulimit] = { .argc = 2, .action = EMULATE },
/*	[__NR_oldolduname] = { .argc = 0 }, */
	[__NR_umask] = { .argc = 1, .action = PASS },
/*	[__NR_chroot] = { .argc = 1, .action = EMULATE }, * XXX */
	[__NR_ustat] = { .argc = 2, .action = EMULATE, .copy = ustat_copy },
	[__NR_dup2] = { .argc = 0, .action = EMULATE|NEWFD, .fd_args = _ARG(0)|_ARG(1) }, /* XXX */
	[__NR_getppid] = { .argc = 0, .action = EMULATE },
	[__NR_getpgrp] = { .argc = 0, .action = EMULATE },
	[__NR_setsid] = { .argc = 0, .action = EMULATE },
	[__NR_sigaction] = { .argc = 3, .action = PASS },
/*
	[__NR_sgetmask] = { .argc = 0 },
	[__NR_ssetmask] = { .argc = 0 },
*/
	[__NR_setreuid] = { .argc = 2, .action = EMULATE }, /* XXX */
	[__NR_setregid] = { .argc = 2, .action = EMULATE }, /* XXX */
	[__NR_sigsuspend] = { .argc = 1, .action = EMULATE },
	[__NR_sigpending] = { .argc = 1, .action = EMULATE, .copy = sigpending_copy },
	[__NR_sethostname] = { .argc = 2, .action = EMULATE },
	[__NR_setrlimit] = { .argc = 2, .action = EMULATE },
	[__NR_getrlimit] = { .argc = 2, .action = EMULATE, .copy = rlimit_copy },
	[__NR_getrusage] = { .argc = 2, .action = EMULATE, .copy = rusage_copy },
	[__NR_gettimeofday] = { .argc = 2, .action = EMULATE, .copy = timeofday_copy },
	[__NR_settimeofday] = { .argc = 2 },
	[__NR_getgroups] = { .argc = 2, .action = EMULATE, .copy = oldgroups_copy },
	[__NR_setgroups] = { .argc = 2, .action = EMULATE },
/*	[__NR_select] = { .argc = 0 }, */
	[__NR_symlink] = { .argc = 2, .action = EMULATE },
/*	[__NR_oldlstat] = { .argc = 0 }, */
	[__NR_readlink] = { .argc = 3, .action = EMULATE, .copy = read_copy },
/*	[__NR_uselib] = { .argc = 0 }, */
	[__NR_swapon] = { .argc = 2, .action = EMULATE },
/*	[__NR_reboot] = { .argc = 0 }, */
	[__NR_readdir] = { .argc = 3, .action = EMULATE, .copy = readdir_copy, .fd_args = _ARG(0) },
/*	[__NR_mmap] = { .argc = 6, .action = EMULATE, .copy = mmap_copy }, */
	[__NR_munmap] = { .argc = 2, .action = PASS },
	[__NR_truncate] = { .argc = 2, .action = EMULATE },
	[__NR_ftruncate] = { .argc = 2, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_fchmod] = { .argc = 2, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_fchown] = { .argc = 3, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_getpriority] = { .argc = 2, .action = EMULATE },
	[__NR_setpriority] = { .argc = 3, .action = EMULATE },
/*	[__NR_profil] = { .argc = 0 }, */
	[__NR_statfs] = { .argc = 2, .action = EMULATE, .copy = statfs_copy },
	[__NR_fstatfs] = { .argc = 2, .action = EMULATE, .copy = statfs_copy, .fd_args = _ARG(0) },
/*	[__NR_ioperm] = { .argc = 0 }, */

/*	lookups to __NR_socketcall are redirected */

/*
	[__NR_syslog] = { .argc = 0 },
	[__NR_setitimer] = { .argc = 0 },
	[__NR_getitimer] = { .argc = 0 },
*/
	[__NR_stat] = { .argc = 2, .action = EMULATE, .copy = stat_copy },
	[__NR_lstat] = { .argc = 2, .action = EMULATE, .copy = stat_copy },
	[__NR_fstat] = { .argc = 2, .action = EMULATE, .copy = stat_copy, .fd_args = _ARG(0) },
/*
	[__NR_olduname] = { .argc = 0 },
	[__NR_iopl] = { .argc = 0 },
*/
	[__NR_vhangup] = { .argc = 0, .action = EMULATE },
	[__NR_idle] = { .argc = 0, .action = EMULATE },
/*	[__NR_vm86old] = { .argc = 0 }, */
	[__NR_wait4] = { .argc = 4, .action = EMULATE, .copy = wait4_copy },
	[__NR_swapoff] = { .argc = 1, .action = EMULATE },
	[__NR_sysinfo] = { .argc = 1, .action = EMULATE, .copy = sysinfo_copy },
/*	[__NR_ipc] = { .argc = 0 }, */
	[__NR_fsync] = { .argc = 1, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_sigreturn] = { .argc = 0, .action = PASS },
	[__NR_clone] = { .argc = 5, .action = PASS|COPY_RESULT },
	[__NR_setdomainname] = { .argc = 2, .action = EMULATE },
	[__NR_uname] = { .argc = 1, .action = EMULATE, .copy = uname_copy },
/*
	[__NR_modify_ldt] = { .argc = 0 },
	[__NR_adjtimex] = { .argc = 0 },
*/
	[__NR_mprotect] = { .argc = 3, .action = PASS },
	[__NR_sigprocmask] = { .argc = 3, .action = PASS },
/*
	[__NR_create_module] = { .argc = 0 },
	[__NR_init_module] = { .argc = 0 },
	[__NR_delete_module] = { .argc = 0 },
	[__NR_get_kernel_syms] = { .argc = 0 },
	[__NR_quotactl] = { .argc = 0 },
*/
	[__NR_getpgid] = { .argc = 1, .action = EMULATE },
	[__NR_fchdir] = { .argc = 1, .action = EMULATE },
/*
	[__NR_bdflush] = { .argc = 0 },
	[__NR_sysfs] = { .argc = 0 },
	[__NR_personality] = { .argc = 0 },
	[__NR_afs_syscall] = { .argc = 0 },
*/
	[__NR_setfsuid] = { .argc = 1, .action = EMULATE },
	[__NR_setfsgid] = { .argc = 1, .action = EMULATE },
	[__NR__llseek] = { .argc = 5, .action = EMULATE, .copy = llseek_copy, .fd_args = _ARG(0) },
	[__NR_getdents] = { .argc = 3, .action = EMULATE, .copy = read_copy, .fd_args = _ARG(0) },
	[__NR__newselect] = { .argc = 5, .action = EMULATE, .copy = select_copy },
	[__NR_flock] = { .argc = 2, .action = EMULATE, .fd_args = _ARG(0) },
/*	[__NR_msync] = { .argc = 0 }, */
	[__NR_readv] = { .argc = 3, .action = EMULATE, .copy = iov_copy, .iov_ptr = ARG(1), .iov_cnt = ARG(2), .fd_args = _ARG(0) },
	[__NR_writev] = { .argc = 3, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_getsid] = { .argc = 1, .action = EMULATE },
	[__NR_fdatasync] = { .argc = 1, .action = EMULATE, .fd_args = _ARG(0) },
/*
	[__NR__sysctl] = { .argc = 0 },
	[__NR_mlock] = { .argc = 0 },
	[__NR_munlock] = { .argc = 0 },
	[__NR_mlockall] = { .argc = 0 },
	[__NR_munlockall] = { .argc = 0 },
	[__NR_sched_setparam] = { .argc = 0 },
	[__NR_sched_getparam] = { .argc = 0 },
	[__NR_sched_setscheduler] = { .argc = 0 },
	[__NR_sched_getscheduler] = { .argc = 0 },
	[__NR_sched_yield] = { .argc = 0 },
	[__NR_sched_get_priority_max] = { .argc = 0 },
	[__NR_sched_get_priority_min] = { .argc = 0 },
	[__NR_sched_rr_get_interval] = { .argc = 0 },
	[__NR_nanosleep] = { .argc = 0 },
	[__NR_mremap] = { .argc = 0 },
*/
	[__NR_setresuid] = { .argc = 3, .action = EMULATE },
	[__NR_getresuid] = { .argc = 3, .action = EMULATE, .copy = olduid_copy },
/*
	[__NR_vm86] = { .argc = 0 },
	[__NR_query_module] = { .argc = 0 },
*/
	[__NR_poll] = { .argc = 3, .action = EMULATE, .copy = poll_copy },
/*	[__NR_nfsservctl] = { .argc = 0 }, */
	[__NR_setresgid] = { .argc = 3, .action = EMULATE },
	[__NR_getresgid] = { .argc = 3, .action = EMULATE, .copy = olduid_copy },
/*	[__NR_prctl] = { .argc = 0 }, */
	[__NR_rt_sigreturn] = { .argc = 0, .action = PASS },
	[__NR_rt_sigaction]   = { .argc = 4, .action = PASS },
	[__NR_rt_sigprocmask] = { .argc = 4, .action = PASS },
	[__NR_rt_sigpending] = { .argc = 2, .action = EMULATE, .copy = rt_sigpending_copy },
/*
	[__NR_rt_sigtimedwait] = { .argc = 0 },
	[__NR_rt_sigqueueinfo] = { .argc = 0 },
	[__NR_rt_sigsuspend] = { .argc = 0 },
*/
	[__NR_pread64] = { .argc = 4+8/sizeof(long), .action = EMULATE, .copy = read_copy },
	[__NR_pwrite64] = { .argc = 4+8/sizeof(long), .action = EMULATE },
	[__NR_chown] = { .argc = 3, .action = EMULATE },
/*
	[__NR_getcwd] = { .argc = 0 },
	[__NR_capget] = { .argc = 0 },
	[__NR_capset] = { .argc = 0 },
*/
	[__NR_sigaltstack] = { .argc = 2, .action = PASS },
/*	[__NR_sendfile] = { .argc = 4, .action = EMULATE, .copy = sendfile_copy, .fd_args = _ARG(0)|_ARG(1) },*/
/*
	[__NR_getpmsg] = { .argc = 0 },
	[__NR_putpmsg] = { .argc = 0 },
*/
	[__NR_vfork] =    { .argc = 0, .action = PASS },
	[__NR_ugetrlimit] = { .argc = 2, .action = EMULATE, .copy = rlimit_copy },
	[__NR_mmap2] = { .argc = 6, .action = EMULATE, .copy = mmap_copy }, /* XXX */
	[__NR_truncate64] = { .argc = 3, .action = EMULATE },  /* low+high */
	[__NR_ftruncate64] = { .argc = 3, .action = EMULATE, .fd_args = _ARG(0) }, /* low+high */
#ifdef __NR_stat64
	[__NR_stat64] = { .argc = 2, .action = EMULATE, .copy = stat64_copy },
#endif
#ifdef __NR_lstat64
	[__NR_lstat64] = { .argc = 2, .action = EMULATE, .copy = stat64_copy },
#endif
#ifdef __NR_fstat64
	[__NR_fstat64] = { .argc = 2, .action = EMULATE, .copy = stat64_copy, .fd_args = _ARG(0) },
#endif
	[__NR_lchown32] = { .argc = 3, .action = EMULATE },
	[__NR_getuid32] = { .argc = 0, .action = EMULATE },
	[__NR_getgid32] = { .argc = 0, .action = EMULATE },
	[__NR_geteuid32] = { .argc = 0, .action = EMULATE },
	[__NR_getegid32] = { .argc = 0, .action = EMULATE },
	[__NR_setreuid32] = { .argc = 2, .action = EMULATE },
	[__NR_setregid32] = { .argc = 2, .action = EMULATE },
	[__NR_getgroups32] = { .argc = 2, .action = EMULATE, .copy= groups32_copy },
	[__NR_setgroups32] = { .argc = 2, .action = EMULATE },
	[__NR_fchown32] = { .argc = 3, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_setresuid32] = { .argc = 3, .action = EMULATE },
	[__NR_getresuid32] = { .argc = 3, .action = EMULATE, .copy =resuid32_copy },
	[__NR_setresgid32] = { .argc = 3, .action = EMULATE },
	[__NR_getresgid32] = { .argc = 3, .action = EMULATE, .copy =resgid32_copy },
	[__NR_chown32] = { .argc = 3, .action = EMULATE },
	[__NR_setuid32] = { .argc = 1, .action = EMULATE }, /* XXX */
	[__NR_setgid32] = { .argc = 1, .action = EMULATE },
	[__NR_setfsuid32] = { .argc = 1, .action = EMULATE },
	[__NR_setfsgid32] = { .argc = 1, .action = EMULATE },
/*
	[__NR_pivot_root] = { .argc = 0 },
	[__NR_mincore] = { .argc = 0 },
	[__NR_madvise] = { .argc = 0 },
	[__NR_madvise1] = { .argc = 0 },
*/
#ifdef __NR_getdents64
	[__NR_getdents64] = { .argc = 3, .action = EMULATE, .copy=read_copy, .fd_args = _ARG(0) },
#endif
#ifdef __NR_fcntl64
	[__NR_fcntl64] = { .argc = 3, .action = EMULATE/*NEWFD*/, .fd_args = _ARG(0) },
#endif
 /* 223 is unused */ 
	[__NR_gettid] = { .argc = 0, .action = EMULATE },
	[__NR_readahead] = { .argc = 3, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_setxattr] = { .argc = 5, .action = EMULATE },
	[__NR_lsetxattr] = { .argc = 5, .action = EMULATE },
	[__NR_fsetxattr] = { .argc = 5, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_getxattr] = { .argc = 4, .action = EMULATE, .copy = xattr_copy },
	[__NR_lgetxattr] = { .argc = 4, .action = EMULATE, .copy = xattr_copy },
	[__NR_fgetxattr] = { .argc = 4, .action = EMULATE, .copy = xattr_copy, .fd_args = _ARG(0) },
	[__NR_listxattr] = { .argc = 3, .action = EMULATE, .copy = read_copy },
	[__NR_llistxattr] = { .argc = 3, .action = EMULATE, .copy = read_copy },
	[__NR_flistxattr] = { .argc = 3, .action = EMULATE, .copy = read_copy, .fd_args = _ARG(0) },
	[__NR_removexattr] = { .argc = 2, .action = EMULATE },
	[__NR_lremovexattr] = { .argc = 2, .action = EMULATE },
	[__NR_fremovexattr] = { .argc = 2, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_tkill] = { .argc = 2, .action = EMULATE },
/*	[__NR_sendfile64] = { .argc = 4, .action = EMULATE, .copy = sendfile64_copy, .fd_args = _ARG(0)|_ARG(1) },*/
	[__NR_futex] = { .argc = 5, .action = PASS },
/*
	[__NR_sched_setaffinity] = { .argc = 0 },
	[__NR_sched_getaffinity] = { .argc = 0 },
*/
	[__NR_set_thread_area] = { .argc = 1, .action = PASS },
/*
	[__NR_get_thread_area] = { .argc = 0 },
	[__NR_io_setup] = { .argc = 0 },
	[__NR_io_destroy] = { .argc = 0 },
	[__NR_io_getevents] = { .argc = 0 },
	[__NR_io_submit] = { .argc = 0 },
	[__NR_io_cancel] = { .argc = 0 },
	[__NR_fadvise64] = { .argc = 0 },
  * 251 is available for reuse (was briefly sys_set_zone_reclaim) */ 
	[__NR_exit_group] = { .argc = 1, .action = PASS },
/*	[__NR_lookup_dcookie] = { .argc = 0 }, */
	[__NR_epoll_create] = { .argc = 1, .action = EMULATE },
	[__NR_epoll_ctl] = { .argc = 4, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_epoll_wait] = { .argc = 4, .action = EMULATE, .copy = epoll_copy, .fd_args = _ARG(0) },
/*	[__NR_remap_file_pages] = { .argc = 0 }, */
	[__NR_set_tid_address] = { .argc = 1, .action = PASS|COPY_RESULT },
/*
	[__NR_timer_create] = { .argc = 0 },
	[__NR_timer_settime] = { .argc = 0 },
	[__NR_timer_gettime] = { .argc = 0 },
	[__NR_timer_getoverrun] = { .argc = 0 },
	[__NR_timer_delete] = { .argc = 0 },
	[__NR_clock_settime] = { .argc = 0 }, * not a good idea :-) *
*/
	[__NR_clock_gettime] = { .argc = 2, .action = EMULATE, .copy = timespec_copy },
	[__NR_clock_getres] = { .argc = 2, .action = EMULATE, .copy = timespec_copy }, /* XXX */
	[__NR_clock_nanosleep] = { .argc = 4, .action = EMULATE, .copy = nanosleep_copy }, /* XXX */
#ifdef __NR_statfs64
	[__NR_statfs64] = { .argc = 3, .action = EMULATE, .copy = statfs64_copy },
#endif
#ifdef __NR_fstatfs64
	[__NR_fstatfs64] = { .argc = 3, .action = EMULATE, .copy = statfs64_copy, .fd_args = _ARG(0) },
#endif
	[__NR_tgkill] = { .argc = 3, .action = EMULATE },
	[__NR_utimes] = { .argc = 2, .action = EMULATE },
/*
	[__NR_fadvise64_64] = { .argc = 0 },
	[__NR_vserver] = { .argc = 0 },
	[__NR_mbind] = { .argc = 0 },
	[__NR_get_mempolicy] = { .argc = 0 },
	[__NR_set_mempolicy] = { .argc = 0 },
	[__NR_mq_open] = { .argc = 0 },
	[__NR_mq_unlink] = { .argc = 0 },
	[__NR_mq_timedsend] = { .argc = 0 },
	[__NR_mq_timedreceive] = { .argc = 0 },
	[__NR_mq_notify] = { .argc = 0 },
	[__NR_mq_getsetattr] = { .argc = 0 },
	[__NR_kexec_load] = { .argc = 0 },
	[__NR_waitid] = { .argc = 0 },
  * #define __NR_sys_setaltroot	285 * 
	[__NR_add_key] = { .argc = 0 },
	[__NR_request_key] = { .argc = 0 },
	[__NR_keyctl] = { .argc = 0 },
	[__NR_ioprio_set] = { .argc = 0 },
	[__NR_ioprio_get] = { .argc = 0 },
	[__NR_inotify_init] = { .argc = 0 },
	[__NR_inotify_add_watch] = { .argc = 0 },
	[__NR_inotify_rm_watch] = { .argc = 0 },
	[__NR_migrate_pages] = { .argc = 0 },
*/
	[__NR_openat] = { .argc = 4, .action = EMULATE|NEWFD, .fd_args = _ARG(0) },
	[__NR_mkdirat] = { .argc = 3, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_mknodat] = { .argc = 4, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_fchownat] = { .argc = 5, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_futimesat] = { .argc = 3, .action = EMULATE, .fd_args = _ARG(0) },
#ifdef __NR_fstatat64
	[__NR_fstatat64] = { .argc = 4, .action = EMULATE, .copy = statat64_copy, .fd_args = _ARG(0) },
#endif
	[__NR_unlinkat] = { .argc = 3, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_renameat] = { .argc = 4, .action = EMULATE, .fd_args = _ARG(0)|_ARG(2) },
	[__NR_linkat] = { .argc = 4, .action = EMULATE, .fd_args = _ARG(0)|_ARG(2) },
	[__NR_symlinkat] = { .argc = 3, .action = EMULATE, .fd_args = _ARG(1) },
	[__NR_readlinkat] = { .argc = 4, .action = EMULATE, .copy=readlinkat_copy, .fd_args = _ARG(0) },
	[__NR_fchmodat] = { .argc = 3, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_faccessat] = { .argc = 3, .action = EMULATE, .fd_args = _ARG(0) },
	[__NR_pselect6] = { .argc = 6, .action = EMULATE, .copy = pselect_copy },
	[__NR_ppoll] = { .argc = 5, .action = EMULATE, .copy = ppoll_copy },
	[__NR_unshare] = { .argc = 1, .action = PASS },
	[__NR_set_robust_list] = { .argc = 2, .action = EMULATE },
	[__NR_get_robust_list] = { .argc = 3, .action = EMULATE, .copy = robust_list_copy, .len_ptr = ARG(2) },
/*
	[__NR_splice] = { .argc = 0 },
	[__NR_sync_file_range] = { .argc = 0 },
	[__NR_tee] = { .argc = 0 },
	[__NR_vmsplice] = { .argc = 0 },
	[__NR_move_pages] = { .argc = 0 },
	[__NR_getcpu] = { .argc = 0 },
*/
	[__NR_epoll_pwait] = { .argc = 6, .action = EMULATE, .copy = epoll_copy, .fd_args = _ARG(0) },
/*
	[__NR_utimensat] = { .argc = 0 },
	[__NR_signalfd] = { .argc = 0 },
	[__NR_timerfd_create] = { .argc = 0 },
	[__NR_eventfd] = { .argc = 0 },
	[__NR_fallocate] = { .argc = 0 },
	[__NR_timerfd_settime] = { .argc = 0 },
	[__NR_timerfd_gettime] = { .argc = 0 },

*/
};

static syscall_info_t socketcall_info_array[] =
{
	[SYS_SOCKET] =      { .action = EMULATE|NEWFD, .argc = 2, .sock_argc = 3 }, 
	[SYS_BIND] =        { .action = EMULATE, .argc = 2, .sock_argc = 3, .fd_args = _SOCK_ARG(0) }, 
	[SYS_CONNECT] =     { .action = EMULATE, .argc = 2, .sock_argc = 3, .fd_args = _SOCK_ARG(0) }, 
	[SYS_LISTEN] =      { .action = EMULATE, .argc = 2, .sock_argc = 2, .fd_args = _SOCK_ARG(0) }, 
	[SYS_ACCEPT] =      { .action = EMULATE, .argc = 2, .sock_argc = 3, .fd_args = _SOCK_ARG(0), .len_ptr = SOCK_ARG(2), .copy = sockaddr_copy },
	[SYS_GETSOCKNAME] = { .action = EMULATE, .argc = 2, .sock_argc = 3, .fd_args = _SOCK_ARG(0), .len_ptr = SOCK_ARG(2), .copy = sockaddr_copy }, 
	[SYS_GETPEERNAME] = { .action = EMULATE, .argc = 2, .sock_argc = 3, .fd_args = _SOCK_ARG(0), .len_ptr = SOCK_ARG(2), .copy = sockaddr_copy }, 
	[SYS_SOCKETPAIR] =  { .action = EMULATE, .argc = 2, .sock_argc = 4, .fd_args = _SOCK_ARG(0), .copy = sockpair_copy }, 
	[SYS_SEND] =        { .action = EMULATE, .argc = 2, .sock_argc = 4, .fd_args = _SOCK_ARG(0) }, 
	[SYS_RECV] =        { .action = EMULATE, .argc = 2, .sock_argc = 4, .fd_args = _SOCK_ARG(0), .copy = sockrecv_copy },
	[SYS_SENDTO] =      { .action = EMULATE, .argc = 2, .sock_argc = 6, .fd_args = _SOCK_ARG(0) }, 
	[SYS_RECVFROM] =    { .action = EMULATE, .argc = 2, .sock_argc = 6, .fd_args = _SOCK_ARG(0), .len_ptr = SOCK_ARG(5), .copy = sockrecvfrom_copy }, 
	[SYS_SHUTDOWN] =    { .action = EMULATE, .argc = 2, .sock_argc = 2, .fd_args = _SOCK_ARG(0) }, 
	[SYS_SETSOCKOPT] =  { .action = EMULATE, .argc = 2, .sock_argc = 5, .fd_args = _SOCK_ARG(0) }, 
	[SYS_GETSOCKOPT] =  { .action = EMULATE, .argc = 2, .sock_argc = 5, .fd_args = _SOCK_ARG(0), .len_ptr = SOCK_ARG(4), .copy = sockopt_copy }, 
	[SYS_SENDMSG] =     { .action = EMULATE, .argc = 2, .sock_argc = 3, .fd_args = _SOCK_ARG(0) },
	[SYS_RECVMSG] =     { .action = EMULATE, .argc = 2, .sock_argc = 3, .fd_args = _SOCK_ARG(0), .msg_ptr = SOCK_ARG(1), .iov_ptr = PRE_MSG_IOV, .iov_cnt = PRE_MSG_IOVLEN, .copy = recvmsg_copy },
};

#define N_SYSCALLS \
(sizeof(syscall_info_array)/sizeof(syscall_info_array[0]))

#define N_SOCKETCALLS \
(sizeof(socketcall_info_array)/sizeof(socketcall_info_array[0]))

syscall_info_t *syscall_info(trace_t *t)
{
	long callno = t->syscall;

	if ( (callno < 0) || (callno >= N_SYSCALLS) )
		return &unknown_call_info;

	if ( callno == __NR_socketcall )
	{
		callno = get_syscall_arg(t, 0);
		if ( (callno < 0) || (callno >= N_SOCKETCALLS) )
			return &unknown_call_info;

		return &socketcall_info_array[callno];
	}

	return &syscall_info_array[callno];
}

