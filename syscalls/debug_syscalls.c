
#include <inttypes.h>

#include <linux/unistd.h>
#include <linux/net.h>

#include <signal.h>
#include <string.h>
#include <stdio.h>

#include "util.h"
#include "debug.h"
#include "debug_syscalls.h"
#include "syscall_info.h"

/* ripped from asm/unistd(_32).h */
static const char *syscall_names[] =
{
	[__NR_restart_syscall] = "restart_syscall",
	[__NR_exit] = "exit",
	[__NR_fork] = "fork",
	[__NR_read] = "read",
	[__NR_write] = "write",
	[__NR_open] = "open",
	[__NR_close] = "close",
	[__NR_waitpid] = "waitpid",
	[__NR_creat] = "creat",
	[__NR_link] = "link",
	[__NR_unlink] = "unlink",
	[__NR_execve] = "execve",
	[__NR_chdir] = "chdir",
	[__NR_time] = "time",
	[__NR_mknod] = "mknod",
	[__NR_chmod] = "chmod",
	[__NR_lchown] = "lchown",
	[__NR_break] = "break",
	[__NR_oldstat] = "oldstat",
	[__NR_lseek] = "lseek",
	[__NR_getpid] = "getpid",
	[__NR_mount] = "mount",
	[__NR_umount] = "umount",
	[__NR_setuid] = "setuid",
	[__NR_getuid] = "getuid",
	[__NR_stime] = "stime",
	[__NR_ptrace] = "ptrace",
	[__NR_alarm] = "alarm",
	[__NR_oldfstat] = "oldfstat",
	[__NR_pause] = "pause",
	[__NR_utime] = "utime",
	[__NR_stty] = "stty",
	[__NR_gtty] = "gtty",
	[__NR_access] = "access",
	[__NR_nice] = "nice",
	[__NR_ftime] = "ftime",
	[__NR_sync] = "sync",
	[__NR_kill] = "kill",
	[__NR_rename] = "rename",
	[__NR_mkdir] = "mkdir",
	[__NR_rmdir] = "rmdir",
	[__NR_dup] = "dup",
	[__NR_pipe] = "pipe",
	[__NR_times] = "times",
	[__NR_prof] = "prof",
	[__NR_brk] = "brk",
	[__NR_setgid] = "setgid",
	[__NR_getgid] = "getgid",
	[__NR_signal] = "signal",
	[__NR_geteuid] = "geteuid",
	[__NR_getegid] = "getegid",
	[__NR_acct] = "acct",
	[__NR_umount2] = "umount2",
	[__NR_lock] = "lock",
	[__NR_ioctl] = "ioctl",
	[__NR_fcntl] = "fcntl",
	[__NR_mpx] = "mpx",
	[__NR_setpgid] = "setpgid",
	[__NR_ulimit] = "ulimit",
	[__NR_oldolduname] = "oldolduname",
	[__NR_umask] = "umask",
	[__NR_chroot] = "chroot",
	[__NR_ustat] = "ustat",
	[__NR_dup2] = "dup2",
	[__NR_getppid] = "getppid",
	[__NR_getpgrp] = "getpgrp",
	[__NR_setsid] = "setsid",
	[__NR_sigaction] = "sigaction",
	[__NR_sgetmask] = "sgetmask",
	[__NR_ssetmask] = "ssetmask",
	[__NR_setreuid] = "setreuid",
	[__NR_setregid] = "setregid",
	[__NR_sigsuspend] = "sigsuspend",
	[__NR_sigpending] = "sigpending",
	[__NR_sethostname] = "sethostname",
	[__NR_setrlimit] = "setrlimit",
	[__NR_getrlimit] = "getrlimit",
	[__NR_getrusage] = "getrusage",
	[__NR_gettimeofday] = "gettimeofday",
	[__NR_settimeofday] = "settimeofday",
	[__NR_getgroups] = "getgroups",
	[__NR_setgroups] = "setgroups",
	[__NR_select] = "select",
	[__NR_symlink] = "symlink",
	[__NR_oldlstat] = "oldlstat",
	[__NR_readlink] = "readlink",
	[__NR_uselib] = "uselib",
	[__NR_swapon] = "swapon",
	[__NR_reboot] = "reboot",
	[__NR_readdir] = "readdir",
	[__NR_mmap] = "mmap",
	[__NR_munmap] = "munmap",
	[__NR_truncate] = "truncate",
	[__NR_ftruncate] = "ftruncate",
	[__NR_fchmod] = "fchmod",
	[__NR_fchown] = "fchown",
	[__NR_getpriority] = "getpriority",
	[__NR_setpriority] = "setpriority",
	[__NR_profil] = "profil",
	[__NR_statfs] = "statfs",
	[__NR_fstatfs] = "fstatfs",
	[__NR_ioperm] = "ioperm",
	[__NR_socketcall] = "socketcall",
	[__NR_syslog] = "syslog",
	[__NR_setitimer] = "setitimer",
	[__NR_getitimer] = "getitimer",
	[__NR_stat] = "stat",
	[__NR_lstat] = "lstat",
	[__NR_fstat] = "fstat",
	[__NR_olduname] = "olduname",
	[__NR_iopl] = "iopl",
	[__NR_vhangup] = "vhangup",
	[__NR_idle] = "idle",
	[__NR_vm86old] = "vm86old",
	[__NR_wait4] = "wait4",
	[__NR_swapoff] = "swapoff",
	[__NR_sysinfo] = "sysinfo",
	[__NR_ipc] = "ipc",
	[__NR_fsync] = "fsync",
	[__NR_sigreturn] = "sigreturn",
	[__NR_clone] = "clone",
	[__NR_setdomainname] = "setdomainname",
	[__NR_uname] = "uname",
	[__NR_modify_ldt] = "modify_ldt",
	[__NR_adjtimex] = "adjtimex",
	[__NR_mprotect] = "mprotect",
	[__NR_sigprocmask] = "sigprocmask",
	[__NR_create_module] = "create_module",
	[__NR_init_module] = "init_module",
	[__NR_delete_module] = "delete_module",
	[__NR_get_kernel_syms] = "get_kernel_syms",
	[__NR_quotactl] = "quotactl",
	[__NR_getpgid] = "getpgid",
	[__NR_fchdir] = "fchdir",
	[__NR_bdflush] = "bdflush",
	[__NR_sysfs] = "sysfs",
	[__NR_personality] = "personality",
	[__NR_afs_syscall] = "afs_syscall",
	[__NR_setfsuid] = "setfsuid",
	[__NR_setfsgid] = "setfsgid",
	[__NR__llseek] = "_llseek",
	[__NR_getdents] = "getdents",
	[__NR__newselect] = "_newselect",
	[__NR_flock] = "flock",
	[__NR_msync] = "msync",
	[__NR_readv] = "readv",
	[__NR_writev] = "writev",
	[__NR_getsid] = "getsid",
	[__NR_fdatasync] = "fdatasync",
	[__NR__sysctl] = "_sysctl",
	[__NR_mlock] = "mlock",
	[__NR_munlock] = "munlock",
	[__NR_mlockall] = "mlockall",
	[__NR_munlockall] = "munlockall",
	[__NR_sched_setparam] = "sched_setparam",
	[__NR_sched_getparam] = "sched_getparam",
	[__NR_sched_setscheduler] = "sched_setscheduler",
	[__NR_sched_getscheduler] = "sched_getscheduler",
	[__NR_sched_yield] = "sched_yield",
	[__NR_sched_get_priority_max] = "sched_get_priority_max",
	[__NR_sched_get_priority_min] = "sched_get_priority_min",
	[__NR_sched_rr_get_interval] = "sched_rr_get_interval",
	[__NR_nanosleep] = "nanosleep",
	[__NR_mremap] = "mremap",
	[__NR_setresuid] = "setresuid",
	[__NR_getresuid] = "getresuid",
	[__NR_vm86] = "vm86",
	[__NR_query_module] = "query_module",
	[__NR_poll] = "poll",
	[__NR_nfsservctl] = "nfsservctl",
	[__NR_setresgid] = "setresgid",
	[__NR_getresgid] = "getresgid",
	[__NR_prctl] = "prctl",
	[__NR_rt_sigreturn] = "rt_sigreturn",
	[__NR_rt_sigaction] = "rt_sigaction",
	[__NR_rt_sigprocmask] = "rt_sigprocmask",
	[__NR_rt_sigpending] = "rt_sigpending",
	[__NR_rt_sigtimedwait] = "rt_sigtimedwait",
	[__NR_rt_sigqueueinfo] = "rt_sigqueueinfo",
	[__NR_rt_sigsuspend] = "rt_sigsuspend",
	[__NR_pread64] = "pread64",
	[__NR_pwrite64] = "pwrite64",
	[__NR_chown] = "chown",
	[__NR_getcwd] = "getcwd",
	[__NR_capget] = "capget",
	[__NR_capset] = "capset",
	[__NR_sigaltstack] = "sigaltstack",
	[__NR_sendfile] = "sendfile",
	[__NR_getpmsg] = "getpmsg",
	[__NR_putpmsg] = "putpmsg",
	[__NR_vfork] = "vfork",
	[__NR_ugetrlimit] = "ugetrlimit",
	[__NR_mmap2] = "mmap2",
	[__NR_truncate64] = "truncate64",
	[__NR_ftruncate64] = "ftruncate64",
	[__NR_stat64] = "stat64",
	[__NR_lstat64] = "lstat64",
	[__NR_fstat64] = "fstat64",
	[__NR_lchown32] = "lchown32",
	[__NR_getuid32] = "getuid32",
	[__NR_getgid32] = "getgid32",
	[__NR_geteuid32] = "geteuid32",
	[__NR_getegid32] = "getegid32",
	[__NR_setreuid32] = "setreuid32",
	[__NR_setregid32] = "setregid32",
	[__NR_getgroups32] = "getgroups32",
	[__NR_setgroups32] = "setgroups32",
	[__NR_fchown32] = "fchown32",
	[__NR_setresuid32] = "setresuid32",
	[__NR_getresuid32] = "getresuid32",
	[__NR_setresgid32] = "setresgid32",
	[__NR_getresgid32] = "getresgid32",
	[__NR_chown32] = "chown32",
	[__NR_setuid32] = "setuid32",
	[__NR_setgid32] = "setgid32",
	[__NR_setfsuid32] = "setfsuid32",
	[__NR_setfsgid32] = "setfsgid32",
	[__NR_pivot_root] = "pivot_root",
	[__NR_mincore] = "mincore",
	[__NR_madvise] = "madvise",
	[__NR_madvise1] = "madvise1",
	[__NR_getdents64] = "getdents64",
	[__NR_fcntl64] = "fcntl64",
/* 223 is unused */
	[__NR_gettid] = "gettid",
	[__NR_readahead] = "readahead",
	[__NR_setxattr] = "setxattr",
	[__NR_lsetxattr] = "lsetxattr",
	[__NR_fsetxattr] = "fsetxattr",
	[__NR_getxattr] = "getxattr",
	[__NR_lgetxattr] = "lgetxattr",
	[__NR_fgetxattr] = "fgetxattr",
	[__NR_listxattr] = "listxattr",
	[__NR_llistxattr] = "llistxattr",
	[__NR_flistxattr] = "flistxattr",
	[__NR_removexattr] = "removexattr",
	[__NR_lremovexattr] = "lremovexattr",
	[__NR_fremovexattr] = "fremovexattr",
	[__NR_tkill] = "tkill",
	[__NR_sendfile64] = "sendfile64",
	[__NR_futex] = "futex",
	[__NR_sched_setaffinity] = "sched_setaffinity",
	[__NR_sched_getaffinity] = "sched_getaffinity",
	[__NR_set_thread_area] = "set_thread_area",
	[__NR_get_thread_area] = "get_thread_area",
	[__NR_io_setup] = "io_setup",
	[__NR_io_destroy] = "io_destroy",
	[__NR_io_getevents] = "io_getevents",
	[__NR_io_submit] = "io_submit",
	[__NR_io_cancel] = "io_cancel",
	[__NR_fadvise64] = "fadvise64",
/* 251 is available for reuse (was briefly sys_set_zone_reclaim) */
	[__NR_exit_group] = "exit_group",
	[__NR_lookup_dcookie] = "lookup_dcookie",
	[__NR_epoll_create] = "epoll_create",
	[__NR_epoll_ctl] = "epoll_ctl",
	[__NR_epoll_wait] = "epoll_wait",
	[__NR_remap_file_pages] = "remap_file_pages",
	[__NR_set_tid_address] = "set_tid_address",
	[__NR_timer_create] = "timer_create",
	[__NR_timer_settime] = "timer_settime",
	[__NR_timer_gettime] = "timer_gettime",
	[__NR_timer_getoverrun] = "timer_getoverrun",
	[__NR_timer_delete] = "timer_delete",
	[__NR_clock_settime] = "clock_settime",
	[__NR_clock_gettime] = "clock_gettime",
	[__NR_clock_getres] = "clock_getres",
	[__NR_clock_nanosleep] = "clock_nanosleep",
	[__NR_statfs64] = "statfs64",
	[__NR_fstatfs64] = "fstatfs64",
	[__NR_tgkill] = "tgkill",
	[__NR_utimes] = "utimes",
	[__NR_fadvise64_64] = "fadvise64_64",
	[__NR_vserver] = "vserver",
	[__NR_mbind] = "mbind",
	[__NR_get_mempolicy] = "get_mempolicy",
	[__NR_set_mempolicy] = "set_mempolicy",
	[__NR_mq_open] = "mq_open",
	[__NR_mq_unlink] = "mq_unlink",
	[__NR_mq_timedsend] = "mq_timedsend",
	[__NR_mq_timedreceive] = "mq_timedreceive",
	[__NR_mq_notify] = "mq_notify",
	[__NR_mq_getsetattr] = "mq_getsetattr",
	[__NR_kexec_load] = "kexec_load",
	[__NR_waitid] = "waitid",
/* #define __NR_sys_setaltroot	285 */
	[__NR_add_key] = "add_key",
	[__NR_request_key] = "request_key",
	[__NR_keyctl] = "keyctl",
	[__NR_ioprio_set] = "ioprio_set",
	[__NR_ioprio_get] = "ioprio_get",
	[__NR_inotify_init] = "inotify_init",
	[__NR_inotify_add_watch] = "inotify_add_watch",
	[__NR_inotify_rm_watch] = "inotify_rm_watch",
	[__NR_migrate_pages] = "migrate_pages",
	[__NR_openat] = "openat",
	[__NR_mkdirat] = "mkdirat",
	[__NR_mknodat] = "mknodat",
	[__NR_fchownat] = "fchownat",
	[__NR_futimesat] = "futimesat",
	[__NR_fstatat64] = "fstatat64",
	[__NR_unlinkat] = "unlinkat",
	[__NR_renameat] = "renameat",
	[__NR_linkat] = "linkat",
	[__NR_symlinkat] = "symlinkat",
	[__NR_readlinkat] = "readlinkat",
	[__NR_fchmodat] = "fchmodat",
	[__NR_faccessat] = "faccessat",
	[__NR_pselect6] = "pselect6",
	[__NR_ppoll] = "ppoll",
	[__NR_unshare] = "unshare",
	[__NR_set_robust_list] = "set_robust_list",
	[__NR_get_robust_list] = "get_robust_list",
	[__NR_splice] = "splice",
	[__NR_sync_file_range] = "sync_file_range",
	[__NR_tee] = "tee",
	[__NR_vmsplice] = "vmsplice",
	[__NR_move_pages] = "move_pages",
	[__NR_getcpu] = "getcpu",
	[__NR_epoll_pwait] = "epoll_pwait",
	[__NR_utimensat] = "utimensat",
	[__NR_signalfd] = "signalfd",
	[__NR_timerfd_create] = "timerfd_create",
	[__NR_eventfd] = "eventfd",
	[__NR_fallocate] = "fallocate",
	[__NR_timerfd_settime] = "timerfd_settime",
	[__NR_timerfd_gettime] = "timerfd_gettime",
};
#define N_SYSCALLS (sizeof(syscall_names)/sizeof(syscall_names[0]))

const char *syscall_name(long no)
{
	if ( no == -1 )
		return "-1";

	if ( (no < N_SYSCALLS) || (syscall_names[no]) )
		return syscall_names[no];

	return "UNKNOWN SYSCALL";
}

static const char *socketcall_names[] =
{
	[SYS_SOCKET] = "socket",
	[SYS_BIND] = "bind",
	[SYS_CONNECT] = "connect",
	[SYS_LISTEN] = "listen",
	[SYS_ACCEPT] = "accept",
	[SYS_GETSOCKNAME] = "getsockname",
	[SYS_GETPEERNAME] = "getpeername",
	[SYS_SOCKETPAIR] = "socketpair",
	[SYS_SEND] = "send",
	[SYS_RECV] = "recv",
	[SYS_SENDTO] = "sendto",
	[SYS_RECVFROM] = "recvfrom",
	[SYS_SHUTDOWN] = "shutdown",
	[SYS_SETSOCKOPT] = "setsockopt",
	[SYS_GETSOCKOPT] = "getsockopt",
	[SYS_SENDMSG] = "sendmsg",
	[SYS_RECVMSG] = "recvmsg",
};
#define N_SOCKETCALLS (sizeof(socketcall_names)/sizeof(socketcall_names[0]))

const char *socketcall_name(long no)
{
	if ( ( no >= 0 ) && ( no < N_SOCKETCALLS ) && ( socketcall_names[no] ) )
		return socketcall_names[no];

	return "UNKNOWN SOCKETCALL";
}

static const char *signal_names[32] =
{
	[0] = "[ no signal ]",
	[SIGHUP] = "SIGHUP",
	[SIGINT] = "SIGINT",
	[SIGQUIT] = "SIGQUIT",
	[SIGILL] = "SIGILL",
	[SIGTRAP] = "SIGTRAP",
	[SIGABRT] = "SIGABRT",
	[SIGBUS] = "SIGBUS",
	[SIGFPE] = "SIGFPE",
	[SIGKILL] = "SIGKILL",
	[SIGUSR1] = "SIGUSR1",
	[SIGSEGV] = "SIGSEGV",
	[SIGUSR2] = "SIGUSR2",
	[SIGPIPE] = "SIGPIPE",
	[SIGALRM] = "SIGALRM",
	[SIGTERM] = "SIGTERM",
	[SIGSTKFLT] = "SIGSTKFLT",
	[SIGCHLD] = "SIGCHLD",
	[SIGCONT] = "SIGCONT",
	[SIGSTOP] = "SIGSTOP",
	[SIGTSTP] = "SIGTSTP",
	[SIGTTIN] = "SIGTTIN",
	[SIGTTOU] = "SIGTTOU",
	[SIGURG] = "SIGURG",
	[SIGXCPU] = "SIGXCPU",
	[SIGXFSZ] = "SIGXFSZ",
	[SIGVTALRM] = "SIGVTALRM",
	[SIGPROF] = "SIGPROF",
	[SIGWINCH] = "SIGWINCH",
	[SIGIO] = "SIGIO",
	[SIGPWR] = "SIGPWR",
	[SIGSYS] = "SIGSYS",
};

const char *signal_name(int no)
{
	if ( (no < 0) || (no >= 32) || (signal_names[no] == NULL) )
		return "UNKNOWN SIGNAL";

	return signal_names[no];
}

int signal_no(const char *name)
{
	int i;
	for (i=0; i<32; i++)
		if (signal_names[i] && strcmp(name, signal_names[i]) == 0)
			return i;

	return -1;
}

static const char *hi = "\033[0;34m", *color = "\033[0;31m", *reset = "\033[m";

void print_flags(int flags)
{
	FILE *out = debug_out();

	const struct
	{
		int number;
		char *name;
	}
	flagnames[] =
	{
		{ FAIL,        "FAIL"        },
		{ PASS,        "PASS"        },
/*		{ EMULATE,     "EMULATE"     }, */
		{ COPY_RESULT, "COPY_RESULT" },
	};

	int i;

	for (i=0; i<sizeof(flagnames)/sizeof(*flagnames); i++)
		if ( (flagnames[i].number & flags) || (flagnames[i].number == flags) )
			fprintf(out, "%s%s%s ", color, flagnames[i].name, reset);
}

void print_args(long *args, int argc)
{
	FILE *out = debug_out();
	int i;

	fprintf(out, " (");

	if (argc)
		fprintf(out, " %ld", args[0]);

	for (i=1; i<argc; i++)
		fprintf(out, ", %ld", args[i]);
	
	fprintf(out, " )");
}

void print_call_name(long call)
{
	FILE *out = debug_out();
	fprintf(out, "%s%s%s", hi, syscall_name(call), reset);
}

void print_socketcall_name(long call)
{
	FILE *out = debug_out();
	fprintf(out, "%s%s%s", hi, socketcall_name(call), reset);
}

void print_call(long call, long args[], int argc)
{
	print_call_name(call);
	print_args(args, argc);
}

void print_trace_call(trace_t *t)
{
	FILE *out = debug_out();
	syscall_info_t *info = syscall_info(t);
	long args[info->argc];
	get_args(t, args, info->argc);

	print_call(get_syscall(t), args, info->argc);

	if ( get_syscall(t) == __NR_socketcall )
	{
		fprintf(out, " => ");
		print_socketcall_name(get_arg(t, 0));
	}
	fprintf(out, "\n");
}

void print_trace_return(trace_t *t)
{
	FILE *out = debug_out();
	fprintf(out, "%sreturn%s %ld;\n", hi, reset, get_result(t));
}

