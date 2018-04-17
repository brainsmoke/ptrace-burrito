
#include <linux/unistd.h>

#include <signal.h>
#include <errno.h>

#include "signal_info.h"

int is_synchronous(siginfo_t *info)
{
	switch (info->si_signo)
	{
		case SIGILL:
		case SIGTRAP:
		case SIGABRT:
		case SIGBUS:
		case SIGFPE:
		case SIGSEGV:
		case SIGSTKFLT:
			if ( info->si_code != SI_KERNEL && info->si_code > 0 )
				return 1;
		default:
			return 0;
	}
}

int signal_restartsys(long syscall, long retval)
{
	return (retval <= -ERESTARTSYS) &&
	       (retval >= -ERESTART_RESTARTBLOCK);
}

int signal_pending(long syscall, long retval)
{
	return signal_restartsys(syscall, retval) ||
#ifdef __NR_sigreturn
	       ( (retval == -EPIPE) && (syscall != __NR_sigreturn) ) ||
#endif
	       ( (retval == -EPIPE) && (syscall != __NR_rt_sigreturn) ) ||
#ifdef __NR_sigreturn
	       (syscall == __NR_sigprocmask) ||
#endif
	       (syscall == __NR_rt_sigprocmask);
}

