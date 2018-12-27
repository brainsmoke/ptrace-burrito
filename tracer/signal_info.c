
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

