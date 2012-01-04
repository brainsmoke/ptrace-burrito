#ifndef SIGNAL_INFO_H
#define SIGNAL_INFO_H

#include <signal.h>

/* The 'signal number' for not delivering a signal */
#define NO_SIGNAL (0)

#define ERESTARTSYS (512)
#define ERESTART_RESTARTBLOCK (516)

int is_synchronous(siginfo_t *info);

int signal_pending(long syscall, long retval);
int signal_restartsys(long syscall, long retval);

#endif /* SIGNAL_INFO_H */
