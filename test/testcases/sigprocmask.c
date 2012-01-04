/*
 * trigger and catch a signal while not inside a syscall
 */

#include <sys/mman.h>
#include <sys/time.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <wait.h>
#include <time.h>

/* bogus loop
 *
 */
void do_loop(long long count)
{
	long long i;
	int a = 1, b = 1, c;
	for (i=0; i<count; i++)
	{
		c = b + a;
		a = b;
		b = c;
	}
}

long long time_loop(long long count)
{
	struct timeval tv1, tv2;
	long long dur;
	printf("count = %lld, ", count);
	gettimeofday(&tv1, NULL);
	do_loop(count);
	gettimeofday(&tv2, NULL);
	dur = (tv2.tv_sec-tv1.tv_sec)*1000000+(tv2.tv_usec-tv1.tv_usec);
	printf("duration = %lld usec\n", dur);
	return dur;
}

long long get_min_duration(long long dur)
{
	long long count = 1;
	while ( time_loop(count) < dur )
		count *= 2;

	return count;
}

void sigalrm_cb(int sig)
{
	write(1, "sigalrm_cb\n", 11);
}

void sigchld_cb(int sig)
{
	write(1, "sigchld_cb\n", 11);
}

int main(int argc, char **argv)
{
	int i, block = 1;
	long long count = get_min_duration(1500000);
	sigset_t old, new;
	sigemptyset(&new);
	sigemptyset(&old);

	for (argv++; *argv; argv++)
		if ( strcmp("-noblock", *argv) != 0 )
			block = 0;

	if ( block )
	{
		sigaddset(&new, SIGCHLD);
		sigaddset(&new, SIGALRM);
	}

	signal(SIGALRM, sigalrm_cb);
	signal(SIGCHLD, sigchld_cb);

	printf("alarm first\n");

	sigprocmask(SIG_BLOCK, &new, &old);

	alarm(1);
	do_loop(count);
	printf("done counting\n");

	for (i=0; i<100; i++) if (!fork()) exit(EXIT_SUCCESS);
	for (i=0; i<100; i++) wait(NULL);

	sigprocmask(SIG_UNBLOCK, &new, &old);

	printf("forks first\n");

	sigprocmask(SIG_BLOCK, &new, &old);

	for (i=0; i<100; i++) if (!fork()) exit(EXIT_SUCCESS);
	for (i=0; i<100; i++) wait(NULL);

	alarm(1);
	do_loop(count);
	printf("done counting\n");

	sigprocmask(SIG_UNBLOCK, &new, &old);
}

