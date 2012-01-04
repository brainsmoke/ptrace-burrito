/*
 * trigger and catch a signal while not inside a syscall
 */

#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <wait.h>

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

void sigchld_cb(int sig)
{
	write(1, "sigchld_cb\n", 11);
	do_loop(10000000);
}

int main(int argc, char **argv)
{
	signal(SIGCHLD, sigchld_cb);
	int i;
	for (i=0; i<10; i++)
		if (!fork())
		{
			do_loop(1000000);
			exit(0);
		}

	for (i=0; i<10; i++)
		wait(NULL);
}
