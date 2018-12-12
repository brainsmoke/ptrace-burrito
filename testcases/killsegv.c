
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>

#include <sys/time.h>
#include <time.h>
#include <wait.h>


/* bogus loop
 *
 */
long long i;
void do_loop(long long count)
{
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
	gettimeofday(&tv1, NULL);
	do_loop(count);
	gettimeofday(&tv2, NULL);
	dur = (tv2.tv_sec-tv1.tv_sec)*1000000+(tv2.tv_usec-tv1.tv_usec);
	return dur;
}

long long get_min_duration(long long dur)
{
	long long count = 1;
	while ( time_loop(count) < dur )
		count *= 2;

	return count;
}

long long j;
void sigsegv_cb(int sig)
{
	j=i;
}

int main(int argc, char **argv)
{
	long long count = get_min_duration(150000);
	signal(SIGSEGV, sigsegv_cb);
	pid_t pid = fork();

	if (pid)
	{
		do_loop(count);
		kill(pid, SIGSEGV);
		wait(NULL);
	}
	else
	{
		do_loop(count * 2);
		printf("%lld\n", j);
	}
}

