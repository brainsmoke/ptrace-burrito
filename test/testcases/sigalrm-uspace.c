
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>

#include <sys/time.h>
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
	write(1, "SIGALRM\n", 8);
}

int main(int argc, char **argv)
{
	long long count = get_min_duration(1500000);
	alarm(1);
	signal(SIGALRM, sigalrm_cb);
	do_loop(count);
	write(1, "done counting\n", 14);
}
