
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>

#include <sys/time.h>
#include <time.h>

uint64_t timestamp(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec*1000000+tv.tv_usec;
}

uint64_t rdtsc(void)
{
	uint32_t lo, hi;
	/* We cannot use "=A", since this would use %rax on x86_64 */
	__asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
	return (uint64_t)hi << 32 | lo;
}

void sigalrm(int x)
{
	/* */
}

int main(int argc, char **argv)
{
	signal(SIGALRM, sigalrm);
	uint64_t timestamp1, timestamp2, rdtsc1, rdtsc2;
	timestamp1 = timestamp();
	rdtsc1 = rdtsc();
	alarm(1);
	pause();
	timestamp2 = timestamp();
	rdtsc2 = rdtsc();
	printf("timestamp diff = %llu\n",
		(unsigned long long)timestamp2-timestamp1);
	printf("rdtsc diff = %llu\n",
		(unsigned long long)rdtsc2-rdtsc1);
}
