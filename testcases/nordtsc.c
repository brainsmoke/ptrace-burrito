
#include <sys/personality.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <linux/prctl.h>

/* Get/set the process' ability to use the timestamp counter instruction */
#ifndef PR_GET_TSC
#define PR_GET_TSC 25
#define PR_SET_TSC 26
# define PR_TSC_ENABLE		1   /* allow the use of the timestamp counter */
# define PR_TSC_SIGSEGV		2   /* throw a SIGSEGV instead of reading the TSC */
#endif


int main(int argc, char **argv)
{
	if (argc < 2)
	{
		fprintf(stderr, "usage: %s <command> <args>...\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if ( prctl(PR_SET_TSC, PR_TSC_SIGSEGV) == -1)
	{
		perror("prctl");
		exit(EXIT_FAILURE);
	}

	execvp(argv[1], &argv[1]);
}

