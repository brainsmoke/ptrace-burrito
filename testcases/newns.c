
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <linux/sched.h>

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		fprintf(stderr, "usage: %s <command> <args>...\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if ( unshare(CLONE_NEWNS) == -1)
	{
		perror("unshare");
		exit(EXIT_FAILURE);
	}

	execvp(argv[1], &argv[1]);
}

