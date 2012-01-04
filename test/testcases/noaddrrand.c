
#include <sys/personality.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int persona;

	if (argc < 2)
	{
		fprintf(stderr, "usage: %s <command> <args>...\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	persona = personality(0xffffffff);
	if ( personality(persona | ADDR_NO_RANDOMIZE) == -1)
	{
		perror("personality");
		exit(EXIT_FAILURE);
	}

	execvp(argv[1], &argv[1]);
}

