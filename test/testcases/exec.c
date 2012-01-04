
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	printf("%s\n", argv[argc-1]);
	argv[argc-1] = NULL;

	if (argv[0])
		execvp(argv[0], argv);

	exit(EXIT_SUCCESS);
}

