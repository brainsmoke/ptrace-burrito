
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	printf("%d %d\n", fork(), getpid());
	printf("%d %d\n", fork(), getpid());
	exit(EXIT_SUCCESS);
}

