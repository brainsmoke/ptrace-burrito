
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
	int fd;

	if ( (fd=open("./junk", O_RDONLY|O_TRUNC)) < 0)
	{
		perror("open");
		exit(EXIT_FAILURE);
	}

	write(fd, "bla\n", 4);
}

