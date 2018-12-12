
#include <fcntl.h>

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <errors.h>

#include "debug.h"

void bdiff(int fd1, int fd2, int grane)
{
	int r1=1, r2=1, chunk=grane*16;
	char buf1[chunk], buf2[chunk];

	while ( r1>0 || r2>0 )
	{
		if ( r1>0 )
			r1=read(fd1, buf1, chunk);

		if ( r2>0 )
			r2=read(fd2, buf2, chunk);

		printhex_diff(buf1, r1, buf2, r2, grane);
	}
}

int main(int argc, char **argv)
{
	if (argc != 4)
	{
		fprintf(stderr, "usage: %s <grane> <file1> <file2>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	int fd[2], i, grane = atoi(argv[1]); if (grane==0) grane=1;

	debug_init(stdout);

	for (i=0; i<2; i++)
		if ( strcmp(argv[i+2], "-") == 0)
			fd[i] = 0;
		else if ( (fd[i] = open(argv[i+2], O_RDONLY)) == -1 )
			fatal_error("open: %s", strerror(errno));

	bdiff(fd[0], fd[1], grane);

	close(fd[0]); close(fd[1]);

	exit(EXIT_SUCCESS);
}
