
#include <sys/time.h>
#include <sys/resource.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

/* changes the given filedescriptor to be the highest possible */
int high_fd(int fd)
{
	struct rlimit lim, hard_lim;
	int newfd, i;

	getrlimit(RLIMIT_NOFILE, &lim);
	hard_lim.rlim_cur = hard_lim.rlim_max = lim.rlim_max;
	setrlimit(RLIMIT_NOFILE, &hard_lim);

	for (i=lim.rlim_max-1; fd < i; i--)
		if ( (newfd = fcntl(fd, F_DUPFD, i)) > -1)
		{
			close(fd);

			fd = newfd;

			if (lim.rlim_cur > fd)
				lim.rlim_cur = fd;

			break;
		}

	setrlimit(RLIMIT_NOFILE, &lim);

	return fd;
}

int main(int argc, char **argv)
{
	struct rlimit lim;
	char var[11]; memcpy(var, "EPIC FAIL\n", 11);
	int tochild[2], fromchild[2];

	if ( pipe(tochild) < 0 )
		perror("pipe");
	if ( pipe(fromchild) < 0 )
		perror("pipe");

	fromchild[1] = high_fd(fromchild[1]);
	tochild[0] = high_fd(tochild[0]);

	printf("high file descriptor: %d\n", fromchild[1]);
	printf("high file descriptor: %d\n", tochild[0]);

	getrlimit(RLIMIT_NOFILE, &lim);
	printf("Soft limit: %ld\n", lim.rlim_cur);
	printf("Hard limit: %ld\n", lim.rlim_max);

	if ( fork() )
	{
		if (write(tochild[1], "EPIC WIN!\n", 10) < 0)
			perror("write (tochild[1])");
		if ( read(fromchild[0], var, 10) < 0 )
			perror("read (fromchild[0])");
		if ( write(1, var, 10) < 0 )
			perror("write");
	}
	else
	{
		if ( read(tochild[0], var, 10) < 0 )
			perror("read (fromchild[0])");
		if (write(fromchild[1], var, 10) < 0)
			perror("write (fromchild[1])");
	}
}

