#define _XOPEN_SOURCE (500)

#include <stdio.h>
#include <unistd.h>

int main()
{
	printf("pid: %d\n", getpid());
	printf("ppid: %d\n", getppid());
	printf("pgid: %d\n", getpgid(getpid()));
}


