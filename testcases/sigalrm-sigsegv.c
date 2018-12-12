
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

static int filedes[2];

int segv;

void sigalrm_cb(int sig)
{
	segv = *(int *)0x12345678;
	
	write(filedes[1], "SIGALRM\n", 8);
}

int main(int argc, char **argv)
{
	char buf[8];
	alarm(1);
	signal(SIGALRM, sigalrm_cb);
	pipe(filedes);
	read(filedes[0], buf, 8);
	write(1, buf, 8);
	close(filedes[0]);
	close(filedes[1]);
}
