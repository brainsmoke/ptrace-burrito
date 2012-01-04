
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

static int filedes[2];

void sigalrm_cb(int sig)
{
	write(filedes[1], "SIGALRM\n", 8);
}

int main(int argc, char **argv)
{
	char buf[8];
	memcpy(buf, "notread\n", 8);
	siginterrupt(SIGALRM, 1);
	alarm(1);
	signal(SIGALRM, sigalrm_cb);
	pipe(filedes);
	read(filedes[0], buf, 8);
	write(1, buf, 8);
	close(filedes[0]);
	close(filedes[1]);
}
