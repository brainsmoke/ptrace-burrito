
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void sigpipe_cb(int sig)
{
	int n = 10+1;
	write(1, "sigpipe_cb\n", n);
	signal(SIGPIPE, NULL);
}

int main(int argc, char **argv)
{
	int filedes[2];
	signal(SIGPIPE, sigpipe_cb);
	pipe(filedes);
	close(filedes[0]);
	write(filedes[1], "SIGPIPE\n", 8);
	write(1, "recovered from sigpipe\n", 23);
	write(filedes[1], "SIGPIPE\n", 8);
	close(filedes[1]);
}
