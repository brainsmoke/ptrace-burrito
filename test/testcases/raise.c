
#include "../../syscalls/debug_syscalls.c"

#include <stdlib.h>

int main(int argc, char **argv)
{
	int sig = signal_no(argv[1]);
	if (sig < 0)
		sig = atoi(argv[1]);
	raise(sig);
}
