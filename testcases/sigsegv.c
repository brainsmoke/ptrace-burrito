/*
 * trigger and catch a signal while not inside a syscall
 */

#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void sigsegv_cb(int sig)
{
	int n = 10+1;
	write(1, "sigsegv_cb\n", n);
	signal(SIGSEGV, NULL);

}

int main(int argc, char **argv)
{
	signal(SIGSEGV, sigsegv_cb);
	int a = *(int *)(0x12345678); /* SEGV */
	exit(a);
}

