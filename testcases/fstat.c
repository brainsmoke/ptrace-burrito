#include <stdio.h>
#include <error.h>
#include <sys/types.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
	struct stat stat;

	if ( fstat(0, &stat) < 0)
		perror("fstat: ");

	printf("st_dev = %lx, st_rdev = %lx\n", (unsigned long)stat.st_dev,
	                                        (unsigned long)stat.st_rdev);
}
