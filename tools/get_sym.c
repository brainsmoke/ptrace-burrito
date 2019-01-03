
#include <stdio.h>
#include <stdlib.h>

#include "symbols.h"

int main(int argc, char *argv[])
{
	if (argc > 1)
	{
		uintptr_t offset;
		const char *libname = get_symbol(argv[1], &offset);
	
		if (libname)
		{
			printf("%s %lx\n", libname, (unsigned long)offset);
			exit(EXIT_SUCCESS);
		}
	}
	exit(EXIT_FAILURE);
}
