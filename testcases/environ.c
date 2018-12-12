
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

extern char **environ;

int execvpe(char *filename, char *argv[], char *envp[])
{
	char **tmp = environ;
	int err;
	environ = envp;
	err = execvp(filename, argv);
	environ = tmp;
	return err;
}

int main(int argc, char **argv)
{
	char *myenv[] = { "TESTSUCCESS=yes", NULL };

	if (getenv("TESTSUCCESS"))
	{
		printf("TESTSUCCESS=%s\n", getenv("TESTSUCCESS"));
	}
	else
	{
		setenv("TESTSUCCESS", "no", 1);
		execvpe(argv[0], argv, myenv);
	}

	exit(EXIT_SUCCESS);
}

