
#define _GNU_SOURCE /* for syscall(...) */
#include <linux/unistd.h>

#include <sys/resource.h>
#include <sys/uio.h>

#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wait.h>

#define beefeaten(...) _beefeaten(__func__, __VA_ARGS__, NULL)
void _beefeaten(const char *msg, ...)
{
	va_list ap;
	char *beef;
	va_start(ap, msg);

	while ( (beef = va_arg(ap, char *)) != NULL )
	{
		if ( bcmp(beef, "\xDE\xAD\xBE\xEF", 4) != 0 )
		{
			printf("%s: beef got eaten\n", msg);
			fflush(stdout);
		}
	}

	va_end(ap);
}

#define setbeef(...) _setbeef(__func__, __VA_ARGS__, NULL)
void _setbeef(const char *msg, ...)
{
	va_list ap;
	char *beef;
	va_start(ap, msg);

	while ( (beef = va_arg(ap, char *)) != NULL )
		memcpy(beef, "\xDE\xAD\xBE\xEF", 4);

	va_end(ap);
}

void print_timeval(struct timeval *tv)
{
	printf("{ tv_sec = %ld, tv_usec = %ld }\n", tv->tv_sec, tv->tv_usec);
	fflush(stdout);
}

void print_rusage(struct rusage *u)
{
	printf("struct rusage {\n");
	printf("\tstruct timeval ru_utime = "); print_timeval(&u->ru_utime);
	printf("\tstruct timeval ru_stime = "); print_timeval(&u->ru_stime);
	printf("\tlong   ru_maxrss        = %ld\n", u->ru_maxrss );
	printf("\tlong   ru_ixrss         = %ld\n", u->ru_ixrss );
	printf("\tlong   ru_idrss         = %ld\n", u->ru_idrss );
	printf("\tlong   ru_isrss         = %ld\n", u->ru_isrss );
	printf("\tlong   ru_minflt        = %ld\n", u->ru_minflt );
	printf("\tlong   ru_majflt        = %ld\n", u->ru_majflt );
	printf("\tlong   ru_nswap         = %ld\n", u->ru_nswap );
	printf("\tlong   ru_inblock       = %ld\n", u->ru_inblock );
	printf("\tlong   ru_oublock       = %ld\n", u->ru_oublock );
	printf("\tlong   ru_msgsnd        = %ld\n", u->ru_msgsnd );
	printf("\tlong   ru_msgrcv        = %ld\n", u->ru_msgrcv );
	printf("\tlong   ru_nsignals      = %ld\n", u->ru_nsignals );
	printf("\tlong   ru_nvcsw         = %ld\n", u->ru_nvcsw );
	printf("\tlong   ru_nivcsw        = %ld\n", u->ru_nivcsw );
	printf("}\n");fflush(stdout);
}


char *s1 = "test_read_write_one\n", *s2 = "test_read_write_two\n";

void test_read_write(void)
{
								char a[4];
	int status;
								char b[4];
	char r1[strlen(s1)+1];
								char c[4];
	char r2[strlen(s2)+1];
								char d[4];
	int pipe1[2];
								char e[4];
	int pipe2[2];
								char f[4];

	setbeef(a,b,c,d,e,f);

	r1[strlen(s1)]='\0'; r2[strlen(s2)]='\0';

	pipe(pipe1); pipe(pipe2);

	if (fork())
	{
		write(pipe1[1], s1, strlen(s1));
		read(pipe2[0], r2, strlen(s2));
		if ( strcmp(r2, s2) != 0 )
			write(1, "ERROR\n", 6);

		write(1, r2, strlen(s2));

		close(pipe1[0]); close(pipe1[1]); close(pipe2[0]); close(pipe2[1]);

		waitpid(-1, &status, 0);

		printf("status: %d\n", status);fflush(stdout);

		beefeaten(a,b,c,d,e,f);
	}
	else
	{
		read(pipe1[0], r1, strlen(s1));
		write(pipe2[1], s2, strlen(s2));
		if ( strcmp(r1, s1) != 0 )
			write(1, "ERROR\n", 6);

		write(1, r1, strlen(s1));

		beefeaten(a,b,c,d,e,f);
		exit(0);
	}
}

void test_readv_writev(void)
{
													char a[4];
	int filedes[2];
													char b[4];
	int status;
													char c[4];
	char w1[4] = { 'A', 'B', 'C', 'D' };
													char d[4];
	char w2[6] = { 'e', 'f', 'g', 'h', 'i', 'j' };
													char e[4];
	char w3[3] = { 'K', 'L', '\n' };
													char f[4];
	char r1[5];
													char g[4];
	char r2[2];
													char h[4];
	char r3[6];
													char i[4];
	struct iovec iov_w[3] = { { w1, 4 }, { w2, 6 }, { w3, 3 } };
													char j[4];
	struct iovec iov_r[3] = { { r1, 5 }, { r2, 2 }, { r3, 6 } };
													char k[4];
	char *cmp = "ABCDefghijKL\n";

	setbeef(a,b,c,d,e,f,g,h,i,j,k);

	pipe(filedes);
	if (fork())
	{
		readv(filedes[0], iov_r, 3);
		writev(1, iov_r, 3);
		write(1, cmp, 13);
		close(filedes[0]); close(filedes[1]);
		waitpid(-1, &status, 0);
		printf("status: %d\n", status);fflush(stdout);
		beefeaten(a,b,c,d,e,f,g,h,i,j,k);
	}
	else
	{
		writev(filedes[1], iov_w, 3);
		beefeaten(a,b,c,d,e,f,g,h,i,j,k);
		exit(0);
	}
}

void test_wait(void)
{
	char a[4];
	struct rusage usage;
	char b[4];
	int status;
	char c[4];

	setbeef(a,b,c);

	if ( fork() == 0 )
	{
#ifdef __NR_waitpid
		if ( fork() == 0 )
		{
			exit(0);
		}
		syscall(__NR_waitpid, -1, &status, 0);
		printf("status: %d\n", status);fflush(stdout);
#endif
		exit(0);
	}
	syscall(__NR_wait4, -1, &status, 0, &usage);

	print_rusage(&usage);

	beefeaten(a,b,c);
}

int main(int argc, char **argv)
{
	
	test_read_write();
	test_readv_writev();
	test_wait();

	exit(0);
}

