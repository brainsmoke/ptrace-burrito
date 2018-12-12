CC=gcc
LINK=gcc

LDFLAGS=
#LDFLAGS=-static
#CFLAGS=-Wall -Wshadow -pedantic -std=gnu99 -I. -g
CFLAGS=-Wall -Wshadow -pedantic -std=gnu99 -Os
STRIP=strip --strip-all

TEST_TARGETS=\
	test/testcases/getppid\
	test/testcases/hello_world\
	test/testcases/pidgallore\
	test/testcases/sigalrm\
	test/testcases/sigpipe\
	test/testcases/sigsegv\
	test/testcases/sigalrm-sysv\
	test/testcases/highfd\
	test/testcases/noaddrrand\
	test/testcases/rdtsc\
	test/testcases/fork\
	test/testcases/exec\
	test/testcases/abort\
	test/testcases/sigalrm-uspace\
	test/testcases/sigalrm-sigsegv\
	test/testcases/nordtsc\
	test/testcases/timestamps\
	test/testcases/sigchld\
	test/testcases/sigprocmask\
	test/testcases/killsegv\
	test/testcases/fstat\
	test/testcases/rdtrunc
#	test/testcases/environ\
#	test/testcases/newfs\
#	test/testcases/newns\
#	test/testcases/sysall\
#	test/testcases/raise\
#	test/testcases/intint\

TARGETS=$(TEST_TARGETS)\
	test/bdiff\
	test/tracer/writeecho\
	test/tracer/faketsc\
	test/syscalls/nosignals\
	test/maps/codecov\
	test/syscalls/printregs

TRACER_OBJECTS=\
	tracer/dataset.o\
	tracer/debug.o\
	tracer/errors.o\
	tracer/signal_info.o\
	tracer/signal_queue.o\
	tracer/trace.o\
	tracer/trace_map.o\
	tracer/util.o\
	tracer/process.o

SYSCALLS_OBJECTS=\
	syscalls/debug_syscalls.o\
	syscalls/debug_wrap.o
#	syscalls/syscall_info.o\

MAPS_OBJECTS=\
	maps/maps.o

OBJECTS=$(TRACER_OBJECTS) $(SYSCALLS_OBJECTS)

CLEAN=$(TARGETS) $(OBJECTS)

.PHONY: depend clean strip

all: $(TARGETS)

strip: $(TARGETS)
	$(STRIP) --strip-all $^

$(OBJECTS): depend

tracer/%.o: tracer/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

maps/%.o: maps/%.c
	$(CC) $(CFLAGS) -Isyscalls -Itracer -c -o $@ $<

syscalls/%.o: syscalls/%.c
	$(CC) $(CFLAGS) -Itracer -c -o $@ $<

test/maps/%.o: test/maps/%.c
	$(CC) $(CFLAGS) -Imaps -Isyscalls -Itracer -c -o $@ $<

test/syscalls/%.o: test/syscalls/%.c
	$(CC) $(CFLAGS) -Isyscalls -Itracer -c -o $@ $<

test/%.o: test/%.c
	$(CC) $(CFLAGS) -Itracer -c -o $@ $<

test/testcases/%: test/testcases/%.c
	$(CC) $(CFLAGS) -o $@ $<

test/testcases/intint: test/testcases/intint.S
	$(CC) -nostdlib -o $@ $<

test/syscalls/%: test/syscalls/%.o $(TRACER_OBJECTS) $(SYSCALLS_OBJECTS)
	$(LINK) -o $@ $^ $(LDFLAGS)

test/maps/%: test/maps/%.o $(TRACER_OBJECTS) $(SYSCALLS_OBJECTS) $(MAPS_OBJECTS)
	$(LINK) -o $@ $^ $(LDFLAGS)

test/%: test/%.o $(TRACER_OBJECTS)
	$(LINK) -o $@ $^ $(LDFLAGS)

depend:
	#makedepend -- -Y. -- *.c test/*.c 2>/dev/null

clean:
	-rm $(CLEAN)
	makedepend -- -Y. -- 2>/dev/null
	-rm Makefile.bak

# DO NOT DELETE
