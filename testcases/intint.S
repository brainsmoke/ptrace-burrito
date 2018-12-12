#ifdef __i386__

	.file	"intint.S"
	.section .rodata
.msg:
	.string "write returns getpid\n"
	.text
.globl _start
	.type	_start, @function
_start:
	movl    $4,    %eax
	movl    $1,    %ebx
	movl    $.msg, %ecx
	movl    $20,   %edx
	int     $0x80
	int     $0x80
	movl    $4,    %eax
	movl    $.msg+20, %ecx
	movl    $1,    %edx
	int     $0x80
	int     $0x80
	.size	_start, .-_start
	.ident	"test"

#elif defined(__amd64__)

	.file	"intint.S"
	.section .rodata
.msg:
	.string "write returns getpid on amd64 as well!\n"
	.text
.globl _start
	.type	_start, @function
_start:
	movq    $1,    %rax
	movq    $1,    %rdi
	movq    $.msg, %rsi
	movq    $39,   %rdx
	syscall
	syscall
	movq    $60,   %rax
	syscall
	.size	_start, .-_start
	.ident	"test"


#endif
