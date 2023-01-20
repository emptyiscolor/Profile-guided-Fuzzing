#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>


void __global_logging(unsigned long long id){

	char fd = '@';

	register int    syscall_no  asm("rax") = SYS_write;
	register int    arg1        asm("rdi") = 2;
	register char*  arg2        asm("rsi") = &fd;
	register int    arg3        asm("rdx") = 1;
	asm("syscall");

	register int    syscall_no1  asm("rax") = SYS_write;
	register int    arg11        asm("rdi") = 2;
	register char*  arg21        asm("rsi") = &id;
	register int    arg31        asm("rdx") = 8;
	asm("syscall");


	register int    syscall_no2  asm("rax") = SYS_write;
	register int    arg12        asm("rdi") = 2;
	register char*  arg22        asm("rsi") = &fd;
	register int    arg32        asm("rdx") = 1;
	asm("syscall");

}


