#define _GNU_SOURCE
       #include <unistd.h>
       #include <sys/syscall.h>
       #include <sys/types.h>
       #include <signal.h>

       int
       main(int argc, char *argv[])
       {
           pid_t tid;

	   char str[] =  "123";
           syscall(SYS_write, 2, str, 3);
       }

