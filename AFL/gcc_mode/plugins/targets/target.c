#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>




char str2[20];

struct aaa{int a;};

struct test{
	int a;
	int b;
	int c;
	struct aaa saa;
};

struct test test1;

static int var[10];
static int var1;

int main()
{
  static int a = 0;
  int b = 1;
  b = b + 1;
  int c = a + b;


  var1 = 2;

  str2[3] = 'a';

  *(str2+2) = 'b';

  int *ptr = &var1;


  var[1] = c;

  *ptr = c;

  ((struct test *)(&var1))->a = 10;

  test1.saa.a = 1;

  int *ptr2 = &test1.b;

  test1.c = test1.a + test1.b;

  return 0;
}

