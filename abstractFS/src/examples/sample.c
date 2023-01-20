/* -*- indent-tabs-mode: nil -*-
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <ctype.h>

static int test_cnt;
static int error_cnt;

void hexdump(void *ptr, int buflen)
{
    unsigned char *buf = (unsigned char *)ptr;
    int i, j;
    for (i = 0; i < buflen; i += 16)
    {
        printf("%06x: ", i);
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        printf(" ");
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        printf("\n");
    }
}

static void read_content_by_open(const char *filename, char *buf, size_t bufsiz)
{
    int fd = open(filename, O_RDONLY);
    ssize_t size = read(fd, buf, bufsiz);

    if (size >= 0)
    {
        buf[size] = '\0';
    }
    else
    {
        strcpy(buf, "read error");
    }
    close(fd);
}

static void read_content_by_fopen(const char *filename, char *buf, size_t bufsiz)
{
    FILE *fp = fopen(filename, "r");
    if (fp != NULL)
    {
        if (fgets(buf, bufsiz, fp) == NULL)
        {
            strcpy(buf, "read error");
        }
        fclose(fp);
    }
    else
    {
        strcpy(buf, "open error");
    }
}

static void check_content(const char *filename, const char *expect, int line)
{
    char buf[512];

    read_content_by_open(filename, buf, sizeof(buf));
    if (strcmp(buf, expect) != 0)
    {
        printf("ERROR at line %d: '%s' != '%s' (open)\n", line, buf, expect);
        error_cnt++;
    }
    read_content_by_fopen(filename, buf, sizeof(buf));
    if (strcmp(buf, expect) != 0)
    {
        printf("ERROR at line %d: '%s' != '%s' (fopen)\n", line, buf, expect);
        error_cnt++;
    }
}

static void check_shared_content(const char *filename, int line)
{
    char buf[128];
    char expbuf[128];

    /* Expected 'B'++ in shared memory */
    memset(expbuf, 0x42, 128);
    expbuf[127] = 0;

    read_content_by_open(filename, buf, sizeof(buf) - 1);
    if (strcmp(buf, expbuf) != 0)
    {
        hexdump(buf, 128);

        printf("expected buf: \n");
        hexdump(expbuf, 128);

        printf("ERROR at line %d: 'A'*128 != inputfile (fopen)\n", line);
        error_cnt++;
    }
}

static void test_open_and_fopen(void)
{
    FILE *fp;

    char expbuf[65536];

    memset(expbuf, 0x41, 65536);

    test_cnt++;
    printf("[%d] test_hook_open_and_fopen\n", test_cnt);

    /* prepare file contents */
    fp = fopen("test-1.txt", "w");
    fputs("This is test-1.txt.", fp);
    fclose(fp);
    fp = fopen("test-2.txt", "w");
    fputs("This is test-2.txt.", fp);
    fclose(fp);

    /* Open test-1.txt. */
#ifdef TEST_OUTPUT
    check_content("test-1.txt", "This is test-2.txt.", __LINE__);
#endif

    check_shared_content(".cur_input", __LINE__);
}

static void *load_func(const char *module, const char *func)
{
    void *addr;
#ifdef WIN32
    HMODULE hMod = GetModuleHandleA(module);

    if (hMod == NULL)
    {
        printf("ERROR: Could not open module %s.\n", module ? module : "(null)");
        exit(1);
    }
    addr = (void *)GetProcAddress(hMod, func);
#else
    void *handle = dlopen(module, RTLD_LAZY | RTLD_NOLOAD);
    if (handle == NULL)
    {
        printf("ERROR: Could not open file %s.\n", module ? module : "(null)");
        exit(1);
    }
    addr = dlsym(handle, func);
    dlclose(handle);
#endif
    if (addr == NULL)
    {
        printf("ERROR: Could not get function address of %s.\n", func);
        exit(1);
    }
    return addr;
}

#define TEST_FUNCHOOK_INT(func, load_type) test_funchook_int(func, #func, load_type)

int main()
{
    // load_func("hook.so", "reset_register");
    void *handle;
    // int (*reset)();
    if (getenv("HOOKOPEN"))
        handle = dlopen("./fs_hook.so", RTLD_LAZY);
    // *(int**)reset = dlsym(handle, "reset_register");

    test_open_and_fopen();

    if (error_cnt == 0)
    {
        printf("all %d tests are passed.\n", test_cnt);
        return 0;
    }
    else
    {
        printf("%d of %d tests are failed.\n", error_cnt, test_cnt);
        return 1;
    }
}
