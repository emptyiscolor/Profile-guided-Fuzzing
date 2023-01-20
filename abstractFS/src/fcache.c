/* -*- indent-tabs-mode: nil -*-
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include "fcache.h"

/* open(/dev/null) from AFL */
int dev_null_fd;
/* AFL input filename */
char *afl_out_filename;
/* Non-exist files */
char fs_filename_nonexist[TOT][BUF];
/* FD in cache */
abs_file_t *fcache_fds_t[TOT + TOT];
/* events for poll() */
short int fcache_socket_events_masks[TOT];
/* free fds */
int current_fd;
int current_sock_fd;
int count_enoent;
/* mmap address entry */
/* TODO: new struct */
abs_mem_t *abs_mem_p;

unsigned long fs_free_space = MAX_FSMAP;

/* Hash table entry */
ENTRY en;
ENTRY *enp;

/**
 * @brief Configure shared memory for in-memory data. This is called at startup.
 */
static void setup_shm(void)
{
    // uint8_t *fs_buffer;
    uint8_t *shm_str;
    int key;
    struct stat st;
    int set_cnt;
    abs_file_t *abs_fp;

    char *fs_shm_key_str = getenv("FS_AFL_SHM_ID");
    int fs_shm_key = fs_shm_key_str ? atoi(fs_shm_key_str) : SHM_DEFAULT_ID;
    log_s(LOG_LEVEL_VERBOSE, "fs_shm_key_str: %#08x\n", fs_shm_key);

    key = ftok(SHM_TMP_PATH, fs_shm_key);
    if (key == -1)
    {
        perror("ftok error");
        exit(-1);
    }

    if (fs_shm_key == SHM_DEFAULT_ID)
        fs_afl_shm_id = shmget(IPC_PRIVATE, MAX_FSMAP, IPC_CREAT | IPC_EXCL | 0600);
    else
        fs_afl_shm_id = shmget(key, MAX_FSMAP, IPC_CREAT | 0600);

    if (fs_afl_shm_id < 0)
        FATAL("shmget() failed");

    void *shared_memory = shmat(fs_afl_shm_id, NULL, 0);
    abs_fp = (abs_file_t *)shared_memory;

    /* Simple simulation of AFL to write virtual files, only for testing */
    if (fs_shm_key == SHM_DEFAULT_ID)
    {
        FILE *fp;
        char *testfile_var;
        testfile_var = getenv(TEST_EVAL_FILE_ENV);
        if (testfile_var)
        {
            fp = fopen(testfile_var, "rb");
            log_s(LOG_LEVEL_VERBOSE, "Loading test file: %s\n", testfile_var);
        }
        else
            fp = fopen(TEST_IN_FILE, "rb");

        if (fp == NULL)
            FATAL("Failed to open test file");

        fseek(fp, 0, SEEK_END);
        long fsize = ftell(fp);
        if (fsize > MIN_FSMAP)
            FATAL("Test file too large");

        fseek(fp, 0, SEEK_SET);

        if (fp < 0)
            FATAL("open error");

        if (fstat(fileno(fp), &st) != 0)
        {
            fclose(fp);
            FATAL("Failed to stat");
        }

        if (testfile_var)
        {
            log_s(LOG_LEVEL_VERBOSE, "loading %s\n", testfile_var);
            fread(abs_fp->dfile.contents, fsize, 1, fp);
            strncpy(abs_fp->dfile.filename, testfile_var, FN_LEN);
        }
        else
        {
            memset(abs_fp->dfile.contents, 0x42, MIN_FSMAP);
            strncpy(abs_fp->dfile.filename, TEST_IN_FILE, FN_LEN);
        }

        memcpy(&abs_fp->dfile.stat, &st, sizeof(st));

        abs_fp->offset = 0;
        abs_fp->fd = SHM_AFL_FD;
        abs_fp->info.flock_release = 0;

        fclose(fp);
    }

    afl_out_filename = abs_fp->dfile.filename;
    fcache_fds_t[0] = abs_fp;
    set_cnt = fcache_set(afl_out_filename, abs_fp);
    if (set_cnt < 0)
        FATAL("Hashmap set error");
}

/**
 * @brief Pre-allocate a portion of memory
 */
void setup_mmap()
{
    FILE *fpmmap = NULL;
    size_t length;
    char sz_str[32] = {};
    char *ptr;
    void *addr;

    fpmmap = fopen(NUM_MEM_SIZE_FILE, "r");
    if (!fpmmap)
        return;

    fgets(sz_str, 32, fpmmap);
    length = strtol(sz_str, &ptr, 10);
    if (length <= 0)
        return;

    addr = mmap(NULL, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
        FATAL("mmap error");

    /* Init global memory obj */
    abs_mem_p = malloc(sizeof(abs_mem_t));
    abs_mem_p->mmap_size = length;
    abs_mem_p->mmap_base_addr = addr + length;
    abs_mem_p->mmap_cur_addr = abs_mem_p->mmap_base_addr;

    setenv("FS_AFL_INIT_MMAP", "1", 1);
}

bool fcache_no_such_file(const char *filename)
{
    int bottom = 0;
    int mid;
    int top = count_enoent - 1;
    while (bottom <= top)
    {
        mid = (bottom + top) / 2;
        if (strcmp(fs_filename_nonexist[mid], filename) == 0)
        {
            return True;
        }
        else if (strcmp(fs_filename_nonexist[mid], filename) > 0)
        {
            top = mid - 1;
        }
        else if (strcmp(fs_filename_nonexist[mid], filename) < 0)
        {
            bottom = mid + 1;
        }
    }
    return False;
}

void fcache_init()
{
    op_cnt = 0;
    current_fd = FD_START;
    current_sock_fd = FD_SOCK_START;
    FILE *fpnonexist = NULL;
    FILE *fpexist = NULL;
    FILE *fpexist_item = NULL;
    abs_file_t *abs_fp;
    char filename_exist[BUF];
    struct stat st;
    count_enoent = 0;
    int j = 1;
    int total = 0;
    long fsize = 0;
    int init_ret = hcreate(MAX_FILES);
    // char *afl_dev_null_fd_str = getenv("AFL_DEV_NULL_FD");
    // int dev_null_fd = afl_dev_null_fd_str ? atoi(afl_dev_null_fd_str) : 0;

    // log_s(LOG_LEVEL_DEBUG, "== Virtual FS ==");
    if (init_ret == 0)
    {
        FATAL("hcreate error");
    }

    /* No such files */
    fpnonexist = fopen(LIST_FILE_NONEXIST, "r");
    if (fpnonexist != NULL)
    {
        while (fgets(fs_filename_nonexist[count_enoent], BUF, fpnonexist) && count_enoent < TOT)
        {
            /* get rid of ending \n from fgets */
            fs_filename_nonexist[count_enoent][strlen(fs_filename_nonexist[count_enoent]) - 1] = '\0';
            count_enoent++;
        }

        fclose(fpnonexist);
    }

    /* Put files into mem cache */
    fpexist = fopen(LIST_FILE_EXIST, "rb");
    if (fpexist != NULL)
    {
        while (fgets(filename_exist, BUF, fpexist) && j < TOT)
        {
            /* get rid of ending \n from fgets */
            filename_exist[strlen(filename_exist) - 1] = '\0';
            fpexist_item = fopen(filename_exist, "rb");
            if (fpexist_item == NULL)
                break;

            fseek(fpexist_item, 0, SEEK_END);
            fsize = ftell(fpexist_item);
            if (fsize >= MIN_FSMAP)
                continue;

            /* same as rewind(f); */
            fseek(fpexist_item, 0, SEEK_SET);
            abs_fp = malloc(sizeof(abs_file_t));
            if (abs_fp == NULL)
                FATAL("malloc failed.");

            if (fstat(fileno(fpexist_item), &st) != 0)
                FATAL("Failed to stat");

            /* Copying data from disk to memory */
            memcpy(&abs_fp->dfile.stat, &st, sizeof(st));
            fread(abs_fp->dfile.contents, fsize, 1, fpexist_item);
            strcpy(abs_fp->dfile.filename, filename_exist);
            abs_fp->offset = 0;
            abs_fp->fd = SHM_AFL_FD + j;
            fcache_fds_t[j] = abs_fp;
            fclose(fpexist_item);
            if (fcache_set(abs_fp->dfile.filename, abs_fp) < 0)
                FATAL("Hashmap set error");

            j++;
            current_fd++;
        }

        fclose(fpexist);
    }

    memset(fcache_socket_events_masks, 0, TOT);
    setup_shm();
    setup_mmap();
    /* Real FS stats*/
    // struct statvfs fsst;
    // if (afl_out_filename)
    //     statvfs(afl_out_filename, &fsst);
    // else
    //     statvfs("/bin/true", &fsst);
    // fs_free_space = fsst.f_blocks * fsst.f_frsize;
}

void fcache_fini()
{
    // shmctl(fs_afl_shm_id, IPC_RMID, NULL);
    hdestroy();
}

int fcache_set(char *filename, abs_file_t *item)
{
    int last_err = errno;
    en.key = filename;
    /* mmap to memory area */
    en.data = (void *)item;

    enp = hsearch(en, ENTER);
    errno = last_err;
    /* there should be no failures */
    if (enp == NULL)
    {
        fprintf(stderr, "entry failed\n");
        return -1;
    }

    op_cnt++;
    return op_cnt;
}

void *fcache_get(const char *filename)
{
    int last_err = errno;
    en.key = (char *)filename;
    enp = hsearch(en, FIND);
    errno = last_err;
    if (enp)
        return enp->data;

    return NULL;
}