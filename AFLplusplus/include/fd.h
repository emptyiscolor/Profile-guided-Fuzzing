/* === fd.h === */

#ifndef ABSFS_FD_H
#define ABSFS_FD_H

#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#endif

#define SHM_AFL_FD 0x1337
#define FN_LEN 256

/* Max Shared memory size: 64 MB */
// #define MAX_FSMAP (4194304 >> 5)
#define MAX_FSMAP 4194304

#define MIN_FSMAP 262144

/* can change the buffer size as well */
#define BUF 256
/* change to accomodate Number of files */
#define TOT 96

typedef struct disk_file
{
  struct stat stat;
  char filename[FN_LEN];
  unsigned char contents[MIN_FSMAP];
} disk_file_t;

typedef struct file_info
{
  /* for open and release */
  int flags;
  unsigned short flush : 1;
  /* nonseekable_open */
  unsigned short nonseekable : 1;
  /* flock - apply or remove an advisory lock on an open file */
  unsigned short flock_release : 1;
  unsigned short opened : 1;
} file_info_t;

typedef struct abs_file
{
  int fd;
  off_t offset;
  file_info_t info;
  disk_file_t dfile;
  // int sockfd;
} abs_file_t;

typedef struct abs_memory
{
  void *mmap_base_addr;
  void *mmap_cur_addr;
  size_t mmap_size;
} abs_mem_t;
