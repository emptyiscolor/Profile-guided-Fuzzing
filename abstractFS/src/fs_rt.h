#ifndef FS_RT_H
#define FS_RT_H
#endif
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#ifdef WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <poll.h>
#include <fcntl.h>
#include <stdarg.h>
#ifdef WIN32
#include <windows.h>
#include <io.h>
#define mode_t int
#define ssize_t int
#define open _open
/* cast the third argument of _read to suppress warning C4267 */
#define read(fd, buf, count) _read((fd), (buf), (unsigned int)(count))
/* cast the second argument of fgets to suppress warning C4267 */
#define fgets(s, size, fp) fgets((s), (int)(size), (fp))
#define close _close
#else
#include <unistd.h>
#include <dlfcn.h>
#endif
#include <funchook.h>
#include "fd.h"

#ifdef WIN32
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

#ifdef __GNUC__
#define NOINLINE __attribute__((noinline))
#endif
#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#endif

#if defined(__APPLE__) && defined(__clang_major__) && __clang_major__ >= 11
#define SKIP_TESTS_CHANGING_EXE
#endif

#define handle_error(msg)   \
    do                      \
    {                       \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    } while (0)

#define _FD_SET(n, p) ((p)->fds_bits[(n) / NFDBITS] |= (1 << ((n) % NFDBITS)))
#define _FD_CLR(n, p) ((p)->fds_bits[(n) / NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define _FD_ISSET(n, p) ((p)->fds_bits[(n) / NFDBITS] & (1 << ((n) % NFDBITS)))
#define _FD_ZERO(p) memset((char *)(p), '\0', sizeof(*(p)))

typedef int (*int_func_t)(void);
typedef uint64_t (*uint64_func_t)(uint64_t);

/* open(/dev/null) from AFL */
extern int dev_null_fd;
/* AFL input filename */
extern char *afl_out_filename;
/* Non-exist files */
extern char fs_filename_nonexist[TOT][BUF];
/* FD in cache */
extern abs_file_t *fcache_fds_t[TOT + TOT];
/* events for poll() */
extern short int fcache_socket_events_masks[TOT];
/* free fds */
extern int current_fd;
extern int current_sock_fd;
extern int count_enoent;
/* mmap address entry */
/* TODO: new struct */
extern abs_mem_t *abs_mem_p;
extern unsigned long fs_free_space;

#ifdef __ANDROID__
static int (*open_func)(const char *const pass_object_size, int, ...);
#else
static int (*open_func)(const char *pathname, int flags, mode_t mode);
#endif

static int (*open64_func)(const char *pathname, int flags, mode_t mode);

static int (*close_func)(int fd);
static int (*__close_nocancel_func)(int fd);
static FILE *(*fopen_func)(const char *pathname, const char *mode);
static int (*fclose_func)(FILE *stream);
static ssize_t (*write_func)(int fd, const void *buf, size_t count);
static ssize_t (*read_func)(int fd, void *buf, size_t count);
static ssize_t (*pread_func)(int fd, void *buf, size_t count, off_t offset);
static ssize_t (*pread64_func)(int fd, void *buf, size_t count, off64_t offset);
static int (*lstat_func)(const char *pathname, struct stat *statbuf);
static int (*stat_func)(const char *pathname, struct stat *statbuf);
static int (*xstat_func)(int vers, const char *pathname, struct stat *statbuf);
static int (*fstat_func)(int fd, struct stat *statbuf);
static off_t (*lseek_func)(int fd, off_t offset, int whence);
static int (*fxstat_func)(int vers, int fd, struct stat *buf);
static int (*fcntl_func)(int fd, int cmd, ... /* arg */);
static int (*socket_func)(int domain, int type, int protocol);
static int (*socketpair_func)(int domain, int type, int protocol, int sv[2]);
static ssize_t (*send_func)(int sockfd, const void *buf, size_t len, int flags);
static ssize_t (*sendto_func)(int sockfd, const void *buf, size_t len, int flags,
                              const struct sockaddr *dest_addr, socklen_t addrlen);
static ssize_t (*recv_func)(int sockfd, void *buf, size_t len, int flags);
static ssize_t (*recvfrom_func)(int sockfd, void *buf, size_t len, int flags,
                                struct sockaddr *src_addr, socklen_t *addrlen);
static int (*select_func)(int nfds, fd_set *restrict readfds,
                          fd_set *restrict writefds, fd_set *restrict errorfds,
                          struct timeval *restrict timeout);
static void *(*mmap_func)(void *addr, size_t length, int prot, int flags,
                          int fd, off_t offset);
static int (*munmap_func)(void *addr, size_t length);
static int (*poll_func)(struct pollfd *fds, nfds_t nfds, int timeout);
static void *(*memchr_func)(const void *s, int c, size_t n);
static int (*dup2_func)(int oldfd, int newfd);
