/** -*- indent-tabs-mode: nil -*-
 * @file fs_rt.c
 * @brief Runtime API hook for fuzzing
 * @version 0.1
 * @date 2022-06
 * @todo
 *  - [] support for vsf events
 *  - [] select() and poll()
 *  - [] more FS related sturcts
 */

#include "fs_rt.h"
#include "fcache.h"
#include <limits.h>

#define MAX_DUP_FD 1024
#define FS_AVA_VALID_SOCK(s) ((s > 0) && (s < TOT))
#define FS_VALID_SOCK(s) ((s > 0) && (s <= current_sock_fd - TOT))
#define FS_GET_FILE_T(fd) (fd < SHM_AFL_FD || fd > SHM_AFL_FD + TOT) ? get_dup2_file_t(fd) : fcache_fds_t[fd - SHM_AFL_FD]
#define FD_EVENTS(fd_cnt, fds) ({fd_cnt++; fds->revents = fcache_socket_events_masks[fdi] & filter; })

abs_file_t *abs_fp_socket[2];
static int dup_fds[MAX_DUP_FD];

/* Reset the register for return values.
 *  %eax for x86.
 *  %rax for x86_64.
 */
NOINLINE int reset_register()
{
    return 0;
}

static int error_cnt;
static funchook_t *funchook;

static int _is_non_blocking(abs_file_t *file_t)
{
    return file_t->info.flags & O_NONBLOCK;
}

/* If file exists in cache */
static bool file_exists(const char *filename)
{
    if (fcache_get(filename) != NULL)
        return True;

    return False;
}

/* If file exists in cache */
abs_file_t *get_dup2_file_t(int fd)
{
    return dup_fds[fd] ? fcache_fds_t[dup_fds[fd]] : NULL;
}

/* Currently only handle the AFL testcases and cached files */
static int open_hook(const char *pathname, int flags, mode_t mode)
{
#ifdef TEST_OUTPUT
    if (strcmp(pathname, "test-1.txt") == 0)
    {
        pathname = "test-2.txt";
    }
#endif

    if (count_enoent && fcache_no_such_file(pathname))
        return ENOENT;

    abs_file_t *file_t = (abs_file_t *)fcache_get(pathname);

    if (file_t != NULL)
    {
        file_t->info.flags = flags;
        file_t->info.opened = 1;
        file_t->offset = 0;
        return file_t->fd;
    }

    return open_func(pathname, flags, mode);
}

/* Error on double close */
static int close_hook(int fd)
{
    abs_file_t *file_t = FS_GET_FILE_T(fd);
    if (file_t == NULL)
    {
        if (!FS_VALID_SOCK(fd))
            return close_func(fd);

        file_t = fcache_fds_t[TOT + fd];
        if (file_t)
        {
            file_t->info.opened = 0;
            free(file_t);
            fcache_fds_t[TOT + fd] = NULL;
        }
        return close_func(fd);
    }

    if (file_t->info.opened == 0)
    {
        return -1;
    }

    file_t->info.opened = 0;
    return 0;
}

/* Another way of hooking foppen */
static FILE *fopen_hook(const char *pathname, const char *mode)
{
#ifdef TEST_OUTPUT
    if (strcmp(pathname, "test-1.txt") == 0)
    {
        pathname = "test-2.txt";
    }
#endif

    abs_file_t *file_t = (abs_file_t *)fcache_get(pathname);

    if (file_t != NULL)
    {
        FILE *ret = fmemopen((void *)file_t->dfile.contents,
                             file_t->dfile.stat.st_size, mode);
        if (ret == NULL)
            FATAL("fmemopen() failed");

        ret->_fileno = file_t->fd;
        return ret;
    }

    return fopen_func(pathname, mode);
}

static int fclose_hook(FILE *stream)
{
    int fd = stream->_fileno;
    abs_file_t *file_t = FS_GET_FILE_T(fd);
    if (file_t == NULL)
        return fclose_func(stream);

    if (file_t->info.opened == 0)
    {
        return -1;
    }

    file_t->info.opened = 0;
    return 0;
}

static ssize_t read_hook(int fd, void *buf, size_t count)
{
    bool is_socket = False;
    if (count == 0)
        return count;

    abs_file_t *file_t = FS_GET_FILE_T(fd);
    if (fd == 0)
        file_t = fcache_fds_t[0];

    if (file_t == NULL)
    {
        if (!FS_VALID_SOCK(fd))
            return read_func(fd, buf, count);

        if (!(file_t = fcache_fds_t[TOT + fd]))
            return read_func(fd, buf, count);

        is_socket = True;
    }

    if (file_t->offset >= file_t->dfile.stat.st_size)
    {
        if (is_socket)
            return -1;

        return 0;
    }

    if (count > (file_t->dfile.stat.st_size - file_t->offset))
        count = file_t->dfile.stat.st_size - file_t->offset;

    if (count > 0)
    {
        memcpy(buf, file_t->dfile.contents + file_t->offset, count);
        if (is_socket)
            fcache_socket_events_masks[fd] |= POLLOUT | POLLWRNORM;
    }

    if (!is_socket)
        file_t->offset += count;

    return count;
}


static ssize_t pread_hook(int fd, void *buf, size_t count, off64_t offset)
{
    bool is_socket = False;
    if (count == 0)
        return count;

    abs_file_t *file_t = FS_GET_FILE_T(fd);
    if (fd == 0)
        file_t = fcache_fds_t[0];

    if (file_t == NULL)
    {
        // if (!FS_VALID_SOCK(fd))
            return pread64_func(fd, buf, count, offset);

        // if (!(file_t = fcache_fds_t[TOT + fd]))
        //     return read_func(fd, buf, count);

        // is_socket = True;
    }

    if (offset < 0 || count < 0)
    {
        errno = EINVAL;
        return -1;
    }

    if (offset > 2147483646)
    {
        errno = EOVERFLOW;
        return -1;
    }

    if (offset >= file_t->dfile.stat.st_size)
        return 0;

    if (count > (file_t->dfile.stat.st_size - offset))
        count = file_t->dfile.stat.st_size - offset;

    if (count > 0)
    {
        memcpy(buf, file_t->dfile.contents + offset, count);
        if (is_socket)
            fcache_socket_events_masks[fd] |= POLLOUT | POLLWRNORM;
    }

    return count;
}

/* AFL ignores what the program prints */
ssize_t write_hook(int fd, const void *buf, size_t count)
{
    bool is_socket = False;
    // if (fd == dev_null_fd)
    //     return count;

#ifdef DISABLE_OUTPUT
    if (fd == 1 || fd == 2)
        return count;
#endif

    abs_file_t *file_t = FS_GET_FILE_T(fd);
    if (file_t == NULL)
    {
        if (!FS_VALID_SOCK(fd))
            return write_func(fd, buf, count);

        if (!(file_t = fcache_fds_t[TOT + fd]))
            return write_func(fd, buf, count);

        is_socket = True;
        if (file_t->pair_sockfd)
            file_t = fcache_fds_t[TOT + file_t->pair_sockfd];

        if (!file_t)
            return write_func(fd, buf, count);
    }

    if (count + file_t->offset > MIN_FSMAP)
    {
        count = MIN_FSMAP - file_t->offset;
        file_t->dfile.stat.st_size = MIN_FSMAP;
    }

    if (count + file_t->offset > file_t->dfile.stat.st_size)
    {
        file_t->dfile.stat.st_size = count + file_t->offset;
    }

    memcpy(file_t->dfile.contents + file_t->offset, buf, count);
    if (!is_socket)
        file_t->offset += count;

    if (is_socket)
    {
        fcache_socket_events_masks[file_t->fd] |= POLLIN | POLLRDNORM;
        fcache_socket_events_masks[fd] |= POLLIN | POLLRDNORM;
    }

    return count;
}

static off_t lseek_hook(int fd, off_t offset, int whence)
{
    off_t retval;
    abs_file_t *file_t = FS_GET_FILE_T(fd);
    if (file_t == NULL)
        return lseek_func(fd, offset, whence);

    switch (whence)
    {
    case SEEK_SET:
        /* The file offset is set to offset bytes. */
        if (offset < 0)
        {
            errno = EINVAL;
            retval = (off_t)-1;
        }

        else if (offset > fs_free_space)
        {
            errno = EINVAL;
            retval = (off_t)-1;
        }
        else
        {
            file_t->offset = offset;
            retval = file_t->offset;
        }

        break;

    case SEEK_CUR:
        /* The file offset is set to its current location plus offset bytes. */
        if (offset + file_t->offset < 0)
        {
            errno = EINVAL;
            retval = (off_t)-1;
        }
        else if (offset + file_t->offset > fs_free_space)
        {
            errno = EINVAL;
            retval = (off_t)-1;
        }
        else
        {
            file_t->offset += offset;
            retval = file_t->offset;
        }

        break;

    case SEEK_END:
        /* The file offset is set to the size of the file plus offset bytes. */
        if (file_t->dfile.stat.st_size + offset < 0)
        {
            errno = EINVAL;
            retval = (off_t)-1;
        }
        else if (file_t->dfile.stat.st_size + offset > fs_free_space)
        {
            errno = EINVAL;
            retval = (off_t)-1;
        }
        else
        {
            file_t->offset = file_t->dfile.stat.st_size + offset;
            retval = file_t->offset;
        }

        break;

    case SEEK_DATA:
        if (offset >= file_t->dfile.stat.st_size)
        {
            errno = ENXIO;
            retval = (off_t)-1;
        }

        break;

    case SEEK_HOLE:
        if (offset >= file_t->dfile.stat.st_size)
        {
            errno = ENXIO;
            retval = (off_t)-1;
        }

        file_t->offset = file_t->dfile.stat.st_size;
        break;

    default:
        errno = EINVAL;
        retval = (off_t)-1;
        break;
    }

    loff_t res = retval;
    if (res != (loff_t)retval)
    {
        errno = EOVERFLOW;
        retval = (off_t)-1; // only for 32 bit
    }

    return retval;
}

static int fstat_hook(int fd, struct stat *statbuf)
{
    abs_file_t *file_t = FS_GET_FILE_T(fd);
    if (file_t == NULL)
        return fstat_func(fd, statbuf);

    memcpy(statbuf, &(file_t->dfile.stat), sizeof(struct stat));
    return 0;
}

static int fxstat_hook(int vers, int fd, struct stat *statbuf)
{
    abs_file_t *file_t = FS_GET_FILE_T(fd);
    if (file_t == NULL)
        return fxstat_func(vers, fd, statbuf);

    memcpy(statbuf, &(file_t->dfile.stat), sizeof(struct stat));
    return 0;
}

static int xstat_hook(int vers, const char *pathname, struct stat *statbuf)
{
    abs_file_t *file_t = (abs_file_t *)fcache_get(pathname);

    if (file_t != NULL)
    {
        memcpy(statbuf, &(file_t->dfile.stat), sizeof(struct stat));
        return 0;
    }

    return xstat_func(vers, pathname, statbuf);
}

static int stat_hook(const char *pathname, struct stat *statbuf)
{
    abs_file_t *file_t = (abs_file_t *)fcache_get(pathname);

    if (file_t != NULL)
    {
        memcpy(statbuf, &(file_t->dfile.stat), sizeof(struct stat));
        return 0;
    }

    return stat_func(pathname, statbuf);
}

static int lstat_hook(const char *pathname, struct stat *statbuf)
{
    return stat_hook(pathname, statbuf);
}

static int dup2_hook(int fd, int fd2)
{
    abs_file_t *file_t = FS_GET_FILE_T(fd);
    if (file_t == NULL)
        return dup2_func(fd, fd2);

    if (fd2 >= MAX_DUP_FD)
    {
        errno = EBADF;
        return -1;
    }

    int save;
    abs_file_t *abs_fp;
    if (fd2 < 0)
    {
        errno = EBADF;
        return -1;
    }

    if (fd == fd2)
        return fd2;
    int fdi = 1;

    while (fdi < TOT && fcache_fds_t[fdi] != NULL)
    {
        if (fcache_fds_t[fdi]->fd == fd2)
        {
            free(fcache_fds_t[fdi]);
            fcache_fds_t[fdi] = NULL;
            break;
        }
        fdi++;
    }

    current_fd = FD_START + fdi;

    abs_fp = malloc(sizeof(abs_file_t));
    abs_fp->dfile = file_t->dfile;
    // memcpy(&abs_fp->dfile.stat, &file_t->dfile.stat, sizeof(file_t->dfile.stat));
    // memcpy(abs_fp->dfile.contents, file_t->dfile.contents, file_t->dfile.stat.st_size);
    abs_fp->fd = fd2;
    abs_fp->offset = file_t->offset;
    memcpy(&abs_fp->info, &file_t->info, sizeof(file_t->info));
    abs_fp->info.opened = 1;

    fcache_fds_t[fdi] = abs_fp;
    dup_fds[fd2] = fdi;

    // save = errno;
    // close_func(fd2);
    // errno = save;

    return fd2;
}

static int fcntl_hook(int fd, int cmd, ...)
{
    va_list arg_list;
    va_start(arg_list, cmd);
    int ret = -1;
    bool is_socket;

    abs_file_t *file_t = FS_GET_FILE_T(fd);
    if (file_t == NULL && FS_VALID_SOCK(fd))
        if ((file_t = fcache_fds_t[TOT + fd]))
            is_socket = True;

    switch (cmd)
    {
    case F_DUPFD:
    {
        int param = va_arg(arg_list, int);
        ret = fcntl_func(fd, cmd, param);
        break;
    }
    case F_GETFD:
    {
        if (file_t != NULL)
            ret = file_t->info.flags;
        else
            ret = fcntl_func(fd, cmd);
        break;
    }
    case F_SETFD:
    {
        int param = va_arg(arg_list, int);
        if (file_t != NULL)
        {
            file_t->info.flags = param;
            ret = 0;
        }
        else
            ret = fcntl_func(fd, cmd, param);
        break;
    }
    case F_GETFL:
    {
        if (file_t)
        {
            ret = file_t->info.flags;
        }
        else
        {
            ret = fcntl_func(fd, cmd);
        }

        break;
    }
    case F_SETFL:
    {
        int param = va_arg(arg_list, int);
        int flag = param;

        if (file_t && is_socket)
        {
            file_t->info.flags |= param;
        }
        // flag |= O_NONBLOCK;
        ret = fcntl_func(fd, cmd, flag);
        break;
    }
    case F_GETOWN:
    {
        ret = fcntl_func(fd, cmd);
        break;
    }
    case F_SETOWN:
    {
        int param = va_arg(arg_list, int);
        ret = fcntl_func(fd, cmd, param);
        break;
    }
    case F_GETLK:
    {
        struct flock *param = va_arg(arg_list, struct flock *);
        ret = fcntl_func(fd, cmd, param);
        break;
    }
    case F_SETLK:
    {
        struct flock *param = va_arg(arg_list, struct flock *);
        ret = fcntl_func(fd, cmd, param);
        break;
    }
    case F_SETLKW:
    {
        struct flock *param = va_arg(arg_list, struct flock *);
        ret = fcntl_func(fd, cmd, param);
        break;
    }
    }
    va_end(arg_list);
    return ret;
}

/**
 * @brief Wrapper for socket.
 * Record the socket that was created
 */
static int socket_hook(int family, int type, int protocol)
{
    int retval;
    abs_file_t *abs_fp;

    retval = socket_func(family, type, protocol);

    if (FS_AVA_VALID_SOCK(retval))
    {
        abs_fp = malloc(sizeof(abs_file_t));

        if (abs_fp == NULL)
            FATAL("malloc failed.");

        abs_fp->info.opened = 1;
        abs_fp->offset = 0;
        abs_fp->fd = retval;
        current_sock_fd = TOT + retval;
        // abs_fp->sockfd = retval;
        fcache_fds_t[current_sock_fd] = abs_fp;
    }

    return retval;
}

/**
 * @brief Wrapper for socketpair - create a pair of connected sockets
 * On success, zero is returned.
 * On error, -1 is returned, errno is set appropriately,
 * and sv is left unchanged
 * @return  0 or -1 on error
 */
static int socketpair_hook(int domain, int type, int protocol, int sv[2])
{
    int retval;
    abs_file_t *abs_fp;

    if (!abs_fp_socket[0])
    {
        for (int8_t i = 0; i < 2; i++)
            abs_fp_socket[i] = malloc(sizeof(abs_file_t));
    }

    retval = socketpair_func(domain, type, protocol, sv);

    if (FS_AVA_VALID_SOCK(sv[1]))
    {
        for (int8_t i = 0; i < 2; i++)
        {
            // abs_fp = malloc(sizeof(abs_file_t));
            abs_fp = abs_fp_socket[i];

            if (abs_fp == NULL)
                FATAL("malloc failed.");

            abs_fp->info.opened = 1;
            abs_fp->offset = 0;
            abs_fp->fd = sv[i];
            abs_fp->pair_sockfd = sv[i ^ 1];
            current_sock_fd = TOT + sv[i];
            fcache_fds_t[current_sock_fd] = abs_fp;
        }
    }

    return retval;
}

static ssize_t sendto_hook(int sockfd, const void *buf, size_t len, int flags,
                           const struct sockaddr *dest_addr, socklen_t addrlen)
{
    abs_file_t *file_t;

    if (!dest_addr && !addrlen && FS_VALID_SOCK(sockfd))
        if ((file_t = fcache_fds_t[TOT + sockfd]))
        {
            if (file_t->pair_sockfd)
                file_t = fcache_fds_t[TOT + file_t->pair_sockfd];

            if (file_t)
            {
                if (len + file_t->offset > MIN_FSMAP)
                {
                    len = MIN_FSMAP - file_t->offset;
                    file_t->dfile.stat.st_size = MIN_FSMAP;
                }

                if (len + file_t->offset > file_t->dfile.stat.st_size)
                {
                    file_t->dfile.stat.st_size = len + file_t->offset;
                }

                memcpy(file_t->dfile.contents, buf, len);
                fcache_socket_events_masks[file_t->fd] |= POLLIN | POLLRDNORM;
                fcache_socket_events_masks[file_t->pair_sockfd] |= POLLIN | POLLRDNORM;
                file_t->offset += len;
                return len;
            }
        }

    return sendto_func(sockfd, buf, len, flags, dest_addr, addrlen);
}

static ssize_t send_hook(int sockfd, const void *buf, size_t len, int flags)
{
    return sendto_hook(sockfd, buf, len, flags, NULL, 0);
}

static ssize_t recvfrom_hook(int sockfd, void *buf, size_t len, int flags,
                             struct sockaddr *src_addr, socklen_t *addrlen)
{
    abs_file_t *file_t;

    if (!src_addr && !addrlen && FS_VALID_SOCK(sockfd))
        if ((file_t = fcache_fds_t[TOT + sockfd]))
        {
            // file_t->offset = 0;
            if ((file_t = fcache_fds_t[TOT + sockfd]))
            {
                if (file_t->dfile.stat.st_size <= 0)
                    return 0;

                if (file_t->offset >= file_t->dfile.stat.st_size)
                    return 0;

                if (len > (file_t->dfile.stat.st_size - file_t->offset))
                    len = file_t->dfile.stat.st_size - file_t->offset;

                if (len > 0)
                    memcpy(buf, file_t->dfile.contents, len);

                file_t->offset += len;
                return len;
            }
        }

    return recvfrom_func(sockfd, buf, len, flags, src_addr, addrlen);
}

static ssize_t recv_hook(int sockfd, void *buf, size_t len, int flags)
{
    return recvfrom_hook(sockfd, buf, len, flags, NULL, NULL);
}

/**
 * @brief Wrapper for select()
 * Inconsistent with expectations, deprecate this hook
 */
int select_hook(int nfds,
                fd_set *readfds,
                fd_set *writefds,
                fd_set *exceptfds,
                struct timeval *timeout)
{
    abs_file_t *file_t;
    fd_set in_read, in_write, in_except, os_read, os_write, os_except;
    int fd_cnt = 0;
    int count = 0;
    int fdi;

    if (readfds)
    {
        in_read = *readfds;
        _FD_ZERO(readfds);
    }
    else
    {
        _FD_ZERO(&in_read);
    }

    if (writefds)
    {
        in_write = *writefds;
        _FD_ZERO(writefds);
    }
    else
    {
        _FD_ZERO(&in_write);
    }

    if (exceptfds)
    {
        in_except = *exceptfds;
        _FD_ZERO(exceptfds);
    }
    else
    {
        _FD_ZERO(&in_except);
    }

    // Anchor point

    for (fdi = 0; fdi < nfds; fdi++)
    {
        if (_FD_ISSET(fdi, &in_read) || _FD_ISSET(fdi, &in_write) || _FD_ISSET(fdi, &in_except))
        {
            file_t = FS_VALID_SOCK(fdi) ? fcache_fds_t[TOT + fdi] : NULL;
            if (file_t &&
                file_t->info.opened)
            {
                if (_is_non_blocking(file_t))
                {
                    if (_FD_ISSET(fdi, &in_read) && fcache_socket_events_masks[fdi] & (POLLIN | POLLRDNORM))
                        _FD_SET(fdi, readfds);

                    ++fd_cnt;
                    continue;
                }

                while (file_t->dfile.stat.st_size == 0 &&
                       count < 10000)
                {
                    if (_FD_ISSET(fdi, &in_read))
                        _FD_SET(fdi, readfds);

                    if (_FD_ISSET(fdi, &in_write))
                        _FD_SET(fdi, writefds);

                    if (_FD_ISSET(fdi, &in_except))
                        _FD_SET(fdi, exceptfds);

                    ++count;
                    ++fd_cnt;
                }
            }
            else
            {
                errno = EBADF;
                return -1;
            }
        }
    }

    return fd_cnt ? fd_cnt : select_func(nfds, readfds, writefds, exceptfds, timeout);
}

/**
 * @brief poll() performs a similar task to select(2):
 * it waits for one of a set of file descriptors to become ready to perform I/O.
 */
static int poll_hook(struct pollfd *fds, nfds_t nfds, int timeout)
{
    int fdi, fd_cnt = 0, count = 0;
    abs_file_t *file_t;
    unsigned int mask = 0, filter;
    int is_block = 0;
    /* return timeout */
    if (!fds && nfds == 0)
        return 0;

    for (nfds_t i = 0; i < nfds; i++)
    {
        fdi = fds[i].fd;
        file_t = FS_VALID_SOCK(fdi) ? fcache_fds_t[TOT + fdi] : NULL;
        if (file_t && file_t->info.opened)
        {
            filter = fds[i].events | EPOLLERR | EPOLLHUP;
            if (fdi < 0)
                return 0;

            if (fds[i].events & (POLLOUT | POLLWRNORM))
            {
                fd_cnt++;
                fds[i].revents |= POLLOUT | POLLWRNORM;
                // return fd_cnt;
            }

            mask = fcache_socket_events_masks[fdi];
            // mask |= fds->events;
            if (_is_non_blocking(file_t) || timeout == 0)
                if (mask & filter)
                {
                    fd_cnt++;
                    fds[i].revents = fcache_socket_events_masks[fdi] & filter;
                }
            // FD_EVENTS(fd_cnt, fds);

            return fd_cnt;
        }

        while (is_block && count < timeout * 1000)
        {
            if (fcache_socket_events_masks[fdi] & filter)
                FD_EVENTS(fd_cnt, fds);
            return fd_cnt;

            count++;
        }
    }

    return poll_func(fds, nfds, timeout);
}

/**
 * @brief mmap() creates a new mapping in the virtual address space
 * of the calling process.
 *
 * @return void* the pre-allocated memory address
 */
static void *mmap_hook(void *addr, size_t length, int prot, int flags,
                       int fd, off_t offset)
{
    size_t size;
    void *base_addr;

    abs_file_t *file_t = FS_GET_FILE_T(fd);
    if (file_t != NULL)
        return (void *)file_t->dfile.contents;

    if (abs_mem_p &&
        abs_mem_p->mmap_base_addr &&
        addr == NULL &&
        flags == (MAP_PRIVATE | MAP_ANONYMOUS) &&
        fd == -1 &&
        offset == 0)
    {
        size = (length == ((length >> 12) << 12))
                   ? length
                   : ((length >> 12) << 12) + DEFAULT_MMAP_SIZE;

        if (size <= (abs_mem_p->mmap_size - (abs_mem_p->mmap_base_addr - abs_mem_p->mmap_cur_addr)))
        {
            base_addr = abs_mem_p->mmap_cur_addr - size;
            abs_mem_p->mmap_cur_addr = base_addr;

            if (mprotect(base_addr, size, prot) == 0)
                return base_addr;
        }
    }

    return mmap_func(addr, length, prot, flags, fd, offset);
}

/**
 * @brief Remove memory mapping
 *
 * @return int
 */
static int munmap_hook(void *addr, size_t length)
{
    for (int i = 1; i < 4; i++)
        if (addr == (void *)fcache_fds_t[i]->dfile.contents)
            return 0;

    if (abs_mem_p &&
        abs_mem_p->mmap_base_addr &&
        addr < abs_mem_p->mmap_base_addr &&
        addr >= abs_mem_p->mmap_base_addr - abs_mem_p->mmap_size)
    {
        if (mprotect(addr, length, PROT_NONE) == 0)
            return 0;
        else
        {
            errno = EINVAL;
            return -1;
        }
    }

    if (addr == (void *)0x1337 && length == 0)
    {
        abs_mem_p->mmap_cur_addr = abs_mem_p->mmap_base_addr;
        return mprotect(
            abs_mem_p->mmap_base_addr - abs_mem_p->mmap_size,
            abs_mem_p->mmap_size,
            PROT_NONE);
    }

    return munmap_func(addr, length);
}

static void *memchr_hook(const void *s, int c, size_t n)
{
    reset_register();
    return memchr_func(s, c, n);
}

/**
 * @brief libpthread.so is part of glibc too,
 * and they both contain (identical) definitions of some symbols.
 */
static bool func_is_libc(void *func, void *base)
{
    Dl_info info;
    int rc;
    void *base_addr;

    rc = dladdr(func, &info);

    if (!rc)
    {
        FATAL("Problem retrieving program information ");
    }

    return base == info.dli_fbase;
}

static void *get_module_base(void *func)
{
    Dl_info info;
    int rc;
    void *base_addr;

    rc = dladdr(func, &info);

    if (!rc)
    {
        FATAL("Problem retrieving program information ");
    }

    return info.dli_fbase;
}

__attribute__((constructor)) static void ctor()
{
    int rv;

    void *libc_base = get_module_base(pipe2);

    fcache_init();
    funchook = funchook_create();
#ifdef __ANDROID__
    open_func = (int (*)(const char *const pass_object_size, int, ...))open;
#else
    open_func = (int (*)(const char *, int, mode_t))open;
#endif
    funchook_prepare(funchook, (void **)&open_func, open_hook);
    // open_func = (int (*)(const char *, int, mode_t))dlsym(RTLD_NEXT, "open");
    // funchook_prepare(funchook, (void **)&open_func, open_hook);
    open64_func = (int (*)(const char *, int, mode_t))open64;
    funchook_prepare(funchook, (void **)&open64_func, open_hook);
    fopen_func = fopen;
    // funchook_prepare(funchook, (void **)&fopen_func, fopen_hook);
    fclose_func = fclose;
    funchook_prepare(funchook, (void **)&fclose_func, fclose_hook);
    read_func = read;
    funchook_prepare(funchook, (void **)&read_func, read_hook);
    pread64_func = pread64;
    funchook_prepare(funchook, (void **)&pread64_func, pread_hook);
    write_func = write;
    funchook_prepare(funchook, (void **)&write_func, write_hook);
    fstat_func = fstat;
    funchook_prepare(funchook, (void **)&fstat_func, fstat_hook);
    fxstat_func = __fxstat;
    funchook_prepare(funchook, (void **)&fxstat_func, fxstat_hook);
    xstat_func = __xstat;
    funchook_prepare(funchook, (void **)&xstat_func, xstat_hook);
    stat_func = stat;
    funchook_prepare(funchook, (void **)&stat_func, stat_hook);
    lstat_func = lstat;
    funchook_prepare(funchook, (void **)&lstat_func, lstat_hook);
    lseek_func = lseek;
    funchook_prepare(funchook, (void **)&lseek_func, lseek_hook);
    close_func = close;
    funchook_prepare(funchook, (void **)&close_func, close_hook);
    __close_nocancel_func = dlsym(RTLD_NEXT, "__close_nocancel");
    // funchook_prepare(funchook, (void **)&__close_nocancel_func, close_hook);
    fcntl_func = fcntl;
    funchook_prepare(funchook, (void **)&fcntl_func, fcntl_hook);
    socket_func = socket;
    // funchook_prepare(funchook, (void **)&socket_func, socket_hook);
    socketpair_func = socketpair;
    // funchook_prepare(funchook, (void **)&socketpair_func, socketpair_hook);
    sendto_func = sendto;
    funchook_prepare(funchook, (void **)&sendto_func, sendto_hook);
    send_func = send;
    funchook_prepare(funchook, (void **)&send_func, send_hook);
    recvfrom_func = recvfrom;
    funchook_prepare(funchook, (void **)&recvfrom_func, recvfrom_hook);
    recv_func = recv;
    funchook_prepare(funchook, (void **)&recv_func, recv_hook);
    select_func = select;
    funchook_prepare(funchook, (void **)&select_func, select_hook);
    poll_func = poll;
    funchook_prepare(funchook, (void **)&poll_func, poll_hook);
    mmap_func = mmap;
    // funchook_prepare(funchook, (void **)&mmap_func, mmap_hook);
    munmap_func = munmap;
    // funchook_prepare(funchook, (void **)&munmap_func, munmap_hook);
    memchr_func = memchr;
    // funchook_prepare(funchook, (void **)&memchr_func, memchr_hook);
    dup2_func = dup2;
    funchook_prepare(funchook, (void **)&dup2_func, dup2_hook);

    if (!func_is_libc(open, libc_base))
    {
        open_func = (int (*)(const char *, int, mode_t))dlsym(RTLD_NEXT, "open");
        funchook_prepare(funchook, (void **)&open_func, open_hook);
        fopen_func = dlsym(RTLD_NEXT, "fopen");
        // funchook_prepare(funchook, (void **)&fopen_func, fopen_hook);
        read_func = dlsym(RTLD_NEXT, "read");
        funchook_prepare(funchook, (void **)&read_func, read_hook);
        pread64_func = dlsym(RTLD_NEXT, "pread64");
        funchook_prepare(funchook, (void **)&pread64_func, pread_hook);
        write_func = dlsym(RTLD_NEXT, "write");
        funchook_prepare(funchook, (void **)&write_func, write_hook);
        // stat_func = dlsym(RTLD_NEXT, "stat");
        // funchook_prepare(funchook, (void **)&stat_func, stat_hook);
        // lstat_func = dlsym(RTLD_NEXT, "lstat");
        // funchook_prepare(funchook, (void **)&lstat_func, lstat_hook);
        // fstat_func = dlsym(RTLD_NEXT, "fstat");
        // funchook_prepare(funchook, (void **)&fstat_func, fstat_hook);
        fxstat_func = dlsym(RTLD_NEXT, "__fxstat");
        funchook_prepare(funchook, (void **)&fxstat_func, fxstat_hook);
        xstat_func = dlsym(RTLD_NEXT, "__xstat");
        funchook_prepare(funchook, (void **)&xstat_func, xstat_hook);
        lseek_func = dlsym(RTLD_NEXT, "lseek");
        funchook_prepare(funchook, (void **)&lseek_func, lseek_hook);
        close_func = dlsym(RTLD_NEXT, "close");
        funchook_prepare(funchook, (void **)&close_func, close_hook);
        __close_nocancel_func = dlsym(RTLD_NEXT, "__close_nocancel");
        // funchook_prepare(funchook, (void **)&__close_nocancel_func, close_hook);
        fcntl_func = dlsym(RTLD_NEXT, "fcntl");
        funchook_prepare(funchook, (void **)&fcntl_func, fcntl_hook);
        sendto_func = dlsym(RTLD_NEXT, "sendto");
        funchook_prepare(funchook, (void **)&sendto_func, sendto_hook);
        recvfrom_func = dlsym(RTLD_NEXT, "recvfrom");
        funchook_prepare(funchook, (void **)&recvfrom_func, recvfrom_hook);
    }

    /* The contents of test-1.txt should be "This is test-1.txt". */

    /* hook `open' and `fopen` */
    rv = funchook_install(funchook, 0);
    if (rv != 0)
    {
        log_s(LOG_LEVEL_ERR,
              "ERROR: failed to install open and fopen hooks. (%s)\n",
              funchook_error_message(funchook));
        error_cnt++;
        return;
    }
}

/*__attribute__((destructor))*/ static void dtor()
{
    fcache_fini();
    if (funchook)
    {
        funchook_uninstall(funchook, 0);
        funchook_destroy(funchook);
    }
}