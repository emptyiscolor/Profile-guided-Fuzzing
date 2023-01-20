#pragma once
#ifndef FCACHE_H
#define FCACHE_H
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <search.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include "common.h"
#include "fd.h"
#include "debug.h"

#define MAX_FILES 1024
#define SHM_DEFAULT_ID 0x1337
#define LIST_FILE_NONEXIST "/tmp/strace-stat/open.ENOENT.txt"
#define LIST_FILE_EXIST "/tmp/strace-stat/open.EXIST.txt"
#define NUM_MEM_SIZE_FILE "/tmp/strace-stat/PRIVATE.mmap.txt"

#define SHM_TMP_PATH "/tmp/"
#define TEST_IN_FILE ".cur_input"
#define TEST_EVAL_FILE_ENV "TESTFILE"
#define FD_START SHM_AFL_FD + 1
#define FD_SOCK_START FD_START + TOT
#define DEFAULT_MMAP_SIZE 4096

/* tsearch root */
static void *set_root = NULL;
/* Number of files in memory */
// static void *data[MAX_FILES];
static unsigned long long op_cnt;
/* Shared memory id */
static int32_t fs_afl_shm_id;


/**
 * No such file
 * @param       Filename
 * @return      False: file exists
 */
bool fcache_no_such_file(const char *filename);

/**
 * Initialization
 * @noreturn
 */
void fcache_init();

/**
 * Destroy the hash table.
 */
void fcache_fini();

/**
 * Set Key:Value
 *
 * @param filename    filename as the Key.
 * @param item        Data as the Value.
 * @return            error code.
 */
int fcache_set(char *filename, abs_file_t *item);

/**
 * Get Value
 *
 * @param filename    filename as the Key.
 * @return            error code.
 */
void *fcache_get(const char *filename);

/**
 * Not available
 */
bool fcache_delete(void *item);

/**
 * Dump the hash table
 */
void hashmap_scan(void);
