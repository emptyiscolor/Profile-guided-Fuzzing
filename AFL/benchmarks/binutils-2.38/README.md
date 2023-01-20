## Build the image

```
docker build -t benchmark-afl-objdump .
```

## Build for Sec 2

```
docker run --privileged --shm-size=256m --rm -it benchmark-afl-objdump bash

# inside docker container
MODE=profile FUZZER=baseline bash build.sh

AFL_NO_AFFINITY=1 AFL_PERFORM_DRY_RUN_ONLY=1 afl-fuzz  -i /out/objdump_corpus -o /dev/shm/output_objdump -f /dev/shm/afl_bin_input /out/objdump -d @@
```

##  Build and run benchmarks

```
docker run --shm-size=256m --rm -it benchmark-afl-objdump bash

cd /src
# Fork Server mode
FUZZER=baseline bash build.sh

# VAR mode
FUZZER=aflfstab bash build.sh

# Persistent mode without var rec
bash build.sh

# Run AFL
afl-fuzz  -i /out/seeds -o /dev/shm/output_objdump -f /dev/shm/afl_bin_input /out/objdump -d @@

# Run AFL with VFS enable

FS_AFL_SHM_ID=6789 afl-fuzz  -i /out/seeds -o /dev/shm/output_objdump -f /dev/shm/afl_bin_input /out/objdump -d @@

```

#### Run profiling

```
AFL_PERFORM_DRY_RUN_ONLY=1 AFL_NO_AFFINITY=1 perf stat /home/test/Desktop/code/AFL/afl-fuzz -i /out/corpus_objdump_snap -o /dev/shm/rm_objdump -f /dev/shm/afl_bin_input ./objdump -d @@
```


### Profiling

Fork Server(on disk)

```
Profiling information: 
7545 ms total work, 151133 ns/work,             
33129 ms total running, 663538 ns/run, 
1487 ms total write testcase, 29794 ns/write             
3005 ms total forking, 60192 ns/fork, 
28235 ms total purely run, 565523 ns/purely run             
44263 ns/system running, 503925 ns/user running             
7545 ms total pre-fuzzing, 151133 ns/pre-fuzzing,             
0 ms total post-fuzzing, 0 ns/post-fuzzing
total execution is 49928
      35592.688642      task-clock (msec)         #    0.947 CPUs utilized
           202,224      context-switches          #    0.006 M/sec
             1,515      cpu-migrations            #    0.043 K/sec
         6,477,484      page-faults               #    0.182 M/sec

                 0      syscalls:sys_enter_socket                                   
                 0      syscalls:sys_enter_socketpair                                   
                 0      syscalls:sys_enter_bind                                     
                 0      syscalls:sys_enter_listen                                   
                 0      syscalls:sys_enter_accept4                                   
                 0      syscalls:sys_enter_accept                                   
                 0      syscalls:sys_enter_connect                                   
                 0      syscalls:sys_enter_getsockname                                   
                 0      syscalls:sys_enter_getpeername                                   
                 0      syscalls:sys_enter_sendto                                   
                 0      syscalls:sys_enter_recvfrom                                   
                 0      syscalls:sys_enter_setsockopt                                   
                 0      syscalls:sys_enter_getsockopt                                   
                 0      syscalls:sys_enter_shutdown                                   
                 0      syscalls:sys_enter_sendmsg                                   
                 0      syscalls:sys_enter_sendmmsg                                   
                 0      syscalls:sys_enter_recvmsg                                   
                 0      syscalls:sys_enter_recvmmsg                                   
                 0      syscalls:sys_enter_getrandom                                   
                 0      syscalls:sys_enter_ioprio_set                                   
                 0      syscalls:sys_enter_ioprio_get                                   
                 0      syscalls:sys_enter_add_key                                   
                 0      syscalls:sys_enter_request_key                                   
                 0      syscalls:sys_enter_keyctl                                   
                 0      syscalls:sys_enter_mq_open                                   
                 0      syscalls:sys_enter_mq_unlink                                   
                 0      syscalls:sys_enter_mq_timedsend                                   
                 0      syscalls:sys_enter_mq_timedreceive                                   
                 0      syscalls:sys_enter_mq_notify                                   
                 0      syscalls:sys_enter_mq_getsetattr                                   
                 1      syscalls:sys_enter_shmget                                   
                 2      syscalls:sys_enter_shmctl                                   
                 2      syscalls:sys_enter_shmat                                    
                 0      syscalls:sys_enter_shmdt                                    
                 0      syscalls:sys_enter_semget                                   
                 0      syscalls:sys_enter_semctl                                   
                 0      syscalls:sys_enter_semtimedop                                   
                 0      syscalls:sys_enter_semop                                    
                 0      syscalls:sys_enter_msgget                                   
                 0      syscalls:sys_enter_msgctl                                   
                 0      syscalls:sys_enter_msgsnd                                   
                 0      syscalls:sys_enter_msgrcv                                   
                 0      syscalls:sys_enter_lookup_dcookie                                   
                 0      syscalls:sys_enter_quotactl                                   
                 0      syscalls:sys_enter_name_to_handle_at                                   
                 0      syscalls:sys_enter_open_by_handle_at                                   
                 1      syscalls:sys_enter_flock                                    
                 0      syscalls:sys_enter_io_setup                                   
                 0      syscalls:sys_enter_io_destroy                                   
                 0      syscalls:sys_enter_io_submit                                   
                 0      syscalls:sys_enter_io_cancel                                   
                 0      syscalls:sys_enter_io_getevents                                   
                 0      syscalls:sys_enter_userfaultfd                                   
                 0      syscalls:sys_enter_eventfd2                                   
                 0      syscalls:sys_enter_eventfd                                   
                 0      syscalls:sys_enter_timerfd_create                                   
                 0      syscalls:sys_enter_timerfd_settime                                   
                 0      syscalls:sys_enter_timerfd_gettime                                   
                 0      syscalls:sys_enter_signalfd4                                   
                 0      syscalls:sys_enter_signalfd                                   
                 0      syscalls:sys_enter_epoll_create1                                   
                 0      syscalls:sys_enter_epoll_create                                   
                 0      syscalls:sys_enter_epoll_ctl                                   
                 0      syscalls:sys_enter_epoll_wait                                   
                 0      syscalls:sys_enter_epoll_pwait                                   
                 0      syscalls:sys_enter_fanotify_init                                   
                 0      syscalls:sys_enter_fanotify_mark                                   
                 0      syscalls:sys_enter_inotify_init1                                   
                 0      syscalls:sys_enter_inotify_init                                   
                 0      syscalls:sys_enter_inotify_add_watch                                   
                 0      syscalls:sys_enter_inotify_rm_watch                                   
                 0      syscalls:sys_enter_statfs                                   
                 0      syscalls:sys_enter_fstatfs                                   
                 0      syscalls:sys_enter_ustat                                    
                 0      syscalls:sys_enter_utime                                    
                 0      syscalls:sys_enter_utimensat                                   
                 0      syscalls:sys_enter_futimesat                                   
                 0      syscalls:sys_enter_utimes                                   
                 0      syscalls:sys_enter_sync                                     
                 0      syscalls:sys_enter_syncfs                                   
                 0      syscalls:sys_enter_fsync                                    
                 0      syscalls:sys_enter_fdatasync                                   
                 0      syscalls:sys_enter_sync_file_range                                   
                 0      syscalls:sys_enter_vmsplice                                   
                 0      syscalls:sys_enter_splice                                   
                 0      syscalls:sys_enter_tee                                      
                 0      syscalls:sys_enter_setxattr                                   
                 0      syscalls:sys_enter_lsetxattr                                   
                 0      syscalls:sys_enter_fsetxattr                                   
                 0      syscalls:sys_enter_getxattr                                   
                 0      syscalls:sys_enter_lgetxattr                                   
                 0      syscalls:sys_enter_fgetxattr                                   
                 0      syscalls:sys_enter_listxattr                                   
                 0      syscalls:sys_enter_llistxattr                                   
                 0      syscalls:sys_enter_flistxattr                                   
                 0      syscalls:sys_enter_removexattr                                   
                 0      syscalls:sys_enter_lremovexattr                                   
                 0      syscalls:sys_enter_fremovexattr                                   
                 0      syscalls:sys_enter_umount                                   
                 0      syscalls:sys_enter_mount                                    
                 0      syscalls:sys_enter_pivot_root                                   
                 0      syscalls:sys_enter_sysfs                                    
                 0      syscalls:sys_enter_dup3                                     
                 5      syscalls:sys_enter_dup2                                     
                 0      syscalls:sys_enter_dup                                      
                 1      syscalls:sys_enter_getcwd                                   
                 0      syscalls:sys_enter_select                                   
                 0      syscalls:sys_enter_pselect6                                   
                 0      syscalls:sys_enter_poll                                     
                 0      syscalls:sys_enter_ppoll                                    
                38      syscalls:sys_enter_getdents                                   
                 0      syscalls:sys_enter_getdents64                                   
            35,777      syscalls:sys_enter_ioctl                                    
            99,857      syscalls:sys_enter_fcntl                                    
                 0      syscalls:sys_enter_mknodat                                   
                 0      syscalls:sys_enter_mknod                                    
                 0      syscalls:sys_enter_mkdirat                                   
                 9      syscalls:sys_enter_mkdir                                    
                 8      syscalls:sys_enter_rmdir                                    
                 0      syscalls:sys_enter_unlinkat                                   
            56,174      syscalls:sys_enter_unlink                                   
                 0      syscalls:sys_enter_symlinkat                                   
                 0      syscalls:sys_enter_symlink                                   
                 0      syscalls:sys_enter_linkat                                   
             6,241      syscalls:sys_enter_link                                     
                 0      syscalls:sys_enter_renameat2                                   
                 0      syscalls:sys_enter_renameat                                   
                 0      syscalls:sys_enter_rename                                   
                 0      syscalls:sys_enter_pipe2                                    
                 2      syscalls:sys_enter_pipe                                     
                 1      syscalls:sys_enter_execve                                   
                 0      syscalls:sys_enter_execveat                                   
            49,929      syscalls:sys_enter_newstat                                   
             6,243      syscalls:sys_enter_newlstat                                   
                 0      syscalls:sys_enter_newfstatat                                   
           235,505      syscalls:sys_enter_newfstat                                   
                 0      syscalls:sys_enter_readlinkat                                   
                 0      syscalls:sys_enter_readlink                                   
                 0      syscalls:sys_enter_statx                                    
         2,375,456      syscalls:sys_enter_lseek                                    
           398,476      syscalls:sys_enter_read                                     
         1,116,861      syscalls:sys_enter_write                                    
                 0      syscalls:sys_enter_pread64                                   
                 0      syscalls:sys_enter_pwrite64                                   
                 0      syscalls:sys_enter_readv                                    
                 0      syscalls:sys_enter_writev                                   
                 0      syscalls:sys_enter_preadv                                   
                 0      syscalls:sys_enter_preadv2                                   
                 0      syscalls:sys_enter_pwritev                                   
                 0      syscalls:sys_enter_pwritev2                                   
                 0      syscalls:sys_enter_sendfile64                                   
                 0      syscalls:sys_enter_copy_file_range                                   
                 0      syscalls:sys_enter_truncate                                   
                 0      syscalls:sys_enter_ftruncate                                   
                 0      syscalls:sys_enter_fallocate                                   
                 0      syscalls:sys_enter_faccessat                                   
            12,494      syscalls:sys_enter_access                                   
                 0      syscalls:sys_enter_chdir                                    
                 0      syscalls:sys_enter_fchdir                                   
                 0      syscalls:sys_enter_chroot                                   
                 0      syscalls:sys_enter_fchmod                                   
                 0      syscalls:sys_enter_fchmodat                                   
                 0      syscalls:sys_enter_chmod                                    
                 0      syscalls:sys_enter_fchownat                                   
                 0      syscalls:sys_enter_chown                                    
                 0      syscalls:sys_enter_lchown                                   
                 0      syscalls:sys_enter_fchown                                   
         1,094,852      syscalls:sys_enter_open                                     
                 0      syscalls:sys_enter_openat                                   
                 0      syscalls:sys_enter_creat                                    
           301,454      syscalls:sys_enter_close                                    
                 0      syscalls:sys_enter_vhangup                                   
                 0      syscalls:sys_enter_move_pages                                   
                 0      syscalls:sys_enter_mbind                                    
                 0      syscalls:sys_enter_set_mempolicy                                   
                 0      syscalls:sys_enter_migrate_pages                                   
                 0      syscalls:sys_enter_get_mempolicy                                   
                 0      syscalls:sys_enter_swapoff                                   
                 0      syscalls:sys_enter_swapon                                   
                 0      syscalls:sys_enter_madvise                                   
                 0      syscalls:sys_enter_fadvise64                                   
                 0      syscalls:sys_enter_process_vm_readv                                   
                 0      syscalls:sys_enter_process_vm_writev                                   
                 0      syscalls:sys_enter_msync                                    
                 0      syscalls:sys_enter_mremap                                   
                12      syscalls:sys_enter_mprotect                                   
                 0      syscalls:sys_enter_pkey_mprotect                                   
                 0      syscalls:sys_enter_pkey_alloc                                   
                 0      syscalls:sys_enter_pkey_free                                   
           101,141      syscalls:sys_enter_brk                                      
                27      syscalls:sys_enter_munmap                                   
                 0      syscalls:sys_enter_remap_file_pages                                   
                 0      syscalls:sys_enter_mlock                                    
                 0      syscalls:sys_enter_mlock2                                   
                 0      syscalls:sys_enter_munlock                                   
                 0      syscalls:sys_enter_mlockall                                   
                 0      syscalls:sys_enter_munlockall                                   
                 0      syscalls:sys_enter_mincore                                   
                 0      syscalls:sys_enter_memfd_create                                   
                 0      syscalls:sys_enter_readahead                                   
                 0      syscalls:sys_enter_perf_event_open                                   
                 0      syscalls:sys_enter_bpf                                      
                 0      syscalls:sys_enter_seccomp                                   
                 0      syscalls:sys_enter_kexec_file_load                                   
                 0      syscalls:sys_enter_kexec_load                                   
                 0      syscalls:sys_enter_acct                                     
                 0      syscalls:sys_enter_delete_module                                   
                 0      syscalls:sys_enter_init_module                                   
                 0      syscalls:sys_enter_finit_module                                   
                 0      syscalls:sys_enter_set_robust_list                                   
                 0      syscalls:sys_enter_get_robust_list                                   
                 0      syscalls:sys_enter_futex                                    
            49,928      syscalls:sys_enter_getitimer                                   
                 0      syscalls:sys_enter_alarm                                    
            99,858      syscalls:sys_enter_setitimer                                   
                 0      syscalls:sys_enter_timer_create                                   
                 0      syscalls:sys_enter_timer_gettime                                   
                 0      syscalls:sys_enter_timer_getoverrun                                   
                 0      syscalls:sys_enter_timer_settime                                   
                 0      syscalls:sys_enter_timer_delete                                   
                 0      syscalls:sys_enter_clock_settime                                   
                 0      syscalls:sys_enter_clock_gettime                                   
                 0      syscalls:sys_enter_clock_adjtime                                   
                 0      syscalls:sys_enter_clock_getres                                   
                 0      syscalls:sys_enter_clock_nanosleep                                   
                 0      syscalls:sys_enter_nanosleep                                   
                 0      syscalls:sys_enter_time                                     
                 0      syscalls:sys_enter_gettimeofday                                   
                 0      syscalls:sys_enter_settimeofday                                   
                 0      syscalls:sys_enter_adjtimex                                   
                 0      syscalls:sys_enter_kcmp                                     
                 0      syscalls:sys_enter_syslog                                   
                 0      syscalls:sys_enter_membarrier                                   
                 0      syscalls:sys_enter_sched_setscheduler                                   
                 0      syscalls:sys_enter_sched_setparam                                   
                 0      syscalls:sys_enter_sched_setattr                                   
                 0      syscalls:sys_enter_sched_getscheduler                                   
                 0      syscalls:sys_enter_sched_getparam                                   
                 0      syscalls:sys_enter_sched_getattr                                   
                 0      syscalls:sys_enter_sched_setaffinity                                   
                 0      syscalls:sys_enter_sched_getaffinity                                   
                 0      syscalls:sys_enter_sched_yield                                   
                 0      syscalls:sys_enter_sched_get_priority_max                                   
                 0      syscalls:sys_enter_sched_get_priority_min                                   
                 0      syscalls:sys_enter_sched_rr_get_interval                                   
                 0      syscalls:sys_enter_getgroups                                   
                 0      syscalls:sys_enter_setgroups                                   
                 0      syscalls:sys_enter_reboot                                   
                 0      syscalls:sys_enter_setns                                    
                 0      syscalls:sys_enter_setpriority                                   
                 0      syscalls:sys_enter_getpriority                                   
                 0      syscalls:sys_enter_setregid                                   
                 0      syscalls:sys_enter_setgid                                   
                 0      syscalls:sys_enter_setreuid                                   
                 0      syscalls:sys_enter_setuid                                   
                 0      syscalls:sys_enter_setresuid                                   
                 0      syscalls:sys_enter_getresuid                                   
                 0      syscalls:sys_enter_setresgid                                   
                 0      syscalls:sys_enter_getresgid                                   
                 0      syscalls:sys_enter_setfsuid                                   
                 0      syscalls:sys_enter_setfsgid                                   
                 1      syscalls:sys_enter_getpid                                   
                 0      syscalls:sys_enter_gettid                                   
                 0      syscalls:sys_enter_getppid                                   
                 0      syscalls:sys_enter_getuid                                   
                 0      syscalls:sys_enter_geteuid                                   
                 0      syscalls:sys_enter_getgid                                   
                 0      syscalls:sys_enter_getegid                                   
                 0      syscalls:sys_enter_times                                    
                 0      syscalls:sys_enter_setpgid                                   
                 0      syscalls:sys_enter_getpgid                                   
                 0      syscalls:sys_enter_getpgrp                                   
                 0      syscalls:sys_enter_getsid                                   
                 1      syscalls:sys_enter_setsid                                   
                 0      syscalls:sys_enter_newuname                                   
                 0      syscalls:sys_enter_sethostname                                   
                 0      syscalls:sys_enter_setdomainname                                   
            49,929      syscalls:sys_enter_getrlimit                                   
                 0      syscalls:sys_enter_prlimit64                                   
                 1      syscalls:sys_enter_setrlimit                                   
                 0      syscalls:sys_enter_getrusage                                   
                 0      syscalls:sys_enter_umask                                    
                 0      syscalls:sys_enter_prctl                                    
                 0      syscalls:sys_enter_getcpu                                   
                 1      syscalls:sys_enter_sysinfo                                   
                 0      syscalls:sys_enter_restart_syscall                                   
                 0      syscalls:sys_enter_rt_sigprocmask                                   
                 0      syscalls:sys_enter_rt_sigpending                                   
                 0      syscalls:sys_enter_rt_sigtimedwait                                   
                 0      syscalls:sys_enter_kill                                     
                 0      syscalls:sys_enter_tgkill                                   
                 0      syscalls:sys_enter_tkill                                    
                 0      syscalls:sys_enter_rt_sigqueueinfo                                   
                 0      syscalls:sys_enter_rt_tgsigqueueinfo                                   
                 0      syscalls:sys_enter_sigaltstack                                   
                 8      syscalls:sys_enter_rt_sigaction                                   
                 0      syscalls:sys_enter_pause                                    
                 0      syscalls:sys_enter_rt_sigsuspend                                   
                 0      syscalls:sys_enter_ptrace                                   
                 0      syscalls:sys_enter_capget                                   
                 0      syscalls:sys_enter_capset                                   
                 0      syscalls:sys_enter_sysctl                                   
                 0      syscalls:sys_enter_exit                                     
            49,930      syscalls:sys_enter_exit_group                                   
                 0      syscalls:sys_enter_waitid                                   
            49,928      syscalls:sys_enter_wait4                                    
                 0      syscalls:sys_enter_personality                                   
                 0      syscalls:sys_enter_set_tid_address                                   
                 0      syscalls:sys_enter_fork                                     
                 0      syscalls:sys_enter_vfork                                    
            49,929      syscalls:sys_enter_clone                                    
                 0      syscalls:sys_enter_unshare                                   
            99,925      syscalls:sys_enter_mmap                                     
                 0      syscalls:sys_enter_modify_ldt                                   
                 0      syscalls:sys_enter_iopl                                     
                 2      syscalls:sys_enter_arch_prctl     
```


Fork Server(RAMFS)

```
Profiling information: 
7139 ms total work, 142991 ns/work,             
32873 ms total running, 658415 ns/run, 
1021 ms total write testcase, 20460 ns/write             
3001 ms total forking, 60118 ns/fork, 
28082 ms total purely run, 562455 ns/purely run             
44864 ns/system running, 501321 ns/user running             
7139 ms total pre-fuzzing, 142991 ns/pre-fuzzing,             
0 ms total post-fuzzing, 0 ns/post-fuzzing
total execution is 49928 

      34918.414922      task-clock (msec)         #    0.944 CPUs utilized
           202,297      context-switches          #    0.006 M/sec
             1,555      cpu-migrations            #    0.045 K/sec
         6,544,855      page-faults               #    0.187 M/sec

                 0      syscalls:sys_enter_socket                                   
                 0      syscalls:sys_enter_socketpair                                   
                 0      syscalls:sys_enter_bind                                     
                 0      syscalls:sys_enter_listen                                   
                 0      syscalls:sys_enter_accept4                                   
                 0      syscalls:sys_enter_accept                                   
                 0      syscalls:sys_enter_connect                                   
                 0      syscalls:sys_enter_getsockname                                   
                 0      syscalls:sys_enter_getpeername                                   
                 0      syscalls:sys_enter_sendto                                   
                 0      syscalls:sys_enter_recvfrom                                   
                 0      syscalls:sys_enter_setsockopt                                   
                 0      syscalls:sys_enter_getsockopt                                   
                 0      syscalls:sys_enter_shutdown                                   
                 0      syscalls:sys_enter_sendmsg                                   
                 0      syscalls:sys_enter_sendmmsg                                   
                 0      syscalls:sys_enter_recvmsg                                   
                 0      syscalls:sys_enter_recvmmsg                                   
                 0      syscalls:sys_enter_getrandom                                   
                 0      syscalls:sys_enter_ioprio_set                                   
                 0      syscalls:sys_enter_ioprio_get                                   
                 0      syscalls:sys_enter_add_key                                   
                 0      syscalls:sys_enter_request_key                                   
                 0      syscalls:sys_enter_keyctl                                   
                 0      syscalls:sys_enter_mq_open                                   
                 0      syscalls:sys_enter_mq_unlink                                   
                 0      syscalls:sys_enter_mq_timedsend                                   
                 0      syscalls:sys_enter_mq_timedreceive                                   
                 0      syscalls:sys_enter_mq_notify                                   
                 0      syscalls:sys_enter_mq_getsetattr                                   
                 1      syscalls:sys_enter_shmget                                   
                 2      syscalls:sys_enter_shmctl                                   
                 2      syscalls:sys_enter_shmat                                    
                 0      syscalls:sys_enter_shmdt                                    
                 0      syscalls:sys_enter_semget                                   
                 0      syscalls:sys_enter_semctl                                   
                 0      syscalls:sys_enter_semtimedop                                   
                 0      syscalls:sys_enter_semop                                    
                 0      syscalls:sys_enter_msgget                                   
                 0      syscalls:sys_enter_msgctl                                   
                 0      syscalls:sys_enter_msgsnd                                   
                 0      syscalls:sys_enter_msgrcv                                   
                 0      syscalls:sys_enter_lookup_dcookie                                   
                 0      syscalls:sys_enter_quotactl                                   
                 0      syscalls:sys_enter_name_to_handle_at                                   
                 0      syscalls:sys_enter_open_by_handle_at                                   
                 1      syscalls:sys_enter_flock                                    
                 0      syscalls:sys_enter_io_setup                                   
                 0      syscalls:sys_enter_io_destroy                                   
                 0      syscalls:sys_enter_io_submit                                   
                 0      syscalls:sys_enter_io_cancel                                   
                 0      syscalls:sys_enter_io_getevents                                   
                 0      syscalls:sys_enter_userfaultfd                                   
                 0      syscalls:sys_enter_eventfd2                                   
                 0      syscalls:sys_enter_eventfd                                   
                 0      syscalls:sys_enter_timerfd_create                                   
                 0      syscalls:sys_enter_timerfd_settime                                   
                 0      syscalls:sys_enter_timerfd_gettime                                   
                 0      syscalls:sys_enter_signalfd4                                   
                 0      syscalls:sys_enter_signalfd                                   
                 0      syscalls:sys_enter_epoll_create1                                   
                 0      syscalls:sys_enter_epoll_create                                   
                 0      syscalls:sys_enter_epoll_ctl                                   
                 0      syscalls:sys_enter_epoll_wait                                   
                 0      syscalls:sys_enter_epoll_pwait                                   
                 0      syscalls:sys_enter_fanotify_init                                   
                 0      syscalls:sys_enter_fanotify_mark                                   
                 0      syscalls:sys_enter_inotify_init1                                   
                 0      syscalls:sys_enter_inotify_init                                   
                 0      syscalls:sys_enter_inotify_add_watch                                   
                 0      syscalls:sys_enter_inotify_rm_watch                                   
                 0      syscalls:sys_enter_statfs                                   
                 0      syscalls:sys_enter_fstatfs                                   
                 0      syscalls:sys_enter_ustat                                    
                 0      syscalls:sys_enter_utime                                    
                 0      syscalls:sys_enter_utimensat                                   
                 0      syscalls:sys_enter_futimesat                                   
                 0      syscalls:sys_enter_utimes                                   
                 0      syscalls:sys_enter_sync                                     
                 0      syscalls:sys_enter_syncfs                                   
                 0      syscalls:sys_enter_fsync                                    
                 0      syscalls:sys_enter_fdatasync                                   
                 0      syscalls:sys_enter_sync_file_range                                   
                 0      syscalls:sys_enter_vmsplice                                   
                 0      syscalls:sys_enter_splice                                   
                 0      syscalls:sys_enter_tee                                      
                 0      syscalls:sys_enter_setxattr                                   
                 0      syscalls:sys_enter_lsetxattr                                   
                 0      syscalls:sys_enter_fsetxattr                                   
                 0      syscalls:sys_enter_getxattr                                   
                 0      syscalls:sys_enter_lgetxattr                                   
                 0      syscalls:sys_enter_fgetxattr                                   
                 0      syscalls:sys_enter_listxattr                                   
                 0      syscalls:sys_enter_llistxattr                                   
                 0      syscalls:sys_enter_flistxattr                                   
                 0      syscalls:sys_enter_removexattr                                   
                 0      syscalls:sys_enter_lremovexattr                                   
                 0      syscalls:sys_enter_fremovexattr                                   
                 0      syscalls:sys_enter_umount                                   
                 0      syscalls:sys_enter_mount                                    
                 0      syscalls:sys_enter_pivot_root                                   
                 0      syscalls:sys_enter_sysfs                                    
                 0      syscalls:sys_enter_dup3                                     
                 5      syscalls:sys_enter_dup2                                     
                 0      syscalls:sys_enter_dup                                      
                 1      syscalls:sys_enter_getcwd                                   
                 0      syscalls:sys_enter_select                                   
                 0      syscalls:sys_enter_pselect6                                   
                 0      syscalls:sys_enter_poll                                     
                 0      syscalls:sys_enter_ppoll                                    
                38      syscalls:sys_enter_getdents                                   
                 0      syscalls:sys_enter_getdents64                                   
            35,777      syscalls:sys_enter_ioctl                                    
            99,857      syscalls:sys_enter_fcntl                                    
                 0      syscalls:sys_enter_mknodat                                   
                 0      syscalls:sys_enter_mknod                                    
                 0      syscalls:sys_enter_mkdirat                                   
                 9      syscalls:sys_enter_mkdir                                    
                 8      syscalls:sys_enter_rmdir                                    
                 0      syscalls:sys_enter_unlinkat                                   
            56,174      syscalls:sys_enter_unlink                                   
                 0      syscalls:sys_enter_symlinkat                                   
                 0      syscalls:sys_enter_symlink                                   
                 0      syscalls:sys_enter_linkat                                   
             6,241      syscalls:sys_enter_link                                     
                 0      syscalls:sys_enter_renameat2                                   
                 0      syscalls:sys_enter_renameat                                   
                 0      syscalls:sys_enter_rename                                   
                 0      syscalls:sys_enter_pipe2                                    
                 2      syscalls:sys_enter_pipe                                     
                 1      syscalls:sys_enter_execve                                   
                 0      syscalls:sys_enter_execveat                                   
            49,929      syscalls:sys_enter_newstat                                   
             6,243      syscalls:sys_enter_newlstat                                   
                 0      syscalls:sys_enter_newfstatat                                   
           235,505      syscalls:sys_enter_newfstat                                   
                 0      syscalls:sys_enter_readlinkat                                   
                 0      syscalls:sys_enter_readlink                                   
                 0      syscalls:sys_enter_statx                                    
         2,375,544      syscalls:sys_enter_lseek                                    
           411,222      syscalls:sys_enter_read                                     
         1,123,101      syscalls:sys_enter_write                                    
                 0      syscalls:sys_enter_pread64                                   
                 0      syscalls:sys_enter_pwrite64                                   
                 0      syscalls:sys_enter_readv                                    
                 0      syscalls:sys_enter_writev                                   
                 0      syscalls:sys_enter_preadv                                   
                 0      syscalls:sys_enter_preadv2                                   
                 0      syscalls:sys_enter_pwritev                                   
                 0      syscalls:sys_enter_pwritev2                                   
                 0      syscalls:sys_enter_sendfile64                                   
                 0      syscalls:sys_enter_copy_file_range                                   
                 0      syscalls:sys_enter_truncate                                   
                 0      syscalls:sys_enter_ftruncate                                   
                 0      syscalls:sys_enter_fallocate                                   
                 0      syscalls:sys_enter_faccessat                                   
            12,494      syscalls:sys_enter_access                                   
                 0      syscalls:sys_enter_chdir                                    
                 0      syscalls:sys_enter_fchdir                                   
                 0      syscalls:sys_enter_chroot                                   
                 0      syscalls:sys_enter_fchmod                                   
                 0      syscalls:sys_enter_fchmodat                                   
                 0      syscalls:sys_enter_chmod                                    
                 0      syscalls:sys_enter_fchownat                                   
                 0      syscalls:sys_enter_chown                                    
                 0      syscalls:sys_enter_lchown                                   
                 0      syscalls:sys_enter_fchown                                   
         1,107,334      syscalls:sys_enter_open                                     
                 0      syscalls:sys_enter_openat                                   
                 0      syscalls:sys_enter_creat                                    
           313,936      syscalls:sys_enter_close                                    
                 0      syscalls:sys_enter_vhangup                                   
                 0      syscalls:sys_enter_move_pages                                   
                 0      syscalls:sys_enter_mbind                                    
                 0      syscalls:sys_enter_set_mempolicy                                   
                 0      syscalls:sys_enter_migrate_pages                                   
                 0      syscalls:sys_enter_get_mempolicy                                   
                 0      syscalls:sys_enter_swapoff                                   
                 0      syscalls:sys_enter_swapon                                   
                 0      syscalls:sys_enter_madvise                                   
                 0      syscalls:sys_enter_fadvise64                                   
                 0      syscalls:sys_enter_process_vm_readv                                   
                 0      syscalls:sys_enter_process_vm_writev                                   
                 0      syscalls:sys_enter_msync                                    
                 0      syscalls:sys_enter_mremap                                   
                12      syscalls:sys_enter_mprotect                                   
                 0      syscalls:sys_enter_pkey_mprotect                                   
                 0      syscalls:sys_enter_pkey_alloc                                   
                 0      syscalls:sys_enter_pkey_free                                   
           101,138      syscalls:sys_enter_brk                                      
                27      syscalls:sys_enter_munmap                                   
                 0      syscalls:sys_enter_remap_file_pages                                   
                 0      syscalls:sys_enter_mlock                                    
                 0      syscalls:sys_enter_mlock2                                   
                 0      syscalls:sys_enter_munlock                                   
                 0      syscalls:sys_enter_mlockall                                   
                 0      syscalls:sys_enter_munlockall                                   
                 0      syscalls:sys_enter_mincore                                   
                 0      syscalls:sys_enter_memfd_create                                   
                 0      syscalls:sys_enter_readahead                                   
                 0      syscalls:sys_enter_perf_event_open                                   
                 0      syscalls:sys_enter_bpf                                      
                 0      syscalls:sys_enter_seccomp                                   
                 0      syscalls:sys_enter_kexec_file_load                                   
                 0      syscalls:sys_enter_kexec_load                                   
                 0      syscalls:sys_enter_acct                                     
                 0      syscalls:sys_enter_delete_module                                   
                 0      syscalls:sys_enter_init_module                                   
                 0      syscalls:sys_enter_finit_module                                   
                 0      syscalls:sys_enter_set_robust_list                                   
                 0      syscalls:sys_enter_get_robust_list                                   
                 0      syscalls:sys_enter_futex                                    
            49,928      syscalls:sys_enter_getitimer                                   
                 0      syscalls:sys_enter_alarm                                    
            99,858      syscalls:sys_enter_setitimer                                   
                 0      syscalls:sys_enter_timer_create                                   
                 0      syscalls:sys_enter_timer_gettime                                   
                 0      syscalls:sys_enter_timer_getoverrun                                   
                 0      syscalls:sys_enter_timer_settime                                   
                 0      syscalls:sys_enter_timer_delete                                   
                 0      syscalls:sys_enter_clock_settime                                   
                 0      syscalls:sys_enter_clock_gettime                                   
                 0      syscalls:sys_enter_clock_adjtime                                   
                 0      syscalls:sys_enter_clock_getres                                   
                 0      syscalls:sys_enter_clock_nanosleep                                   
                 0      syscalls:sys_enter_nanosleep                                   
                 0      syscalls:sys_enter_time                                     
                 0      syscalls:sys_enter_gettimeofday                                   
                 0      syscalls:sys_enter_settimeofday                                   
                 0      syscalls:sys_enter_adjtimex                                   
                 0      syscalls:sys_enter_kcmp                                     
                 0      syscalls:sys_enter_syslog                                   
                 0      syscalls:sys_enter_membarrier                                   
                 0      syscalls:sys_enter_sched_setscheduler                                   
                 0      syscalls:sys_enter_sched_setparam                                   
                 0      syscalls:sys_enter_sched_setattr                                   
                 0      syscalls:sys_enter_sched_getscheduler                                   
                 0      syscalls:sys_enter_sched_getparam                                   
                 0      syscalls:sys_enter_sched_getattr                                   
                 0      syscalls:sys_enter_sched_setaffinity                                   
                 0      syscalls:sys_enter_sched_getaffinity                                   
                 0      syscalls:sys_enter_sched_yield                                   
                 0      syscalls:sys_enter_sched_get_priority_max                                   
                 0      syscalls:sys_enter_sched_get_priority_min                                   
                 0      syscalls:sys_enter_sched_rr_get_interval                                   
                 0      syscalls:sys_enter_getgroups                                   
                 0      syscalls:sys_enter_setgroups                                   
                 0      syscalls:sys_enter_reboot                                   
                 0      syscalls:sys_enter_setns                                    
                 0      syscalls:sys_enter_setpriority                                   
                 0      syscalls:sys_enter_getpriority                                   
                 0      syscalls:sys_enter_setregid                                   
                 0      syscalls:sys_enter_setgid                                   
                 0      syscalls:sys_enter_setreuid                                   
                 0      syscalls:sys_enter_setuid                                   
                 0      syscalls:sys_enter_setresuid                                   
                 0      syscalls:sys_enter_getresuid                                   
                 0      syscalls:sys_enter_setresgid                                   
                 0      syscalls:sys_enter_getresgid                                   
                 0      syscalls:sys_enter_setfsuid                                   
                 0      syscalls:sys_enter_setfsgid                                   
                 1      syscalls:sys_enter_getpid                                   
                 0      syscalls:sys_enter_gettid                                   
                 0      syscalls:sys_enter_getppid                                   
                 0      syscalls:sys_enter_getuid                                   
                 0      syscalls:sys_enter_geteuid                                   
                 0      syscalls:sys_enter_getgid                                   
                 0      syscalls:sys_enter_getegid                                   
                 0      syscalls:sys_enter_times                                    
                 0      syscalls:sys_enter_setpgid                                   
                 0      syscalls:sys_enter_getpgid                                   
                 0      syscalls:sys_enter_getpgrp                                   
                 0      syscalls:sys_enter_getsid                                   
                 1      syscalls:sys_enter_setsid                                   
                 0      syscalls:sys_enter_newuname                                   
                 0      syscalls:sys_enter_sethostname                                   
                 0      syscalls:sys_enter_setdomainname                                   
            49,929      syscalls:sys_enter_getrlimit                                   
                 0      syscalls:sys_enter_prlimit64                                   
                 1      syscalls:sys_enter_setrlimit                                   
                 0      syscalls:sys_enter_getrusage                                   
                 0      syscalls:sys_enter_umask                                    
                 0      syscalls:sys_enter_prctl                                    
                 0      syscalls:sys_enter_getcpu                                   
                 1      syscalls:sys_enter_sysinfo                                   
                 0      syscalls:sys_enter_restart_syscall                                   
                 0      syscalls:sys_enter_rt_sigprocmask                                   
                 0      syscalls:sys_enter_rt_sigpending                                   
                 0      syscalls:sys_enter_rt_sigtimedwait                                   
                 0      syscalls:sys_enter_kill                                     
                 0      syscalls:sys_enter_tgkill                                   
                 0      syscalls:sys_enter_tkill                                    
                 0      syscalls:sys_enter_rt_sigqueueinfo                                   
                 0      syscalls:sys_enter_rt_tgsigqueueinfo                                   
                 0      syscalls:sys_enter_sigaltstack                                   
                 8      syscalls:sys_enter_rt_sigaction                                   
                 0      syscalls:sys_enter_pause                                    
                 0      syscalls:sys_enter_rt_sigsuspend                                   
                 0      syscalls:sys_enter_ptrace                                   
                 0      syscalls:sys_enter_capget                                   
                 0      syscalls:sys_enter_capset                                   
                 0      syscalls:sys_enter_sysctl                                   
                 0      syscalls:sys_enter_exit                                     
            49,930      syscalls:sys_enter_exit_group                                   
                 0      syscalls:sys_enter_waitid                                   
            49,928      syscalls:sys_enter_wait4                                    
                 0      syscalls:sys_enter_personality                                   
                 0      syscalls:sys_enter_set_tid_address                                   
                 0      syscalls:sys_enter_fork                                     
                 0      syscalls:sys_enter_vfork                                    
            49,929      syscalls:sys_enter_clone                                    
                 0      syscalls:sys_enter_unshare                                   
            99,925      syscalls:sys_enter_mmap                                     
                 0      syscalls:sys_enter_modify_ldt                                   
                 0      syscalls:sys_enter_iopl                                     
                 2      syscalls:sys_enter_arch_prctl     

```

Snapshot Kernel

```
Profiling information: 
7300 ms total work, 146219 ns/work
22111 ms total running, 442858 ns/run
859 ms total write testcase, 17217 ns/write
303 ms total forking, 6072 ns/fork
19287 ms total purely run, 386298 ns/purely run
7300 ms total pre-fuzzing, 146219 ns/pre-fuzzing
total execution is 49928

      20546.477147      task-clock (msec)         #    0.926 CPUs utilized
           299,305      context-switches          #    0.015 M/sec
             5,998      cpu-migrations            #    0.292 K/sec
         1,911,660      page-faults               #    0.093 M/sec

                 0      syscalls:sys_enter_socket                                   
                 0      syscalls:sys_enter_socketpair                                   
                 0      syscalls:sys_enter_bind                                     
                 0      syscalls:sys_enter_listen                                   
                 0      syscalls:sys_enter_accept4                                   
                 0      syscalls:sys_enter_accept                                   
                 0      syscalls:sys_enter_connect                                   
                 0      syscalls:sys_enter_getsockname                                   
                 0      syscalls:sys_enter_getpeername                                   
                 0      syscalls:sys_enter_sendto                                   
                 0      syscalls:sys_enter_recvfrom                                   
                 0      syscalls:sys_enter_setsockopt                                   
                 0      syscalls:sys_enter_getsockopt                                   
                 0      syscalls:sys_enter_shutdown                                   
                 0      syscalls:sys_enter_sendmsg                                   
                 0      syscalls:sys_enter_sendmmsg                                   
                 0      syscalls:sys_enter_recvmsg                                   
                 0      syscalls:sys_enter_recvmmsg                                   
                 0      syscalls:sys_enter_getrandom                                   
                 0      syscalls:sys_enter_ioprio_set                                   
                 0      syscalls:sys_enter_ioprio_get                                   
                 0      syscalls:sys_enter_add_key                                   
                 0      syscalls:sys_enter_request_key                                   
                 0      syscalls:sys_enter_keyctl                                   
                 0      syscalls:sys_enter_mq_open                                   
                 0      syscalls:sys_enter_mq_unlink                                   
                 0      syscalls:sys_enter_mq_timedsend                                   
                 0      syscalls:sys_enter_mq_timedreceive                                   
                 0      syscalls:sys_enter_mq_notify                                   
                 0      syscalls:sys_enter_mq_getsetattr                                   
                 1      syscalls:sys_enter_shmget                                   
                 2      syscalls:sys_enter_shmctl                                   
                 2      syscalls:sys_enter_shmat                                    
                 0      syscalls:sys_enter_shmdt                                    
                 0      syscalls:sys_enter_semget                                   
                 0      syscalls:sys_enter_semctl                                   
                 0      syscalls:sys_enter_semtimedop                                   
                 0      syscalls:sys_enter_semop                                    
                 0      syscalls:sys_enter_msgget                                   
                 0      syscalls:sys_enter_msgctl                                   
                 0      syscalls:sys_enter_msgsnd                                   
                 0      syscalls:sys_enter_msgrcv                                   
                 0      syscalls:sys_enter_lookup_dcookie                                   
                 0      syscalls:sys_enter_quotactl                                   
                 0      syscalls:sys_enter_name_to_handle_at                                   
                 0      syscalls:sys_enter_open_by_handle_at                                   
                 1      syscalls:sys_enter_flock                                    
                 0      syscalls:sys_enter_io_setup                                   
                 0      syscalls:sys_enter_io_destroy                                   
                 0      syscalls:sys_enter_io_submit                                   
                 0      syscalls:sys_enter_io_cancel                                   
                 0      syscalls:sys_enter_io_getevents                                   
                 0      syscalls:sys_enter_userfaultfd                                   
                 0      syscalls:sys_enter_eventfd2                                   
                 0      syscalls:sys_enter_eventfd                                   
                 0      syscalls:sys_enter_timerfd_create                                   
                 0      syscalls:sys_enter_timerfd_settime                                   
                 0      syscalls:sys_enter_timerfd_gettime                                   
                 0      syscalls:sys_enter_signalfd4                                   
                 0      syscalls:sys_enter_signalfd                                   
                 0      syscalls:sys_enter_epoll_create1                                   
                 0      syscalls:sys_enter_epoll_create                                   
                 0      syscalls:sys_enter_epoll_ctl                                   
                 0      syscalls:sys_enter_epoll_wait                                   
                 0      syscalls:sys_enter_epoll_pwait                                   
                 0      syscalls:sys_enter_fanotify_init                                   
                 0      syscalls:sys_enter_fanotify_mark                                   
                 0      syscalls:sys_enter_inotify_init1                                   
                 0      syscalls:sys_enter_inotify_init                                   
                 0      syscalls:sys_enter_inotify_add_watch                                   
                 0      syscalls:sys_enter_inotify_rm_watch                                   
                 0      syscalls:sys_enter_statfs                                   
                 0      syscalls:sys_enter_fstatfs                                   
                 0      syscalls:sys_enter_ustat                                    
                 0      syscalls:sys_enter_utime                                    
                 0      syscalls:sys_enter_utimensat                                   
                 0      syscalls:sys_enter_futimesat                                   
                 0      syscalls:sys_enter_utimes                                   
                 0      syscalls:sys_enter_sync                                     
                 0      syscalls:sys_enter_syncfs                                   
                 0      syscalls:sys_enter_fsync                                    
                 0      syscalls:sys_enter_fdatasync                                   
                 0      syscalls:sys_enter_sync_file_range                                   
                 0      syscalls:sys_enter_vmsplice                                   
                 0      syscalls:sys_enter_splice                                   
                 0      syscalls:sys_enter_tee                                      
                 0      syscalls:sys_enter_setxattr                                   
                 0      syscalls:sys_enter_lsetxattr                                   
                 0      syscalls:sys_enter_fsetxattr                                   
                 0      syscalls:sys_enter_getxattr                                   
                 0      syscalls:sys_enter_lgetxattr                                   
                 0      syscalls:sys_enter_fgetxattr                                   
                 0      syscalls:sys_enter_listxattr                                   
                 0      syscalls:sys_enter_llistxattr                                   
                 0      syscalls:sys_enter_flistxattr                                   
                 0      syscalls:sys_enter_removexattr                                   
                 0      syscalls:sys_enter_lremovexattr                                   
                 0      syscalls:sys_enter_fremovexattr                                   
                 0      syscalls:sys_enter_umount                                   
                 0      syscalls:sys_enter_mount                                    
                 0      syscalls:sys_enter_pivot_root                                   
                 0      syscalls:sys_enter_sysfs                                    
                 0      syscalls:sys_enter_dup3                                     
                 5      syscalls:sys_enter_dup2                                     
                 0      syscalls:sys_enter_dup                                      
                 1      syscalls:sys_enter_getcwd                                   
                 0      syscalls:sys_enter_select                                   
                 0      syscalls:sys_enter_pselect6                                   
                 0      syscalls:sys_enter_poll                                     
                 0      syscalls:sys_enter_ppoll                                    
                38      syscalls:sys_enter_getdents                                   
                 0      syscalls:sys_enter_getdents64                                   
            35,777      syscalls:sys_enter_ioctl                                    
            99,857      syscalls:sys_enter_fcntl                                    
                 0      syscalls:sys_enter_mknodat                                   
                 0      syscalls:sys_enter_mknod                                    
                 0      syscalls:sys_enter_mkdirat                                   
                 9      syscalls:sys_enter_mkdir                                    
                 8      syscalls:sys_enter_rmdir                                    
                 0      syscalls:sys_enter_unlinkat                                   
            56,174      syscalls:sys_enter_unlink                                   
                 0      syscalls:sys_enter_symlinkat                                   
                 0      syscalls:sys_enter_symlink                                   
                 0      syscalls:sys_enter_linkat                                   
             6,241      syscalls:sys_enter_link                                     
                 0      syscalls:sys_enter_renameat2                                   
                 0      syscalls:sys_enter_renameat                                   
                 0      syscalls:sys_enter_rename                                   
                 0      syscalls:sys_enter_pipe2                                    
                 2      syscalls:sys_enter_pipe                                     
            49,929      syscalls:sys_enter_newstat                                   
             6,243      syscalls:sys_enter_newlstat                                   
                 0      syscalls:sys_enter_newfstatat                                   
           285,351      syscalls:sys_enter_newfstat                                   
                 0      syscalls:sys_enter_readlinkat                                   
                 0      syscalls:sys_enter_readlink                                   
         2,372,152      syscalls:sys_enter_lseek                                    
           411,166      syscalls:sys_enter_read                                     
         1,096,176      syscalls:sys_enter_write                                    
                 0      syscalls:sys_enter_pread64                                   
                 0      syscalls:sys_enter_pwrite64                                   
                 0      syscalls:sys_enter_readv                                    
                 0      syscalls:sys_enter_writev                                   
                 0      syscalls:sys_enter_preadv                                   
                 0      syscalls:sys_enter_preadv2                                   
                 0      syscalls:sys_enter_pwritev                                   
                 0      syscalls:sys_enter_pwritev2                                   
                 0      syscalls:sys_enter_sendfile64                                   
                 0      syscalls:sys_enter_copy_file_range                                   
                 0      syscalls:sys_enter_truncate                                   
                 0      syscalls:sys_enter_ftruncate                                   
                 0      syscalls:sys_enter_fallocate                                   
                 0      syscalls:sys_enter_faccessat                                   
            12,494      syscalls:sys_enter_access                                   
                 0      syscalls:sys_enter_chdir                                    
                 0      syscalls:sys_enter_fchdir                                   
                 0      syscalls:sys_enter_chroot                                   
                 0      syscalls:sys_enter_fchmod                                   
                 0      syscalls:sys_enter_fchmodat                                   
                 0      syscalls:sys_enter_chmod                                    
                 0      syscalls:sys_enter_fchownat                                   
                 0      syscalls:sys_enter_chown                                    
                 0      syscalls:sys_enter_lchown                                   
                 0      syscalls:sys_enter_fchown                                   
         1,216,448      syscalls:sys_enter_open                                     
                 0      syscalls:sys_enter_openat                                   
                 0      syscalls:sys_enter_creat                                    
           263,928      syscalls:sys_enter_close                                    
                 0      syscalls:sys_enter_vhangup                                   
                 0      syscalls:sys_enter_move_pages                                   
                 0      syscalls:sys_enter_mbind                                    
                 0      syscalls:sys_enter_set_mempolicy                                   
                 0      syscalls:sys_enter_migrate_pages                                   
                 0      syscalls:sys_enter_get_mempolicy                                   
                 0      syscalls:sys_enter_swapoff                                   
                 0      syscalls:sys_enter_swapon                                   
                 0      syscalls:sys_enter_madvise                                   
                 0      syscalls:sys_enter_fadvise64                                   
                 0      syscalls:sys_enter_process_vm_readv                                   
                 0      syscalls:sys_enter_process_vm_writev                                   
                 0      syscalls:sys_enter_msync                                    
                 0      syscalls:sys_enter_mremap                                   
                12      syscalls:sys_enter_mprotect                                   
           105,485      syscalls:sys_enter_brk                                      
                 3      syscalls:sys_enter_munmap                                   
                 0      syscalls:sys_enter_remap_file_pages                                   
                 0      syscalls:sys_enter_mlock                                    
                 0      syscalls:sys_enter_mlock2                                   
                 0      syscalls:sys_enter_munlock                                   
                 0      syscalls:sys_enter_mlockall                                   
                 0      syscalls:sys_enter_munlockall                                   
                 0      syscalls:sys_enter_mincore                                   
                 0      syscalls:sys_enter_memfd_create                                   
                 0      syscalls:sys_enter_readahead                                   
                 0      syscalls:sys_enter_membarrier                                   
                 0      syscalls:sys_enter_perf_event_open                                   
                 0      syscalls:sys_enter_bpf                                      
                 0      syscalls:sys_enter_seccomp                                   
                 0      syscalls:sys_enter_kexec_file_load                                   
                 0      syscalls:sys_enter_kexec_load                                   
                 0      syscalls:sys_enter_acct                                     
                 0      syscalls:sys_enter_delete_module                                   
                 0      syscalls:sys_enter_init_module                                   
                 0      syscalls:sys_enter_finit_module                                   
                 0      syscalls:sys_enter_set_robust_list                                   
                 0      syscalls:sys_enter_get_robust_list                                   
                 0      syscalls:sys_enter_futex                                    
                 0      syscalls:sys_enter_timer_create                                   
                 0      syscalls:sys_enter_timer_gettime                                   
                 0      syscalls:sys_enter_timer_getoverrun                                   
                 0      syscalls:sys_enter_timer_settime                                   
                 0      syscalls:sys_enter_timer_delete                                   
                 0      syscalls:sys_enter_clock_settime                                   
                 0      syscalls:sys_enter_clock_gettime                                   
                 0      syscalls:sys_enter_clock_adjtime                                   
                 0      syscalls:sys_enter_clock_getres                                   
                 0      syscalls:sys_enter_clock_nanosleep                                   
            49,928      syscalls:sys_enter_getitimer                                   
            99,858      syscalls:sys_enter_setitimer                                   
                 0      syscalls:sys_enter_nanosleep                                   
                 0      syscalls:sys_enter_alarm                                    
                 0      syscalls:sys_enter_time                                     
                 0      syscalls:sys_enter_gettimeofday                                   
                 0      syscalls:sys_enter_settimeofday                                   
                 0      syscalls:sys_enter_adjtimex                                   
                 0      syscalls:sys_enter_kcmp                                     
                 0      syscalls:sys_enter_syslog                                   
                 0      syscalls:sys_enter_sched_setscheduler                                   
                 0      syscalls:sys_enter_sched_setparam                                   
                 0      syscalls:sys_enter_sched_setattr                                   
                 0      syscalls:sys_enter_sched_getscheduler                                   
                 0      syscalls:sys_enter_sched_getparam                                   
                 0      syscalls:sys_enter_sched_getattr                                   
                 0      syscalls:sys_enter_sched_setaffinity                                   
                 0      syscalls:sys_enter_sched_getaffinity                                   
                 0      syscalls:sys_enter_sched_yield                                   
                 0      syscalls:sys_enter_sched_get_priority_max                                   
                 0      syscalls:sys_enter_sched_get_priority_min                                   
                 0      syscalls:sys_enter_sched_rr_get_interval                                   
                 0      syscalls:sys_enter_getgroups                                   
                 0      syscalls:sys_enter_setgroups                                   
            99,856      syscalls:sys_enter_snapshot                                   
                 0      syscalls:sys_enter_reboot                                   
                 0      syscalls:sys_enter_setns                                    
                 0      syscalls:sys_enter_setpriority                                   
                 0      syscalls:sys_enter_getpriority                                   
                 0      syscalls:sys_enter_setregid                                   
                 0      syscalls:sys_enter_setgid                                   
                 0      syscalls:sys_enter_setreuid                                   
                 0      syscalls:sys_enter_setuid                                   
                 0      syscalls:sys_enter_setresuid                                   
                 0      syscalls:sys_enter_getresuid                                   
                 0      syscalls:sys_enter_setresgid                                   
                 0      syscalls:sys_enter_getresgid                                   
                 0      syscalls:sys_enter_setfsuid                                   
                 0      syscalls:sys_enter_setfsgid                                   
                 1      syscalls:sys_enter_getpid                                   
                 0      syscalls:sys_enter_gettid                                   
                 0      syscalls:sys_enter_getppid                                   
                 0      syscalls:sys_enter_getuid                                   
                 0      syscalls:sys_enter_geteuid                                   
                 0      syscalls:sys_enter_getgid                                   
                 0      syscalls:sys_enter_getegid                                   
                 0      syscalls:sys_enter_times                                    
                 0      syscalls:sys_enter_setpgid                                   
                 0      syscalls:sys_enter_getpgid                                   
                 0      syscalls:sys_enter_getpgrp                                   
                 0      syscalls:sys_enter_getsid                                   
                 1      syscalls:sys_enter_setsid                                   
                 0      syscalls:sys_enter_newuname                                   
                 0      syscalls:sys_enter_sethostname                                   
                 0      syscalls:sys_enter_setdomainname                                   
            49,929      syscalls:sys_enter_getrlimit                                   
                 0      syscalls:sys_enter_prlimit64                                   
                 2      syscalls:sys_enter_setrlimit                                   
                 0      syscalls:sys_enter_getrusage                                   
                 0      syscalls:sys_enter_umask                                    
                 0      syscalls:sys_enter_prctl                                    
                 0      syscalls:sys_enter_getcpu                                   
                 1      syscalls:sys_enter_sysinfo                                   
                 0      syscalls:sys_enter_restart_syscall                                   
             4,385      syscalls:sys_enter_rt_sigprocmask                                   
                 0      syscalls:sys_enter_rt_sigpending                                   
                 0      syscalls:sys_enter_rt_sigtimedwait                                   
            49,927      syscalls:sys_enter_kill                                     
            49,928      syscalls:sys_enter_tgkill                                   
                 0      syscalls:sys_enter_tkill                                    
                 0      syscalls:sys_enter_rt_sigqueueinfo                                   
                 0      syscalls:sys_enter_rt_tgsigqueueinfo                                   
                 0      syscalls:sys_enter_sigaltstack                                   
                 8      syscalls:sys_enter_rt_sigaction                                   
                 0      syscalls:sys_enter_pause                                    
                 0      syscalls:sys_enter_rt_sigsuspend                                   
                 0      syscalls:sys_enter_ptrace                                   
                 0      syscalls:sys_enter_capget                                   
                 0      syscalls:sys_enter_capset                                   
                 0      syscalls:sys_enter_sysctl                                   
                 0      syscalls:sys_enter_exit                                     
                 2      syscalls:sys_enter_exit_group                                   
                 0      syscalls:sys_enter_waitid                                   
            49,928      syscalls:sys_enter_wait4                                    
                 0      syscalls:sys_enter_personality                                   
                 0      syscalls:sys_enter_set_tid_address                                   
                 0      syscalls:sys_enter_unshare                                   
            50,311      syscalls:sys_enter_mmap              

```

Persistent Mode

```
Profiling information: 
7305 ms total work, 146141 ns/work,             
13410 ms total running, 268259 ns/run, 
952 ms total write testcase, 19046 ns/write             
539 ms total forking, 10798 ns/fork, 
10973 ms total purely run, 219497 ns/purely run             
37606 ns/system running, 165026 ns/user running             
7305 ms total pre-fuzzing, 146141 ns/pre-fuzzing,             
0 ms total post-fuzzing, 0 ns/post-fuzzing
total execution is 50728

       9290.189403      task-clock (msec)         #    0.884 CPUs utilized
           298,029      context-switches          #    0.032 M/sec
            13,865      cpu-migrations            #    0.001 M/sec
             4,315      page-faults               #    0.464 K/sec

                 0      syscalls:sys_enter_socket                                   
                 0      syscalls:sys_enter_socketpair                                   
                 0      syscalls:sys_enter_bind                                     
                 0      syscalls:sys_enter_listen                                   
                 0      syscalls:sys_enter_accept4                                   
                 0      syscalls:sys_enter_accept                                   
                 0      syscalls:sys_enter_connect                                   
                 0      syscalls:sys_enter_getsockname                                   
                 0      syscalls:sys_enter_getpeername                                   
                 0      syscalls:sys_enter_sendto                                   
                 0      syscalls:sys_enter_recvfrom                                   
                 0      syscalls:sys_enter_setsockopt                                   
                 0      syscalls:sys_enter_getsockopt                                   
                 0      syscalls:sys_enter_shutdown                                   
                 0      syscalls:sys_enter_sendmsg                                   
                 0      syscalls:sys_enter_sendmmsg                                   
                 0      syscalls:sys_enter_recvmsg                                   
                 0      syscalls:sys_enter_recvmmsg                                   
                 0      syscalls:sys_enter_getrandom                                   
                 0      syscalls:sys_enter_ioprio_set                                   
                 0      syscalls:sys_enter_ioprio_get                                   
                 0      syscalls:sys_enter_add_key                                   
                 0      syscalls:sys_enter_request_key                                   
                 0      syscalls:sys_enter_keyctl                                   
                 0      syscalls:sys_enter_mq_open                                   
                 0      syscalls:sys_enter_mq_unlink                                   
                 0      syscalls:sys_enter_mq_timedsend                                   
                 0      syscalls:sys_enter_mq_timedreceive                                   
                 0      syscalls:sys_enter_mq_notify                                   
                 0      syscalls:sys_enter_mq_getsetattr                                   
                 1      syscalls:sys_enter_shmget                                   
                 2      syscalls:sys_enter_shmctl                                   
                 2      syscalls:sys_enter_shmat                                    
                 0      syscalls:sys_enter_shmdt                                    
                 0      syscalls:sys_enter_semget                                   
                 0      syscalls:sys_enter_semctl                                   
                 0      syscalls:sys_enter_semtimedop                                   
                 0      syscalls:sys_enter_semop                                    
                 0      syscalls:sys_enter_msgget                                   
                 0      syscalls:sys_enter_msgctl                                   
                 0      syscalls:sys_enter_msgsnd                                   
                 0      syscalls:sys_enter_msgrcv                                   
                 0      syscalls:sys_enter_lookup_dcookie                                   
                 0      syscalls:sys_enter_quotactl                                   
                 0      syscalls:sys_enter_name_to_handle_at                                   
                 0      syscalls:sys_enter_open_by_handle_at                                   
                 1      syscalls:sys_enter_flock                                    
                 0      syscalls:sys_enter_io_setup                                   
                 0      syscalls:sys_enter_io_destroy                                   
                 0      syscalls:sys_enter_io_submit                                   
                 0      syscalls:sys_enter_io_cancel                                   
                 0      syscalls:sys_enter_io_getevents                                   
                 0      syscalls:sys_enter_userfaultfd                                   
                 0      syscalls:sys_enter_eventfd2                                   
                 0      syscalls:sys_enter_eventfd                                   
                 0      syscalls:sys_enter_timerfd_create                                   
                 0      syscalls:sys_enter_timerfd_settime                                   
                 0      syscalls:sys_enter_timerfd_gettime                                   
                 0      syscalls:sys_enter_signalfd4                                   
                 0      syscalls:sys_enter_signalfd                                   
                 0      syscalls:sys_enter_epoll_create1                                   
                 0      syscalls:sys_enter_epoll_create                                   
                 0      syscalls:sys_enter_epoll_ctl                                   
                 0      syscalls:sys_enter_epoll_wait                                   
                 0      syscalls:sys_enter_epoll_pwait                                   
                 0      syscalls:sys_enter_fanotify_init                                   
                 0      syscalls:sys_enter_fanotify_mark                                   
                 0      syscalls:sys_enter_inotify_init1                                   
                 0      syscalls:sys_enter_inotify_init                                   
                 0      syscalls:sys_enter_inotify_add_watch                                   
                 0      syscalls:sys_enter_inotify_rm_watch                                   
                 0      syscalls:sys_enter_statfs                                   
                 0      syscalls:sys_enter_fstatfs                                   
                 0      syscalls:sys_enter_ustat                                    
                 0      syscalls:sys_enter_utime                                    
                 0      syscalls:sys_enter_utimensat                                   
                 0      syscalls:sys_enter_futimesat                                   
                 0      syscalls:sys_enter_utimes                                   
                 0      syscalls:sys_enter_sync                                     
                 0      syscalls:sys_enter_syncfs                                   
                 0      syscalls:sys_enter_fsync                                    
                 0      syscalls:sys_enter_fdatasync                                   
                 0      syscalls:sys_enter_sync_file_range                                   
                 0      syscalls:sys_enter_vmsplice                                   
                 0      syscalls:sys_enter_splice                                   
                 0      syscalls:sys_enter_tee                                      
                 0      syscalls:sys_enter_setxattr                                   
                 0      syscalls:sys_enter_lsetxattr                                   
                 0      syscalls:sys_enter_fsetxattr                                   
                 0      syscalls:sys_enter_getxattr                                   
                 0      syscalls:sys_enter_lgetxattr                                   
                 0      syscalls:sys_enter_fgetxattr                                   
                 0      syscalls:sys_enter_listxattr                                   
                 0      syscalls:sys_enter_llistxattr                                   
                 0      syscalls:sys_enter_flistxattr                                   
                 0      syscalls:sys_enter_removexattr                                   
                 0      syscalls:sys_enter_lremovexattr                                   
                 0      syscalls:sys_enter_fremovexattr                                   
                 0      syscalls:sys_enter_umount                                   
                 0      syscalls:sys_enter_mount                                    
                 0      syscalls:sys_enter_pivot_root                                   
                 0      syscalls:sys_enter_sysfs                                    
                 0      syscalls:sys_enter_dup3                                     
                 5      syscalls:sys_enter_dup2                                     
                 0      syscalls:sys_enter_dup                                      
                 1      syscalls:sys_enter_getcwd                                   
                 0      syscalls:sys_enter_select                                   
                 0      syscalls:sys_enter_pselect6                                   
                 0      syscalls:sys_enter_poll                                     
                 0      syscalls:sys_enter_ppoll                                    
                38      syscalls:sys_enter_getdents                                   
                 0      syscalls:sys_enter_getdents64                                   
                 7      syscalls:sys_enter_ioctl                                    
            26,137      syscalls:sys_enter_fcntl                                    
                 0      syscalls:sys_enter_mknodat                                   
                 0      syscalls:sys_enter_mknod                                    
                 0      syscalls:sys_enter_mkdirat                                   
                 9      syscalls:sys_enter_mkdir                                    
                 8      syscalls:sys_enter_rmdir                                    
                 0      syscalls:sys_enter_unlinkat                                   
            56,378      syscalls:sys_enter_unlink                                   
                 0      syscalls:sys_enter_symlinkat                                   
                12      syscalls:sys_enter_symlink                                   
                 0      syscalls:sys_enter_linkat                                   
             6,241      syscalls:sys_enter_link                                     
                 0      syscalls:sys_enter_renameat2                                   
                 0      syscalls:sys_enter_renameat                                   
                 0      syscalls:sys_enter_rename                                   
                 0      syscalls:sys_enter_pipe2                                    
                 2      syscalls:sys_enter_pipe                                     
                 1      syscalls:sys_enter_execve                                   
                 0      syscalls:sys_enter_execveat                                   
            13,069      syscalls:sys_enter_newstat                                   
             6,243      syscalls:sys_enter_newlstat                                   
                 0      syscalls:sys_enter_newfstatat                                   
            26,171      syscalls:sys_enter_newfstat                                   
                 0      syscalls:sys_enter_readlinkat                                   
                 0      syscalls:sys_enter_readlink                                   
                 0      syscalls:sys_enter_statx                                    
           617,896      syscalls:sys_enter_lseek                                    
           211,550      syscalls:sys_enter_read                                     
         1,461,989      syscalls:sys_enter_write                                    
                 0      syscalls:sys_enter_pread64                                   
                 0      syscalls:sys_enter_pwrite64                                   
                 0      syscalls:sys_enter_readv                                    
                 0      syscalls:sys_enter_writev                                   
                 0      syscalls:sys_enter_preadv                                   
                 0      syscalls:sys_enter_preadv2                                   
                 0      syscalls:sys_enter_pwritev                                   
                 0      syscalls:sys_enter_pwritev2                                   
                 0      syscalls:sys_enter_sendfile64                                   
                 0      syscalls:sys_enter_copy_file_range                                   
                 0      syscalls:sys_enter_truncate                                   
                 0      syscalls:sys_enter_ftruncate                                   
                 0      syscalls:sys_enter_fallocate                                   
                 0      syscalls:sys_enter_faccessat                                   
            12,494      syscalls:sys_enter_access                                   
                 0      syscalls:sys_enter_chdir                                    
                 0      syscalls:sys_enter_fchdir                                   
                 0      syscalls:sys_enter_chroot                                   
                 0      syscalls:sys_enter_fchmod                                   
                 0      syscalls:sys_enter_fchmodat                                   
                 0      syscalls:sys_enter_chmod                                    
                 0      syscalls:sys_enter_fchownat                                   
                 0      syscalls:sys_enter_chown                                    
                 0      syscalls:sys_enter_lchown                                   
                 0      syscalls:sys_enter_fchown                                   
            82,100      syscalls:sys_enter_open                                     
                 0      syscalls:sys_enter_openat                                   
                 0      syscalls:sys_enter_creat                                    
            81,960      syscalls:sys_enter_close                                    
                 0      syscalls:sys_enter_vhangup                                   
                 0      syscalls:sys_enter_move_pages                                   
                 0      syscalls:sys_enter_mbind                                    
                 0      syscalls:sys_enter_set_mempolicy                                   
                 0      syscalls:sys_enter_migrate_pages                                   
                 0      syscalls:sys_enter_get_mempolicy                                   
                 0      syscalls:sys_enter_swapoff                                   
                 0      syscalls:sys_enter_swapon                                   
                 0      syscalls:sys_enter_madvise                                   
                 0      syscalls:sys_enter_fadvise64                                   
                 0      syscalls:sys_enter_process_vm_readv                                   
                 0      syscalls:sys_enter_process_vm_writev                                   
                 0      syscalls:sys_enter_msync                                    
                 0      syscalls:sys_enter_mremap                                   
                12      syscalls:sys_enter_mprotect                                   
                 0      syscalls:sys_enter_pkey_mprotect                                   
                 0      syscalls:sys_enter_pkey_alloc                                   
                 0      syscalls:sys_enter_pkey_free                                   
               872      syscalls:sys_enter_brk                                      
                 3      syscalls:sys_enter_munmap                                   
                 0      syscalls:sys_enter_remap_file_pages                                   
                 0      syscalls:sys_enter_mlock                                    
                 0      syscalls:sys_enter_mlock2                                   
                 0      syscalls:sys_enter_munlock                                   
                 0      syscalls:sys_enter_mlockall                                   
                 0      syscalls:sys_enter_munlockall                                   
                 0      syscalls:sys_enter_mincore                                   
                 0      syscalls:sys_enter_memfd_create                                   
                 0      syscalls:sys_enter_readahead                                   
                 0      syscalls:sys_enter_perf_event_open                                   
                 0      syscalls:sys_enter_bpf                                      
                 0      syscalls:sys_enter_seccomp                                   
                 0      syscalls:sys_enter_kexec_file_load                                   
                 0      syscalls:sys_enter_kexec_load                                   
                 0      syscalls:sys_enter_acct                                     
                 0      syscalls:sys_enter_delete_module                                   
                 0      syscalls:sys_enter_init_module                                   
                 0      syscalls:sys_enter_finit_module                                   
                 0      syscalls:sys_enter_set_robust_list                                   
                 0      syscalls:sys_enter_get_robust_list                                   
                 0      syscalls:sys_enter_futex                                    
            50,120      syscalls:sys_enter_getitimer                                   
                 0      syscalls:sys_enter_alarm                                    
           100,242      syscalls:sys_enter_setitimer                                   
                 0      syscalls:sys_enter_timer_create                                   
                 0      syscalls:sys_enter_timer_gettime                                   
                 0      syscalls:sys_enter_timer_getoverrun                                   
                 0      syscalls:sys_enter_timer_settime                                   
                 0      syscalls:sys_enter_timer_delete                                   
                 0      syscalls:sys_enter_clock_settime                                   
                 0      syscalls:sys_enter_clock_gettime                                   
                 0      syscalls:sys_enter_clock_adjtime                                   
                 0      syscalls:sys_enter_clock_getres                                   
                 0      syscalls:sys_enter_clock_nanosleep                                   
                 0      syscalls:sys_enter_nanosleep                                   
                 0      syscalls:sys_enter_time                                     
                 0      syscalls:sys_enter_gettimeofday                                   
                 0      syscalls:sys_enter_settimeofday                                   
                 0      syscalls:sys_enter_adjtimex                                   
                 0      syscalls:sys_enter_kcmp                                     
                 0      syscalls:sys_enter_syslog                                   
                 0      syscalls:sys_enter_membarrier                                   
                 0      syscalls:sys_enter_sched_setscheduler                                   
                 0      syscalls:sys_enter_sched_setparam                                   
                 0      syscalls:sys_enter_sched_setattr                                   
                 0      syscalls:sys_enter_sched_getscheduler                                   
                 0      syscalls:sys_enter_sched_getparam                                   
                 0      syscalls:sys_enter_sched_getattr                                   
                 0      syscalls:sys_enter_sched_setaffinity                                   
                 0      syscalls:sys_enter_sched_getaffinity                                   
                 0      syscalls:sys_enter_sched_yield                                   
                 0      syscalls:sys_enter_sched_get_priority_max                                   
                 0      syscalls:sys_enter_sched_get_priority_min                                   
                 0      syscalls:sys_enter_sched_rr_get_interval                                   
                 0      syscalls:sys_enter_getgroups                                   
                 0      syscalls:sys_enter_setgroups                                   
                 0      syscalls:sys_enter_reboot                                   
                 0      syscalls:sys_enter_setns                                    
                 0      syscalls:sys_enter_setpriority                                   
                 0      syscalls:sys_enter_getpriority                                   
                 0      syscalls:sys_enter_setregid                                   
                 0      syscalls:sys_enter_setgid                                   
                 0      syscalls:sys_enter_setreuid                                   
                 0      syscalls:sys_enter_setuid                                   
                 0      syscalls:sys_enter_setresuid                                   
                 0      syscalls:sys_enter_getresuid                                   
                 0      syscalls:sys_enter_setresgid                                   
                 0      syscalls:sys_enter_getresgid                                   
                 0      syscalls:sys_enter_setfsuid                                   
                 0      syscalls:sys_enter_setfsgid                                   
                 1      syscalls:sys_enter_getpid                                   
                 0      syscalls:sys_enter_gettid                                   
                 0      syscalls:sys_enter_getppid                                   
                 0      syscalls:sys_enter_getuid                                   
                 0      syscalls:sys_enter_geteuid                                   
                 0      syscalls:sys_enter_getgid                                   
                 0      syscalls:sys_enter_getegid                                   
                 0      syscalls:sys_enter_times                                    
                 0      syscalls:sys_enter_setpgid                                   
                 0      syscalls:sys_enter_getpgid                                   
                 0      syscalls:sys_enter_getpgrp                                   
                 0      syscalls:sys_enter_getsid                                   
                 1      syscalls:sys_enter_setsid                                   
                 0      syscalls:sys_enter_newuname                                   
                 0      syscalls:sys_enter_sethostname                                   
                 0      syscalls:sys_enter_setdomainname                                   
                 7      syscalls:sys_enter_getrlimit                                   
                 0      syscalls:sys_enter_prlimit64                                   
                 1      syscalls:sys_enter_setrlimit                                   
                 0      syscalls:sys_enter_getrusage                                   
                 0      syscalls:sys_enter_umask                                    
                 0      syscalls:sys_enter_prctl                                    
                 0      syscalls:sys_enter_getcpu                                   
                 1      syscalls:sys_enter_sysinfo                                   
                 0      syscalls:sys_enter_restart_syscall                                   
            37,062      syscalls:sys_enter_rt_sigprocmask                                   
                 0      syscalls:sys_enter_rt_sigpending                                   
                 0      syscalls:sys_enter_rt_sigtimedwait                                   
            50,114      syscalls:sys_enter_kill                                     
            50,115      syscalls:sys_enter_tgkill                                   
                 0      syscalls:sys_enter_tkill                                    
                 0      syscalls:sys_enter_rt_sigqueueinfo                                   
                 0      syscalls:sys_enter_rt_tgsigqueueinfo                                   
                 0      syscalls:sys_enter_sigaltstack                                   
                 8      syscalls:sys_enter_rt_sigaction                                   
                 0      syscalls:sys_enter_pause                                    
                 0      syscalls:sys_enter_rt_sigsuspend                                   
                 0      syscalls:sys_enter_ptrace                                   
                 0      syscalls:sys_enter_capget                                   
                 0      syscalls:sys_enter_capset                                   
                 0      syscalls:sys_enter_sysctl                                   
                 0      syscalls:sys_enter_exit                                     
                 7      syscalls:sys_enter_exit_group                                   
                 0      syscalls:sys_enter_waitid                                   
            50,120      syscalls:sys_enter_wait4                                    
                 0      syscalls:sys_enter_personality                                   
                 0      syscalls:sys_enter_set_tid_address                                   
                 0      syscalls:sys_enter_fork                                     
                 0      syscalls:sys_enter_vfork                                    
                 7      syscalls:sys_enter_clone                                    
                 0      syscalls:sys_enter_unshare                                   
                33      syscalls:sys_enter_mmap                                     
                 0      syscalls:sys_enter_modify_ldt                                   
                 0      syscalls:sys_enter_iopl                                     
                 2      syscalls:sys_enter_arch_prctl        
```


Persitent Mode (VAR)

```
 Profiling information: 
7370 ms total work, 147613 ns/work,             
12736 ms total running, 255096 ns/run, 
1072 ms total write testcase, 21482 ns/write             
347 ms total forking, 6965 ns/fork, 
10335 ms total purely run, 207004 ns/purely run             
48469 ns/system running, 136596 ns/user running             
7370 ms total pre-fuzzing, 147613 ns/pre-fuzzing,             
0 ms total post-fuzzing, 0 ns/post-fuzzing
total execution is 49928

      13825.172922      task-clock (msec)         #    0.911 CPUs utilized
           298,068      context-switches          #    0.022 M/sec
             9,094      cpu-migrations            #    0.658 K/sec
            34,390      page-faults               #    0.002 M/sec

                 0      syscalls:sys_enter_socket                                   
                 0      syscalls:sys_enter_socketpair                                   
                 0      syscalls:sys_enter_bind                                     
                 0      syscalls:sys_enter_listen                                   
                 0      syscalls:sys_enter_accept4                                   
                 0      syscalls:sys_enter_accept                                   
                 0      syscalls:sys_enter_connect                                   
                 0      syscalls:sys_enter_getsockname                                   
                 0      syscalls:sys_enter_getpeername                                   
                 0      syscalls:sys_enter_sendto                                   
                 0      syscalls:sys_enter_recvfrom                                   
                 0      syscalls:sys_enter_setsockopt                                   
                 0      syscalls:sys_enter_getsockopt                                   
                 0      syscalls:sys_enter_shutdown                                   
                 0      syscalls:sys_enter_sendmsg                                   
                 0      syscalls:sys_enter_sendmmsg                                   
                 0      syscalls:sys_enter_recvmsg                                   
                 0      syscalls:sys_enter_recvmmsg                                   
                 0      syscalls:sys_enter_getrandom                                   
                 0      syscalls:sys_enter_ioprio_set                                   
                 0      syscalls:sys_enter_ioprio_get                                   
                 0      syscalls:sys_enter_add_key                                   
                 0      syscalls:sys_enter_request_key                                   
                 0      syscalls:sys_enter_keyctl                                   
                 0      syscalls:sys_enter_mq_open                                   
                 0      syscalls:sys_enter_mq_unlink                                   
                 0      syscalls:sys_enter_mq_timedsend                                   
                 0      syscalls:sys_enter_mq_timedreceive                                   
                 0      syscalls:sys_enter_mq_notify                                   
                 0      syscalls:sys_enter_mq_getsetattr                                   
                 1      syscalls:sys_enter_shmget                                   
                 2      syscalls:sys_enter_shmctl                                   
                 2      syscalls:sys_enter_shmat                                    
                 0      syscalls:sys_enter_shmdt                                    
                 0      syscalls:sys_enter_semget                                   
                 0      syscalls:sys_enter_semctl                                   
                 0      syscalls:sys_enter_semtimedop                                   
                 0      syscalls:sys_enter_semop                                    
                 0      syscalls:sys_enter_msgget                                   
                 0      syscalls:sys_enter_msgctl                                   
                 0      syscalls:sys_enter_msgsnd                                   
                 0      syscalls:sys_enter_msgrcv                                   
                 0      syscalls:sys_enter_lookup_dcookie                                   
                 0      syscalls:sys_enter_quotactl                                   
                 0      syscalls:sys_enter_name_to_handle_at                                   
                 0      syscalls:sys_enter_open_by_handle_at                                   
                 1      syscalls:sys_enter_flock                                    
                 0      syscalls:sys_enter_io_setup                                   
                 0      syscalls:sys_enter_io_destroy                                   
                 0      syscalls:sys_enter_io_submit                                   
                 0      syscalls:sys_enter_io_cancel                                   
                 0      syscalls:sys_enter_io_getevents                                   
                 0      syscalls:sys_enter_userfaultfd                                   
                 0      syscalls:sys_enter_eventfd2                                   
                 0      syscalls:sys_enter_eventfd                                   
                 0      syscalls:sys_enter_timerfd_create                                   
                 0      syscalls:sys_enter_timerfd_settime                                   
                 0      syscalls:sys_enter_timerfd_gettime                                   
                 0      syscalls:sys_enter_signalfd4                                   
                 0      syscalls:sys_enter_signalfd                                   
                 0      syscalls:sys_enter_epoll_create1                                   
                 0      syscalls:sys_enter_epoll_create                                   
                 0      syscalls:sys_enter_epoll_ctl                                   
                 0      syscalls:sys_enter_epoll_wait                                   
                 0      syscalls:sys_enter_epoll_pwait                                   
                 0      syscalls:sys_enter_fanotify_init                                   
                 0      syscalls:sys_enter_fanotify_mark                                   
                 0      syscalls:sys_enter_inotify_init1                                   
                 0      syscalls:sys_enter_inotify_init                                   
                 0      syscalls:sys_enter_inotify_add_watch                                   
                 0      syscalls:sys_enter_inotify_rm_watch                                   
                 0      syscalls:sys_enter_statfs                                   
                 0      syscalls:sys_enter_fstatfs                                   
                 0      syscalls:sys_enter_ustat                                    
                 0      syscalls:sys_enter_utime                                    
                 0      syscalls:sys_enter_utimensat                                   
                 0      syscalls:sys_enter_futimesat                                   
                 0      syscalls:sys_enter_utimes                                   
                 0      syscalls:sys_enter_sync                                     
                 0      syscalls:sys_enter_syncfs                                   
                 0      syscalls:sys_enter_fsync                                    
                 0      syscalls:sys_enter_fdatasync                                   
                 0      syscalls:sys_enter_sync_file_range                                   
                 0      syscalls:sys_enter_vmsplice                                   
                 0      syscalls:sys_enter_splice                                   
                 0      syscalls:sys_enter_tee                                      
                 0      syscalls:sys_enter_setxattr                                   
                 0      syscalls:sys_enter_lsetxattr                                   
                 0      syscalls:sys_enter_fsetxattr                                   
                 0      syscalls:sys_enter_getxattr                                   
                 0      syscalls:sys_enter_lgetxattr                                   
                 0      syscalls:sys_enter_fgetxattr                                   
                 0      syscalls:sys_enter_listxattr                                   
                 0      syscalls:sys_enter_llistxattr                                   
                 0      syscalls:sys_enter_flistxattr                                   
                 0      syscalls:sys_enter_removexattr                                   
                 0      syscalls:sys_enter_lremovexattr                                   
                 0      syscalls:sys_enter_fremovexattr                                   
                 0      syscalls:sys_enter_umount                                   
                 0      syscalls:sys_enter_mount                                    
                 0      syscalls:sys_enter_pivot_root                                   
                 0      syscalls:sys_enter_sysfs                                    
                 0      syscalls:sys_enter_dup3                                     
                 5      syscalls:sys_enter_dup2                                     
                 0      syscalls:sys_enter_dup                                      
                 1      syscalls:sys_enter_getcwd                                   
                 0      syscalls:sys_enter_select                                   
                 0      syscalls:sys_enter_pselect6                                   
                 0      syscalls:sys_enter_poll                                     
                 0      syscalls:sys_enter_ppoll                                    
                38      syscalls:sys_enter_getdents                                   
                 0      syscalls:sys_enter_getdents64                                   
                 6      syscalls:sys_enter_ioctl                                    
            87,765      syscalls:sys_enter_fcntl                                    
                 0      syscalls:sys_enter_mknodat                                   
                 0      syscalls:sys_enter_mknod                                    
                 0      syscalls:sys_enter_mkdirat                                   
                 9      syscalls:sys_enter_mkdir                                    
                 8      syscalls:sys_enter_rmdir                                    
                 0      syscalls:sys_enter_unlinkat                                   
            56,240      syscalls:sys_enter_unlink                                   
                 0      syscalls:sys_enter_symlinkat                                   
                 2      syscalls:sys_enter_symlink                                   
                 0      syscalls:sys_enter_linkat                                   
             6,241      syscalls:sys_enter_link                                     
                 0      syscalls:sys_enter_renameat2                                   
                 0      syscalls:sys_enter_renameat                                   
                 0      syscalls:sys_enter_rename                                   
                 0      syscalls:sys_enter_pipe2                                    
                 2      syscalls:sys_enter_pipe                                     
                 1      syscalls:sys_enter_execve                                   
                 0      syscalls:sys_enter_execveat                                   
            49,993      syscalls:sys_enter_newstat                                   
             6,243      syscalls:sys_enter_newlstat                                   
                 0      syscalls:sys_enter_newfstatat                                   
            87,796      syscalls:sys_enter_newfstat                                   
                 0      syscalls:sys_enter_readlinkat                                   
                 0      syscalls:sys_enter_readlink                                   
                 0      syscalls:sys_enter_statx                                    
         2,102,551      syscalls:sys_enter_lseek                                    
           390,806      syscalls:sys_enter_read                                     
           963,924      syscalls:sys_enter_write                                    
                 0      syscalls:sys_enter_pread64                                   
                 0      syscalls:sys_enter_pwrite64                                   
                 0      syscalls:sys_enter_readv                                    
                 0      syscalls:sys_enter_writev                                   
                 0      syscalls:sys_enter_preadv                                   
                 0      syscalls:sys_enter_preadv2                                   
                 0      syscalls:sys_enter_pwritev                                   
                 0      syscalls:sys_enter_pwritev2                                   
                 0      syscalls:sys_enter_sendfile64                                   
                 0      syscalls:sys_enter_copy_file_range                                   
                 0      syscalls:sys_enter_truncate                                   
                 0      syscalls:sys_enter_ftruncate                                   
                 0      syscalls:sys_enter_fallocate                                   
                 0      syscalls:sys_enter_faccessat                                   
            12,494      syscalls:sys_enter_access                                   
                 0      syscalls:sys_enter_chdir                                    
                 0      syscalls:sys_enter_fchdir                                   
                 0      syscalls:sys_enter_chroot                                   
                 0      syscalls:sys_enter_fchmod                                   
                 0      syscalls:sys_enter_fchmodat                                   
                 0      syscalls:sys_enter_chmod                                    
                 0      syscalls:sys_enter_fchownat                                   
                 0      syscalls:sys_enter_chown                                    
                 0      syscalls:sys_enter_lchown                                   
                 0      syscalls:sys_enter_fchown                                   
           118,893      syscalls:sys_enter_open                                     
                 0      syscalls:sys_enter_openat                                   
                 0      syscalls:sys_enter_creat                                    
           110,132      syscalls:sys_enter_close                                    
                 0      syscalls:sys_enter_vhangup                                   
                 0      syscalls:sys_enter_move_pages                                   
                 0      syscalls:sys_enter_mbind                                    
                 0      syscalls:sys_enter_set_mempolicy                                   
                 0      syscalls:sys_enter_migrate_pages                                   
                 0      syscalls:sys_enter_get_mempolicy                                   
                 0      syscalls:sys_enter_swapoff                                   
                 0      syscalls:sys_enter_swapon                                   
                 0      syscalls:sys_enter_madvise                                   
                 0      syscalls:sys_enter_fadvise64                                   
                 0      syscalls:sys_enter_process_vm_readv                                   
                 0      syscalls:sys_enter_process_vm_writev                                   
                 0      syscalls:sys_enter_msync                                    
                 0      syscalls:sys_enter_mremap                                   
                12      syscalls:sys_enter_mprotect                                   
                 0      syscalls:sys_enter_pkey_mprotect                                   
                 0      syscalls:sys_enter_pkey_alloc                                   
                 0      syscalls:sys_enter_pkey_free                                   
             1,722      syscalls:sys_enter_brk                                      
                 6      syscalls:sys_enter_munmap                                   
                 0      syscalls:sys_enter_remap_file_pages                                   
                 0      syscalls:sys_enter_mlock                                    
                 0      syscalls:sys_enter_mlock2                                   
                 0      syscalls:sys_enter_munlock                                   
                 0      syscalls:sys_enter_mlockall                                   
                 0      syscalls:sys_enter_munlockall                                   
                 0      syscalls:sys_enter_mincore                                   
                 0      syscalls:sys_enter_memfd_create                                   
                 0      syscalls:sys_enter_readahead                                   
                 0      syscalls:sys_enter_perf_event_open                                   
                 0      syscalls:sys_enter_bpf                                      
                 0      syscalls:sys_enter_seccomp                                   
                 0      syscalls:sys_enter_kexec_file_load                                   
                 0      syscalls:sys_enter_kexec_load                                   
                 0      syscalls:sys_enter_acct                                     
                 0      syscalls:sys_enter_delete_module                                   
                 0      syscalls:sys_enter_init_module                                   
                 0      syscalls:sys_enter_finit_module                                   
                 0      syscalls:sys_enter_set_robust_list                                   
                 0      syscalls:sys_enter_get_robust_list                                   
                 0      syscalls:sys_enter_futex                                    
            49,992      syscalls:sys_enter_getitimer                                   
                 0      syscalls:sys_enter_alarm                                    
            99,986      syscalls:sys_enter_setitimer                                   
                 0      syscalls:sys_enter_timer_create                                   
                 0      syscalls:sys_enter_timer_gettime                                   
                 0      syscalls:sys_enter_timer_getoverrun                                   
                 0      syscalls:sys_enter_timer_settime                                   
                 0      syscalls:sys_enter_timer_delete                                   
                 0      syscalls:sys_enter_clock_settime                                   
                 0      syscalls:sys_enter_clock_gettime                                   
                 0      syscalls:sys_enter_clock_adjtime                                   
                 0      syscalls:sys_enter_clock_getres                                   
                 0      syscalls:sys_enter_clock_nanosleep                                   
                 0      syscalls:sys_enter_nanosleep                                   
                 0      syscalls:sys_enter_time                                     
                 0      syscalls:sys_enter_gettimeofday                                   
                 0      syscalls:sys_enter_settimeofday                                   
                 0      syscalls:sys_enter_adjtimex                                   
                 0      syscalls:sys_enter_kcmp                                     
                 0      syscalls:sys_enter_syslog                                   
                 0      syscalls:sys_enter_membarrier                                   
                 0      syscalls:sys_enter_sched_setscheduler                                   
                 0      syscalls:sys_enter_sched_setparam                                   
                 0      syscalls:sys_enter_sched_setattr                                   
                 0      syscalls:sys_enter_sched_getscheduler                                   
                 0      syscalls:sys_enter_sched_getparam                                   
                 0      syscalls:sys_enter_sched_getattr                                   
                 0      syscalls:sys_enter_sched_setaffinity                                   
                 0      syscalls:sys_enter_sched_getaffinity                                   
                 0      syscalls:sys_enter_sched_yield                                   
                 0      syscalls:sys_enter_sched_get_priority_max                                   
                 0      syscalls:sys_enter_sched_get_priority_min                                   
                 0      syscalls:sys_enter_sched_rr_get_interval                                   
                 0      syscalls:sys_enter_getgroups                                   
                 0      syscalls:sys_enter_setgroups                                   
                 0      syscalls:sys_enter_reboot                                   
                 0      syscalls:sys_enter_setns                                    
                 0      syscalls:sys_enter_setpriority                                   
                 0      syscalls:sys_enter_getpriority                                   
                 0      syscalls:sys_enter_setregid                                   
                 0      syscalls:sys_enter_setgid                                   
                 0      syscalls:sys_enter_setreuid                                   
                 0      syscalls:sys_enter_setuid                                   
                 0      syscalls:sys_enter_setresuid                                   
                 0      syscalls:sys_enter_getresuid                                   
                 0      syscalls:sys_enter_setresgid                                   
                 0      syscalls:sys_enter_getresgid                                   
                 0      syscalls:sys_enter_setfsuid                                   
                 0      syscalls:sys_enter_setfsgid                                   
                 1      syscalls:sys_enter_getpid                                   
                 0      syscalls:sys_enter_gettid                                   
                 0      syscalls:sys_enter_getppid                                   
                 0      syscalls:sys_enter_getuid                                   
                 0      syscalls:sys_enter_geteuid                                   
                 0      syscalls:sys_enter_getgid                                   
                 0      syscalls:sys_enter_getegid                                   
                 0      syscalls:sys_enter_times                                    
                 0      syscalls:sys_enter_setpgid                                   
                 0      syscalls:sys_enter_getpgid                                   
                 0      syscalls:sys_enter_getpgrp                                   
                 0      syscalls:sys_enter_getsid                                   
                 1      syscalls:sys_enter_setsid                                   
                 0      syscalls:sys_enter_newuname                                   
                 0      syscalls:sys_enter_sethostname                                   
                 0      syscalls:sys_enter_setdomainname                                   
            43,883      syscalls:sys_enter_getrlimit                                   
                 0      syscalls:sys_enter_prlimit64                                   
                 1      syscalls:sys_enter_setrlimit                                   
                 0      syscalls:sys_enter_getrusage                                   
                 0      syscalls:sys_enter_umask                                    
                 0      syscalls:sys_enter_prctl                                    
                 0      syscalls:sys_enter_getcpu                                   
                 1      syscalls:sys_enter_sysinfo                                   
                 0      syscalls:sys_enter_restart_syscall                                   
             2,519      syscalls:sys_enter_rt_sigprocmask                                   
                 0      syscalls:sys_enter_rt_sigpending                                   
                 0      syscalls:sys_enter_rt_sigtimedwait                                   
            49,987      syscalls:sys_enter_kill                                     
            49,988      syscalls:sys_enter_tgkill                                   
                 0      syscalls:sys_enter_tkill                                    
                 0      syscalls:sys_enter_rt_sigqueueinfo                                   
                 0      syscalls:sys_enter_rt_tgsigqueueinfo                                   
                 0      syscalls:sys_enter_sigaltstack                                   
                 8      syscalls:sys_enter_rt_sigaction                                   
                 0      syscalls:sys_enter_pause                                    
                 0      syscalls:sys_enter_rt_sigsuspend                                   
                 0      syscalls:sys_enter_ptrace                                   
                 0      syscalls:sys_enter_capget                                   
                 0      syscalls:sys_enter_capset                                   
                 0      syscalls:sys_enter_sysctl                                   
                 0      syscalls:sys_enter_exit                                     
                 6      syscalls:sys_enter_exit_group                                   
                 0      syscalls:sys_enter_waitid                                   
            49,992      syscalls:sys_enter_wait4                                    
                 0      syscalls:sys_enter_personality                                   
                 0      syscalls:sys_enter_set_tid_address                                   
                 0      syscalls:sys_enter_fork                                     
                 0      syscalls:sys_enter_vfork                                    
                 6      syscalls:sys_enter_clone                                    
                 0      syscalls:sys_enter_unshare                                   
                58      syscalls:sys_enter_mmap                                     
                 0      syscalls:sys_enter_modify_ldt                                   
                 0      syscalls:sys_enter_iopl                                     
                 2      syscalls:sys_enter_arch_prctl          
```

Persistent Mode (VFS)

```
Profiling information: 
6547 ms total work, 129069 ns/work,             
10748 ms total running, 211875 ns/run, 
33 ms total write testcase, 662 ns/write             
358 ms total forking, 7068 ns/fork, 
8181 ms total purely run, 161282 ns/purely run             
19712 ns/system running, 122023 ns/user running             
6547 ms total pre-fuzzing, 129069 ns/pre-fuzzing,             
0 ms total post-fuzzing, 0 ns/post-fuzzing
total execution is 50728

 Performance counter stats for 'system wide':

       7715.711723      task-clock (msec)         #    0.864 CPUs utilized
           297,385      context-switches          #    0.039 M/sec
            14,890      cpu-migrations            #    0.002 M/sec
             4,442      page-faults               #    0.576 K/sec

                 0      syscalls:sys_enter_socket                                   
                 0      syscalls:sys_enter_socketpair                                   
                 0      syscalls:sys_enter_bind                                     
                 0      syscalls:sys_enter_listen                                   
                 0      syscalls:sys_enter_accept4                                   
                 0      syscalls:sys_enter_accept                                   
                 0      syscalls:sys_enter_connect                                   
                 0      syscalls:sys_enter_getsockname                                   
                 0      syscalls:sys_enter_getpeername                                   
                 0      syscalls:sys_enter_sendto                                   
                 0      syscalls:sys_enter_recvfrom                                   
                 0      syscalls:sys_enter_setsockopt                                   
                 0      syscalls:sys_enter_getsockopt                                   
                 0      syscalls:sys_enter_shutdown                                   
                 0      syscalls:sys_enter_sendmsg                                   
                 0      syscalls:sys_enter_sendmmsg                                   
                 0      syscalls:sys_enter_recvmsg                                   
                 0      syscalls:sys_enter_recvmmsg                                   
                 0      syscalls:sys_enter_getrandom                                   
                 0      syscalls:sys_enter_ioprio_set                                   
                 0      syscalls:sys_enter_ioprio_get                                   
                 0      syscalls:sys_enter_add_key                                   
                 0      syscalls:sys_enter_request_key                                   
                 0      syscalls:sys_enter_keyctl                                   
                 0      syscalls:sys_enter_mq_open                                   
                 0      syscalls:sys_enter_mq_unlink                                   
                 0      syscalls:sys_enter_mq_timedsend                                   
                 0      syscalls:sys_enter_mq_timedreceive                                   
                 0      syscalls:sys_enter_mq_notify                                   
                 0      syscalls:sys_enter_mq_getsetattr                                   
                 3      syscalls:sys_enter_shmget                                   
                 2      syscalls:sys_enter_shmctl                                   
                 4      syscalls:sys_enter_shmat                                    
                 0      syscalls:sys_enter_shmdt                                    
                 0      syscalls:sys_enter_semget                                   
                 0      syscalls:sys_enter_semctl                                   
                 0      syscalls:sys_enter_semtimedop                                   
                 0      syscalls:sys_enter_semop                                    
                 0      syscalls:sys_enter_msgget                                   
                 0      syscalls:sys_enter_msgctl                                   
                 0      syscalls:sys_enter_msgsnd                                   
                 0      syscalls:sys_enter_msgrcv                                   
                 0      syscalls:sys_enter_lookup_dcookie                                   
                 0      syscalls:sys_enter_quotactl                                   
                 0      syscalls:sys_enter_name_to_handle_at                                   
                 0      syscalls:sys_enter_open_by_handle_at                                   
                 1      syscalls:sys_enter_flock                                    
                 0      syscalls:sys_enter_io_setup                                   
                 0      syscalls:sys_enter_io_destroy                                   
                 0      syscalls:sys_enter_io_submit                                   
                 0      syscalls:sys_enter_io_cancel                                   
                 0      syscalls:sys_enter_io_getevents                                   
                 0      syscalls:sys_enter_userfaultfd                                   
                 0      syscalls:sys_enter_eventfd2                                   
                 0      syscalls:sys_enter_eventfd                                   
                 0      syscalls:sys_enter_timerfd_create                                   
                 0      syscalls:sys_enter_timerfd_settime                                   
                 0      syscalls:sys_enter_timerfd_gettime                                   
                 0      syscalls:sys_enter_signalfd4                                   
                 0      syscalls:sys_enter_signalfd                                   
                 0      syscalls:sys_enter_epoll_create1                                   
                 0      syscalls:sys_enter_epoll_create                                   
                 0      syscalls:sys_enter_epoll_ctl                                   
                 0      syscalls:sys_enter_epoll_wait                                   
                 0      syscalls:sys_enter_epoll_pwait                                   
                 0      syscalls:sys_enter_fanotify_init                                   
                 0      syscalls:sys_enter_fanotify_mark                                   
                 0      syscalls:sys_enter_inotify_init1                                   
                 0      syscalls:sys_enter_inotify_init                                   
                 0      syscalls:sys_enter_inotify_add_watch                                   
                 0      syscalls:sys_enter_inotify_rm_watch                                   
                 0      syscalls:sys_enter_statfs                                   
                 0      syscalls:sys_enter_fstatfs                                   
                 0      syscalls:sys_enter_ustat                                    
                 0      syscalls:sys_enter_utime                                    
                 0      syscalls:sys_enter_utimensat                                   
                 0      syscalls:sys_enter_futimesat                                   
                 0      syscalls:sys_enter_utimes                                   
                 0      syscalls:sys_enter_sync                                     
                 0      syscalls:sys_enter_syncfs                                   
                 0      syscalls:sys_enter_fsync                                    
                 0      syscalls:sys_enter_fdatasync                                   
                 0      syscalls:sys_enter_sync_file_range                                   
                 0      syscalls:sys_enter_vmsplice                                   
                 0      syscalls:sys_enter_splice                                   
                 0      syscalls:sys_enter_tee                                      
                 0      syscalls:sys_enter_setxattr                                   
                 0      syscalls:sys_enter_lsetxattr                                   
                 0      syscalls:sys_enter_fsetxattr                                   
                 0      syscalls:sys_enter_getxattr                                   
                 0      syscalls:sys_enter_lgetxattr                                   
                 0      syscalls:sys_enter_fgetxattr                                   
                 0      syscalls:sys_enter_listxattr                                   
                 0      syscalls:sys_enter_llistxattr                                   
                 0      syscalls:sys_enter_flistxattr                                   
                 0      syscalls:sys_enter_removexattr                                   
                 0      syscalls:sys_enter_lremovexattr                                   
                 0      syscalls:sys_enter_fremovexattr                                   
                 0      syscalls:sys_enter_umount                                   
                 0      syscalls:sys_enter_mount                                    
                 0      syscalls:sys_enter_pivot_root                                   
                 0      syscalls:sys_enter_sysfs                                    
                 0      syscalls:sys_enter_dup3                                     
                 5      syscalls:sys_enter_dup2                                     
                 0      syscalls:sys_enter_dup                                      
                 1      syscalls:sys_enter_getcwd                                   
                 0      syscalls:sys_enter_select                                   
                 0      syscalls:sys_enter_pselect6                                   
                 0      syscalls:sys_enter_poll                                     
                 0      syscalls:sys_enter_ppoll                                    
                38      syscalls:sys_enter_getdents                                   
                 0      syscalls:sys_enter_getdents64                                   
                 7      syscalls:sys_enter_ioctl                                    
                 1      syscalls:sys_enter_fcntl                                    
                 0      syscalls:sys_enter_mknodat                                   
                 0      syscalls:sys_enter_mknod                                    
                 0      syscalls:sys_enter_mkdirat                                   
                 9      syscalls:sys_enter_mkdir                                    
                 8      syscalls:sys_enter_rmdir                                    
                 0      syscalls:sys_enter_unlinkat                                   
             6,259      syscalls:sys_enter_unlink                                   
                 0      syscalls:sys_enter_symlinkat                                   
                12      syscalls:sys_enter_symlink                                   
                 0      syscalls:sys_enter_linkat                                   
             6,241      syscalls:sys_enter_link                                     
                 0      syscalls:sys_enter_renameat2                                   
                 0      syscalls:sys_enter_renameat                                   
                 0      syscalls:sys_enter_rename                                   
                 0      syscalls:sys_enter_pipe2                                    
                 2      syscalls:sys_enter_pipe                                     
                 1      syscalls:sys_enter_execve                                   
                 0      syscalls:sys_enter_execveat                                   
                 6      syscalls:sys_enter_newstat                                   
             6,243      syscalls:sys_enter_newlstat                                   
                 0      syscalls:sys_enter_newfstatat                                   
                39      syscalls:sys_enter_newfstat                                   
                 0      syscalls:sys_enter_readlinkat                                   
                 0      syscalls:sys_enter_readlink                                   
                 0      syscalls:sys_enter_statx                                    
                 0      syscalls:sys_enter_lseek                                    
           169,099      syscalls:sys_enter_read                                     
           174,132      syscalls:sys_enter_write                                    
                 0      syscalls:sys_enter_pread64                                   
                 0      syscalls:sys_enter_pwrite64                                   
                 0      syscalls:sys_enter_readv                                    
                 0      syscalls:sys_enter_writev                                   
                 0      syscalls:sys_enter_preadv                                   
                 0      syscalls:sys_enter_preadv2                                   
                 0      syscalls:sys_enter_pwritev                                   
                 0      syscalls:sys_enter_pwritev2                                   
                 0      syscalls:sys_enter_sendfile64                                   
                 0      syscalls:sys_enter_copy_file_range                                   
                 0      syscalls:sys_enter_truncate                                   
                 0      syscalls:sys_enter_ftruncate                                   
                 0      syscalls:sys_enter_fallocate                                   
                 0      syscalls:sys_enter_faccessat                                   
            12,494      syscalls:sys_enter_access                                   
                 0      syscalls:sys_enter_chdir                                    
                 0      syscalls:sys_enter_fchdir                                   
                 0      syscalls:sys_enter_chroot                                   
                 0      syscalls:sys_enter_fchmod                                   
                 0      syscalls:sys_enter_fchmodat                                   
                 0      syscalls:sys_enter_chmod                                    
                 0      syscalls:sys_enter_fchownat                                   
                 0      syscalls:sys_enter_chown                                    
                 0      syscalls:sys_enter_lchown                                   
                 0      syscalls:sys_enter_fchown                                   
            18,922      syscalls:sys_enter_open                                     
                 0      syscalls:sys_enter_openat                                   
                 0      syscalls:sys_enter_creat                                    
            81,963      syscalls:sys_enter_close                                    
                 0      syscalls:sys_enter_vhangup                                   
                 0      syscalls:sys_enter_move_pages                                   
                 0      syscalls:sys_enter_mbind                                    
                 0      syscalls:sys_enter_set_mempolicy                                   
                 0      syscalls:sys_enter_migrate_pages                                   
                 0      syscalls:sys_enter_get_mempolicy                                   
                 0      syscalls:sys_enter_swapoff                                   
                 0      syscalls:sys_enter_swapon                                   
                 0      syscalls:sys_enter_madvise                                   
                 0      syscalls:sys_enter_fadvise64                                   
                 0      syscalls:sys_enter_process_vm_readv                                   
                 0      syscalls:sys_enter_process_vm_writev                                   
                 0      syscalls:sys_enter_msync                                    
                 0      syscalls:sys_enter_mremap                                   
                56      syscalls:sys_enter_mprotect                                   
                 0      syscalls:sys_enter_pkey_mprotect                                   
                 0      syscalls:sys_enter_pkey_alloc                                   
                 0      syscalls:sys_enter_pkey_free                                   
               877      syscalls:sys_enter_brk                                      
                 3      syscalls:sys_enter_munmap                                   
                 0      syscalls:sys_enter_remap_file_pages                                   
                 0      syscalls:sys_enter_mlock                                    
                 0      syscalls:sys_enter_mlock2                                   
                 0      syscalls:sys_enter_munlock                                   
                 0      syscalls:sys_enter_mlockall                                   
                 0      syscalls:sys_enter_munlockall                                   
                 0      syscalls:sys_enter_mincore                                   
                 0      syscalls:sys_enter_memfd_create                                   
                 0      syscalls:sys_enter_readahead                                   
                 0      syscalls:sys_enter_perf_event_open                                   
                 0      syscalls:sys_enter_bpf                                      
                 0      syscalls:sys_enter_seccomp                                   
                 0      syscalls:sys_enter_kexec_file_load                                   
                 0      syscalls:sys_enter_kexec_load                                   
                 0      syscalls:sys_enter_acct                                     
                 0      syscalls:sys_enter_delete_module                                   
                 0      syscalls:sys_enter_init_module                                   
                 0      syscalls:sys_enter_finit_module                                   
                 0      syscalls:sys_enter_set_robust_list                                   
                 0      syscalls:sys_enter_get_robust_list                                   
                 0      syscalls:sys_enter_futex                                    
            50,120      syscalls:sys_enter_getitimer                                   
                 0      syscalls:sys_enter_alarm                                    
           100,242      syscalls:sys_enter_setitimer                                   
                 0      syscalls:sys_enter_timer_create                                   
                 0      syscalls:sys_enter_timer_gettime                                   
                 0      syscalls:sys_enter_timer_getoverrun                                   
                 0      syscalls:sys_enter_timer_settime                                   
                 0      syscalls:sys_enter_timer_delete                                   
                 0      syscalls:sys_enter_clock_settime                                   
                 0      syscalls:sys_enter_clock_gettime                                   
                 0      syscalls:sys_enter_clock_adjtime                                   
                 0      syscalls:sys_enter_clock_getres                                   
                 0      syscalls:sys_enter_clock_nanosleep                                   
                 0      syscalls:sys_enter_nanosleep                                   
                 0      syscalls:sys_enter_time                                     
                 0      syscalls:sys_enter_gettimeofday                                   
                 0      syscalls:sys_enter_settimeofday                                   
                 0      syscalls:sys_enter_adjtimex                                   
                 0      syscalls:sys_enter_kcmp                                     
                 0      syscalls:sys_enter_syslog                                   
                 0      syscalls:sys_enter_membarrier                                   
                 0      syscalls:sys_enter_sched_setscheduler                                   
                 0      syscalls:sys_enter_sched_setparam                                   
                 0      syscalls:sys_enter_sched_setattr                                   
                 0      syscalls:sys_enter_sched_getscheduler                                   
                 0      syscalls:sys_enter_sched_getparam                                   
                 0      syscalls:sys_enter_sched_getattr                                   
                 0      syscalls:sys_enter_sched_setaffinity                                   
                 0      syscalls:sys_enter_sched_getaffinity                                   
                 0      syscalls:sys_enter_sched_yield                                   
                 0      syscalls:sys_enter_sched_get_priority_max                                   
                 0      syscalls:sys_enter_sched_get_priority_min                                   
                 0      syscalls:sys_enter_sched_rr_get_interval                                   
                 0      syscalls:sys_enter_getgroups                                   
                 0      syscalls:sys_enter_setgroups                                   
                 0      syscalls:sys_enter_reboot                                   
                 0      syscalls:sys_enter_setns                                    
                 0      syscalls:sys_enter_setpriority                                   
                 0      syscalls:sys_enter_getpriority                                   
                 0      syscalls:sys_enter_setregid                                   
                 0      syscalls:sys_enter_setgid                                   
                 0      syscalls:sys_enter_setreuid                                   
                 0      syscalls:sys_enter_setuid                                   
                 0      syscalls:sys_enter_setresuid                                   
                 0      syscalls:sys_enter_getresuid                                   
                 0      syscalls:sys_enter_setresgid                                   
                 0      syscalls:sys_enter_getresgid                                   
                 0      syscalls:sys_enter_setfsuid                                   
                 0      syscalls:sys_enter_setfsgid                                   
                 1      syscalls:sys_enter_getpid                                   
                 0      syscalls:sys_enter_gettid                                   
                 0      syscalls:sys_enter_getppid                                   
                 0      syscalls:sys_enter_getuid                                   
                 0      syscalls:sys_enter_geteuid                                   
                 0      syscalls:sys_enter_getgid                                   
                 0      syscalls:sys_enter_getegid                                   
                 0      syscalls:sys_enter_times                                    
                 0      syscalls:sys_enter_setpgid                                   
                 0      syscalls:sys_enter_getpgid                                   
                 0      syscalls:sys_enter_getpgrp                                   
                 0      syscalls:sys_enter_getsid                                   
                 1      syscalls:sys_enter_setsid                                   
                 0      syscalls:sys_enter_newuname                                   
                 0      syscalls:sys_enter_sethostname                                   
                 0      syscalls:sys_enter_setdomainname                                   
                 7      syscalls:sys_enter_getrlimit                                   
                 0      syscalls:sys_enter_prlimit64                                   
                 1      syscalls:sys_enter_setrlimit                                   
                 0      syscalls:sys_enter_getrusage                                   
                 0      syscalls:sys_enter_umask                                    
                 0      syscalls:sys_enter_prctl                                    
                 0      syscalls:sys_enter_getcpu                                   
                 1      syscalls:sys_enter_sysinfo                                   
                 0      syscalls:sys_enter_restart_syscall                                   
            37,062      syscalls:sys_enter_rt_sigprocmask                                   
                 0      syscalls:sys_enter_rt_sigpending                                   
                 0      syscalls:sys_enter_rt_sigtimedwait                                   
            50,114      syscalls:sys_enter_kill                                     
            50,115      syscalls:sys_enter_tgkill                                   
                 0      syscalls:sys_enter_tkill                                    
                 0      syscalls:sys_enter_rt_sigqueueinfo                                   
                 0      syscalls:sys_enter_rt_tgsigqueueinfo                                   
                 0      syscalls:sys_enter_sigaltstack                                   
                 8      syscalls:sys_enter_rt_sigaction                                   
                 0      syscalls:sys_enter_pause                                    
                 0      syscalls:sys_enter_rt_sigsuspend                                   
                 0      syscalls:sys_enter_ptrace                                   
                 0      syscalls:sys_enter_capget                                   
                 0      syscalls:sys_enter_capset                                   
                 0      syscalls:sys_enter_sysctl                                   
                 0      syscalls:sys_enter_exit                                     
                 7      syscalls:sys_enter_exit_group                                   
                 0      syscalls:sys_enter_waitid                                   
            50,120      syscalls:sys_enter_wait4                                    
                 0      syscalls:sys_enter_personality                                   
                 0      syscalls:sys_enter_set_tid_address                                   
                 0      syscalls:sys_enter_fork                                     
                 0      syscalls:sys_enter_vfork                                    
                 7      syscalls:sys_enter_clone                                    
                 0      syscalls:sys_enter_unshare                                   
                43      syscalls:sys_enter_mmap                                     
                 0      syscalls:sys_enter_modify_ldt                                   
                 0      syscalls:sys_enter_iopl                                     
                 2      syscalls:sys_enter_arch_prctl           
```

Persistent Mode (VAR + VFS)

```
Profiling information: 
5024 ms total work, 100566 ns/work,             
11471 ms total running, 229621 ns/run, 
31 ms total write testcase, 635 ns/write             
583 ms total forking, 11678 ns/fork, 
9088 ms total purely run, 181916 ns/purely run             
21617 ns/system running, 131104 ns/user running             
5024 ms total pre-fuzzing, 100566 ns/pre-fuzzing,             
0 ms total post-fuzzing, 0 ns/post-fuzzing
total execution is 49928

 Performance counter stats for 'system wide':

      12671.313092      task-clock (msec)         #    0.901 CPUs utilized
           297,270      context-switches          #    0.023 M/sec
            11,117      cpu-migrations            #    0.877 K/sec
            61,139      page-faults               #    0.005 M/sec

                 0      syscalls:sys_enter_socket                                   
                 0      syscalls:sys_enter_socketpair                                   
                 0      syscalls:sys_enter_bind                                     
                 0      syscalls:sys_enter_listen                                   
                 0      syscalls:sys_enter_accept4                                   
                 0      syscalls:sys_enter_accept                                   
                 0      syscalls:sys_enter_connect                                   
                 0      syscalls:sys_enter_getsockname                                   
                 0      syscalls:sys_enter_getpeername                                   
                 0      syscalls:sys_enter_sendto                                   
                 0      syscalls:sys_enter_recvfrom                                   
                 0      syscalls:sys_enter_setsockopt                                   
                 0      syscalls:sys_enter_getsockopt                                   
                 0      syscalls:sys_enter_shutdown                                   
                 0      syscalls:sys_enter_sendmsg                                   
                 0      syscalls:sys_enter_sendmmsg                                   
                 0      syscalls:sys_enter_recvmsg                                   
                 0      syscalls:sys_enter_recvmmsg                                   
                 0      syscalls:sys_enter_getrandom                                   
                 0      syscalls:sys_enter_ioprio_set                                   
                 0      syscalls:sys_enter_ioprio_get                                   
                 0      syscalls:sys_enter_add_key                                   
                 0      syscalls:sys_enter_request_key                                   
                 0      syscalls:sys_enter_keyctl                                   
                 0      syscalls:sys_enter_mq_open                                   
                 0      syscalls:sys_enter_mq_unlink                                   
                 0      syscalls:sys_enter_mq_timedsend                                   
                 0      syscalls:sys_enter_mq_timedreceive                                   
                 0      syscalls:sys_enter_mq_notify                                   
                 0      syscalls:sys_enter_mq_getsetattr                                   
                 3      syscalls:sys_enter_shmget                                   
                 2      syscalls:sys_enter_shmctl                                   
                 4      syscalls:sys_enter_shmat                                    
                 0      syscalls:sys_enter_shmdt                                    
                 0      syscalls:sys_enter_semget                                   
                 0      syscalls:sys_enter_semctl                                   
                 0      syscalls:sys_enter_semtimedop                                   
                 0      syscalls:sys_enter_semop                                    
                 0      syscalls:sys_enter_msgget                                   
                 0      syscalls:sys_enter_msgctl                                   
                 0      syscalls:sys_enter_msgsnd                                   
                 0      syscalls:sys_enter_msgrcv                                   
                 0      syscalls:sys_enter_lookup_dcookie                                   
                 0      syscalls:sys_enter_quotactl                                   
                 0      syscalls:sys_enter_name_to_handle_at                                   
                 0      syscalls:sys_enter_open_by_handle_at                                   
                 1      syscalls:sys_enter_flock                                    
                 0      syscalls:sys_enter_io_setup                                   
                 0      syscalls:sys_enter_io_destroy                                   
                 0      syscalls:sys_enter_io_submit                                   
                 0      syscalls:sys_enter_io_cancel                                   
                 0      syscalls:sys_enter_io_getevents                                   
                 0      syscalls:sys_enter_userfaultfd                                   
                 0      syscalls:sys_enter_eventfd2                                   
                 0      syscalls:sys_enter_eventfd                                   
                 0      syscalls:sys_enter_timerfd_create                                   
                 0      syscalls:sys_enter_timerfd_settime                                   
                 0      syscalls:sys_enter_timerfd_gettime                                   
                 0      syscalls:sys_enter_signalfd4                                   
                 0      syscalls:sys_enter_signalfd                                   
                 0      syscalls:sys_enter_epoll_create1                                   
                 0      syscalls:sys_enter_epoll_create                                   
                 0      syscalls:sys_enter_epoll_ctl                                   
                 0      syscalls:sys_enter_epoll_wait                                   
                 0      syscalls:sys_enter_epoll_pwait                                   
                 0      syscalls:sys_enter_fanotify_init                                   
                 0      syscalls:sys_enter_fanotify_mark                                   
                 0      syscalls:sys_enter_inotify_init1                                   
                 0      syscalls:sys_enter_inotify_init                                   
                 0      syscalls:sys_enter_inotify_add_watch                                   
                 0      syscalls:sys_enter_inotify_rm_watch                                   
                 0      syscalls:sys_enter_statfs                                   
                 0      syscalls:sys_enter_fstatfs                                   
                 0      syscalls:sys_enter_ustat                                    
                 0      syscalls:sys_enter_utime                                    
                 0      syscalls:sys_enter_utimensat                                   
                 0      syscalls:sys_enter_futimesat                                   
                 0      syscalls:sys_enter_utimes                                   
                 0      syscalls:sys_enter_sync                                     
                 0      syscalls:sys_enter_syncfs                                   
                 0      syscalls:sys_enter_fsync                                    
                 0      syscalls:sys_enter_fdatasync                                   
                 0      syscalls:sys_enter_sync_file_range                                   
                 0      syscalls:sys_enter_vmsplice                                   
                 0      syscalls:sys_enter_splice                                   
                 0      syscalls:sys_enter_tee                                      
                 0      syscalls:sys_enter_setxattr                                   
                 0      syscalls:sys_enter_lsetxattr                                   
                 0      syscalls:sys_enter_fsetxattr                                   
                 0      syscalls:sys_enter_getxattr                                   
                 0      syscalls:sys_enter_lgetxattr                                   
                 0      syscalls:sys_enter_fgetxattr                                   
                 0      syscalls:sys_enter_listxattr                                   
                 0      syscalls:sys_enter_llistxattr                                   
                 0      syscalls:sys_enter_flistxattr                                   
                 0      syscalls:sys_enter_removexattr                                   
                 0      syscalls:sys_enter_lremovexattr                                   
                 0      syscalls:sys_enter_fremovexattr                                   
                 0      syscalls:sys_enter_umount                                   
                 0      syscalls:sys_enter_mount                                    
                 0      syscalls:sys_enter_pivot_root                                   
                 0      syscalls:sys_enter_sysfs                                    
                 0      syscalls:sys_enter_dup3                                     
                 5      syscalls:sys_enter_dup2                                     
                 0      syscalls:sys_enter_dup                                      
                 1      syscalls:sys_enter_getcwd                                   
                 0      syscalls:sys_enter_select                                   
                 0      syscalls:sys_enter_pselect6                                   
                 0      syscalls:sys_enter_poll                                     
                 0      syscalls:sys_enter_ppoll                                    
                38      syscalls:sys_enter_getdents                                   
                 0      syscalls:sys_enter_getdents64                                   
                 6      syscalls:sys_enter_ioctl                                    
                 1      syscalls:sys_enter_fcntl                                    
                 0      syscalls:sys_enter_mknodat                                   
                 0      syscalls:sys_enter_mknod                                    
                 0      syscalls:sys_enter_mkdirat                                   
                 9      syscalls:sys_enter_mkdir                                    
                 8      syscalls:sys_enter_rmdir                                    
                 0      syscalls:sys_enter_unlinkat                                   
             6,247      syscalls:sys_enter_unlink                                   
                 0      syscalls:sys_enter_symlinkat                                   
                 0      syscalls:sys_enter_symlink                                   
                 0      syscalls:sys_enter_linkat                                   
             6,241      syscalls:sys_enter_link                                     
                 0      syscalls:sys_enter_renameat2                                   
                 0      syscalls:sys_enter_renameat                                   
                 0      syscalls:sys_enter_rename                                   
                 0      syscalls:sys_enter_pipe2                                    
                 2      syscalls:sys_enter_pipe                                     
                 1      syscalls:sys_enter_execve                                   
                 0      syscalls:sys_enter_execveat                                   
                 6      syscalls:sys_enter_newstat                                   
             6,243      syscalls:sys_enter_newlstat                                   
                 0      syscalls:sys_enter_newfstatat                                   
                36      syscalls:sys_enter_newfstat                                   
                 0      syscalls:sys_enter_readlinkat                                   
                 0      syscalls:sys_enter_readlink                                   
                 0      syscalls:sys_enter_statx                                    
                 0      syscalls:sys_enter_lseek                                    
           168,523      syscalls:sys_enter_read                                     
           170,824      syscalls:sys_enter_write                                    
                 0      syscalls:sys_enter_pread64                                   
                 0      syscalls:sys_enter_pwrite64                                   
                 0      syscalls:sys_enter_readv                                    
                 0      syscalls:sys_enter_writev                                   
                 0      syscalls:sys_enter_preadv                                   
                 0      syscalls:sys_enter_preadv2                                   
                 0      syscalls:sys_enter_pwritev                                   
                 0      syscalls:sys_enter_pwritev2                                   
                 0      syscalls:sys_enter_sendfile64                                   
                 0      syscalls:sys_enter_copy_file_range                                   
                 0      syscalls:sys_enter_truncate                                   
                 0      syscalls:sys_enter_ftruncate                                   
                 0      syscalls:sys_enter_fallocate                                   
                 0      syscalls:sys_enter_faccessat                                   
            12,494      syscalls:sys_enter_access                                   
                 0      syscalls:sys_enter_chdir                                    
                 0      syscalls:sys_enter_fchdir                                   
                 0      syscalls:sys_enter_chroot                                   
                 0      syscalls:sys_enter_fchmod                                   
                 0      syscalls:sys_enter_fchmodat                                   
                 0      syscalls:sys_enter_chmod                                    
                 0      syscalls:sys_enter_fchownat                                   
                 0      syscalls:sys_enter_chown                                    
                 0      syscalls:sys_enter_lchown                                   
                 0      syscalls:sys_enter_fchown                                   
            18,895      syscalls:sys_enter_open                                     
                 0      syscalls:sys_enter_openat                                   
                 0      syscalls:sys_enter_creat                                    
           114,255      syscalls:sys_enter_close                                    
                 0      syscalls:sys_enter_vhangup                                   
                 0      syscalls:sys_enter_move_pages                                   
                 0      syscalls:sys_enter_mbind                                    
                 0      syscalls:sys_enter_set_mempolicy                                   
                 0      syscalls:sys_enter_migrate_pages                                   
                 0      syscalls:sys_enter_get_mempolicy                                   
                 0      syscalls:sys_enter_swapoff                                   
                 0      syscalls:sys_enter_swapon                                   
                 0      syscalls:sys_enter_madvise                                   
                 0      syscalls:sys_enter_fadvise64                                   
                 0      syscalls:sys_enter_process_vm_readv                                   
                 0      syscalls:sys_enter_process_vm_writev                                   
                 0      syscalls:sys_enter_msync                                    
                 0      syscalls:sys_enter_mremap                                   
                56      syscalls:sys_enter_mprotect                                   
                 0      syscalls:sys_enter_pkey_mprotect                                   
                 0      syscalls:sys_enter_pkey_alloc                                   
                 0      syscalls:sys_enter_pkey_free                                   
             2,615      syscalls:sys_enter_brk                                      
                 6      syscalls:sys_enter_munmap                                   
                 0      syscalls:sys_enter_remap_file_pages                                   
                 0      syscalls:sys_enter_mlock                                    
                 0      syscalls:sys_enter_mlock2                                   
                 0      syscalls:sys_enter_munlock                                   
                 0      syscalls:sys_enter_mlockall                                   
                 0      syscalls:sys_enter_munlockall                                   
                 0      syscalls:sys_enter_mincore                                   
                 0      syscalls:sys_enter_memfd_create                                   
                 0      syscalls:sys_enter_readahead                                   
                 0      syscalls:sys_enter_perf_event_open                                   
                 0      syscalls:sys_enter_bpf                                      
                 0      syscalls:sys_enter_seccomp                                   
                 0      syscalls:sys_enter_kexec_file_load                                   
                 0      syscalls:sys_enter_kexec_load                                   
                 0      syscalls:sys_enter_acct                                     
                 0      syscalls:sys_enter_delete_module                                   
                 0      syscalls:sys_enter_init_module                                   
                 0      syscalls:sys_enter_finit_module                                   
                 0      syscalls:sys_enter_set_robust_list                                   
                 0      syscalls:sys_enter_get_robust_list                                   
                 0      syscalls:sys_enter_futex                                    
            49,928      syscalls:sys_enter_getitimer                                   
                 0      syscalls:sys_enter_alarm                                    
            99,858      syscalls:sys_enter_setitimer                                   
                 0      syscalls:sys_enter_timer_create                                   
                 0      syscalls:sys_enter_timer_gettime                                   
                 0      syscalls:sys_enter_timer_getoverrun                                   
                 0      syscalls:sys_enter_timer_settime                                   
                 0      syscalls:sys_enter_timer_delete                                   
                 0      syscalls:sys_enter_clock_settime                                   
                 0      syscalls:sys_enter_clock_gettime                                   
                 0      syscalls:sys_enter_clock_adjtime                                   
                 0      syscalls:sys_enter_clock_getres                                   
                 0      syscalls:sys_enter_clock_nanosleep                                   
                 0      syscalls:sys_enter_nanosleep                                   
                 0      syscalls:sys_enter_time                                     
                 0      syscalls:sys_enter_gettimeofday                                   
                 0      syscalls:sys_enter_settimeofday                                   
                 0      syscalls:sys_enter_adjtimex                                   
                 0      syscalls:sys_enter_kcmp                                     
                 0      syscalls:sys_enter_syslog                                   
                 0      syscalls:sys_enter_membarrier                                   
                 0      syscalls:sys_enter_sched_setscheduler                                   
                 0      syscalls:sys_enter_sched_setparam                                   
                 0      syscalls:sys_enter_sched_setattr                                   
                 0      syscalls:sys_enter_sched_getscheduler                                   
                 0      syscalls:sys_enter_sched_getparam                                   
                 0      syscalls:sys_enter_sched_getattr                                   
                 0      syscalls:sys_enter_sched_setaffinity                                   
                 0      syscalls:sys_enter_sched_getaffinity                                   
                 0      syscalls:sys_enter_sched_yield                                   
                 0      syscalls:sys_enter_sched_get_priority_max                                   
                 0      syscalls:sys_enter_sched_get_priority_min                                   
                 0      syscalls:sys_enter_sched_rr_get_interval                                   
                 0      syscalls:sys_enter_getgroups                                   
                 0      syscalls:sys_enter_setgroups                                   
                 0      syscalls:sys_enter_reboot                                   
                 0      syscalls:sys_enter_setns                                    
                 0      syscalls:sys_enter_setpriority                                   
                 0      syscalls:sys_enter_getpriority                                   
                 0      syscalls:sys_enter_setregid                                   
                 0      syscalls:sys_enter_setgid                                   
                 0      syscalls:sys_enter_setreuid                                   
                 0      syscalls:sys_enter_setuid                                   
                 0      syscalls:sys_enter_setresuid                                   
                 0      syscalls:sys_enter_getresuid                                   
                 0      syscalls:sys_enter_setresgid                                   
                 0      syscalls:sys_enter_getresgid                                   
                 0      syscalls:sys_enter_setfsuid                                   
                 0      syscalls:sys_enter_setfsgid                                   
                 1      syscalls:sys_enter_getpid                                   
                 0      syscalls:sys_enter_gettid                                   
                 0      syscalls:sys_enter_getppid                                   
                 0      syscalls:sys_enter_getuid                                   
                 0      syscalls:sys_enter_geteuid                                   
                 0      syscalls:sys_enter_getgid                                   
                 0      syscalls:sys_enter_getegid                                   
                 0      syscalls:sys_enter_times                                    
                 0      syscalls:sys_enter_setpgid                                   
                 0      syscalls:sys_enter_getpgid                                   
                 0      syscalls:sys_enter_getpgrp                                   
                 0      syscalls:sys_enter_getsid                                   
                 1      syscalls:sys_enter_setsid                                   
                 0      syscalls:sys_enter_newuname                                   
                 0      syscalls:sys_enter_sethostname                                   
                 0      syscalls:sys_enter_setdomainname                                   
            49,929      syscalls:sys_enter_getrlimit                                   
                 0      syscalls:sys_enter_prlimit64                                   
                 1      syscalls:sys_enter_setrlimit                                   
                 0      syscalls:sys_enter_getrusage                                   
                 0      syscalls:sys_enter_umask                                    
                 0      syscalls:sys_enter_prctl                                    
                 0      syscalls:sys_enter_getcpu                                   
                 1      syscalls:sys_enter_sysinfo                                   
                 0      syscalls:sys_enter_restart_syscall                                   
             4,381      syscalls:sys_enter_rt_sigprocmask                                   
                 0      syscalls:sys_enter_rt_sigpending                                   
                 0      syscalls:sys_enter_rt_sigtimedwait                                   
            49,923      syscalls:sys_enter_kill                                     
            49,924      syscalls:sys_enter_tgkill                                   
                 0      syscalls:sys_enter_tkill                                    
                 0      syscalls:sys_enter_rt_sigqueueinfo                                   
                 0      syscalls:sys_enter_rt_tgsigqueueinfo                                   
                 0      syscalls:sys_enter_sigaltstack                                   
                 8      syscalls:sys_enter_rt_sigaction                                   
                 0      syscalls:sys_enter_pause                                    
                 0      syscalls:sys_enter_rt_sigsuspend                                   
                 0      syscalls:sys_enter_ptrace                                   
                 0      syscalls:sys_enter_capget                                   
                 0      syscalls:sys_enter_capset                                   
                 0      syscalls:sys_enter_sysctl                                   
                 0      syscalls:sys_enter_exit                                     
                 6      syscalls:sys_enter_exit_group                                   
                 0      syscalls:sys_enter_waitid                                   
            49,928      syscalls:sys_enter_wait4                                    
                 0      syscalls:sys_enter_personality                                   
                 0      syscalls:sys_enter_set_tid_address                                   
                 0      syscalls:sys_enter_fork                                     
                 0      syscalls:sys_enter_vfork                                    
                 6      syscalls:sys_enter_clone                                    
                 0      syscalls:sys_enter_unshare                                   
                68      syscalls:sys_enter_mmap                                     
                 0      syscalls:sys_enter_modify_ldt                                   
                 0      syscalls:sys_enter_iopl                                     
                 2      syscalls:sys_enter_arch_prctl           

```


## Evaluation

Command

```
AFL_NO_AFFINITY=1 timeout 1d afl-fuzz -i /out/elf_one -o /dev/shm/output_per1 -m none -f /dev/shm/afl_per1 -- /out/objdump -d @@
```

### Fuzzer stats


**Fork Server**

```
start_time        : 1671847294
last_update       : 1671933690
fuzzer_pid        : 24321
cycles_done       : 7
execs_done        : 101727206
execs_per_sec     : 1264.17
paths_total       : 3611
paths_favored     : 613
paths_found       : 3610
paths_imported    : 0
max_depth         : 16
cur_path          : 1881
pending_favs      : 0
pending_total     : 1633
variable_paths    : 0
stability         : 100.00%
bitmap_cvg        : 11.20%
unique_crashes    : 0
unique_hangs      : 0
last_path         : 1671933496
last_crash        : 0
last_hang         : 0
execs_since_crash : 101727206
exec_timeout      : 20
afl_banner        : objdump_fork
afl_version       : 2.57b
target_mode       : default
command_line      : afl-fuzz -i /out/elf_one/ -o /dev/shm/output_objdump_fork2 -f /dev/shm/afl_input2 /out/objdump_fork -d @@
slowest_exec_ms   : 13
peak_rss_mb       : 4

```

**Snapshot**

```
start_time        : 1671992183
last_update       : 1672078579
fuzzer_pid        : 15762
cycles_done       : 6
execs_done        : 171853163
execs_per_sec     : 2403.88
paths_total       : 6432
paths_favored     : 1230
paths_found       : 6431
paths_imported    : 0
max_depth         : 31
cur_path          : 6257
pending_favs      : 6
pending_total     : 3667
variable_paths    : 0
stability         : 100.00%
bitmap_cvg        : 13.78%
unique_crashes    : 56
unique_hangs      : 0
last_path         : 1672077727
last_crash        : 1672077164
last_hang         : 0
execs_since_crash : 3450942
exec_timeout      : 20
afl_banner        : objdump
afl_version       : 2.40b
command_line      : /home/test/Desktop/code/perf-fuzz/afl/afl-fuzz -f /dev/shm/afl_in1 -i /out/elf_one -o /dev/shm/out_snap1 -- /out/objdump -d @@
```

**Persistent mode**

```
start_time        : 1671990740
last_update       : 1672077136
fuzzer_pid        : 18000
cycles_done       : 27
execs_done        : 225643993
execs_per_sec     : 1153.53
paths_total       : 5144
paths_favored     : 649
paths_found       : 5143
paths_imported    : 0
max_depth         : 24
cur_path          : 5143
pending_favs      : 0
pending_total     : 1754
variable_paths    : 382
stability         : 98.78%
bitmap_cvg        : 11.99%
unique_crashes    : 0
unique_hangs      : 0
last_path         : 1672077071
last_crash        : 0
last_hang         : 0
execs_since_crash : 225643993
exec_timeout      : 20
afl_banner        : objdump_per
afl_version       : 2.57b
target_mode       : persistent
command_line      : afl-fuzz -i /out/elf_one -o /dev/shm/output_per3 -m none -f /dev/shm/afl_per3 -- /out/objdump_per -d @@
slowest_exec_ms   : 19
peak_rss_mb       : 5
```

**PM + VFS**

```
start_time        : 1671991055
last_update       : 1672077451
fuzzer_pid        : 18398
cycles_done       : 20
execs_done        : 189869807
execs_per_sec     : 349.20
paths_total       : 4870
paths_favored     : 645
paths_found       : 4869
paths_imported    : 0
max_depth         : 29
cur_path          : 4767
pending_favs      : 0
pending_total     : 2281
variable_paths    : 413
stability         : 98.75%
bitmap_cvg        : 11.73%
unique_crashes    : 0
unique_hangs      : 0
last_path         : 1672075331
last_crash        : 0
last_hang         : 0
execs_since_crash : 189869807
exec_timeout      : 20
afl_banner        : objdump_per
afl_version       : 2.57b
target_mode       : persistent
command_line      : afl-fuzz -i /out/elf_one -o /dev/shm/output_fs2 -m none -f /dev/shm/afl_fs2 -- /out/objdump_per -d @@
slowest_exec_ms   : 20
peak_rss_mb       : 9
```

**VAR**
```
start_time        : 1671991626
last_update       : 1672078022
fuzzer_pid        : 5133
cycles_done       : 18
execs_done        : 159849547
execs_per_sec     : 211.04
paths_total       : 4349
paths_favored     : 560
paths_found       : 4348
paths_imported    : 0
max_depth         : 23
cur_path          : 4332
pending_favs      : 0
pending_total     : 2026
variable_paths    : 0
stability         : 100.00%
bitmap_cvg        : 11.19%
unique_crashes    : 0
unique_hangs      : 0
last_path         : 1672068334
last_crash        : 0
last_hang         : 0
execs_since_crash : 159849547
exec_timeout      : 20
afl_banner        : objdump_var
afl_version       : 2.57b
target_mode       : persistent
command_line      : afl-fuzz -i /out/elf_one -o /dev/shm/output_var2 -m none -f /dev/shm/afl_var2 -- /out/objdump_var -d @@
slowest_exec_ms   : 20
peak_rss_mb       : 5
```

**VAR + VFS**
```
start_time        : 1671991943
last_update       : 1672078339
fuzzer_pid        : 27418
cycles_done       : 25
execs_done        : 213768195
execs_per_sec     : 237.02
paths_total       : 4728
paths_favored     : 654
paths_found       : 4727
paths_imported    : 0
max_depth         : 31
cur_path          : 4711
pending_favs      : 4
pending_total     : 1632
variable_paths    : 13
stability         : 99.97%
bitmap_cvg        : 12.13%
unique_crashes    : 0
unique_hangs      : 0
last_path         : 1672075767
last_crash        : 0
last_hang         : 0
execs_since_crash : 213768195
exec_timeout      : 20
afl_banner        : objdump_var
afl_version       : 2.57b
target_mode       : persistent
command_line      : afl-fuzz -i /out/elf_one -o /dev/shm/output_varfs2 -m none -f /dev/shm/afl_varfs2 -- /out/objdump_var -d @@
slowest_exec_ms   : 19
peak_rss_mb       : 13
```