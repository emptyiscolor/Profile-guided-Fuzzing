## Build the image

```
docker build -t benchmark-aflpp-objdump .
```

## Build for Sec.2

```
docker run --privileged --shm-size=256m --rm -it benchmark-aflpp-objdump bash

# Build target with fork server mode
FUZZER=baseline bash build.sh

# Build target with persistent mode without var rec
bash build.sh

# Build target with persistent VAR mode (TODO: update new LLVM pass)
FUZZER=aflfstab bash build.sh

# Dry run with corpus
AFL_NO_SNAPSHOT=1 AFL_PERFORM_DRY_RUN_ONLY=1 AFL_NO_AFFINITY=1  perf stat afl-fuzz -i /out/corpus_objdump_snap -o /dev/shm/out_rm -f /dev/shm/afl_f /out/objdump -d /dev/shm/afl_f
AFL_NO_SNAPSHOT=1 AFL_PERFORM_DRY_RUN_ONLY=1 AFL_NO_AFFINITY=1  perf stat -e 'syscalls:sys_enter_*' afl-fuzz -i /out/corpus_objdump_snap -o /dev/shm/out_rm -f /dev/shm/afl_f /out/objdump -d /dev/shm/afl_f

# ( 2>/tmp/perf_syscall_per.txt )
# (set FS_AFL_SHM_ID=6789 to enable VFS mode)
```

### Result sample

Fork server

```
Profiling information: 
5453 ms total work, 109229 ns/work,             
30585 ms total running, 612602 ns/run, 
772 ms total write testcase, 15477 ns/write             
4179 ms total forking, 83714 ns/fork, 
25365 ms total purely run, 508045 ns/purely run             
41259 ns/system running, 438030 ns/user running,             
5453 ms total pre-fuzzing, 109229 ns/pre-fuzzing,             
0 ms total post-fuzzing, 0 ns/post-fuzzing
total execution is 0x49928

 Performance counter stats for 'afl-fuzz -i /out/corpus_objdump_snap -o /dev/shm/out_rm -f /dev/shm/afl_f /out/objdump_fork -d /dev/shm/afl_f':

          37940.55 msec task-clock                #    0.903 CPUs utilized
            209543      context-switches          #    0.006 M/sec
             49278      cpu-migrations            #    0.001 M/sec
           6364521      page-faults               #    0.168 M/sec
      122002560880      cycles                    #    3.216 GHz                      (83.91%)
       11949619744      stalled-cycles-frontend   #    9.79% frontend cycles idle     (83.08%)
       35013277967      stalled-cycles-backend    #   28.70% backend cycles idle      (83.96%)
      109958673440      instructions              #    0.90  insn per cycle
                                                  #    0.32  stalled cycles per insn  (82.96%)
       18720640792      branches                  #  493.420 M/sec                    (81.95%)
         275880926      branch-misses             #    1.47% of all branches          (84.14%)

 Performance counter stats for 'afl-fuzz -i /out/corpus_objdump_snap -o /dev/shm/out_rm -f /dev/shm/afl_f /out/objdump_fork -d /dev/shm/afl_f':

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
                 2      syscalls:sys_enter_shmget                                   
                 3      syscalls:sys_enter_shmctl                                   
                 3      syscalls:sys_enter_shmat                                    
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
                 0      syscalls:sys_enter_io_uring_enter                                   
                 0      syscalls:sys_enter_io_uring_setup                                   
                 0      syscalls:sys_enter_io_uring_register                                   
                 0      syscalls:sys_enter_io_setup                                   
                 0      syscalls:sys_enter_io_destroy                                   
                 0      syscalls:sys_enter_io_submit                                   
                 0      syscalls:sys_enter_io_cancel                                   
                 0      syscalls:sys_enter_io_getevents                                   
                 0      syscalls:sys_enter_io_pgetevents                                   
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
                 0      syscalls:sys_enter_fsopen                                   
                 0      syscalls:sys_enter_fspick                                   
                 0      syscalls:sys_enter_fsconfig                                   
                 0      syscalls:sys_enter_statfs                                   
                 0      syscalls:sys_enter_fstatfs                                   
                 0      syscalls:sys_enter_ustat                                    
                 0      syscalls:sys_enter_getcwd                                   
                 0      syscalls:sys_enter_utimensat                                   
                 0      syscalls:sys_enter_futimesat                                   
                 0      syscalls:sys_enter_utimes                                   
                 0      syscalls:sys_enter_utime                                    
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
                 0      syscalls:sys_enter_open_tree                                   
                 0      syscalls:sys_enter_mount                                    
                 0      syscalls:sys_enter_fsmount                                   
                 0      syscalls:sys_enter_move_mount                                   
                 0      syscalls:sys_enter_pivot_root                                   
                 0      syscalls:sys_enter_sysfs                                    
                 0      syscalls:sys_enter_dup3                                     
                 5      syscalls:sys_enter_dup2                                     
                 0      syscalls:sys_enter_dup                                      
             49929      syscalls:sys_enter_select                                   
                 0      syscalls:sys_enter_pselect6                                   
                 0      syscalls:sys_enter_poll                                     
                 0      syscalls:sys_enter_ppoll                                    
                 0      syscalls:sys_enter_getdents                                   
                46      syscalls:sys_enter_getdents64                                   
             35777      syscalls:sys_enter_ioctl                                    
             99860      syscalls:sys_enter_fcntl                                    
                 0      syscalls:sys_enter_mknodat                                   
                 0      syscalls:sys_enter_mknod                                    
                 0      syscalls:sys_enter_mkdirat                                   
                11      syscalls:sys_enter_mkdir                                    
                 9      syscalls:sys_enter_rmdir                                    
                 0      syscalls:sys_enter_unlinkat                                   
             56176      syscalls:sys_enter_unlink                                   
                 0      syscalls:sys_enter_symlinkat                                   
                 0      syscalls:sys_enter_symlink                                   
                 0      syscalls:sys_enter_linkat                                   
              6241      syscalls:sys_enter_link                                     
                 0      syscalls:sys_enter_renameat2                                   
                 0      syscalls:sys_enter_renameat                                   
                 0      syscalls:sys_enter_rename                                   
                 0      syscalls:sys_enter_pipe2                                    
                 2      syscalls:sys_enter_pipe                                     
                 1      syscalls:sys_enter_execve                                   
                 0      syscalls:sys_enter_execveat                                   
             49929      syscalls:sys_enter_newstat                                   
              6243      syscalls:sys_enter_newlstat                                   
                 0      syscalls:sys_enter_newfstatat                                   
            135664      syscalls:sys_enter_newfstat                                   
                 0      syscalls:sys_enter_readlinkat                                   
                 1      syscalls:sys_enter_readlink                                   
                 0      syscalls:sys_enter_statx                                    
           2375544      syscalls:sys_enter_lseek                                    
            610891      syscalls:sys_enter_read                                     
           1324213      syscalls:sys_enter_write                                    
                16      syscalls:sys_enter_pread64                                   
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
             12488      syscalls:sys_enter_access                                   
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
                 2      syscalls:sys_enter_open                                     
            118621      syscalls:sys_enter_openat                                   
                 0      syscalls:sys_enter_creat                                    
            214100      syscalls:sys_enter_close                                    
                 0      syscalls:sys_enter_vhangup                                   
                 0      syscalls:sys_enter_memfd_create                                   
                 0      syscalls:sys_enter_move_pages                                   
                 0      syscalls:sys_enter_mbind                                    
                 0      syscalls:sys_enter_set_mempolicy                                   
                 0      syscalls:sys_enter_migrate_pages                                   
                 0      syscalls:sys_enter_get_mempolicy                                   
                 0      syscalls:sys_enter_swapoff                                   
                 0      syscalls:sys_enter_swapon                                   
                 0      syscalls:sys_enter_madvise                                   
                 0      syscalls:sys_enter_process_vm_readv                                   
                 0      syscalls:sys_enter_process_vm_writev                                   
                 0      syscalls:sys_enter_msync                                    
                 0      syscalls:sys_enter_mremap                                   
                21      syscalls:sys_enter_mprotect                                   
                 0      syscalls:sys_enter_pkey_mprotect                                   
                 0      syscalls:sys_enter_pkey_alloc                                   
                 0      syscalls:sys_enter_pkey_free                                   
               599      syscalls:sys_enter_brk                                      
                23      syscalls:sys_enter_munmap                                   
                 0      syscalls:sys_enter_remap_file_pages                                   
                 0      syscalls:sys_enter_mlock                                    
                 0      syscalls:sys_enter_mlock2                                   
                 0      syscalls:sys_enter_munlock                                   
                 0      syscalls:sys_enter_mlockall                                   
                 0      syscalls:sys_enter_munlockall                                   
                 0      syscalls:sys_enter_mincore                                   
                 0      syscalls:sys_enter_readahead                                   
                 0      syscalls:sys_enter_fadvise64                                   
                 0      syscalls:sys_enter_rseq                                     
                 0      syscalls:sys_enter_perf_event_open                                   
                 0      syscalls:sys_enter_bpf                                      
                 0      syscalls:sys_enter_seccomp                                   
                 0      syscalls:sys_enter_kexec_file_load                                   
                 0      syscalls:sys_enter_kexec_load                                   
                 0      syscalls:sys_enter_acct                                     
                 0      syscalls:sys_enter_delete_module                                   
                 0      syscalls:sys_enter_init_module                                   
                 0      syscalls:sys_enter_finit_module                                   
             49931      syscalls:sys_enter_set_robust_list                                   
                 0      syscalls:sys_enter_get_robust_list                                   
                 1      syscalls:sys_enter_futex                                    
                 0      syscalls:sys_enter_getitimer                                   
                 0      syscalls:sys_enter_alarm                                    
                 0      syscalls:sys_enter_setitimer                                   
                 0      syscalls:sys_enter_timer_create                                   
                 0      syscalls:sys_enter_timer_gettime                                   
                 0      syscalls:sys_enter_timer_getoverrun                                   
                 0      syscalls:sys_enter_timer_settime                                   
                 0      syscalls:sys_enter_timer_delete                                   
                 0      syscalls:sys_enter_clock_settime                                   
                 0      syscalls:sys_enter_clock_gettime                                   
                 0      syscalls:sys_enter_clock_adjtime                                   
                 0      syscalls:sys_enter_clock_getres                                   
                 1      syscalls:sys_enter_clock_nanosleep                                   
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
                 0      syscalls:sys_enter_pidfd_open                                   
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
                 2      syscalls:sys_enter_getpid                                   
                 0      syscalls:sys_enter_gettid                                   
                 0      syscalls:sys_enter_getppid                                   
                 0      syscalls:sys_enter_getuid                                   
                 0      syscalls:sys_enter_geteuid                                   
                 0      syscalls:sys_enter_getgid                                   
                 0      syscalls:sys_enter_getegid                                   
             49929      syscalls:sys_enter_times                                    
                 0      syscalls:sys_enter_setpgid                                   
                 2      syscalls:sys_enter_getpgid                                   
                 0      syscalls:sys_enter_getpgrp                                   
                 0      syscalls:sys_enter_getsid                                   
                 1      syscalls:sys_enter_setsid                                   
                 0      syscalls:sys_enter_newuname                                   
                 0      syscalls:sys_enter_sethostname                                   
                 0      syscalls:sys_enter_setdomainname                                   
                 0      syscalls:sys_enter_getrlimit                                   
             49932      syscalls:sys_enter_prlimit64                                   
                 0      syscalls:sys_enter_setrlimit                                   
                 1      syscalls:sys_enter_getrusage                                   
                 0      syscalls:sys_enter_umask                                    
                 0      syscalls:sys_enter_prctl                                    
                 0      syscalls:sys_enter_getcpu                                   
                 1      syscalls:sys_enter_sysinfo                                   
                 0      syscalls:sys_enter_restart_syscall                                   
                 2      syscalls:sys_enter_rt_sigprocmask                                   
                 0      syscalls:sys_enter_rt_sigpending                                   
                 0      syscalls:sys_enter_rt_sigtimedwait                                   
                 3      syscalls:sys_enter_kill                                     
                 0      syscalls:sys_enter_pidfd_send_signal                                   
                 0      syscalls:sys_enter_tgkill                                   
                 0      syscalls:sys_enter_tkill                                    
                 0      syscalls:sys_enter_rt_sigqueueinfo                                   
                 0      syscalls:sys_enter_rt_tgsigqueueinfo                                   
                 2      syscalls:sys_enter_sigaltstack                                   
             99871      syscalls:sys_enter_rt_sigaction                                   
                 0      syscalls:sys_enter_pause                                    
                 0      syscalls:sys_enter_rt_sigsuspend                                   
                 0      syscalls:sys_enter_ptrace                                   
                 0      syscalls:sys_enter_capget                                   
                 0      syscalls:sys_enter_capset                                   
                 0      syscalls:sys_enter_sysctl                                   
                 0      syscalls:sys_enter_exit                                     
             49929      syscalls:sys_enter_exit_group                                   
                 0      syscalls:sys_enter_waitid                                   
             49929      syscalls:sys_enter_wait4                                    
                 0      syscalls:sys_enter_personality                                   
                 2      syscalls:sys_enter_set_tid_address                                   
                 0      syscalls:sys_enter_fork                                     
                 0      syscalls:sys_enter_vfork                                    
             49929      syscalls:sys_enter_clone                                    
                 0      syscalls:sys_enter_clone3                                   
                 0      syscalls:sys_enter_unshare                                   
                94      syscalls:sys_enter_mmap                                     
                 0      syscalls:sys_enter_modify_ldt                                   
                 0      syscalls:sys_enter_ioperm                                   
                 0      syscalls:sys_enter_iopl                                     
                 0      syscalls:sys_enter_rt_sigreturn                                   
                 4      syscalls:sys_enter_arch_prctl         
```

Snapshot

```
 Profiling information: 
 5233 ms total work, 104823 ns/work,             
 12087 ms total running, 242104 ns/run, 
 669 ms total write testcase, 13413 ns/write             
 99 ms total forking, 1998 ns/fork, 
 0 ms total purely run, 0 ns/purely run             
 10 ns/system running, 0 ns/user running,            
 5233 ms total pre-fuzzing, 104823 ns/pre-fuzzing,             
 0 ms total post-fuzzing, 0 ns/post-fuzzing
total execution is 0x49928

 Performance counter stats for 'afl-fuzz -i /out/corpus_objdump_snap -o /dev/shm/out_rm -f /dev/shm/afl_f /out/objdump_fork -d /dev/shm/afl_f':

          18832.74 msec task-clock                #    0.914 CPUs utilized
            300788      context-switches          #    0.016 M/sec
             42977      cpu-migrations            #    0.002 M/sec
           2709011      page-faults               #    0.144 M/sec
       59420911852      cycles                    #    3.155 GHz                      (83.26%)
        3405907274      stalled-cycles-frontend   #    5.73% frontend cycles idle     (83.65%)
       15879519145      stalled-cycles-backend    #   26.72% backend cycles idle      (83.19%)
       66543849614      instructions              #    1.12  insn per cycle
                                                  #    0.24  stalled cycles per insn  (83.57%)
       10209569851      branches                  #  542.118 M/sec                    (83.21%)
         146075405      branch-misses             #    1.43% of all branches          (83.12%)

Performance counter stats for 'afl-fuzz -i /out/corpus_objdump_snap -o /dev/shm/out_rm -f /dev/shm/afl_f /out/objdump_fork -d /dev/shm/afl_f':

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
                 2      syscalls:sys_enter_shmget                                   
                 3      syscalls:sys_enter_shmctl                                   
                 3      syscalls:sys_enter_shmat                                    
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
                 0      syscalls:sys_enter_io_uring_enter                                   
                 0      syscalls:sys_enter_io_uring_setup                                   
                 0      syscalls:sys_enter_io_uring_register                                   
                 0      syscalls:sys_enter_io_setup                                   
                 0      syscalls:sys_enter_io_destroy                                   
                 0      syscalls:sys_enter_io_submit                                   
                 0      syscalls:sys_enter_io_cancel                                   
                 0      syscalls:sys_enter_io_getevents                                   
                 0      syscalls:sys_enter_io_pgetevents                                   
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
                 0      syscalls:sys_enter_fsopen                                   
                 0      syscalls:sys_enter_fspick                                   
                 0      syscalls:sys_enter_fsconfig                                   
                 0      syscalls:sys_enter_statfs                                   
                 0      syscalls:sys_enter_fstatfs                                   
                 0      syscalls:sys_enter_ustat                                    
                 0      syscalls:sys_enter_getcwd                                   
                 0      syscalls:sys_enter_utimensat                                   
                 0      syscalls:sys_enter_futimesat                                   
                 0      syscalls:sys_enter_utimes                                   
                 0      syscalls:sys_enter_utime                                    
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
                 0      syscalls:sys_enter_open_tree                                   
                 0      syscalls:sys_enter_mount                                    
                 0      syscalls:sys_enter_fsmount                                   
                 0      syscalls:sys_enter_move_mount                                   
                 0      syscalls:sys_enter_pivot_root                                   
                 0      syscalls:sys_enter_sysfs                                    
                 0      syscalls:sys_enter_dup3                                     
                 5      syscalls:sys_enter_dup2                                     
                 0      syscalls:sys_enter_dup                                      
             49929      syscalls:sys_enter_select                                   
                 0      syscalls:sys_enter_pselect6                                   
                 0      syscalls:sys_enter_poll                                     
                 0      syscalls:sys_enter_ppoll                                    
                 0      syscalls:sys_enter_getdents                                   
                46      syscalls:sys_enter_getdents64                                   
             35778      syscalls:sys_enter_ioctl                                    
             99860      syscalls:sys_enter_fcntl                                    
                 0      syscalls:sys_enter_mknodat                                   
                 0      syscalls:sys_enter_mknod                                    
                 0      syscalls:sys_enter_mkdirat                                   
                11      syscalls:sys_enter_mkdir                                    
                 9      syscalls:sys_enter_rmdir                                    
                 0      syscalls:sys_enter_unlinkat                                   
             56176      syscalls:sys_enter_unlink                                   
                 0      syscalls:sys_enter_symlinkat                                   
                 0      syscalls:sys_enter_symlink                                   
                 0      syscalls:sys_enter_linkat                                   
              6241      syscalls:sys_enter_link                                     
                 0      syscalls:sys_enter_renameat2                                   
                 0      syscalls:sys_enter_renameat                                   
                 0      syscalls:sys_enter_rename                                   
                 0      syscalls:sys_enter_pipe2                                    
                 2      syscalls:sys_enter_pipe                                     
                 1      syscalls:sys_enter_execve                                   
                 0      syscalls:sys_enter_execveat                                   
             49929      syscalls:sys_enter_newstat                                   
              6243      syscalls:sys_enter_newlstat                                   
                 0      syscalls:sys_enter_newfstatat                                   
            135664      syscalls:sys_enter_newfstat                                   
                 0      syscalls:sys_enter_readlinkat                                   
                 1      syscalls:sys_enter_readlink                                   
                 0      syscalls:sys_enter_statx                                    
           2375544      syscalls:sys_enter_lseek                                    
            610891      syscalls:sys_enter_read                                     
           1324214      syscalls:sys_enter_write                                    
                16      syscalls:sys_enter_pread64                                   
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
             12488      syscalls:sys_enter_access                                   
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
                 2      syscalls:sys_enter_open                                     
            118622      syscalls:sys_enter_openat                                   
                 0      syscalls:sys_enter_creat                                    
            114246      syscalls:sys_enter_close                                    
                 0      syscalls:sys_enter_vhangup                                   
                 0      syscalls:sys_enter_memfd_create                                   
                 0      syscalls:sys_enter_move_pages                                   
                 0      syscalls:sys_enter_mbind                                    
                 0      syscalls:sys_enter_set_mempolicy                                   
                 0      syscalls:sys_enter_migrate_pages                                   
                 0      syscalls:sys_enter_get_mempolicy                                   
                 0      syscalls:sys_enter_swapoff                                   
                 0      syscalls:sys_enter_swapon                                   
                 0      syscalls:sys_enter_madvise                                   
                 0      syscalls:sys_enter_process_vm_readv                                   
                 0      syscalls:sys_enter_process_vm_writev                                   
                 0      syscalls:sys_enter_msync                                    
                 0      syscalls:sys_enter_mremap                                   
                21      syscalls:sys_enter_mprotect                                   
                 0      syscalls:sys_enter_pkey_mprotect                                   
                 0      syscalls:sys_enter_pkey_alloc                                   
                 0      syscalls:sys_enter_pkey_free                                   
               599      syscalls:sys_enter_brk                                      
                23      syscalls:sys_enter_munmap                                   
                 0      syscalls:sys_enter_remap_file_pages                                   
                 0      syscalls:sys_enter_mlock                                    
                 0      syscalls:sys_enter_mlock2                                   
                 0      syscalls:sys_enter_munlock                                   
                 0      syscalls:sys_enter_mlockall                                   
                 0      syscalls:sys_enter_munlockall                                   
                 0      syscalls:sys_enter_mincore                                   
                 0      syscalls:sys_enter_readahead                                   
                 0      syscalls:sys_enter_fadvise64                                   
                 0      syscalls:sys_enter_rseq                                     
                 0      syscalls:sys_enter_perf_event_open                                   
                 0      syscalls:sys_enter_bpf                                      
                 0      syscalls:sys_enter_seccomp                                   
                 0      syscalls:sys_enter_kexec_file_load                                   
                 0      syscalls:sys_enter_kexec_load                                   
                 0      syscalls:sys_enter_acct                                     
                 0      syscalls:sys_enter_delete_module                                   
                 0      syscalls:sys_enter_init_module                                   
                 0      syscalls:sys_enter_finit_module                                   
                 4      syscalls:sys_enter_set_robust_list                                   
                 0      syscalls:sys_enter_get_robust_list                                   
                 1      syscalls:sys_enter_futex                                    
                 0      syscalls:sys_enter_getitimer                                   
                 0      syscalls:sys_enter_alarm                                    
                 0      syscalls:sys_enter_setitimer                                   
                 0      syscalls:sys_enter_timer_create                                   
                 0      syscalls:sys_enter_timer_gettime                                   
                 0      syscalls:sys_enter_timer_getoverrun                                   
                 0      syscalls:sys_enter_timer_settime                                   
                 0      syscalls:sys_enter_timer_delete                                   
                 0      syscalls:sys_enter_clock_settime                                   
                 0      syscalls:sys_enter_clock_gettime                                   
                 0      syscalls:sys_enter_clock_adjtime                                   
                 0      syscalls:sys_enter_clock_getres                                   
                 1      syscalls:sys_enter_clock_nanosleep                                   
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
                 0      syscalls:sys_enter_pidfd_open                                   
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
             49930      syscalls:sys_enter_getpid                                   
             49928      syscalls:sys_enter_gettid                                   
                 0      syscalls:sys_enter_getppid                                   
                 0      syscalls:sys_enter_getuid                                   
                 0      syscalls:sys_enter_geteuid                                   
                 0      syscalls:sys_enter_getgid                                   
                 0      syscalls:sys_enter_getegid                                   
             49929      syscalls:sys_enter_times                                    
                 0      syscalls:sys_enter_setpgid                                   
                 2      syscalls:sys_enter_getpgid                                   
                 0      syscalls:sys_enter_getpgrp                                   
                 0      syscalls:sys_enter_getsid                                   
                 1      syscalls:sys_enter_setsid                                   
                 0      syscalls:sys_enter_newuname                                   
                 0      syscalls:sys_enter_sethostname                                   
                 0      syscalls:sys_enter_setdomainname                                   
                 0      syscalls:sys_enter_getrlimit                                   
             49932      syscalls:sys_enter_prlimit64                                   
                 0      syscalls:sys_enter_setrlimit                                   
                 1      syscalls:sys_enter_getrusage                                   
                 0      syscalls:sys_enter_umask                                    
                 0      syscalls:sys_enter_prctl                                    
                 0      syscalls:sys_enter_getcpu                                   
                 1      syscalls:sys_enter_sysinfo                                   
                 0      syscalls:sys_enter_restart_syscall                                   
             99857      syscalls:sys_enter_rt_sigprocmask                                   
                 0      syscalls:sys_enter_rt_sigpending                                   
                 0      syscalls:sys_enter_rt_sigtimedwait                                   
             49931      syscalls:sys_enter_kill                                     
                 0      syscalls:sys_enter_pidfd_send_signal                                   
             49928      syscalls:sys_enter_tgkill                                   
                 0      syscalls:sys_enter_tkill                                    
                 0      syscalls:sys_enter_rt_sigqueueinfo                                   
                 0      syscalls:sys_enter_rt_tgsigqueueinfo                                   
                 2      syscalls:sys_enter_sigaltstack                                   
                17      syscalls:sys_enter_rt_sigaction                                   
                 0      syscalls:sys_enter_pause                                    
                 0      syscalls:sys_enter_rt_sigsuspend                                   
                 0      syscalls:sys_enter_ptrace                                   
                 0      syscalls:sys_enter_capget                                   
                 0      syscalls:sys_enter_capset                                   
                 0      syscalls:sys_enter_sysctl                                   
                 0      syscalls:sys_enter_exit                                     
             49929      syscalls:sys_enter_exit_group                                   
                 0      syscalls:sys_enter_waitid                                   
             49929      syscalls:sys_enter_wait4                                    
                 0      syscalls:sys_enter_personality                                   
                 2      syscalls:sys_enter_set_tid_address                                   
                 0      syscalls:sys_enter_fork                                     
                 0      syscalls:sys_enter_vfork                                    
                 2      syscalls:sys_enter_clone                                    
                 0      syscalls:sys_enter_clone3                                   
                 0      syscalls:sys_enter_unshare                                   
                94      syscalls:sys_enter_mmap                                     
                 0      syscalls:sys_enter_modify_ldt                                   
                 0      syscalls:sys_enter_ioperm                                   
                 0      syscalls:sys_enter_iopl                                     
                 0      syscalls:sys_enter_rt_sigreturn                                   
                 4      syscalls:sys_enter_arch_prctl                                   

```

Persistent Mode

```
Profiling information: 
7069 ms total work, 127806 ns/work,             
10445 ms total running, 188839 ns/run, 
721 ms total write testcase, 13048 ns/write             
642 ms total forking, 11610 ns/fork, 
8919 ms total purely run, 161247 ns/purely run             
20428 ns/system running, 130884 ns/user running,             
7069 ms total pre-fuzzing, 127806 ns/pre-fuzzing,             
0 ms total post-fuzzing, 0 ns/post-fuzzing
total execution is 0x55316

 Performance counter stats for 'afl-fuzz -i /out/corpus_objdump_snap -o /dev/shm/out_rm -f /dev/shm/afl_f /out/objdump_per -d /dev/shm/afl_f':

          19485.77 msec task-clock                #    0.912 CPUs utilized
            321895      context-switches          #    0.017 M/sec
             53455      cpu-migrations            #    0.003 M/sec
            826803      page-faults               #    0.042 M/sec
       61495219401      cycles                    #    3.156 GHz                      (83.73%)
        3483894616      stalled-cycles-frontend   #    5.67% frontend cycles idle     (83.62%)
       17380231586      stalled-cycles-backend    #   28.26% backend cycles idle      (82.77%)
       79361102742      instructions              #    1.29  insn per cycle
                                                  #    0.22  stalled cycles per insn  (82.81%)
       11180578850      branches                  #  573.782 M/sec                    (83.52%)
         137847973      branch-misses             #    1.23% of all branches          (83.56%)

 Performance counter stats for 'afl-fuzz -i /out/corpus_objdump_snap -o /dev/shm/out_rm -f /dev/shm/afl_f /out/objdump_per -d /dev/shm/afl_f':

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
                 2      syscalls:sys_enter_shmget                                   
                 3      syscalls:sys_enter_shmctl                                   
                 3      syscalls:sys_enter_shmat                                    
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
                 0      syscalls:sys_enter_io_uring_enter                                   
                 0      syscalls:sys_enter_io_uring_setup                                   
                 0      syscalls:sys_enter_io_uring_register                                   
                 0      syscalls:sys_enter_io_setup                                   
                 0      syscalls:sys_enter_io_destroy                                   
                 0      syscalls:sys_enter_io_submit                                   
                 0      syscalls:sys_enter_io_cancel                                   
                 0      syscalls:sys_enter_io_getevents                                   
                 0      syscalls:sys_enter_io_pgetevents                                   
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
                 0      syscalls:sys_enter_fsopen                                   
                 0      syscalls:sys_enter_fspick                                   
                 0      syscalls:sys_enter_fsconfig                                   
                 0      syscalls:sys_enter_statfs                                   
                 0      syscalls:sys_enter_fstatfs                                   
                 0      syscalls:sys_enter_ustat                                    
                 0      syscalls:sys_enter_getcwd                                   
                 0      syscalls:sys_enter_utimensat                                   
                 0      syscalls:sys_enter_futimesat                                   
                 0      syscalls:sys_enter_utimes                                   
                 0      syscalls:sys_enter_utime                                    
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
                 0      syscalls:sys_enter_open_tree                                   
                 0      syscalls:sys_enter_mount                                    
                 0      syscalls:sys_enter_fsmount                                   
                 0      syscalls:sys_enter_move_mount                                   
                 0      syscalls:sys_enter_pivot_root                                   
                 0      syscalls:sys_enter_sysfs                                    
                 0      syscalls:sys_enter_dup3                                     
                 5      syscalls:sys_enter_dup2                                     
                 0      syscalls:sys_enter_dup                                      
             55317      syscalls:sys_enter_select                                   
                 0      syscalls:sys_enter_pselect6                                   
                 0      syscalls:sys_enter_poll                                     
                 0      syscalls:sys_enter_ppoll                                    
                 0      syscalls:sys_enter_getdents                                   
                47      syscalls:sys_enter_getdents64                                   
              6360      syscalls:sys_enter_ioctl                                    
            110636      syscalls:sys_enter_fcntl                                    
                 0      syscalls:sys_enter_mknodat                                   
                 0      syscalls:sys_enter_mknod                                    
                 0      syscalls:sys_enter_mkdirat                                   
                11      syscalls:sys_enter_mkdir                                    
                 9      syscalls:sys_enter_rmdir                                    
                 0      syscalls:sys_enter_unlinkat                                   
             62013      syscalls:sys_enter_unlink                                   
                 0      syscalls:sys_enter_symlinkat                                   
               449      syscalls:sys_enter_symlink                                   
                 0      syscalls:sys_enter_linkat                                   
              6241      syscalls:sys_enter_link                                     
                 0      syscalls:sys_enter_renameat2                                   
                 0      syscalls:sys_enter_renameat                                   
                 0      syscalls:sys_enter_rename                                   
                 0      syscalls:sys_enter_pipe2                                    
                 2      syscalls:sys_enter_pipe                                     
                 1      syscalls:sys_enter_execve                                   
                 0      syscalls:sys_enter_execveat                                   
             55317      syscalls:sys_enter_newstat                                   
              6243      syscalls:sys_enter_newlstat                                   
                 0      syscalls:sys_enter_newfstatat                                   
            117023      syscalls:sys_enter_newfstat                                   
                 0      syscalls:sys_enter_readlinkat                                   
                 1      syscalls:sys_enter_readlink                                   
                 0      syscalls:sys_enter_statx                                    
           2599056      syscalls:sys_enter_lseek                                    
            675283      syscalls:sys_enter_read                                     
           1583903      syscalls:sys_enter_write                                    
                16      syscalls:sys_enter_pread64                                   
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
             12488      syscalls:sys_enter_access                                   
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
                 2      syscalls:sys_enter_open                                     
            129397      syscalls:sys_enter_openat                                   
                 0      syscalls:sys_enter_creat                                    
            135794      syscalls:sys_enter_close                                    
                 0      syscalls:sys_enter_vhangup                                   
                 0      syscalls:sys_enter_memfd_create                                   
                 0      syscalls:sys_enter_move_pages                                   
                 0      syscalls:sys_enter_mbind                                    
                 0      syscalls:sys_enter_set_mempolicy                                   
                 0      syscalls:sys_enter_migrate_pages                                   
                 0      syscalls:sys_enter_get_mempolicy                                   
                 0      syscalls:sys_enter_swapoff                                   
                 0      syscalls:sys_enter_swapon                                   
                 0      syscalls:sys_enter_madvise                                   
                 0      syscalls:sys_enter_process_vm_readv                                   
                 0      syscalls:sys_enter_process_vm_writev                                   
                 0      syscalls:sys_enter_msync                                    
                 0      syscalls:sys_enter_mremap                                   
                21      syscalls:sys_enter_mprotect                                   
                 0      syscalls:sys_enter_pkey_mprotect                                   
                 0      syscalls:sys_enter_pkey_alloc                                   
                 0      syscalls:sys_enter_pkey_free                                   
               268      syscalls:sys_enter_brk                                      
                16      syscalls:sys_enter_munmap                                   
                 0      syscalls:sys_enter_remap_file_pages                                   
                 0      syscalls:sys_enter_mlock                                    
                 0      syscalls:sys_enter_mlock2                                   
                 0      syscalls:sys_enter_munlock                                   
                 0      syscalls:sys_enter_mlockall                                   
                 0      syscalls:sys_enter_munlockall                                   
                 0      syscalls:sys_enter_mincore                                   
                 0      syscalls:sys_enter_readahead                                   
                 0      syscalls:sys_enter_fadvise64                                   
                 0      syscalls:sys_enter_rseq                                     
                 0      syscalls:sys_enter_perf_event_open                                   
                 0      syscalls:sys_enter_bpf                                      
                 0      syscalls:sys_enter_seccomp                                   
                 0      syscalls:sys_enter_kexec_file_load                                   
                 0      syscalls:sys_enter_kexec_load                                   
                 0      syscalls:sys_enter_acct                                     
                 0      syscalls:sys_enter_delete_module                                   
                 0      syscalls:sys_enter_init_module                                   
                 0      syscalls:sys_enter_finit_module                                   
              6362      syscalls:sys_enter_set_robust_list                                   
                 0      syscalls:sys_enter_get_robust_list                                   
                 1      syscalls:sys_enter_futex                                    
                 0      syscalls:sys_enter_getitimer                                   
                 0      syscalls:sys_enter_alarm                                    
                 0      syscalls:sys_enter_setitimer                                   
                 0      syscalls:sys_enter_timer_create                                   
                 0      syscalls:sys_enter_timer_gettime                                   
                 0      syscalls:sys_enter_timer_getoverrun                                   
                 0      syscalls:sys_enter_timer_settime                                   
                 0      syscalls:sys_enter_timer_delete                                   
                 0      syscalls:sys_enter_clock_settime                                   
                 0      syscalls:sys_enter_clock_gettime                                   
                 0      syscalls:sys_enter_clock_adjtime                                   
                 0      syscalls:sys_enter_clock_getres                                   
                 1      syscalls:sys_enter_clock_nanosleep                                   
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
                 0      syscalls:sys_enter_pidfd_open                                   
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
             48960      syscalls:sys_enter_getpid                                   
             48958      syscalls:sys_enter_gettid                                   
                 0      syscalls:sys_enter_getppid                                   
                 0      syscalls:sys_enter_getuid                                   
                 0      syscalls:sys_enter_geteuid                                   
                 0      syscalls:sys_enter_getgid                                   
                 0      syscalls:sys_enter_getegid                                   
             55317      syscalls:sys_enter_times                                    
                 0      syscalls:sys_enter_setpgid                                   
                 2      syscalls:sys_enter_getpgid                                   
                 0      syscalls:sys_enter_getpgrp                                   
                 0      syscalls:sys_enter_getsid                                   
                 1      syscalls:sys_enter_setsid                                   
                 0      syscalls:sys_enter_newuname                                   
                 0      syscalls:sys_enter_sethostname                                   
                 0      syscalls:sys_enter_setdomainname                                   
                 0      syscalls:sys_enter_getrlimit                                   
              6363      syscalls:sys_enter_prlimit64                                   
                 0      syscalls:sys_enter_setrlimit                                   
                 1      syscalls:sys_enter_getrusage                                   
                 0      syscalls:sys_enter_umask                                    
                 0      syscalls:sys_enter_prctl                                    
                 0      syscalls:sys_enter_getcpu                                   
                 1      syscalls:sys_enter_sysinfo                                   
                 0      syscalls:sys_enter_restart_syscall                                   
             97917      syscalls:sys_enter_rt_sigprocmask                                   
                 0      syscalls:sys_enter_rt_sigpending                                   
                 0      syscalls:sys_enter_rt_sigtimedwait                                   
             48961      syscalls:sys_enter_kill                                     
                 0      syscalls:sys_enter_pidfd_send_signal                                   
             48958      syscalls:sys_enter_tgkill                                   
                 0      syscalls:sys_enter_tkill                                    
                 0      syscalls:sys_enter_rt_sigqueueinfo                                   
                 0      syscalls:sys_enter_rt_tgsigqueueinfo                                   
                 2      syscalls:sys_enter_sigaltstack                                   
             12733      syscalls:sys_enter_rt_sigaction                                   
                 0      syscalls:sys_enter_pause                                    
                 0      syscalls:sys_enter_rt_sigsuspend                                   
                 0      syscalls:sys_enter_ptrace                                   
                 0      syscalls:sys_enter_capget                                   
                 0      syscalls:sys_enter_capset                                   
                 0      syscalls:sys_enter_sysctl                                   
                 0      syscalls:sys_enter_exit                                     
              6359      syscalls:sys_enter_exit_group                                   
                 0      syscalls:sys_enter_waitid                                   
             55317      syscalls:sys_enter_wait4                                    
                 0      syscalls:sys_enter_personality                                   
                 2      syscalls:sys_enter_set_tid_address                                   
                 0      syscalls:sys_enter_fork                                     
                 0      syscalls:sys_enter_vfork                                    
              6360      syscalls:sys_enter_clone                                    
                 0      syscalls:sys_enter_clone3                                   
                 0      syscalls:sys_enter_unshare                                   
                87      syscalls:sys_enter_mmap                                     
                 0      syscalls:sys_enter_modify_ldt                                   
                 0      syscalls:sys_enter_ioperm                                   
                 0      syscalls:sys_enter_iopl                                     
                 0      syscalls:sys_enter_rt_sigreturn                                   
                 4      syscalls:sys_enter_arch_prctl      

```

Persistent Mode + VFS

```
Profiling information: 
6256 ms total work, 113766 ns/work,             
9870 ms total running, 179494 ns/run, 
28 ms total write testcase, 511 ns/write             
717 ms total forking, 13043 ns/fork, 
8279 ms total purely run, 150565 ns/purely run             
12001 ns/system running, 128564 ns/user running,             
6256 ms total pre-fuzzing, 113766 ns/pre-fuzzing,             
0 ms total post-fuzzing, 0 ns/post-fuzzing
total execution is 0x54992


 Performance counter stats for 'afl-fuzz -i /out/corpus_objdump_snap -o /dev/shm/out_rm -f /dev/shm/afl_f /out/objdump_per -d /dev/shm/afl_f':

          18200.19 msec task-clock                #    0.908 CPUs utilized
            320221      context-switches          #    0.018 M/sec
             53028      cpu-migrations            #    0.003 M/sec
            956084      page-faults               #    0.053 M/sec
       57322990719      cycles                    #    3.150 GHz                      (84.22%)
        3415811390      stalled-cycles-frontend   #    5.96% frontend cycles idle     (83.53%)
       16451149531      stalled-cycles-backend    #   28.70% backend cycles idle      (83.60%)
       75964899547      instructions              #    1.33  insn per cycle
                                                  #    0.22  stalled cycles per insn  (81.81%)
       10620867763      branches                  #  583.558 M/sec                    (83.13%)
         111726635      branch-misses             #    1.05% of all branches          (83.71%)

 Performance counter stats for 'afl-fuzz -i /out/corpus_objdump_snap -o /dev/shm/out_rm -f /dev/shm/afl_f /out/objdump_per -d /dev/shm/afl_f':

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
                 4      syscalls:sys_enter_shmget                                   
                 3      syscalls:sys_enter_shmctl                                   
                 5      syscalls:sys_enter_shmat                                    
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
                 0      syscalls:sys_enter_io_uring_enter                                   
                 0      syscalls:sys_enter_io_uring_setup                                   
                 0      syscalls:sys_enter_io_uring_register                                   
                 0      syscalls:sys_enter_io_setup                                   
                 0      syscalls:sys_enter_io_destroy                                   
                 0      syscalls:sys_enter_io_submit                                   
                 0      syscalls:sys_enter_io_cancel                                   
                 0      syscalls:sys_enter_io_getevents                                   
                 0      syscalls:sys_enter_io_pgetevents                                   
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
                 0      syscalls:sys_enter_fsopen                                   
                 0      syscalls:sys_enter_fspick                                   
                 0      syscalls:sys_enter_fsconfig                                   
                 1      syscalls:sys_enter_statfs                                   
                 0      syscalls:sys_enter_fstatfs                                   
                 0      syscalls:sys_enter_ustat                                    
                 0      syscalls:sys_enter_getcwd                                   
                 0      syscalls:sys_enter_utimensat                                   
                 0      syscalls:sys_enter_futimesat                                   
                 0      syscalls:sys_enter_utimes                                   
                 0      syscalls:sys_enter_utime                                    
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
                 0      syscalls:sys_enter_open_tree                                   
                 0      syscalls:sys_enter_mount                                    
                 0      syscalls:sys_enter_fsmount                                   
                 0      syscalls:sys_enter_move_mount                                   
                 0      syscalls:sys_enter_pivot_root                                   
                 0      syscalls:sys_enter_sysfs                                    
                 0      syscalls:sys_enter_dup3                                     
                 5      syscalls:sys_enter_dup2                                     
                 0      syscalls:sys_enter_dup                                      
             54993      syscalls:sys_enter_select                                   
                 0      syscalls:sys_enter_pselect6                                   
                 0      syscalls:sys_enter_poll                                     
                 0      syscalls:sys_enter_ppoll                                    
                 0      syscalls:sys_enter_getdents                                   
                47      syscalls:sys_enter_getdents64                                   
              6340      syscalls:sys_enter_ioctl                                    
                 4      syscalls:sys_enter_fcntl                                    
                 0      syscalls:sys_enter_mknodat                                   
                 0      syscalls:sys_enter_mknod                                    
                 0      syscalls:sys_enter_mkdirat                                   
                11      syscalls:sys_enter_mkdir                                    
                 9      syscalls:sys_enter_rmdir                                    
                 0      syscalls:sys_enter_unlinkat                                   
              6671      syscalls:sys_enter_unlink                                   
                 0      syscalls:sys_enter_symlinkat                                   
               422      syscalls:sys_enter_symlink                                   
                 0      syscalls:sys_enter_linkat                                   
              6241      syscalls:sys_enter_link                                     
                 0      syscalls:sys_enter_renameat2                                   
                 0      syscalls:sys_enter_renameat                                   
                 0      syscalls:sys_enter_rename                                   
                 0      syscalls:sys_enter_pipe2                                    
                 2      syscalls:sys_enter_pipe                                     
                 1      syscalls:sys_enter_execve                                   
                 0      syscalls:sys_enter_execveat                                   
                10      syscalls:sys_enter_newstat                                   
              6243      syscalls:sys_enter_newlstat                                   
                 0      syscalls:sys_enter_newfstatat                                   
              6377      syscalls:sys_enter_newfstat                                   
                 0      syscalls:sys_enter_readlinkat                                   
                 1      syscalls:sys_enter_readlink                                   
                 0      syscalls:sys_enter_statx                                    
                 0      syscalls:sys_enter_lseek                                    
            403719      syscalls:sys_enter_read                                     
            408240      syscalls:sys_enter_write                                    
                16      syscalls:sys_enter_pread64                                   
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
             12488      syscalls:sys_enter_access                                   
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
                 2      syscalls:sys_enter_open                                     
             18781      syscalls:sys_enter_openat                                   
                 0      syscalls:sys_enter_creat                                    
             86447      syscalls:sys_enter_close                                    
                 0      syscalls:sys_enter_vhangup                                   
                 0      syscalls:sys_enter_memfd_create                                   
                 0      syscalls:sys_enter_move_pages                                   
                 0      syscalls:sys_enter_mbind                                    
                 0      syscalls:sys_enter_set_mempolicy                                   
                 0      syscalls:sys_enter_migrate_pages                                   
                 0      syscalls:sys_enter_get_mempolicy                                   
                 0      syscalls:sys_enter_swapoff                                   
                 0      syscalls:sys_enter_swapon                                   
                 0      syscalls:sys_enter_madvise                                   
                 0      syscalls:sys_enter_process_vm_readv                                   
                 0      syscalls:sys_enter_process_vm_writev                                   
                 0      syscalls:sys_enter_msync                                    
                 0      syscalls:sys_enter_mremap                                   
                88      syscalls:sys_enter_mprotect                                   
                 0      syscalls:sys_enter_pkey_mprotect                                   
                 0      syscalls:sys_enter_pkey_alloc                                   
                 0      syscalls:sys_enter_pkey_free                                   
              7993      syscalls:sys_enter_brk                                      
                16      syscalls:sys_enter_munmap                                   
                 0      syscalls:sys_enter_remap_file_pages                                   
                 0      syscalls:sys_enter_mlock                                    
                 0      syscalls:sys_enter_mlock2                                   
                 0      syscalls:sys_enter_munlock                                   
                 0      syscalls:sys_enter_mlockall                                   
                 0      syscalls:sys_enter_munlockall                                   
                 0      syscalls:sys_enter_mincore                                   
                 0      syscalls:sys_enter_readahead                                   
                 0      syscalls:sys_enter_fadvise64                                   
                 0      syscalls:sys_enter_rseq                                     
                 0      syscalls:sys_enter_perf_event_open                                   
                 0      syscalls:sys_enter_bpf                                      
                 0      syscalls:sys_enter_seccomp                                   
                 0      syscalls:sys_enter_kexec_file_load                                   
                 0      syscalls:sys_enter_kexec_load                                   
                 0      syscalls:sys_enter_acct                                     
                 0      syscalls:sys_enter_delete_module                                   
                 0      syscalls:sys_enter_init_module                                   
                 0      syscalls:sys_enter_finit_module                                   
              6342      syscalls:sys_enter_set_robust_list                                   
                 0      syscalls:sys_enter_get_robust_list                                   
                 1      syscalls:sys_enter_futex                                    
                 0      syscalls:sys_enter_getitimer                                   
                 0      syscalls:sys_enter_alarm                                    
                 0      syscalls:sys_enter_setitimer                                   
                 0      syscalls:sys_enter_timer_create                                   
                 0      syscalls:sys_enter_timer_gettime                                   
                 0      syscalls:sys_enter_timer_getoverrun                                   
                 0      syscalls:sys_enter_timer_settime                                   
                 0      syscalls:sys_enter_timer_delete                                   
                 0      syscalls:sys_enter_clock_settime                                   
                 0      syscalls:sys_enter_clock_gettime                                   
                 0      syscalls:sys_enter_clock_adjtime                                   
                 0      syscalls:sys_enter_clock_getres                                   
                 1      syscalls:sys_enter_clock_nanosleep                                   
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
                 0      syscalls:sys_enter_pidfd_open                                   
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
             48656      syscalls:sys_enter_getpid                                   
             48654      syscalls:sys_enter_gettid                                   
                 0      syscalls:sys_enter_getppid                                   
                 0      syscalls:sys_enter_getuid                                   
                 0      syscalls:sys_enter_geteuid                                   
                 0      syscalls:sys_enter_getgid                                   
                 0      syscalls:sys_enter_getegid                                   
             54993      syscalls:sys_enter_times                                    
                 0      syscalls:sys_enter_setpgid                                   
                 2      syscalls:sys_enter_getpgid                                   
                 0      syscalls:sys_enter_getpgrp                                   
                 0      syscalls:sys_enter_getsid                                   
                 1      syscalls:sys_enter_setsid                                   
                 0      syscalls:sys_enter_newuname                                   
                 0      syscalls:sys_enter_sethostname                                   
                 0      syscalls:sys_enter_setdomainname                                   
                 0      syscalls:sys_enter_getrlimit                                   
              6343      syscalls:sys_enter_prlimit64                                   
                 0      syscalls:sys_enter_setrlimit                                   
                 1      syscalls:sys_enter_getrusage                                   
                 0      syscalls:sys_enter_umask                                    
                 0      syscalls:sys_enter_prctl                                    
                 0      syscalls:sys_enter_getcpu                                   
                 1      syscalls:sys_enter_sysinfo                                   
                 0      syscalls:sys_enter_restart_syscall                                   
             97309      syscalls:sys_enter_rt_sigprocmask                                   
                 0      syscalls:sys_enter_rt_sigpending                                   
                 0      syscalls:sys_enter_rt_sigtimedwait                                   
             48657      syscalls:sys_enter_kill                                     
                 0      syscalls:sys_enter_pidfd_send_signal                                   
             48654      syscalls:sys_enter_tgkill                                   
                 0      syscalls:sys_enter_tkill                                    
                 0      syscalls:sys_enter_rt_sigqueueinfo                                   
                 0      syscalls:sys_enter_rt_tgsigqueueinfo                                   
                 2      syscalls:sys_enter_sigaltstack                                   
             12693      syscalls:sys_enter_rt_sigaction                                   
                 0      syscalls:sys_enter_pause                                    
                 0      syscalls:sys_enter_rt_sigsuspend                                   
                 0      syscalls:sys_enter_ptrace                                   
                 0      syscalls:sys_enter_capget                                   
                 0      syscalls:sys_enter_capset                                   
                 0      syscalls:sys_enter_sysctl                                   
                 0      syscalls:sys_enter_exit                                     
              6339      syscalls:sys_enter_exit_group                                   
                 0      syscalls:sys_enter_waitid                                   
             54993      syscalls:sys_enter_wait4                                    
                 0      syscalls:sys_enter_personality                                   
                 2      syscalls:sys_enter_set_tid_address                                   
                 0      syscalls:sys_enter_fork                                     
                 0      syscalls:sys_enter_vfork                                    
              6340      syscalls:sys_enter_clone                                    
                 0      syscalls:sys_enter_clone3                                   
                 0      syscalls:sys_enter_unshare                                   
               101      syscalls:sys_enter_mmap                                     
                 0      syscalls:sys_enter_modify_ldt                                   
                 0      syscalls:sys_enter_ioperm                                   
                 0      syscalls:sys_enter_iopl                                     
                 0      syscalls:sys_enter_rt_sigreturn                                   
                 4      syscalls:sys_enter_arch_prctl    
```

Per + Var 
```
6782 ms total work, 124206 ns/work,             
10514 ms total running, 192539 ns/run, 
715 ms total write testcase, 13098 ns/write             
643 ms total forking, 11774 ns/fork, 
8975 ms total purely run, 164362 ns/purely run             
23622 ns/system running, 131116 ns/user running,             
6782 ms total pre-fuzzing, 124206 ns/pre-fuzzing,             
0 ms total post-fuzzing, 0 ns/post-fuzzing
total execution is 0x54608

 Performance counter stats for 'afl-fuzz -i /out/corpus_objdump_snap -o /dev/shm/out_rm -f /dev/shm/afl_f /out/objdump -d /dev/shm/afl_f':

          19182.46 msec task-clock                #    0.911 CPUs utilized
            316874      context-switches          #    0.017 M/sec
             52281      cpu-migrations            #    0.003 M/sec
            856992      page-faults               #    0.045 M/sec
       60560278670      cycles                    #    3.157 GHz                      (82.02%)
        3559349252      stalled-cycles-frontend   #    5.88% frontend cycles idle     (83.33%)
       17091249671      stalled-cycles-backend    #   28.22% backend cycles idle      (82.98%)
       76854810466      instructions              #    1.27  insn per cycle
                                                  #    0.22  stalled cycles per insn  (83.22%)
       10916594410      branches                  #  569.093 M/sec                    (84.40%)
         136502754      branch-misses             #    1.25% of all branches          (84.05%)


 Performance counter stats for 'afl-fuzz -i /out/corpus_objdump_snap -o /dev/shm/out_rm -f /dev/shm/afl_f /out/objdump -d /dev/shm/afl_f':

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
                 2      syscalls:sys_enter_shmget                                   
                 3      syscalls:sys_enter_shmctl                                   
                 3      syscalls:sys_enter_shmat                                    
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
                 0      syscalls:sys_enter_io_uring_enter                                   
                 0      syscalls:sys_enter_io_uring_setup                                   
                 0      syscalls:sys_enter_io_uring_register                                   
                 0      syscalls:sys_enter_io_setup                                   
                 0      syscalls:sys_enter_io_destroy                                   
                 0      syscalls:sys_enter_io_submit                                   
                 0      syscalls:sys_enter_io_cancel                                   
                 0      syscalls:sys_enter_io_getevents                                   
                 0      syscalls:sys_enter_io_pgetevents                                   
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
                 0      syscalls:sys_enter_fsopen                                   
                 0      syscalls:sys_enter_fspick                                   
                 0      syscalls:sys_enter_fsconfig                                   
                 0      syscalls:sys_enter_statfs                                   
                 0      syscalls:sys_enter_fstatfs                                   
                 0      syscalls:sys_enter_ustat                                    
                 0      syscalls:sys_enter_getcwd                                   
                 0      syscalls:sys_enter_utimensat                                   
                 0      syscalls:sys_enter_futimesat                                   
                 0      syscalls:sys_enter_utimes                                   
                 0      syscalls:sys_enter_utime                                    
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
                 0      syscalls:sys_enter_open_tree                                   
                 0      syscalls:sys_enter_mount                                    
                 0      syscalls:sys_enter_fsmount                                   
                 0      syscalls:sys_enter_move_mount                                   
                 0      syscalls:sys_enter_pivot_root                                   
                 0      syscalls:sys_enter_sysfs                                    
                 0      syscalls:sys_enter_dup3                                     
                 5      syscalls:sys_enter_dup2                                     
                 0      syscalls:sys_enter_dup                                      
             54609      syscalls:sys_enter_select                                   
                 0      syscalls:sys_enter_pselect6                                   
                 0      syscalls:sys_enter_poll                                     
                 0      syscalls:sys_enter_ppoll                                    
                 0      syscalls:sys_enter_getdents                                   
                47      syscalls:sys_enter_getdents64                                   
              6360      syscalls:sys_enter_ioctl                                    
            109220      syscalls:sys_enter_fcntl                                    
                 0      syscalls:sys_enter_mknodat                                   
                 0      syscalls:sys_enter_mknod                                    
                 0      syscalls:sys_enter_mkdirat                                   
                11      syscalls:sys_enter_mkdir                                    
                 9      syscalls:sys_enter_rmdir                                    
                 0      syscalls:sys_enter_unlinkat                                   
             61246      syscalls:sys_enter_unlink                                   
                 0      syscalls:sys_enter_symlinkat                                   
               390      syscalls:sys_enter_symlink                                   
                 0      syscalls:sys_enter_linkat                                   
              6241      syscalls:sys_enter_link                                     
                 0      syscalls:sys_enter_renameat2                                   
                 0      syscalls:sys_enter_renameat                                   
                 0      syscalls:sys_enter_rename                                   
                 0      syscalls:sys_enter_pipe2                                    
                 2      syscalls:sys_enter_pipe                                     
                 1      syscalls:sys_enter_execve                                   
                 0      syscalls:sys_enter_execveat                                   
             54609      syscalls:sys_enter_newstat                                   
              6243      syscalls:sys_enter_newlstat                                   
                 0      syscalls:sys_enter_newfstatat                                   
            115607      syscalls:sys_enter_newfstat                                   
                 0      syscalls:sys_enter_readlinkat                                   
                 1      syscalls:sys_enter_readlink                                   
                 0      syscalls:sys_enter_statx                                    
           2568948      syscalls:sys_enter_lseek                                    
            667651      syscalls:sys_enter_read                                     
           1569646      syscalls:sys_enter_write                                    
                16      syscalls:sys_enter_pread64                                   
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
             12488      syscalls:sys_enter_access                                   
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
                 2      syscalls:sys_enter_open                                     
            127981      syscalls:sys_enter_openat                                   
                 0      syscalls:sys_enter_creat                                    
            134378      syscalls:sys_enter_close                                    
                 0      syscalls:sys_enter_vhangup                                   
                 0      syscalls:sys_enter_memfd_create                                   
                 0      syscalls:sys_enter_move_pages                                   
                 0      syscalls:sys_enter_mbind                                    
                 0      syscalls:sys_enter_set_mempolicy                                   
                 0      syscalls:sys_enter_migrate_pages                                   
                 0      syscalls:sys_enter_get_mempolicy                                   
                 0      syscalls:sys_enter_swapoff                                   
                 0      syscalls:sys_enter_swapon                                   
                 0      syscalls:sys_enter_madvise                                   
                 0      syscalls:sys_enter_process_vm_readv                                   
                 0      syscalls:sys_enter_process_vm_writev                                   
                 0      syscalls:sys_enter_msync                                    
                 0      syscalls:sys_enter_mremap                                   
                21      syscalls:sys_enter_mprotect                                   
                 0      syscalls:sys_enter_pkey_mprotect                                   
                 0      syscalls:sys_enter_pkey_alloc                                   
                 0      syscalls:sys_enter_pkey_free                                   
               273      syscalls:sys_enter_brk                                      
                16      syscalls:sys_enter_munmap                                   
                 0      syscalls:sys_enter_remap_file_pages                                   
                 0      syscalls:sys_enter_mlock                                    
                 0      syscalls:sys_enter_mlock2                                   
                 0      syscalls:sys_enter_munlock                                   
                 0      syscalls:sys_enter_mlockall                                   
                 0      syscalls:sys_enter_munlockall                                   
                 0      syscalls:sys_enter_mincore                                   
                 0      syscalls:sys_enter_readahead                                   
                 0      syscalls:sys_enter_fadvise64                                   
                 0      syscalls:sys_enter_rseq                                     
                 0      syscalls:sys_enter_perf_event_open                                   
                 0      syscalls:sys_enter_bpf                                      
                 0      syscalls:sys_enter_seccomp                                   
                 0      syscalls:sys_enter_kexec_file_load                                   
                 0      syscalls:sys_enter_kexec_load                                   
                 0      syscalls:sys_enter_acct                                     
                 0      syscalls:sys_enter_delete_module                                   
                 0      syscalls:sys_enter_init_module                                   
                 0      syscalls:sys_enter_finit_module                                   
              6362      syscalls:sys_enter_set_robust_list                                   
                 0      syscalls:sys_enter_get_robust_list                                   
                 1      syscalls:sys_enter_futex                                    
                 0      syscalls:sys_enter_getitimer                                   
                 0      syscalls:sys_enter_alarm                                    
                 0      syscalls:sys_enter_setitimer                                   
                 0      syscalls:sys_enter_timer_create                                   
                 0      syscalls:sys_enter_timer_gettime                                   
                 0      syscalls:sys_enter_timer_getoverrun                                   
                 0      syscalls:sys_enter_timer_settime                                   
                 0      syscalls:sys_enter_timer_delete                                   
                 0      syscalls:sys_enter_clock_settime                                   
                 0      syscalls:sys_enter_clock_gettime                                   
                 0      syscalls:sys_enter_clock_adjtime                                   
                 0      syscalls:sys_enter_clock_getres                                   
                 1      syscalls:sys_enter_clock_nanosleep                                   
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
                 0      syscalls:sys_enter_pidfd_open                                   
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
             48252      syscalls:sys_enter_getpid                                   
             48250      syscalls:sys_enter_gettid                                   
                 0      syscalls:sys_enter_getppid                                   
                 0      syscalls:sys_enter_getuid                                   
                 0      syscalls:sys_enter_geteuid                                   
                 0      syscalls:sys_enter_getgid                                   
                 0      syscalls:sys_enter_getegid                                   
             54609      syscalls:sys_enter_times                                    
                 0      syscalls:sys_enter_setpgid                                   
                 2      syscalls:sys_enter_getpgid                                   
                 0      syscalls:sys_enter_getpgrp                                   
                 0      syscalls:sys_enter_getsid                                   
                 1      syscalls:sys_enter_setsid                                   
                 0      syscalls:sys_enter_newuname                                   
                 0      syscalls:sys_enter_sethostname                                   
                 0      syscalls:sys_enter_setdomainname                                   
                 0      syscalls:sys_enter_getrlimit                                   
             54612      syscalls:sys_enter_prlimit64                                   
                 0      syscalls:sys_enter_setrlimit                                   
                 1      syscalls:sys_enter_getrusage                                   
                 0      syscalls:sys_enter_umask                                    
                 0      syscalls:sys_enter_prctl                                    
                 0      syscalls:sys_enter_getcpu                                   
                 1      syscalls:sys_enter_sysinfo                                   
                 0      syscalls:sys_enter_restart_syscall                                   
             96501      syscalls:sys_enter_rt_sigprocmask                                   
                 0      syscalls:sys_enter_rt_sigpending                                   
                 0      syscalls:sys_enter_rt_sigtimedwait                                   
             48253      syscalls:sys_enter_kill                                     
                 0      syscalls:sys_enter_pidfd_send_signal                                   
             48250      syscalls:sys_enter_tgkill                                   
                 0      syscalls:sys_enter_tkill                                    
                 0      syscalls:sys_enter_rt_sigqueueinfo                                   
                 0      syscalls:sys_enter_rt_tgsigqueueinfo                                   
                 2      syscalls:sys_enter_sigaltstack                                   
             12733      syscalls:sys_enter_rt_sigaction                                   
                 0      syscalls:sys_enter_pause                                    
                 0      syscalls:sys_enter_rt_sigsuspend                                   
                 0      syscalls:sys_enter_ptrace                                   
                 0      syscalls:sys_enter_capget                                   
                 0      syscalls:sys_enter_capset                                   
                 0      syscalls:sys_enter_sysctl                                   
                 0      syscalls:sys_enter_exit                                     
              6359      syscalls:sys_enter_exit_group                                   
                 0      syscalls:sys_enter_waitid                                   
             54609      syscalls:sys_enter_wait4                                    
                 0      syscalls:sys_enter_personality                                   
                 2      syscalls:sys_enter_set_tid_address                                   
                 0      syscalls:sys_enter_fork                                     
                 0      syscalls:sys_enter_vfork                                    
              6360      syscalls:sys_enter_clone                                    
                 0      syscalls:sys_enter_clone3                                   
                 0      syscalls:sys_enter_unshare                                   
                87      syscalls:sys_enter_mmap                                     
                 0      syscalls:sys_enter_modify_ldt                                   
                 0      syscalls:sys_enter_ioperm                                   
                 0      syscalls:sys_enter_iopl                                     
                 0      syscalls:sys_enter_rt_sigreturn                                   
                 4      syscalls:sys_enter_arch_prctl                                   

```

Per + Var + VFS

```
Profiling information: 
5996 ms total work, 110489 ns/work,             
9902 ms total running, 182465 ns/run, 
28 ms total write testcase, 532 ns/write             
717 ms total forking, 13227 ns/fork, 
8323 ms total purely run, 153365 ns/purely run             
12529 ns/system running, 131191 ns/user running,             
5996 ms total pre-fuzzing, 110489 ns/pre-fuzzing,             
0 ms total post-fuzzing, 0 ns/post-fuzzing
total execution is 0x54272

 Performance counter stats for 'afl-fuzz -i /out/corpus_objdump_snap -o /dev/shm/out_rm -f /dev/shm/afl_f /out/objdump -d /dev/shm/afl_f':

          17899.49 msec task-clock                #    0.904 CPUs utilized
            314616      context-switches          #    0.018 M/sec
             53907      cpu-migrations            #    0.003 M/sec
            954930      page-faults               #    0.053 M/sec
       56361596776      cycles                    #    3.149 GHz                      (83.37%)
        3481046170      stalled-cycles-frontend   #    6.18% frontend cycles idle     (83.16%)
       15541524065      stalled-cycles-backend    #   27.57% backend cycles idle      (83.39%)
       73205951703      instructions              #    1.30  insn per cycle
                                                  #    0.21  stalled cycles per insn  (83.30%)
       10320144228      branches                  #  576.561 M/sec                    (82.90%)
         112245343      branch-misses             #    1.09% of all branches          (83.88%)


 Performance counter stats for 'afl-fuzz -i /out/corpus_objdump_snap -o /dev/shm/out_rm -f /dev/shm/afl_f /out/objdump -d /dev/shm/afl_f':

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
                 4      syscalls:sys_enter_shmget                                   
                 3      syscalls:sys_enter_shmctl                                   
                 5      syscalls:sys_enter_shmat                                    
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
                 0      syscalls:sys_enter_io_uring_enter                                   
                 0      syscalls:sys_enter_io_uring_setup                                   
                 0      syscalls:sys_enter_io_uring_register                                   
                 0      syscalls:sys_enter_io_setup                                   
                 0      syscalls:sys_enter_io_destroy                                   
                 0      syscalls:sys_enter_io_submit                                   
                 0      syscalls:sys_enter_io_cancel                                   
                 0      syscalls:sys_enter_io_getevents                                   
                 0      syscalls:sys_enter_io_pgetevents                                   
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
                 0      syscalls:sys_enter_fsopen                                   
                 0      syscalls:sys_enter_fspick                                   
                 0      syscalls:sys_enter_fsconfig                                   
                 1      syscalls:sys_enter_statfs                                   
                 0      syscalls:sys_enter_fstatfs                                   
                 0      syscalls:sys_enter_ustat                                    
                 0      syscalls:sys_enter_getcwd                                   
                 0      syscalls:sys_enter_utimensat                                   
                 0      syscalls:sys_enter_futimesat                                   
                 0      syscalls:sys_enter_utimes                                   
                 0      syscalls:sys_enter_utime                                    
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
                 0      syscalls:sys_enter_open_tree                                   
                 0      syscalls:sys_enter_mount                                    
                 0      syscalls:sys_enter_fsmount                                   
                 0      syscalls:sys_enter_move_mount                                   
                 0      syscalls:sys_enter_pivot_root                                   
                 0      syscalls:sys_enter_sysfs                                    
                 0      syscalls:sys_enter_dup3                                     
                 5      syscalls:sys_enter_dup2                                     
                 0      syscalls:sys_enter_dup                                      
             54273      syscalls:sys_enter_select                                   
                 0      syscalls:sys_enter_pselect6                                   
                 0      syscalls:sys_enter_poll                                     
                 0      syscalls:sys_enter_ppoll                                    
                 0      syscalls:sys_enter_getdents                                   
                47      syscalls:sys_enter_getdents64                                   
              6339      syscalls:sys_enter_ioctl                                    
                 4      syscalls:sys_enter_fcntl                                    
                 0      syscalls:sys_enter_mknodat                                   
                 0      syscalls:sys_enter_mknod                                    
                 0      syscalls:sys_enter_mkdirat                                   
                11      syscalls:sys_enter_mkdir                                    
                 9      syscalls:sys_enter_rmdir                                    
                 0      syscalls:sys_enter_unlinkat                                   
              6611      syscalls:sys_enter_unlink                                   
                 0      syscalls:sys_enter_symlinkat                                   
               362      syscalls:sys_enter_symlink                                   
                 0      syscalls:sys_enter_linkat                                   
              6241      syscalls:sys_enter_link                                     
                 0      syscalls:sys_enter_renameat2                                   
                 0      syscalls:sys_enter_renameat                                   
                 0      syscalls:sys_enter_rename                                   
                 0      syscalls:sys_enter_pipe2                                    
                 2      syscalls:sys_enter_pipe                                     
                 1      syscalls:sys_enter_execve                                   
                 0      syscalls:sys_enter_execveat                                   
                10      syscalls:sys_enter_newstat                                   
              6243      syscalls:sys_enter_newlstat                                   
                 0      syscalls:sys_enter_newfstatat                                   
              6376      syscalls:sys_enter_newfstat                                   
                 0      syscalls:sys_enter_readlinkat                                   
                 1      syscalls:sys_enter_readlink                                   
                 0      syscalls:sys_enter_statx                                    
                 0      syscalls:sys_enter_lseek                                    
            398679      syscalls:sys_enter_read                                     
            403077      syscalls:sys_enter_write                                    
                16      syscalls:sys_enter_pread64                                   
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
             12488      syscalls:sys_enter_access                                   
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
                 2      syscalls:sys_enter_open                                     
             18781      syscalls:sys_enter_openat                                   
                 0      syscalls:sys_enter_creat                                    
             85725      syscalls:sys_enter_close                                    
                 0      syscalls:sys_enter_vhangup                                   
                 0      syscalls:sys_enter_memfd_create                                   
                 0      syscalls:sys_enter_move_pages                                   
                 0      syscalls:sys_enter_mbind                                    
                 0      syscalls:sys_enter_set_mempolicy                                   
                 0      syscalls:sys_enter_migrate_pages                                   
                 0      syscalls:sys_enter_get_mempolicy                                   
                 0      syscalls:sys_enter_swapoff                                   
                 0      syscalls:sys_enter_swapon                                   
                 0      syscalls:sys_enter_madvise                                   
                 0      syscalls:sys_enter_process_vm_readv                                   
                 0      syscalls:sys_enter_process_vm_writev                                   
                 0      syscalls:sys_enter_msync                                    
                 0      syscalls:sys_enter_mremap                                   
                88      syscalls:sys_enter_mprotect                                   
                 0      syscalls:sys_enter_pkey_mprotect                                   
                 0      syscalls:sys_enter_pkey_alloc                                   
                 0      syscalls:sys_enter_pkey_free                                   
              7971      syscalls:sys_enter_brk                                      
                16      syscalls:sys_enter_munmap                                   
                 0      syscalls:sys_enter_remap_file_pages                                   
                 0      syscalls:sys_enter_mlock                                    
                 0      syscalls:sys_enter_mlock2                                   
                 0      syscalls:sys_enter_munlock                                   
                 0      syscalls:sys_enter_mlockall                                   
                 0      syscalls:sys_enter_munlockall                                   
                 0      syscalls:sys_enter_mincore                                   
                 0      syscalls:sys_enter_readahead                                   
                 0      syscalls:sys_enter_fadvise64                                   
                 0      syscalls:sys_enter_rseq                                     
                 0      syscalls:sys_enter_perf_event_open                                   
                 0      syscalls:sys_enter_bpf                                      
                 0      syscalls:sys_enter_seccomp                                   
                 0      syscalls:sys_enter_kexec_file_load                                   
                 0      syscalls:sys_enter_kexec_load                                   
                 0      syscalls:sys_enter_acct                                     
                 0      syscalls:sys_enter_delete_module                                   
                 0      syscalls:sys_enter_init_module                                   
                 0      syscalls:sys_enter_finit_module                                   
              6341      syscalls:sys_enter_set_robust_list                                   
                 0      syscalls:sys_enter_get_robust_list                                   
                 1      syscalls:sys_enter_futex                                    
                 0      syscalls:sys_enter_getitimer                                   
                 0      syscalls:sys_enter_alarm                                    
                 0      syscalls:sys_enter_setitimer                                   
                 0      syscalls:sys_enter_timer_create                                   
                 0      syscalls:sys_enter_timer_gettime                                   
                 0      syscalls:sys_enter_timer_getoverrun                                   
                 0      syscalls:sys_enter_timer_settime                                   
                 0      syscalls:sys_enter_timer_delete                                   
                 0      syscalls:sys_enter_clock_settime                                   
                 0      syscalls:sys_enter_clock_gettime                                   
                 0      syscalls:sys_enter_clock_adjtime                                   
                 0      syscalls:sys_enter_clock_getres                                   
                 1      syscalls:sys_enter_clock_nanosleep                                   
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
                 0      syscalls:sys_enter_pidfd_open                                   
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
             47937      syscalls:sys_enter_getpid                                   
             47935      syscalls:sys_enter_gettid                                   
                 0      syscalls:sys_enter_getppid                                   
                 0      syscalls:sys_enter_getuid                                   
                 0      syscalls:sys_enter_geteuid                                   
                 0      syscalls:sys_enter_getgid                                   
                 0      syscalls:sys_enter_getegid                                   
             54273      syscalls:sys_enter_times                                    
                 0      syscalls:sys_enter_setpgid                                   
                 2      syscalls:sys_enter_getpgid                                   
                 0      syscalls:sys_enter_getpgrp                                   
                 0      syscalls:sys_enter_getsid                                   
                 1      syscalls:sys_enter_setsid                                   
                 0      syscalls:sys_enter_newuname                                   
                 0      syscalls:sys_enter_sethostname                                   
                 0      syscalls:sys_enter_setdomainname                                   
                 0      syscalls:sys_enter_getrlimit                                   
             54276      syscalls:sys_enter_prlimit64                                   
                 0      syscalls:sys_enter_setrlimit                                   
                 1      syscalls:sys_enter_getrusage                                   
                 0      syscalls:sys_enter_umask                                    
                 0      syscalls:sys_enter_prctl                                    
                 0      syscalls:sys_enter_getcpu                                   
                 1      syscalls:sys_enter_sysinfo                                   
                 0      syscalls:sys_enter_restart_syscall                                   
             95871      syscalls:sys_enter_rt_sigprocmask                                   
                 0      syscalls:sys_enter_rt_sigpending                                   
                 0      syscalls:sys_enter_rt_sigtimedwait                                   
             47938      syscalls:sys_enter_kill                                     
                 0      syscalls:sys_enter_pidfd_send_signal                                   
             47935      syscalls:sys_enter_tgkill                                   
                 0      syscalls:sys_enter_tkill                                    
                 0      syscalls:sys_enter_rt_sigqueueinfo                                   
                 0      syscalls:sys_enter_rt_tgsigqueueinfo                                   
                 2      syscalls:sys_enter_sigaltstack                                   
             12691      syscalls:sys_enter_rt_sigaction                                   
                 0      syscalls:sys_enter_pause                                    
                 0      syscalls:sys_enter_rt_sigsuspend                                   
                 0      syscalls:sys_enter_ptrace                                   
                 0      syscalls:sys_enter_capget                                   
                 0      syscalls:sys_enter_capset                                   
                 0      syscalls:sys_enter_sysctl                                   
                 0      syscalls:sys_enter_exit                                     
              6338      syscalls:sys_enter_exit_group                                   
                 0      syscalls:sys_enter_waitid                                   
             54273      syscalls:sys_enter_wait4                                    
                 0      syscalls:sys_enter_personality                                   
                 2      syscalls:sys_enter_set_tid_address                                   
                 0      syscalls:sys_enter_fork                                     
                 0      syscalls:sys_enter_vfork                                    
              6339      syscalls:sys_enter_clone                                    
                 0      syscalls:sys_enter_clone3                                   
                 0      syscalls:sys_enter_unshare                                   
               101      syscalls:sys_enter_mmap                                     
                 0      syscalls:sys_enter_modify_ldt                                   
                 0      syscalls:sys_enter_ioperm                                   
                 0      syscalls:sys_enter_iopl                                     
                 0      syscalls:sys_enter_rt_sigreturn                                   
                 4      syscalls:sys_enter_arch_prctl                                   


```

## Evaluation

Command

```
AFL_NO_AFFINITY=1 timeout 24h afl-fuzz -D -i /out/seeds -o /dev/shm/out_rm -f /dev/shm/afl_f /out/objdump -d /dev/shm/afl_f
```

### Fuzzer stats


**Fork Server**

```
start_time        : xxx

```