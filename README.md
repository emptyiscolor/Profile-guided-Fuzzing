**Note to reviewers: we only modified this README after the paper submission**

# Profile-guided-Fuzzing
Profile-guided System Optimizations for Accelerated Greybox Fuzzing

## Directory Structure

* AFL : Improved version of AFL based on 2.57b gcc
    * `AFL/llvm_mode`: code for "Profile-guided State Recovery".
    * `AFL/var_mode`: scripts for state recovery.
    * `AFL/gcc_mode`: gcc mode for AFL.
* AFLplusplus: Improved version of AFL++ based on 4.01c
    * `AFLplusplus/instrumentation/afl-llvm-var-rec.so.cc`: code for "Profile-guided State Recovery".
    * AFLplusplus/utils/var_mode: scripts for state recovery.
* abstractFS: Profile-guided OS Abstraction

## How to build

AFL:
```
make && make -C llvm_mode
```

AFLplusplus:
```
make distrib
```

abstractFS: Please refer to the [README](./abstractFS/README.md)

### The macros in the code

* `VAR_REC`: enable variable recovery mode for LLVM pass in `AFL/llvm_mode/afl-llvm-pass.so.cc`; and the macro was `AFL_LLVM_VAR_REC` in AFL++.
* `PROFILING_SYS_USR`, `PROFILING_FORK` and `PROFILING` was for profiling of time.
* `AFL_SNAPSHOT`: enable snapshot kernel mode
* `AFL_RT_VAR_REC`: enable variable recover mode
* `AFL_RT_PERSIST`: enable persistent mode with wrap for `exit`.

## Workflow for profiling

**[And example for profiling objdump](./AFL/benchmarks/binutils-2.38)**

### Distribution of Time

1. Edit `AFL/llvm_mode/afl-llvm-rt.o.c` and enable macros(starts with `PROFILING`) from line 47 to line 49 .(Edit line 47 to line 49 in `AFLplusplus/instrumentation/afl-compiler-rt.o.c` for AFLplusplus)
2. Buid AFL with `export CFLAGS="-DPROFILING_SYS_USR=1 -DPROFILING=1 -DPROFILING_FORK=1"`
3. Rebuild the target program with `afl-clang-fast`
4. Fuzz the target program with environment variable `AFL_PERFORM_DRY_RUN_ONLY=1`, and the input seeds can be an existing corpus. 

e.g.
```
AFL_NO_AFFINITY=1 AFL_PERFORM_DRY_RUN_ONLY=1 afl-fuzz  -i /out/objdump_corpus -o /dev/shm/output_objdump -f /dev/shm/afl_bin_input /out/objdump -d @@

# results
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
```

### Global Objects

**Collectiong Global Variables**:

1. Rebuild target program with `afl-clang-fast` variable `AFL_VAR_TRACE=1`
2. Run target with existing corpus to collect variable info (e.g.  `for testcase in /out/output_objdump/queue/id\:0* ; do ./objdump -d $testcase ; done `)
3. The `/tmp/.fs_globals.txt` file will be verbose information for variable. (`cat /tmp/.fs_globals.txt | sort -u > /out/global_objdump.txt`)

**Rebuid Target Binary with state recovery**

1. Rebuild target program with variable `AFL_VAR_SNAPSHOT=1`
2. Generate the assembly code from variable information: `python AFL/var_mode/gen_asm.py /path/to/target_binary /out/global_objdump.txt /tmp/var.s`
3. Comple `.s` to `.o`: `cd AFL/var_mode  && gcc -c /tmp/var.s`
4. Rebuild target program with variable `AFL_VAR_SNAPSHOT=1 AFL_VAR_REC=objdump` (target binary name)

Note: Setting `AFL_VAR_REC=1` environment variable is required for AFL++ to use the `AFLplusplus/instrumentation/afl-llvm-var-rec.so.cc` LLVM Pass.

