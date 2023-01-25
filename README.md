**Note to reviewers: we only modified this README after the paper submission**

# Profile-guided-Fuzzing
Profile-guided System Optimizations for Accelerated Greybox Fuzzing

## Code structure and explanation of terms

### Directory structure
The project consists of three main subdirectories:

* AFL : Improved version of AFL based on 2.57b gcc
    * `AFL/llvm_mode`: code for "Profile-guided State Recovery".
    * `AFL/var_mode`: scripts for "Profile-guided State Recovery".
    * `AFL/gcc_mode`: gcc mode for AFL.
* AFLplusplus: Improved version of AFL++ based on 4.01c
    * `AFLplusplus/instrumentation/afl-llvm-var-rec.so.cc`: code for "Profile-guided State Recovery".
    * `AFLplusplus/utils/var_mode`: scripts for "Profile-guided State Recovery".
* abstractFS: code for "Profile-guided OS Abstraction"

### Terminology Explanation and Corresponding Codes

* `FS`: fork server, the default build method of target binary
* `SS`: snapshot mode, which was implemented in Linux Kernel in AFL, and LKM in AFL++
* `PM`: persistent mode
* `PM_REC`: persistent mode with profile-guided state recovery
* `PM_VOS`: persistent mode on top of our profile-guided OS abstraction.
* `PM_REC_VOS`: persistent mode with both profile-guided state recovery and OS abstraction.

**The following macros in the code are used to enable the modes above.**

* `VAR_REC` in `AFL/llvm_mode/afl-llvm-pass.so.cc`: required by `PM_REC` and `PM_REC_VOS` for AFL
* `AFL_LLVM_VAR_REC` in `AFLplusplus/instrumentation/afl-llvm-var-rec.so.cc`: required by `PM_REC` and `PM_REC_VOS` for AFL++
* `AFL_SNAPSHOT`: enable snapshot kernel mode (`AFL/llvm_mode/afl-llvm-rt.o.c`)
* `AFL_RT_VAR_REC`: enable variable recover mode  (`AFL/llvm_mode/afl-llvm-rt.o.c`)
* `AFL_RT_PERSIST`: enable persistent mode with wrap for `exit`  (`AFL/llvm_mode/afl-llvm-rt.o.c`)

For profiling of time consumed by fuzzing (2.2 Motivating Study), you need to enable these macros : `PROFILING_SYS_USR`, `PROFILING_FORK` and `PROFILING`, which are located in these files: 

* `AFL/afl-fuzz.c`
* `AFL/llvm_mode/afl-llvm-rt.o.c`
* `AFLplusplus/src/afl-fuzz.c`
* `AFLplusplus/instrumentation/afl-compiler-rt.o.c`

## How to build AFL/AFL++/VOS (General Steps)

AFL:
```
make && cd llvm_mode && make
```

AFLplusplus:
```
make distrib
```

abstractFS: 

Please refer to this separate [README](./abstractFS/README.md)

* `VAR_REC`: enable variable recovery mode for LLVM pass in `AFL/llvm_mode/afl-llvm-pass.so.cc`; and the macro was `AFL_LLVM_VAR_REC` in AFL++.
* `PROFILING_SYS_USR`, `PROFILING_FORK` and `PROFILING` was for profiling of time.
* `AFL_SNAPSHOT`: enable snapshot kernel mode
* `AFL_RT_VAR_REC`: enable variable recover mode
* `AFL_RT_PERSIST`: enable persistent mode with wrap for `exit`.

## Reproduce Experiment

### Distribution of Time (2.2 Motivating Study)

1. Edit `AFL/llvm_mode/afl-llvm-rt.o.c` and enable macros(starts with `PROFILING`) from line 47 to line 49 .(Edit line 47 to line 49 in `AFLplusplus/instrumentation/afl-compiler-rt.o.c` for AFLplusplus)
2. Buid AFL with `export CFLAGS="-DPROFILING_SYS_USR=1 -DPROFILING=1 -DPROFILING_FORK=1"`
3. Rebuild the target program with `afl-clang-fast`
4. Fuzz the target program with environment variable `AFL_PERFORM_DRY_RUN_ONLY=1`, and the input seeds can be an existing corpus.  

The following uses objdump as an example:

**Option 1: Build from source code:**

```bash
cd AFL
make clean
CFLAGS="-DPROFILING_SYS_USR=1 -DPROFILING=1 -DPROFILING_FORK=1"
cd llvm_mode
# enable macros that start with PROFILING
make
sudo make install
sudo mkdir -p /out/

# Download the target src:
wget -c https://d29yy0w4awjqw3.cloudfront.net/fuzz/afl/Dec/binutils-2.38-per.tar.gz
tar -xzf binutils-2.38-per.tar.gz

# PM by default
cd binutils-2.38
CC=afl-clang-fast ./configure --disable-shared
make -j4
sudo cp binutils/objdump /out/objdump
```

**Option 2: Build with Docker:**

```
cd AFL/benchmarks/binutils-2.38
docker build -t benchmark-afl-objdump .
docker run --privileged --shm-size=256m --rm -it benchmark-afl-objdump bash

MODE=profile bash build.sh
```

#### Run profiling to collect the time distribution during fuzzing (for Section 2).

There is an tarball of corpus as a [sample](./AFL/benchmarks/binutils-2.38/corpus_objdump_snap.tar.gz) .

```
AFL_NO_AFFINITY=1 AFL_PERFORM_DRY_RUN_ONLY=1 afl-fuzz -i /out/objdump_corpus -o /dev/shm/output_objdump -f /dev/shm/afl_bin_input /out/objdump -d @@

# results FYI
Profiling information: 
7545 ms total work, 151133 ns/work,             
33129 ms total running, 663538 ns/run, 
1487 ms total write testcase, 29794 ns/write             
3005 ms total forking, 60192 ns/fork, 
28235 ms total purely run, 565523 ns/purely run             
44263 ns/system running, 503925 ns/user running             
7545 ms total pre-fuzzing, 151133 ns/pre-fuzzing,             
total execution is 49928
```

**A full example of result for profiling time distribution page fault and syscall of objdump: [Link](./AFL/benchmarks/binutils-2.38/README.md)**

### Reproduce the "5. Evaluation" part 

#### Profile-guided state recovery

**Collectiong Global Objects**:

1. Rebuild target program with `afl-clang-fast` variable `AFL_VAR_TRACE=1`
2. Run target with existing corpus to collect variable info (e.g.  `for testcase in /out/output_objdump/queue/id\:0* ; do ./objdump -d $testcase ; done `)
3. The `/tmp/.fs_globals.txt` file will be verbose information for variable. (`cat /tmp/.fs_globals.txt | sort -u > /out/global_objdump.txt`)

Let's take `objdump` as an example:

```bash
cd binutils-2.38
CC=afl-clang-fast ./configure --disable-shared
make clean
AFL_VAR_TRACE=1 make -j4

# collect the variable information
# NOTE: the corpus_objdump the AFL queue with saved test cases in it
for testcase in ./corpus_objdump/queue/id\:0* ; do ./objdump -s $testcase ; done 

cat /tmp/.fs_globals.txt | sort -u > /out/global_objdump.txt`
```

**Rebuid Target Binary with state recovery(PM_REC)**

Note: Setting `AFL_VAR_REC=1` environment variable is required for AFL++.

1. Rebuild target program with variable `AFL_VAR_SNAPSHOT=1`
2. Generate the assembly code from variable information: `python AFL/var_mode/gen_asm.py /path/to/target_binary /out/global_objdump.txt /tmp/var.s`
3. Comple `.s` to `.o`: `cd AFL/var_mode  && gcc -c /tmp/var.s`
4. Rebuild target program with environment variable `AFL_VAR_SNAPSHOT=1 AFL_VAR_REC=objdump` (target binary name)

Let's take `objdump` as an example:

```bash
# generate the PM_REC object
cd binutils-2.38
CC=afl-clang-fast ./configure --disable-shared
make clean
AFL_VAR_SNAPSHOT=1 make -j4

# /out/global_objdump.txt is the txt file with global info we collected above
python AFL/var_mode/gen_asm.py ./binutils/objdump /out/global_objdump.txt /tmp/var.s
# Just compile the var.s, and we will get var.o
cd AFL/var_mode  && gcc -c /tmp/var.s

# rebuild the AFL llvm runtime object
cd AFL/llvm_mode
# enable "AFL_RT_VAR_REC" macro at AFL/llvm_mode/afl-llvm-rt.o.c to enable the state recover mode
make clean
make  # It's OK to get the testing warning prompt, pls ignore it.
cd .. && sudo make install

# rebuilt the target binary
cd /Path/to/binutils-2.38
LDFLAGS="-Wl,-wrap,_exit -Wl,-wrap,exit -Wl,-wrap,_Exit" AFL_VAR_REC=nothing ./configure --disable-shared
make clean
AFL_VAR_REC=objdump AFL_VAR_SNAPSHOT=1  make -j4
# sudo cp -f binutils/objdump /out/objdump
```

Then, we will get a `PM_REC` version of `objdump`, and it can be verified with the 100% fuzzing stability.

```bash
afl-fuzz  -i /out/seeds -o /dev/shm/output_objdump -f /dev/shm/afl_input -m none -- /out/objdump -d @@
```

**Run Target with profile-guided OS abstraction(VOS)**

Follow the [README](./abstractFS/README.md) for abstractFS, and set `FS_AFL_SHM_ID` to enable `PM_VOS` or `PM_REC_VOS`

e.g.

```
FS_AFL_SHM_ID=6789 afl-fuzz  -i /out/seeds -o /dev/shm/output_objdump -f /dev/shm/afl_input -m none -- /out/objdump -d @@
```