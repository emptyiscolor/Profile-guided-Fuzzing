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

