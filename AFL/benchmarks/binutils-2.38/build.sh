#!/bin/bash -ex

export SRC="/src"
export OUT="/out"

mkdir -p $SRC
mkdir -p $OUT
mkdir -p $OUT/seeds

if [ "$MODE" = "profile" ]; then
	sed -i '47s/\/\/ #define PROFILING_SYS_USR 1/#define PROFILING_SYS_USR 1/'  /afl/llvm_mode/afl-llvm-rt.o.c
	sed -i '48s/\/\/ #define PROFILING_FORK 1/#define PROFILING_FORK 1/'  /afl/llvm_mode/afl-llvm-rt.o.c
	sed -i '49s/\/\/ #define PROFILING 1/#define PROFILING 1/'  /afl/llvm_mode/afl-llvm-rt.o.c
	cd /afl/ && make clean && CFLAGS="-DPROFILING_SYS_USR=1 -DPROFILING=1 -DPROFILING_FORK=1" make && make -C llvm_mode
fi

cd /afl && make install

wget -c https://raw.githubusercontent.com/mirrorer/afl/master/testcases/others/elf/small_exec.elf -O $OUT/seeds/small_exec.elf

wget https://d29yy0w4awjqw3.cloudfront.net/fuzz/afl/Dec/var_profile_binutils_objdump_new1.tar.gz -O /$OUT/var_profile_binutils_objdump.tar.gz && \
    cd $OUT && \
    tar -xzvf var_profile_binutils_objdump.tar.gz

cd "$SRC/binutils-2.38"
# Git is converting CRLF to LF automatically and causing issues when checking
# out the branch. So use -f to ignore the complaint about lost changes that we
# don't even want.
make distclean

# [ ! -d "/afl" ] && echo "[++***++] Building cov measure " &&  ar r /usr/lib/libAFL.a /src/aflplusplus/afl-llvm-rt-64.o && export LDFLAGS="-L/usr/lib/ -lAFL"

CC=afl-clang-fast ./configure --disable-shared

if [ "$FUZZER" = "baseline" ]; then
	sed -i '5354s/while/\/\/while/'  /src/binutils-2.38/binutils/objdump.c
	sed -i '5710s/}/\/\/}/'  /src/binutils-2.38/binutils/objdump.c
fi

make -j8

# env -i HOME="$HOME" LC_CTYPE="${LC_ALL:-${LC_CTYPE:-$LANG}}" PATH="$PATH" USER="$USER" LDFLAGS="$LDFLAGS"  make -j $(nproc)

if [ "$FUZZER" = "aflfstab" ]; then
        cd $SRC/binutils-2.38/binutils &&\
	    rm objdump objdump.o && \
	    env -i HOME="$HOME" LC_CTYPE="${LC_ALL:-${LC_CTYPE:-$LANG}}" PATH="$PATH" USER="$USER" LDFLAGS="$LDFLAGS" AFL_INFINITE=1  make objdump
fi

cp $SRC/binutils-2.38/binutils/objdump $OUT/objdump
