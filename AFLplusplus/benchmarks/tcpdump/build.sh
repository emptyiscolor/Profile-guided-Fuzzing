#!/bin/bash -ex

export SRC="/src"
export OUT="/out"

mkdir -p $SRC
mkdir -p $OUT
mkdir -p $OUT/seeds

cd "$SRC/libpcap"
CC=afl-clang-fast ./configure --disable-shared
AFL_VAR_SNAPSHOT=1 AFL_VAR_REC=1 make -j4

cd "$SRC/tcpdump"
CC=afl-clang-fast ./configure

if [ "$FUZZER" = "baseline" ]; then
	git checkout tcpdump.c
fi

if [ "$FUZZER" = "aflfstab" ]; then
    gcc -c /tmp/var.s
    # modify Makefile   strlcpy$U.o   to  strlcpy$U.o var.o
	sed -i 's/strlcpy\$U.o/strlcpy$U.o var.o/' Makefile
fi

AFL_VAR_SNAPSHOT=1 AFL_VAR_REC=1 make -j4

cp tcpdump $OUT/tcpdump

# AFL_NO_AFFINITY=1  perf stat -a afl-fuzz -i /out/seeds -o /dev/shm/out_rm -f /dev/shm/afl_f /out/tcpdump -vvvvXX -ee -nn -r /dev/shm/afl_f
