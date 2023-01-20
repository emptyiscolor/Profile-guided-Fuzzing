#!/bin/bash -ex

export SRC="/src"
export OUT="/out"

mkdir -p $SRC
mkdir -p $OUT
mkdir -p $OUT/seeds

cd "$SRC/unrtf-0.21.10/build"
# make distclean

# Default is baseline, fork server
CC=afl-clang-fast ../configure
AFL_VAR_REC=1 AFL_VAR_SNAPSHOT=1 make -j4
make install


if [ "$FUZZER" = "per" ]; then
	LDFLAGS="-Wl,-wrap,_exit -Wl,-wrap,exit -Wl,-wrap,_Exit" CC=afl-clang-fast ../configure 
fi

AFL_VAR_SNAPSHOT=1 AFL_VAR_REC=1 make -j8

if [ "$FUZZER" = "aflfstab" ]; then
	echo "pls do it manually"
fi

cp $SRC/unrtf-0.21.10/build/src/unrtf $OUT/unrtf

#  AFL_NO_AFFINITY=1  afl-fuzz -i /out/seeds -o /dev/shm/out_rm -f /dev/shm/afl_f -- /out/djpeg /dev/shm/afl_f
