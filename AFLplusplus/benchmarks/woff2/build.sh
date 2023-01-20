#!/bin/bash -ex

export SRC="/src"
export OUT="/out"
export V=1

mkdir -p $SRC
mkdir -p $OUT

cd "$SRC/woff2"
# make distclean

# Default is baseline, fork server
# export LDFLAGS="-Wl,-wrap,_exit -Wl,-wrap,exit -Wl,-wrap,_Exit"
export AFL_VAR_SNAPSHOT=1 
export AFL_VAR_REC=1

make CC=afl-clang-fast CXX=afl-clang-fast++ all  NOISY_LOGGING=

cp woff2_decompress /out/

if [ "$FUZZER" = "aflfstab" ]; then
	sed -i '5351s/int c;/take_snapshot();int c;/'  /src/binutils-2.38/binutils/objdump.c
	sed -i '5709s/free ((void \*) source_comment);/free ((void \*) source_comment); restore_snapshot();/'  /src/binutils-2.38/binutils/objdump.c
	sed -i '246s/\$(am__objects_2)/\$(am__objects_2)  \/tmp\/var.o/'  /src/binutils-2.38/binutils/Makefile
	cd /tmp/ && gcc -c var.s && \
        cd $SRC/binutils-2.38/binutils && \
	    make clean && \
	    env -i HOME="$HOME" LC_CTYPE="${LC_ALL:-${LC_CTYPE:-$LANG}}" PATH="$PATH" USER="$USER" LDFLAGS="$LDFLAGS" AFL_VAR_SNAPSHOT=1 AFL_VAR_REC=1  make objdump
fi

# AFL_NO_AFFINITY=1 timeout 24h afl-fuzz -i /out/seeds_woff2 -o /dev/shm/rmit -m none -t 20+ -f /dev/shm/afl_in -- ./woff2_decompress @@

