#!/bin/bash -ex

export SRC="/src"
export OUT="/out"

mkdir -p $SRC
mkdir -p $OUT

cd "$SRC/optipng-0.7.7"

# Default is baseline, fork server
export CC=afl-clang-fast 
# export LDFLAGS="-Wl,-wrap,_exit -Wl,-wrap,exit -Wl,-wrap,_Exit"


# mkdir build && cd build

# ../configure --disable-docs --enable-shared=no --enable-static=yes  --prefix="/src/install"
CC=afl-clang-fast ./configure -enable-debug

AFL_VAR_SNAPSHOT=1 AFL_VAR_REC=1 CC=afl-clang-fast CXX=afl-clang-fast++ make -j4

cp src/optipng/optipng /out/optipng

if [ "$FUZZER" = "aflfstab" ]; then
	sed -i '5351s/int c;/take_snapshot();int c;/'  /src/binutils-2.38/binutils/objdump.c
	sed -i '5709s/free ((void \*) source_comment);/free ((void \*) source_comment); restore_snapshot();/'  /src/binutils-2.38/binutils/objdump.c
	sed -i '246s/\$(am__objects_2)/\$(am__objects_2)  \/tmp\/var.o/'  /src/binutils-2.38/binutils/Makefile
	cd /tmp/ && gcc -c var.s && \
        cd $SRC/binutils-2.38/binutils && \
	    make clean && \
	    env -i HOME="$HOME" LC_CTYPE="${LC_ALL:-${LC_CTYPE:-$LANG}}" PATH="$PATH" USER="$USER" LDFLAGS="$LDFLAGS" AFL_VAR_SNAPSHOT=1 AFL_VAR_REC=1  make objdump
fi

#  AFL_NO_AFFINITY=1  afl-fuzz -D -m none -t 20+ -x /out/png.dict  -i /out/seeds -o /dev/shm/out_rm -f /dev/shm/afl_f -- /out/optipng /dev/shm/afl_f -out /dev/null 
