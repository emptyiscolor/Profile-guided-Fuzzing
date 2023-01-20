#!/bin/bash -ex

export SRC="/src"
export OUT="/out"
export V=1

mkdir -p $SRC
mkdir -p $OUT
mkdir -p $OUT/seeds

cd "$SRC/libxml2"
# make distclean

# Default is baseline, fork server
CC=afl-clang-fast ./autogen.sh \
    --disable-shared \
    --without-debug \
    --without-ftp \
    --without-http \
    --without-legacy \
    --without-python

AFL_VAR_SNAPSHOT=1 AFL_VAR_REC=1 make -j8

if [ "$FUZZER" = "aflfstab" ]; then
	sed -i '5351s/int c;/take_snapshot();int c;/'  /src/binutils-2.38/binutils/objdump.c
	sed -i '5709s/free ((void \*) source_comment);/free ((void \*) source_comment); restore_snapshot();/'  /src/binutils-2.38/binutils/objdump.c
	sed -i '246s/\$(am__objects_2)/\$(am__objects_2)  \/tmp\/var.o/'  /src/binutils-2.38/binutils/Makefile
	cd /tmp/ && gcc -c var.s && \
        cd $SRC/binutils-2.38/binutils && \
	    make clean && \
	    env -i HOME="$HOME" LC_CTYPE="${LC_ALL:-${LC_CTYPE:-$LANG}}" PATH="$PATH" USER="$USER" LDFLAGS="$LDFLAGS" AFL_VAR_SNAPSHOT=1 AFL_VAR_REC=1  make objdump
fi

cp $SRC/libxml2/xmllint $OUT/xmllint

#  AFL_NO_AFFINITY=1  afl-fuzz -i /out/seeds -o /dev/shm/out_rm -f /dev/shm/afl_f /out/xmllint /dev/shm/afl_f
