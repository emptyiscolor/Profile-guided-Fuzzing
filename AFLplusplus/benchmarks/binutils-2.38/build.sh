#!/bin/bash -ex

export SRC="/src"
export OUT="/out"

mkdir -p $SRC
mkdir -p $OUT
mkdir -p $OUT/seeds


wget -c https://raw.githubusercontent.com/mirrorer/afl/master/testcases/others/elf/small_exec.elf -O $OUT/seeds/small_exec.elf

wget https://d29yy0w4awjqw3.cloudfront.net/fuzz/afl/Dec/var_profile_binutils_objdump-AFLPP.tar.gz -O /$OUT/var_profile_binutils_objdump.tar.gz && \
    cd $OUT && \
    tar -xzvf var_profile_binutils_objdump.tar.gz

cd "$SRC/binutils-2.38"
# Git is converting CRLF to LF automatically and causing issues when checking
# out the branch. So use -f to ignore the complaint about lost changes that we
# don't even want.
# make distclean

CC=afl-clang-fast ./configure --disable-shared

if [ "$FUZZER" = "baseline" ]; then
	sed -i '5354s/while/\/\/while/'  /src/binutils-2.38/binutils/objdump.c
	sed -i '5710s/}/\/\/}/'  /src/binutils-2.38/binutils/objdump.c
fi

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

cp $SRC/binutils-2.38/binutils/objdump $OUT/objdump

cd /out/ && tar -xzf corpus_objdump_snap.tar.gz

#  AFL_NO_AFFINITY=1  perf stat -a afl-fuzz -i /out/seeds -o /dev/shm/out_rm -f /dev/shm/afl_f /out/objdump -d /dev/shm/afl_f
