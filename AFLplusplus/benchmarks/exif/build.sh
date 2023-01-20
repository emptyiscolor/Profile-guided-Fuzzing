#!/bin/bash -ex

export SRC="/src"
export OUT="/out"
export V=1

mkdir -p $SRC
mkdir -p $OUT

cd "$SRC/libexif"
# make distclean

# Default is baseline, fork server
export CC=afl-clang-fast 
export LDFLAGS="-Wl,-wrap,_exit -Wl,-wrap,exit -Wl,-wrap,_Exit"

autoreconf -f -i

mkdir build && cd build

../configure --disable-docs --enable-shared=no --enable-static=yes  --prefix="/src/install"

AFL_VAR_SNAPSHOT=1 AFL_VAR_REC=1 make -j8

make install

cd "$SRC/exif"
autoreconf -i
mkdir build && cd build
../configure  PKG_CONFIG_PATH=/src/install/lib/pkgconfig  --enable-static=yes --enable-shared=no

AFL_VAR_SNAPSHOT=1 AFL_VAR_REC=1 make
cp exif/exif /out/

if [ "$FUZZER" = "aflfstab" ]; then
	sed -i '5351s/int c;/take_snapshot();int c;/'  /src/binutils-2.38/binutils/objdump.c
	sed -i '5709s/free ((void \*) source_comment);/free ((void \*) source_comment); restore_snapshot();/'  /src/binutils-2.38/binutils/objdump.c
	sed -i '246s/\$(am__objects_2)/\$(am__objects_2)  \/tmp\/var.o/'  /src/binutils-2.38/binutils/Makefile
	cd /tmp/ && gcc -c var.s && \
        cd $SRC/binutils-2.38/binutils && \
	    make clean && \
	    env -i HOME="$HOME" LC_CTYPE="${LC_ALL:-${LC_CTYPE:-$LANG}}" PATH="$PATH" USER="$USER" LDFLAGS="$LDFLAGS" AFL_VAR_SNAPSHOT=1 AFL_VAR_REC=1  make objdump
fi

#  AFL_NO_AFFINITY=1  afl-fuzz -i /out/seeds -o /dev/shm/out_rm -f /dev/shm/afl_f /out/xmllint /dev/shm/afl_f
