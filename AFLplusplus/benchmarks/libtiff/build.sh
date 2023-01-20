#!/bin/bash -ex

export SRC="/src"
export OUT="/out"
export V=1

mkdir -p $SRC
mkdir -p $OUT
mkdir -p $OUT/seeds

cd "$SRC/zlib"
# make distclean

# Default is baseline, fork server
CC=afl-clang-fast ./configure --static 
make -j8 CFLAGS="$CFLAGS -fPIC"
make install

cd "$SRC/libtiff/build"

if [ "$FUZZER" = "per" ]; then
	LDFLAGS="-Wl,-wrap,_exit -Wl,-wrap,exit -Wl,-wrap,_Exit" CC=afl-clang-fast CXX=afl-clang-fast++ cmake .. -DBUILD_SHARED_LIBS=off
	AFL_VAR_SNAPSHOT=1 AFL_VAR_REC=1 make tiff2ps -j8
else
	CC=afl-clang-fast CXX=afl-clang-fast++ cmake .. -DBUILD_SHARED_LIBS=off
	AFL_VAR_SNAPSHOT=1 make tiff2ps -j8
fi



if [ "$FUZZER" = "aflfstab" ]; then
	echo "pls do it manually"
fi

cp $SRC/libtiff/build/tools/tiff2ps $OUT/tiff2ps

# AFL_NO_AFFINITY=1 timeout 24h afl-fuzz  -i /out/seeds -o /dev/shm/out_rm -m none -f /dev/shm/afl_tiff_in -x /out/tiff.dict -- /out/tiff2ps /dev/shm/afl_tiff_in
