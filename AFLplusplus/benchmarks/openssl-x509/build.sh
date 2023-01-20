#!/bin/bash -ex

export SRC="/src"
export OUT="/out"

mkdir -p $SRC
mkdir -p $OUT

cd "$SRC/openssl"
# build quickjs
# Makefile should not override CFLAGS
# edit Makefile

CC=afl-clang-fast ./config enable-fuzz-afl no-shared no-module \
    -DPEDANTIC enable-tls1_3 enable-weak-ssl-ciphers enable-rc5 \
    enable-md2 enable-ssl3 enable-ssl3-method enable-nextprotoneg \
    enable-ec_nistp_64_gcc_128 -fno-sanitize=alignment \
    --debug

AFL_VAR_REC=1 AFL_VAR_SNAPSHOT=1 make -j8

# Default is baseline, fork server
# export CC=afl-clang-fast 
# export LDFLAGS="-Wl,-wrap,_exit -Wl,-wrap,exit -Wl,-wrap,_Exit"

# AFL_VAR_REC=1 AFL_VAR_SNAPSHOT=1 afl-clang-fast -g -Wl,-wrap,_exit -Wl,-wrap,exit -Wl,-wrap,_Exit -rdynamic -o qjs .obj/qjs.o .obj/repl.o .obj/quickjs.o .obj/libregexp.o .obj/libunicode.o .obj/cutils.o .obj/quickjs-libc.o .obj/libbf.o .obj/qjscalc.o -lm -ldl -lpthread
cp /src/openssl/fuzz/x509-test /out/x509-test

# AFL_NO_SNAPSHOT=1 AFL_NO_AFFINITY=1 timeout 24h afl-fuzz -D -i /out/seeds -o /dev/shm/out_mjs_fork3 -m none -t 20+ -x /out/js.dict -f /dev/shm/afl_in -- /out/mjs -f /dev/shm/afl_in
