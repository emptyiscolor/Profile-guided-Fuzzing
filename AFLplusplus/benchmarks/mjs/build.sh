#!/bin/bash -ex

export SRC="/src"
export OUT="/out"

mkdir -p $SRC
mkdir -p $OUT

cd "$SRC/mjs"
mkdir -p build
# make distclean

# Default is baseline, fork server
# export CC=afl-clang-fast 
# export LDFLAGS="-Wl,-wrap,_exit -Wl,-wrap,exit -Wl,-wrap,_Exit"

AFL_VAR_REC=1 AFL_VAR_SNAPSHOT=1 afl-clang-fast -lm -std=c99 -Wall -Wextra -pedantic -g  -I. -Isrc -Isrc/frozen -DMJS_MAIN -DMJS_EXPOSE_PRIVATE -DCS_ENABLE_STDIO -DMJS_ENABLE_DEBUG -I../frozen  -DCS_MMAP -DMJS_MODULE_LINES -Wl,--no-as-needed -ldl src/ffi/ffi.c src/mjs_array.c src/mjs_bcode.c src/mjs_builtin.c src/mjs_conversion.c src/mjs_core.c src/mjs_dataview.c src/mjs_exec.c src/mjs_ffi.c src/mjs_gc.c src/mjs_json.c src/mjs_main.c src/mjs_object.c src/mjs_parser.c src/mjs_primitive.c src/mjs_string.c src/mjs_tok.c src/mjs_util.c src/common/cs_dbg.c src/common/cs_file.c src/common/cs_varint.c src/common/mbuf.c src/common/mg_str.c src/common/str_util.c src/frozen/frozen.c -o build/mjs

cp /src/mjs/build/mjs /out/mjs

# AFL_NO_SNAPSHOT=1 AFL_NO_AFFINITY=1 timeout 24h afl-fuzz -D -i /out/seeds -o /dev/shm/out_mjs_fork3 -m none -t 20+ -x /out/js.dict -f /dev/shm/afl_in -- /out/mjs -f /dev/shm/afl_in
