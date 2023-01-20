## Build with AFL

Target code path: `/code/fuzzing_targets/tcpdump/`

```
cd libpcap
CC=/code/AFL/afl-clang-fast ./configure --enable-shared=no --prefix="/code/fuzzing_targets/tcpdump/install/"
make 
make install

cd ../tcpdump

CC=/code/AFL/afl-clang-fast ./configure  --prefix="/code/fuzzing_targets/tcpdump/install/"
make
make install

# Fuzzing with AFL

afl-fuzz  -i /out/tcpdump_seeds/ -o /dev/shm/output_tcpdump -f /dev/shm/afl_bin_input /code/fuzzing_targets/tcpdump/install/bin/tcpdump -vvvvXX -ee -nn -r @@
```
