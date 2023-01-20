# abstractFS
An high-performance in-memory file system for fuzzing

### Prerequisite

**Build funchook**:

`/path/to/install/directory` could be the path to `abstractFS`.

```bash
$ git clone --recursive https://github.com/kubo/funchook.git
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/tmp/ ../funchook
$ make
$ make install
```

### Build

```bash
$ cd /tmp/
$ git clone https://github.com/emptyiscolor/abstractFS
$ cd abstractFS
$ mkdir build
$ cd build
$ cmake ..
$ make

$ cp -f fs_hook.so /tmp/
```


## Usage

Assume that xxxx_fuzzer is compiled by afl.

#### Single test case

```
FS_AFL_SHM_ID=4919 TESTFILE=/tmp/afl_input /out/xxxx_fuzzer /tmp/afl_input
```

#### Enable FS runtime for AFL.

```
FS_AFL_SHM_ID=6789 ASAN_OPTIONS="symbolize=0:abort_on_error=1" ./afl-fuzz -i seeds -o findings -f /tmp/afl_input -t 100+ -m none -- ./xxxx_fuzzer @@
```
