
#replace this with the path to gcc plugins on your target machine
GCC_PLUGIN_PATH=/usr/lib/gcc/x86_64-linux-gnu/8/plugin/include

CC=gcc
CXX=g++
AR=ar
CFLAGS=-O2 -g -shared -I$(GCC_PLUGIN_PATH) -fPIC -fno-rtti

SRC=inst_plugin.cpp
OBJ=inst_plugin.so

inst_plugin: $(SRC)
	$(CXX) $(CFLAGS) $(SRC) -o $(OBJ)

test: test1 test2

test1:
	 $(CC) -fplugin=/code/AFL/gcc_mode/plugins/inst_plugin.so targets/target.c -g -O0  -L./libs -llog -o targets/target
	 ./targets/target

test2:
	 $(CC) -fplugin=/code/AFL/gcc_mode/plugins/inst_plugin.so targets/syscall.c -g -O0 -o targets/syscall
	 ./targets/syscall

libs: liblog

liblog:
	$(CC) -c libs/log.c -fno-stack-protector -o libs/log.o
	$(AR) rcs libs/liblog.a libs/log.o 

clean:
	rm inst_plugin.so targets/target targets/syscall targets/*.o libs/*.o libs/*.a

