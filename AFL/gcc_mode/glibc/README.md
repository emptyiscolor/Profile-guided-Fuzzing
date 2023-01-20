# how to build glibc with the new plugin [only working for glibc 2.27] 


## Prepare the gcc plugin for compiling glibc

1. Build the gcc plugin by entering the "plugins/" folder and run "make"

2. Build the logging library shipped with the plugin. This can be done by entering the "plugins/" folder and run "make libs". The library will be needed to support the logging feature when compiling glibc

3. Set up an environment variable called "GLB_VAR_FILE" to point to a file location. The file will be used to keep logs about global variables when compiling glibc. The folder of the file must exist while the file itself does not necessarily. Example setup: "export GLB_VAR_FILE=/tmp/glibc_glob_log"

## Prepare the building environments for glibc

1. Replace glibc-2.27/Makeconfig, glibc-2.27/Makerules, glibc-2.27/elf/Makefile with the counterpart in this repo

2. Set up an env var called "PLUGIN_LIBS" to the location of the logging library as explained above. Example setup: "export PLUGIN_LIBS=/code/AFL/gcc_mode/plugins/libs/"

3. Enter "glibc-2.27/", create a folder called "build", enter "build", and run: "CFLAGS="-O2 -g -fplugin=/path/to/gcc/plugins/inst_plugin.so" LDFLAGS="-L${PLUGIN_LIBS} -llog" ../configure prefix=./build"

4. Run "make" (to avoid errors, let's just do single-threaded compilation)

5. Sort and uniq the items in "GLB_VAR_FILE" and save the results into any place you would like; Keep the results available for the next steps 
