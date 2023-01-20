# GCC plugins to instrument glibc

## Install GCC plugins

$ gcc --version # get version of gcc
$ sudo apt install gcc-X.X-plugin-dev # replace X.X with version of gcc

## Find the path of your GCC plugins path

$gcc -print-file-name=plugin

## Replace the GCC plugins path in Makefile with the result of the above command

## Build the plugin by running "make"
