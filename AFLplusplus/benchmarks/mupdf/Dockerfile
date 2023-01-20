FROM aflpp-base:per

WORKDIR /src

ENV SRC=/src

RUN apt-get update && \
    apt-get install -y \
    make \
    wget \
    curl \
    autoconf \
    automake \
    libtool \
    pkg-config \
    gawk \
    unzip 

RUN mkdir -p /out/seeds/  && wget -c https://github.com/google/AFL/raw/master/testcases/others/pdf/small.pdf -qO /out/seeds/small.pdf

RUN cd /src && git clone --recursive git://git.ghostscript.com/mupdf.git && \
	cd mupdf && git submodule update --init 

COPY build.sh $SRC/
COPY new_globals_mupdf.txt /out/
# COPY var.s /tmp/ 
# COPY corpus_objdump_snap.tar.gz /out/corpus_objdump_snap.tar.gz
