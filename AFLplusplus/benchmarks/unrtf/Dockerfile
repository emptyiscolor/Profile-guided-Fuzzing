FROM aflpp-base:per

WORKDIR /src

ENV SRC=/src

RUN apt-get update && \
    apt-get install -y \
    make \
    wget \
    curl \
    autoconf \
    libtool \
    pkg-config \
    gawk \
    texinfo \
    unzip 

RUN mkdir -p /out/seeds/
RUN wget -c https://github.com/google/AFL/raw/master/testcases/others/rtf/small_document.rtf -qO /out/seeds/small_document.rtf

RUN cd $SRC && wget -c https://ftp.gnu.org/gnu/unrtf/unrtf-0.21.10.tar.gz && \
    tar -xzf unrtf-0.21.10.tar.gz && cd unrtf-0.21.10 && \
    mkdir build && cd build 

COPY build.sh $SRC/
COPY new_globals_unrtf.txt /out
# COPY var.s /tmp/ 
# COPY corpus_objdump_snap.tar.gz /out/corpus_objdump_snap.tar.gz
