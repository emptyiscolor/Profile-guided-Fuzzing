FROM aflpp-base:latest

WORKDIR /src

ENV SRC=/src

RUN apt-get update && \
    apt-get install -y \
    make \
    wget \
    autoconf \
    automake \
    libtool \
    libglib2.0-dev\
    gawk \
    texinfo \
    unzip

RUN wget -c https://d29yy0w4awjqw3.cloudfront.net/fuzz/afl/Dec/binutils-2.38-per.tar.gz -qO $SRC/binutils-2.38.tar.gz

RUN cd $SRC && tar -xzf binutils-2.38.tar.gz

COPY build.sh $SRC/
COPY var.s /tmp/ 
COPY corpus_objdump_snap.tar.gz /out/corpus_objdump_snap.tar.gz
