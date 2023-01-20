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
    cmake \
    nasm \
    unzip 

RUN mkdir -p /out/seeds/
RUN wget -c https://github.com/google/AFL/raw/master/testcases/images/tiff/not_kitty.tiff -qO /out/seeds/not_kitty.tiff
RUN wget -c https://github.com/google/AFL/raw/master/dictionaries/tiff.dict -qO /out/tiff.dict

RUN cd $SRC && git clone --depth 1 https://gitlab.com/libtiff/libtiff && \
    git clone --depth 1 https://github.com/madler/zlib 

COPY build.sh $SRC/
COPY new_globals.txt /tmp/ 
# COPY corpus_objdump_snap.tar.gz /out/corpus_objdump_snap.tar.gz
