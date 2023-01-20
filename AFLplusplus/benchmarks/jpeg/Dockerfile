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
RUN wget -c https://github.com/google/AFL/raw/master/testcases/images/jpeg/not_kitty.jpg -qO /out/seeds/not_kitty.jpg
RUN wget -c https://github.com/rc0r/afl-fuzz/raw/master/dictionaries/jpeg.dict -qO /out/jpeg.dict

RUN cd $SRC && wget -c https://www.ijg.org/files/jpegsrc.v9e.tar.gz && \
    tar -xzf jpegsrc.v9e.tar.gz && cd jpeg-9e/ && mkdir build 

COPY build.sh $SRC/
# COPY var.s /tmp/ 
# COPY corpus_objdump_snap.tar.gz /out/corpus_objdump_snap.tar.gz
