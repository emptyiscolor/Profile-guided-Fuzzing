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
    texinfo \
    zip

RUN    mkdir -p /out/seeds && \
    rm -rf /out/seeds/* && \
    wget -c 'https://github.com/google/oss-fuzz/raw/master/projects/woff2/corpus/Ahem.woff2'  -qO /out/seeds/Ahem.woff2

RUN cd /src && git clone --recursive https://github.com/google/woff2.git && \
	cd woff2 && \
	make clean 

COPY build.sh $SRC/
# COPY var.s /tmp/ 
# COPY corpus_objdump_snap.tar.gz /out/corpus_objdump_snap.tar.gz
