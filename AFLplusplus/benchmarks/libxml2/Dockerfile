FROM aflpp-base:latest

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
    unzip \
    zlib1g-dev liblzma-dev 

RUN curl -LO http://mirrors.kernel.org/ubuntu/pool/main/a/automake-1.16/automake_1.16.5-1.3_all.deb && \
    apt install ./automake_1.16.5-1.3_all.deb

RUN mkdir -p /out/seeds/
RUN wget -c https://github.com/google/AFL/raw/master/testcases/others/xml/small_document.xml -qO /out/seeds/small_document.xml
RUN wget -c https://github.com/rc0r/afl-fuzz/raw/master/dictionaries/xml.dict -qO /out/xml.dict

RUN cd $SRC && git clone  https://github.com/GNOME/libxml2 && \
    cd libxml2 && git checkout e2bae1bc049f7ffac9c35eefa33f8a00d4032170

COPY build.sh $SRC/
# COPY var.s /tmp/ 
# COPY corpus_objdump_snap.tar.gz /out/corpus_objdump_snap.tar.gz
