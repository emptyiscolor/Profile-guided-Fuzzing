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

RUN mkdir -p /out/seeds && \
	rm -rf /out/seeds/* && \
	wget -c https://github.com/google/AFL/raw/master/testcases/images/png/not_kitty.png -qO /out/seeds/not_kitty.png && \
	wget -c https://github.com/google/AFL/raw/master/dictionaries/png.dict -qO /out/png.dict 

RUN cd /src && wget -c http://prdownloads.sourceforge.net/optipng/optipng-0.7.7.tar.gz && \
	tar -xzf optipng-0.7.7.tar.gz 

COPY build.sh $SRC/
COPY new_global_optipng.txt /out/
COPY var.s /out/
# COPY var.s /tmp/ 
# COPY corpus_objdump_snap.tar.gz /out/corpus_objdump_snap.tar.gz
