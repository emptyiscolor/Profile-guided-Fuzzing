FROM aflpp-base:latest

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
    zip 


RUN git clone --depth 1 https://github.com/openssl/openssl.git && \
	mkdir -p /out/seeds && \
	rm -rf /out/seeds/* && \
	wget -c https://github.com/openssl/openssl/raw/master/fuzz/corpora/x509/048c1c2ab7d4a4b70a6710791cd4960fb0dd47f8 -qO /out/seeds/test1 && \
	wget -c https://github.com/openssl/openssl/raw/master/fuzz/oids.txt -qO /out/x509.dict

COPY build.sh $SRC/
# COPY var.s $SRC/
# COPY new_globals_tidy.txt $SRC/
# COPY corpus_objdump_snap.tar.gz /out/corpus_objdump_snap.tar.gz
