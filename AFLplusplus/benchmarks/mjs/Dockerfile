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
    unzip 


RUN git clone https://github.com/cesanta/mjs && \
	mkdir -p /out/seeds && \
	rm -rf /out/seeds/* && \
	wget -c https://github.com/cesanta/mjs/raw/master/tests/test_1.js -qO /out/seeds/test_1.js && \
	wget -c https://github.com/google/fuzzing/raw/master/dictionaries/js.dict -qO /out/js.dict

COPY build.sh $SRC/
# COPY var.s $SRC/
# COPY new_globals_tidy.txt $SRC/
# COPY corpus_objdump_snap.tar.gz /out/corpus_objdump_snap.tar.gz
