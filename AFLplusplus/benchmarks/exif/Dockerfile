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
    texinfo \
    unzip \
    autopoint

RUN cd /src && wget -c http://ftp.rpm.org/popt/releases/popt-1.x/popt-1.19.tar.gz && \
	tar -xzf popt-1.19.tar.gz && \
	cd popt-1.19 && \
	CC=afl-clang-fast ./configure  --prefix="/src/install" --enable-shared=no --enable-static=yes && \
	CC=afl-clang-fast make && \
	make install 

RUN git clone --depth 1 https://github.com/libexif/libexif && \
	git clone --depth 1 https://github.com/ianare/exif-samples && \
	mkdir -p /out/seeds && \
	rm -rf /out/seeds/* && \
	cp exif-samples/jpg/Olympus_C8080WZ.jpg /out/seeds

RUN git clone https://github.com/libexif/exif

COPY build.sh $SRC/
# COPY var.s /tmp/ 
# COPY corpus_objdump_snap.tar.gz /out/corpus_objdump_snap.tar.gz
