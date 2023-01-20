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
    unzip

RUN mkdir -p /out/seeds && wget -c https://github.com/google/AFL/raw/master/testcases/others/pcap/small_capture.pcap -qO /out/seeds/small_capture.pcap

RUN mkdir -p $SRC && wget -c https://d29yy0w4awjqw3.cloudfront.net/fuzz/afl/Dec/tcpdump_src.tar.gz -qO $SRC/tcpdump_src.tar.gz

RUN cd $SRC && tar -xzf tcpdump_src.tar.gz

COPY build.sh $SRC/
COPY var.s /tmp/ 