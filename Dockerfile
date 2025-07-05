FROM alpine:latest

# Installing build tools, basic dependencies, and python3
RUN apk update && \
    apk add build-base musl-dev openssl-dev sqlite-dev curl-dev \
    openssl-libs-static sqlite-static curl-static zlib-static \
    libidn2-static nghttp2-static git autoconf automake \
    libtool pkgconfig make cmake python3

# Installing libunistring from source (for libidn2)
RUN wget https://ftp.gnu.org/gnu/libunistring/libunistring-1.3.tar.gz && \
    tar -xzf libunistring-1.3.tar.gz && \
    cd libunistring-1.3 && \
    ./configure --enable-static --disable-shared && \
    make && make install && \
    cd .. && rm -rf libunistring-1.3 libunistring-1.3.tar.gz

# Installing libpsl from source
RUN wget https://github.com/rockdaboot/libpsl/releases/download/0.21.5/libpsl-0.21.5.tar.gz && \
    tar -xzf libpsl-0.21.5.tar.gz && \
    cd libpsl-0.21.5 && \
    ./configure --enable-static --disable-shared && \
    make && make install && \
    cd .. && rm -rf libpsl-0.21.5 libpsl-0.21.5.tar.gz

# Installing c-ares from source (for libcurl)
RUN wget https://github.com/c-ares/c-ares/releases/download/v1.33.1/c-ares-1.33.1.tar.gz && \
    tar -xzf c-ares-1.33.1.tar.gz && \
    cd c-ares-1.33.1 && \
    ./configure --enable-static --disable-shared && \
    make && make install && \
    cd .. && rm -rf c-ares-1.33.1 c-ares-1.33.1.tar.gz

# Installing zstd from source
RUN wget https://github.com/facebook/zstd/releases/download/v1.5.6/zstd-1.5.6.tar.gz && \
    tar -xzf zstd-1.5.6.tar.gz && \
    cd zstd-1.5.6 && \
    make -C lib libzstd.a && \
    cp lib/libzstd.a /usr/lib/ && \
    cp lib/zstd.h /usr/include/ && \
    cp lib/zdict.h /usr/include/ && \
    cp lib/zstd_errors.h /usr/include/ && \
    cd .. && rm -rf zstd-1.5.6 zstd-1.5.6.tar.gz

# Installing brotli from source
RUN wget https://github.com/google/brotli/archive/refs/tags/v1.1.0.tar.gz && \
    tar -xzf v1.1.0.tar.gz && \
    cd brotli-1.1.0 && \
    mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF .. && \
    make && make install && \
    cd ../.. && rm -rf brotli-1.1.0 v1.1.0.tar.gz

WORKDIR /app

# Copying project files
COPY . .

# Compiling source files and linking statically
RUN mkdir -p obj bin && \
    for f in src/*.c; do \
        gcc -O2 -Wall -Wextra -Iinclude -c "$f" -o "obj/$(basename "$f" .c).o"; \
    done && \
    gcc -static -O2 obj/*.o -o bin/fimon-v1.0.0-linux-x86_64-static -L/usr/lib -lssl -lcrypto -lsqlite3 -lcurl -lz -lidn2 -lnghttp2 -lbrotlidec -lbrotlienc -lbrotlicommon -lpsl -lzstd -lunistring -lcares