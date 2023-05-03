#!/usr/bin/env bash

: ${CC=gcc}
: ${AR=ar}
: ${MAKE=make}
: ${CMAKE=cmake}
: ${BIN=www.so}
: ${JOBS=4}

SRCS="src/*.c"
CFLAGS="$CFLAGS -Ilib/prefix/include -fPIC -Ilib/lite-xl/resources/include"
LDFLAGS="$LDFLAGS -lm -Llib/prefix/lib"

[[ $OSTYPE != *'darwin'* ]] && CFLAGS="$CFLAGS -static-libgcc"

[[ "$@" == "clean" ]] && rm -rf lib/zlib/build lib/mbedtls-2.27.0/build lib/prefix *.so && exit 0
$CMAKE --version >/dev/null 2>/dev/null || { echo "Please ensure that you have cmake installed." && exit -1; }

# Build supporting libraries, libz, libmbedtls, libmbedcrypto, libgit2
CMAKE_DEFAULT_FLAGS=" $CMAKE_DEFAULT_FLAGS -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=`pwd`/lib/prefix -DCMAKE_INSTALL_PREFIX=`pwd`/lib/prefix -DBUILD_SHARED_LIBS=OFF"
mkdir -p lib/prefix/include lib/prefix/lib
if [[ "$@" != *"-lz"* ]]; then
  [ ! -e "lib/zlib" ] && echo "Make sure you've cloned submodules. (git submodule update --init --depth=1)" && exit -1
  [[ ! -e "lib/zlib/build" && $OSTYPE != 'msys'* ]] && cd lib/zlib && mkdir build && cd build && $CC $CFLAGS -O3 -D_LARGEFILE64_SOURCE -I.. ../*.c -c && $AR rc libz.a *.o && cp libz.a ../../prefix/lib && cp ../*.h ../../prefix/include && cd ../../../
  LDFLAGS="$LDFLAGS -lz"
fi
if [[ "$@" != *"-lmbedtls"* && "$@" != *"-lmbedcrypto"* ]]; then
  [ ! -e "lib/mbedtls-2.27.0/build" ] && cd lib/mbedtls-2.27.0 && mkdir build && cd build && CFLAGS="$CFLAGS $CFLAGS_MBEDTLS -DMBEDTLS_MD4_C=1 -w" $CMAKE .. $CMAKE_DEFAULT_FLAGS  -G "Unix Makefiles" -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF $SSL_CONFIGURE && CFLAGS="$CFLAGS $CFLAGS_MBEDTLS -DMBEDTLS_MD4_C=1 -w" $MAKE -j $JOBS && $MAKE install && cd ../../../
  LDFLAGS="$LDFLAGS -lmbedtls -lmbedx509 -lmbedcrypto"
fi

[[ $OSTYPE != 'msys'* && $CC != *'mingw'* && $CC != "emcc" ]] && LDFLAGS="$LDFLAGS -ldl"
[[ $OSTYPE == 'msys'* || $CC == *'mingw'* ]]                  && LDFLAGS="$LDFLAGS -lbcrypt -lws2_32 -lz -lwinhttp -lole32 -lcrypt32 -lrpcrt4"
[[ $OSTYPE == *'darwin'* ]]                                   && LDFLAGS="$LDFLAGS -liconv -framework Security -framework Foundation"

[[ " $@" != *" -g"* && " $@" != *" -O"* ]] && CFLAGS="$CFLAGS -O3" && LDFLAGS="$LDFLAGS -s -flto"
$CC $CFLAGS $SRCS $@ -shared -o $BIN $LDFLAGS

