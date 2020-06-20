#!/usr/bin/env bash

set -euo pipefail

if which dpkg-query >/dev/null; then
    if dpkg-query -W g++-mingw-w64-x86-64 mingw-w64-x86-64-dev \
            build-essential libtool autotools-dev automake pkg-config \
            bsdmainutils curl ca-certificates; then
        echo "All dependencies satisfied."
    else
        echo "Missing dependencies detected. Exiting..."
        exit 1
    fi
    #sudo update-alternatives --config x86_64-w64-mingw32-g++ # you have to select posix
fi

if which ccache >/dev/null; then
    echo "ccache config:"
    ccache -ps
fi

pushd depends
make -j$(getconf _NPROCESSORS_ONLN) HOST=x86_64-w64-mingw32 V=1
popd


./autogen.sh
DEPS_DIR=$(pwd)/depends/x86_64-w64-mingw32
CONFIG_SITE=${DEPS_DIR}/share/config.site ./configure --prefix=/ --with-gui --with-icu="$DEPS_DIR" --enable-static --di$
make -j$(getconf _NPROCESSORS_ONLN)
x86_64-w64-mingw32-strip src/lbrycrdd.exe src/lbrycrd-cli.exe src/lbrycrd-tx.exe src/qt/lbrycrd-qt.exe

if which ccache >/dev/null; then
    echo "ccache stats:"
    ccache -s
fi

echo "Windows 64bit build is complete"
