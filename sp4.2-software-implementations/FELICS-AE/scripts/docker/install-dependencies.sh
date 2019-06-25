#!/bin/bash

set -eux

deps_dir="$1"

(
    cd "${deps_dir}/simavr-1.6"
    make build-simavr RELEASE=1
    make install-simavr DESTDIR=/opt/felics/simavr RELEASE=1
)

cp -r "${deps_dir}/msp430-gcc-7.3.2.154_linux64" /opt/felics/msp430-gcc

(
    cd "${deps_dir}/avrora"
    make
    ./makejar.bash beta-1.7.117-patched
    cp jars/*.jar /opt/felics/
)

dpkg -i "${deps_dir}/JLink_Linux_x86_64.deb"
