#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

set -eux

dependencies=(
    # FELICS
    libelf-dev
    make
    python3
    # AVR
    avr-libc
    gcc-avr
    gdb-avr
    openjdk-8-jdk
    openjdk-8-jre
    # MSP
    libreadline-dev
    libusb-dev
    # ARM
    binutils-arm-none-eabi
    bossa-cli
    gcc-arm-none-eabi
    gdb-multiarch
    python3-serial
    # nRF
    cmake
    libusb-1.0
    libusb-1.0-0-dev
    # PC
    gcc
    gdb
    cpufrequtils
    sudo
)

apt-get update
apt-get install --assume-yes ${dependencies[@]}
