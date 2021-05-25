#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2021 Kévin Le Gouguec

set -eux

CONTAINER=$1

run-guest ()
{
    docker exec "${CONTAINER}" "$@"
}

kernel_version=$(uname -r | cut -d- -f1)
kernel_major=${kernel_version%%.*}
kernel_basename=linux-${kernel_version}
kernel_url=https://cdn.kernel.org/pub/linux/kernel/v${kernel_major}.x/${kernel_basename}.tar.xz

run-guest apt-get install --assume-yes libpci-dev gettext wget
run-guest wget --quiet ${kernel_url}
run-guest tar xf ${kernel_basename}.tar.xz -C /tmp
run-guest make -C /tmp/${kernel_basename}/tools/power/cpupower
run-guest make -C /tmp/${kernel_basename}/tools/power/cpupower install libdir=/usr/lib
