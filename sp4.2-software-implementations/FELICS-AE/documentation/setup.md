Setting up FELICS-AE
====================

This guide provides instructions to install the software FELICS-AE
depends on.

1 - Installing dependencies
===========================

NB: this guide has been written with the Ubuntu 16.04 distribution of
GNU/Linux in mind. Although any distribution should be able to run
FELICS-AE, specific steps to install software packages may vary.

AVR-specific
------------

The following dependencies have been installed using the
distribution's package manager:

- avr-gcc
- avr-libc
- default-jdk
- default-jre
- gdb-avr

### simavr

We use version 1.6 of simavr, compiled from the source fetched from
the developer's repository:

<https://github.com/buserror/simavr>

### Avrora

We followed the instructions provided on the FELICS wiki to patch and
install Avrora:

<https://www.cryptolux.org/index.php/FELICS_Avrora_patch>

MSP-specific
------------

The following dependencies have been installed using the
distribution's package manager:

- libusb-dev

### MSP430-GCC

We use version 7.3.2.154 of the compiler provide by Texas Instruments:

<http://software-dl.ti.com/msp430/msp430_public_sw/mcu/msp430/MSPGCC/latest/index_FDS.html>

### MSPDebug

We use version 0.25 of MSPDebug, compiled the source fetched from the
developer's repository:

<https://github.com/dlbeer/mspdebug>

ARM-specific
------------

The following dependencies have been installed using the
distribution's package manager:

- binutils-arm-none-eabi
- bossa-cli
- gcc-arm-none-eabi
- gdb-arm-none-eabi
- python-serial

### J-Link Software

We use the J-Link software collection provided by SEGGER:

<https://www.segger.com/downloads/jlink/#J-LinkSoftwareAndDocumentationPack>

PC-specific
-----------

The distribution's GCC and GDB packages should be enough to run
benchmarks on 64-bit PCs.

CPU frequency scaling can cause jitter when measuring execution
cycles. To counter that, FELICS-AE attempts to set the cpu-freq
governor to "performance" when running benchmarks on PC, so that the
frequency remains constant (and maximum) during measurements.

To do so, FELICS-AE attempts to run the command cpufreq-set, which can
be found in the cpufrequtils package. FELICS-AE will not fail and will
merely warn if the command is not found.

Setting the CPU governor requires root privileges, therefore FELICS-AE
runs cpufreq-set with sudo. To allow the command to succeed without
entering a password, create a new sudoers file,
e.g. /etc/sudoers.d/cpu-governor:

    USERNAME  ALL = NOPASSWD: /usr/bin/cpufreq-set -c [0-9] -g powersave,\
                              /usr/bin/cpufreq-set -c [0-9] -g performance

Replace `USERNAME` with your actual identifier.

2 - Configuring FELICS-AE
=========================

Some configuration files must be edited so that FELICS-AE can find the
newly-installed dependencies.

`config.sh`
-----------

`scripts/config/config.sh` records the path for programs used during
measurements, such as code size analyzers, debuggers and simulators.

Platform-specific makefiles
---------------------------

The folder `source/architecture` contains architecture-specific
makefile snippets:

- `avr.mk`
- `msp.mk`
- `arm.mk`
- `pc.mk`

These include files define several variables pointing to compilers,
header files…

