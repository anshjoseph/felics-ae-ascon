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

- gcc-avr
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
- gdb-multiarch
- python3-serial

Make sure your user account belongs to the `dialout` group:

    $ sudo adduser ${USER} dialout

### J-Link Software

We use the J-Link software collection provided by SEGGER:

<https://www.segger.com/downloads/jlink/#J-LinkSoftwareAndDocumentationPack>

NRF52840-specific
------------

The following dependencies are required :

- GNU Embedded Toolchain available [here](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads).
- J-Link Software and Documentation Pack available [here](https://www.segger.com/downloads/jlink/#J-LinkSoftwareAndDocumentationPack).
- nRF Command Line Tools available [here](https://www.nordicsemi.com/Software-and-Tools/Development-Tools/nRF-Command-Line-Tools/Download#infotabs).
- [python-serial](https://pythonhosted.org/pyserial/). You can get it via distribution's package manager or using `pip` for Python 3.

You can add `bin` directories from all these requirements to your PATH environment variable for more convenience.

### Build `libnrf52840.a`

If you ever need to regenerate the library `libnrf52840.a` that is bundled with FELICS-AE, follow these instructions:

1. Download the Nordic SDK `v14.2.0` available [here](https://developer.nordicsemi.com/nRF5_SDK/nRF5_SDK_v14.x.x/nRF5_SDK_14.2.0_17b948a.zip) and open the `peripheral/uart` example project. This project uses `printf` required by FELICS framework.
2. Build the project using the GNU toolchain. In the build folder, remove the object files (`.o`) specific to the project (e.g. `main.o`) and keep those related to the platform core and drivers.
3. Archive the object files into `libnrf52840.a` using `arm-none-eabi-ar` command.

STM32L053-specific
------------------

The following dependencies are required :

- GNU Embedded Toolchain available [here](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads).
- STLink Open source version available [here](https://github.com/texane/stlink).
- [python-serial](https://pythonhosted.org/pyserial/). You can get it via distribution's package manager or using `pip` for Python 3.

### Build `libstm32l053.a`

If you ever need to regenerate the library `libstm32l053.a` that is bundled with FELICS-AE, follow [these instructions](stm32l053.md).

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
makefile modules: `AVR.mk`, `MSP.mk`, `ARM.mk`, `PC.mk`, etc.

These files define several variables pointing to compilers, header
files…
