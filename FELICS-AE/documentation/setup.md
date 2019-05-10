Setting up FELICS-AE
====================

This guide provides instructions to install the software FELICS-AE
depends on.

1. Installing dependencies
==========================

NB: this guide has been written with the Ubuntu 16.04 distribution of
GNU/Linux in mind. Although any distribution should be able to run
FELICS-AE, specific steps to install software packages may vary.

TODO: add stock ubuntu packages

AVR-specific
------------

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

### MSP430-GCC

We use version 7.3.2.154 of the compiler provide by Texas Instruments:

<http://software-dl.ti.com/msp430/msp430_public_sw/mcu/msp430/MSPGCC/latest/index_FDS.html>

### MSPDebug

We use version 0.25 of MSPDebug, compiled the source fetched from the
developer's repository:

<https://github.com/dlbeer/mspdebug>

ARM-specific
------------

We use the J-Link software collection provided by SEGGER:

<https://www.segger.com/downloads/jlink/#J-LinkSoftwareAndDocumentationPack>

2. Configuring FELICS-AE
========================

TODO: config.sh, msp.mk…
