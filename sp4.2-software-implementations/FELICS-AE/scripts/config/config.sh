#!/bin/bash

#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2015 University of Luxembourg
#
# Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
#
# This file is part of FELICS.
#
# FELICS is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# FELICS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

#
# Configuration constants
#


DEPENDENCIES_DIR=/opt/felics

PC_SIZE=size
AVR_SIZE=avr-size
MSP_SIZE=${DEPENDENCIES_DIR}/msp430-gcc/bin/msp430-elf-size
ARM_SIZE=arm-none-eabi-size
NRF52840_SIZE=arm-none-eabi-size


PC_GDB=gdb
AVR_GDB=avr-gdb
MSP_GDB=${DEPENDENCIES_DIR}/msp430-gcc/bin/msp430-elf-gdb
ARM_GDB=gdb-multiarch
NRF52840_GDB=arm-none-eabi-gdb

SIMAVR_SIMULATOR=${DEPENDENCIES_DIR}/simavr/bin/simavr
MSPDEBUG_SIMULATOR=${DEPENDENCIES_DIR}/mspdebug/usr/local/bin/mspdebug

JLINK_GDB_SERVER=JLinkGDBServer

AVRORA_SIMULATOR="java -jar ${DEPENDENCIES_DIR}/avrora-beta-1.7.117-patched.jar"
