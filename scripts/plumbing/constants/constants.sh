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
# Constants
#


FALSE=0
TRUE=1


SCRIPT_ARCHITECTURE_PC=PC
SCRIPT_ARCHITECTURE_AVR=AVR
SCRIPT_ARCHITECTURE_MSP=MSP
SCRIPT_ARCHITECTURE_ARM=ARM
SCRIPT_ARCHITECTURE_NRF52840=NRF52840
SCRIPT_ARCHITECTURE_STM32L053=STM32L053

SCRIPT_ARCHITECTURES=($SCRIPT_ARCHITECTURE_PC $SCRIPT_ARCHITECTURE_AVR $SCRIPT_ARCHITECTURE_MSP $SCRIPT_ARCHITECTURE_ARM $SCRIPT_ARCHITECTURE_NRF52840 $SCRIPT_ARCHITECTURE_STM32L053)

SCRIPT_COMPILER_OPTION_OPTIMIZE_3="-O3"
SCRIPT_COMPILER_OPTION_OPTIMIZE_2="-O2"
SCRIPT_COMPILER_OPTION_OPTIMIZE_1="-O1"
SCRIPT_COMPILER_OPTION_OPTIMIZE_S="-Os"

SCRIPT_COMPILER_OPTIONS=("$SCRIPT_COMPILER_OPTION_OPTIMIZE_3" "$SCRIPT_COMPILER_OPTION_OPTIMIZE_2" "$SCRIPT_COMPILER_OPTION_OPTIMIZE_1" "$SCRIPT_COMPILER_OPTION_OPTIMIZE_S")

DEFAULT_SCRIPT_OUTPUT=/dev/tty

FILE_NAME_SEPARATOR=_

CIPHER_MAKEFILE=../../../common/cipher.mk

PC_CPU=0
