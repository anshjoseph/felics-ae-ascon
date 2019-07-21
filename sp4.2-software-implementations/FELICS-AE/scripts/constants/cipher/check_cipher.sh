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


SOURCE_DIR=../../..
CIPHER_MAKEFILE=${SOURCE_DIR}/common/cipher.mk
MAKE_FILE_LOG=make.log

SUCCESS_EXIT_CODE=0

CIPHER_ELF_FILE=cipher.elf
RESULT_FILE=result.out

EXPECTED_WRONG_COUNT=0
EXPECTED_CORRECT_COUNT=5

ARM_SERIAL_TERMINAL=${SOURCE_DIR}/architecture/arm/arm_serial_terminal.py
NRF52840_SERIAL_TERMINAL=${SOURCE_DIR}/architecture/nrf52840/arm_serial_terminal.py
STM32L053_SERIAL_TERMINAL=${SOURCE_DIR}/architecture/stm32l053/stm32l053_serial_terminal.py

MSPDEBUG_CHECK_CIPHER_COMMANDS_FILE=${SOURCE_DIR}/architecture/msp/check_cipher.cmd
