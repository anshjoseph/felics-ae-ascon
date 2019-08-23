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


CONSTANTS_SOURCE_FILE=./../source/constants.h
SCENARIO1_CONSTANTS_SOURCE_FILE=./../../../common/scenario1/scenario1.h

RAW_DATA_SIZE_DEFINE='#define RAW_DATA_SIZE'
RAW_ASSOCIATED_DATA_SIZE_DEFINE='#define RAW_ASSOCIATED_DATA_SIZE'

MEMORY_PATTERN=(0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88 0x99 0xAA)

MEMORY_FILE=memory.mem
MEMORY_SIZE=2000

PC_SCENARIO1_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario1_stack.gdb
PC_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario1_stack_sections.gdb

AVR_SCENARIO1_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario1_stack.gdb
AVR_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario1_stack_sections.gdb

MSP_SCENARIO1_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario1_stack.gdb
MSP_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario1_stack_sections.gdb

ARM_SCENARIO1_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario1_stack.gdb
ARM_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario1_stack_sections.gdb

NRF52840_SCENARIO1_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/nrf52840_scenario1_stack.gdb
NRF52840_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/nrf52840_scenario1_stack_sections.gdb

STM32L053_SCENARIO1_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/stm32l053_scenario1_stack.gdb
STM32L053_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/stm32l053_scenario1_stack_sections.gdb

GDB_STACK_LOG_FILE=gdb_stack.log
GDB_STACK_SECTIONS_LOG_FILE=gdb_stack_sections.log

SIMAVR_STACK_LOG_FILE=simavr_stack.log
SIMAVR_STACK_SECTIONS_LOG_FILE=simavr_stack_sections.log

MSPDEBUG_STACK_LOG_FILE=mspdebug_stack.log
MSPDEBUG_STACK_SECTIONS_LOG_FILE=mspdebug_stack_sections.log

JLINK_GDB_SERVER_STACK_LOG_FILE=jlink_gdb_server_stack.log
JLINK_GDB_SERVER_STACK_SECTIONS_LOG_FILE=jlink_gdb_server_stack_sections.log

STLINK_GDB_SERVER_STACK_LOG_FILE=stlink_gdb_server_stack.log
STLINK_GDB_SERVER_STACK_SECTIONS_LOG_FILE=stlink_gdb_server_stack_sections.log

UPLOAD_CIPHER=upload-cipher
UPLOAD_SCENARIO1=upload-scenario1

MAKE_LOG_FILE=cipher_ram_make.log
