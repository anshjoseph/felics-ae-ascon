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


MEMORY_PATTERN=(0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88 0x99 0xAA)

MEMORY_FILE=memory.mem
MEMORY_SIZE=2000

GDB_STACK_SECTIONS_LOG_FILE=gdb_stack_sections.log

SIMAVR_STACK_SECTIONS_LOG_FILE=simavr_stack_sections.log

MSPDEBUG_STACK_SECTIONS_LOG_FILE=mspdebug_stack_sections.log

JLINK_GDB_SERVER_STACK_SECTIONS_LOG_FILE=jlink_gdb_server_stack_sections.log

STLINK_GDB_SERVER_STACK_SECTIONS_LOG_FILE=stlink_gdb_server_stack_sections.log

MAKE_LOG_FILE=cipher_ram_make.log
