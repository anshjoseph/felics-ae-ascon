#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2015 University of Luxembourg
#
# Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu> and 
# Yann Le Corre <yann.lecorre@uni.lu>
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
# MSP make file variables 
#


# Linker printf library path
PRINTF_DIR := ../../../../../common/msp
MSPGCC_DIR = /opt/paclido/msp430-gcc
MSPGCC_BIN_DIR = $(MSPGCC_DIR)/bin
MSPGCC_SUPPORT_DIR = $(MSPGCC_DIR)/support-files/include/

CC := $(MSPGCC_BIN_DIR)/msp430-elf-gcc -I$(MSPGCC_SUPPORT_DIR)

CFLAGS := \
	-std=c99 \
	-mmcu=msp430f1611 \
	-g \
	-fdata-sections \
	-ffunction-sections \
	-fno-builtin-printf \
	-Wcast-align \
	-Wsign-compare \
	-Waggregate-return \
	-Wunused \
	-Wfatal-errors \
	-Wl,--gc-sections \
	-Wl,--relax

OBJDUMP := $(MSPGCC_BIN_DIR)/msp430-elf-objdump

OBJDUMPFLAGS := -dSt

OBJCOPY := $(MSPGCC_BIN_DIR)/msp430-elf-objcopy

# -lprintf is in LDLIBS and not LDFLAGS because we want it to appear on the 
# ... command line after the object files (i.e. our printf function must be used
# ... instead of the libc printf function)
LDLIBS := -L$(PRINTF_DIR) -lprintf -L$(MSPGCC_SUPPORT_DIR)

LDFLAGS := $(CFLAGS)
