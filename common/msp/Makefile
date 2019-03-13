#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2015 University of Luxembourg
#
# Written in 2015 by Yann Le Corre <yann.lecorre@uni.lu>
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

################################################################################
#
# libprintf.a makefile
#
################################################################################

MSPGCC_DIR = /opt/paclido/msp430-gcc
MSPGCC_BIN_DIR = $(MSPGCC_DIR)/bin
MSPGCC_SUPPORT_DIR = $(MSPGCC_DIR)/support-files/include/
AR = $(MSPGCC_BIN_DIR)/msp430-elf-ar
CC = $(MSPGCC_BIN_DIR)/msp430-elf-gcc -I$(MSPGCC_SUPPORT_DIR)

%.o: %.c
	$(CC) -c -mmcu=msp430f1611 -g -O3  -o $@ $<

vpath %.c ./src

libprintf.a : libprintf.a(putchar.o printf.o)

.PHONY: all
all: libprintf.a

.PHONY: clean
clean:
	rm -rf *.a *.o
