#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2015 University of Luxembourg
#
# Written in 2015 by Yann Le Corre <yann.lecorre@uni.lu> and 
# Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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
# NRF52840 make file variables 
#


# System directory code path
SYSTEM_DIR := ../../../architecture/nrf52840

CC := arm-none-eabi-gcc
OBJDUMP := arm-none-eabi-objdump
OBJCOPY := arm-none-eabi-objcopy
NRFJPROG := nrfjprog

NRF52840_SERIAL_TERMINAL := $(SYSTEM_DIR)/nrf52840_serial_terminal.py

PORT := ttyACM0
DEVICE := /dev/$(PORT)

CFLAGS := \
	-std=c99 \
	-DBOARD_PCA10056 \
	-DBSP_DEFINES_ONLY \
	-DCONFIG_GPIO_AS_PINRESET \
	-DFLOAT_ABI_HARD \
	-DNRF52840_XXAA \
	-mcpu=cortex-m4 \
	-mthumb \
	-mabi=aapcs \
	-mfloat-abi=hard \
	-mfpu=fpv4-sp-d16 \
	-ffunction-sections \
	-fdata-sections \
	-fno-strict-aliasing \
	-fno-builtin \
	-fshort-enums \
	-I$(SYSTEM_DIR)/include

LDFLAGS := \
	-mthumb \
	-mabi=aapcs \
	-L$(SYSTEM_DIR) \
	-T$(SYSTEM_DIR)/flash.ld \
	-mcpu=cortex-m4 \
	-mfloat-abi=hard \
	-mfpu=fpv4-sp-d16 \
	-Wl,--gc-sections \
	--specs=nano.specs


LDLIBS := -Wl,--whole-archive -lnrf52840 -Wl,--no-whole-archive

OBJDUMPFLAGS := -dSt


# Upload the program to the board. Should be invoked as: 
#	make -f ./../../../common/cipher.mk ARCHITECTURE=NRF52840 upload-cipher
.PHONY : upload-cipher
upload-cipher : cipher.hex
	@# Communicate with the board
	@# Use nrfjprog to load program in flash
	@$(NRFJPROG) -f NRF52 --program $< --chiperase -r

# Upload the program to the board. Should be invoked as: 
#	make -f ./../../../common/cipher.mk ARCHITECTURE=NRF52840 upload-scenario1
.PHONY : upload-scenario1
upload-scenario1 : scenario1.hex
	@# Communicate with the board
	@# Use nrfjprog to load program in flash
	@$(NRFJPROG) -f NRF52 --program $< --chiperase -r

# Run the program stored in the flash memory of the board. Should be invoked as: 
#	make -f ./../../../common/cipher.mk ARCHITECTURE=NRF52840 run
# Note that the binary should be uploaded first.
.PHONY : run
run :
	@($(NRFJPROG) -f NRF52 -p > /dev/null &); ./$(NRF52840_SERIAL_TERMINAL) $(DEVICE)

pre-build-helpers:
