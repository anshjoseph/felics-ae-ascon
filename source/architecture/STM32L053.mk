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
# STM32L053 make file variables 
#


# System directory code path
SYSTEM_DIR := ../../../architecture/stm32l053

CC := arm-none-eabi-gcc
OBJDUMP := arm-none-eabi-objdump
OBJCOPY := arm-none-eabi-objcopy
ST_FLASH := LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/felics/stlink/usr/local/lib/ /opt/felics/stlink/usr/local/bin/st-flash

STM32L053_SERIAL_TERMINAL := $(SYSTEM_DIR)/stm32l053_serial_terminal.py

PORT := ttyACM0
DEVICE := /dev/$(PORT)

STM_INCLUDES= \
	-I$(SYSTEM_DIR)/include \
	-I$(SYSTEM_DIR)/include/CMSIS/ \
	-I$(SYSTEM_DIR)/include/CMSIS/Device/STM32L0xx \
	-I$(SYSTEM_DIR)/include/STM32L0xx_HAL_Driver \
	-I$(SYSTEM_DIR)/include/STM32L0xx_HAL_Driver/Legacy

CFLAGS := \
	-mcpu=cortex-m0plus \
	-mthumb \
	-DUSE_HAL_DRIVER \
	-DSTM32L053xx \
	-Wall \
	-fdata-sections \
	-ffunction-sections \
	$(STM_INCLUDES)
	

LDFLAGS := \
	-mcpu=cortex-m0plus \
	-mthumb \
	-specs=nano.specs \
	-L$(SYSTEM_DIR) \
	-T$(SYSTEM_DIR)/STM32L053R8Tx_FLASH.ld \
	-Wl,--gc-sections


LDLIBS := -Wl,--whole-archive -lstm32l053 -Wl,--no-whole-archive

OBJDUMPFLAGS := -dSt


# Upload the program to the board. Should be invoked as: 
#	make -f ./../../../common/cipher.mk ARCHITECTURE=STM32L053 upload-check
.PHONY : upload-check
upload-check : felics_check.hex
	@# Communicate with the board
	@# Use st-flash to load program in flash
	@$(ST_FLASH) --format ihex write $<

# Upload the program to the board. Should be invoked as: 
#	make -f ./../../../common/cipher.mk ARCHITECTURE=STM32L053 upload-bench
.PHONY : upload-bench
upload-bench : felics_bench.hex
	@# Communicate with the board
	@# Use st-flash to load program in flash
	@$(ST_FLASH) --format ihex write $<

# Run the program stored in the flash memory of the board. Should be invoked as: 
#	make -f ./../../../common/cipher.mk ARCHITECTURE=STM32L053 run
# Note that the binary should be uploaded first.
.PHONY : run
run :
	@($(ST_FLASH) reset > /dev/null 2>&1 &); ./$(STM32L053_SERIAL_TERMINAL) $(DEVICE)

.PHONY : erase
erase :
	@($(ST_FLASH) erase > /dev/null 2>&1)

pre-build-helpers:
