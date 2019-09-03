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
# Call this makefile from a cipher source directory or build directory to build 
#	... the given cipher:
#	make -f ./../../../common/cipher.mk [ARCHITECTURE=[AVR|MSP|ARM|PC]]
#		[DEBUG=[0|1|3|7]] [MEASURE_CYCLE_COUNT=[0|1]]
#		[COMPILER_OPTIONS='...'] [all|clean|help]
#
# 	Examples: 
#		make -f ./../../../common/cipher.mk
#		make -f ./../../../common/cipher.mk ARCHITECTURE=PC DEBUG=1
#		make -f ./../../../common/cipher.mk clean
#


SOURCEDIR = ./../source
BUILDDIR = ./../build

COMMONSOURCEDIR = ./../../../common

INCLUDES = -I$(SOURCEDIR) -I$(COMMONSOURCEDIR)

VPATH = $(SOURCEDIR):$(COMMONSOURCEDIR)


SOURCES = $(wildcard $(SOURCEDIR)/*.c)
SOURCES_ASM = $(wildcard $(SOURCEDIR)/*.S)
OBJS = $(subst $(SOURCEDIR)/, , $(SOURCES:.c=.o) $(SOURCES_ASM:.S=.o))

BENCH_SOURCES = $(COMMONSOURCEDIR)/felics/main_bench.c
BENCH_OBJECTS = $(subst $(COMMONSOURCEDIR)/felics/, felics_, $(BENCH_SOURCES:.c=.o))

LSTS = $(OBJS:.o=.lst)

CHECK_LISTINGS = felics_check.lst felics_main_check.lst felics_common.lst
BENCH_LISTINGS = felics_bench.lst felics_main_bench.lst felics_common.lst


# TODO: remove this ifeq, use targets directly.

ifeq ($(SCENARIO), 1)
TARGET=target1
LSTS += $(BENCH_LISTINGS)
else
TARGET=target
LSTS += $(CHECK_LISTINGS)
endif


CURRENTPATHDIRS = $(subst /, , $(CURDIR))
LASTCURRENTPATHDIR = $(word $(words $(CURRENTPATHDIRS)), $(CURRENTPATHDIRS))
CIPHERNAME = $(lastword $(subst $(LASTCURRENTPATHDIR), , $(CURRENTPATHDIRS)))  


DELIMITER = ----------


.PHONY : all clean help


all : post-build

.PHONY : post-build
post-build : main-build
	@echo $(DELIMITER) End building $(CIPHERNAME) $(DELIMITER)

.PHONY : main-build
main-build : \
		pre-build \
		$(TARGET)

.PHONY : pre-build
pre-build : \
		pre-build-debug \
		pre-build-scenario \
		pre-build-helpers \
		pre-build-measure_cycle_count \
		pre-build-compiler_options
	@echo $(DELIMITER) Start building $(CIPHERNAME) $(DELIMITER)

ifdef ARCHITECTURE
include ../../../architecture/$(ARCHITECTURE).mk
CFLAGS += -D $(ARCHITECTURE)
endif

.PHONY : pre-build-debug
pre-build-debug :
ifdef DEBUG
	@echo Building with DEBUG flag set to $(DEBUG) ...
$(eval CFLAGS += -D DEBUG=$(DEBUG))
else
	@echo Building with DEBUG flag NOT set ...
endif

.PHONY : pre-build-scenario
pre-build-scenario :
ifdef SCENARIO
	@echo Building with SCENARIO flag set to $(SCENARIO) ...
$(eval CFLAGS += -D SCENARIO=$(SCENARIO))
else
	@echo Building with SCENARIO flag NOT set ...
endif

.PHONY : pre-build-measure_cycle_count
pre-build-measure_cycle_count :
ifdef MEASURE_CYCLE_COUNT
	@echo Building with MEASURE_CYCLE_COUNT flag set to $(MEASURE_CYCLE_COUNT) \
		...
$(eval CFLAGS += -D MEASURE_CYCLE_COUNT=$(MEASURE_CYCLE_COUNT))
else
	@echo Building with MEASURE_CYCLE_COUNT flag NOT set ...
endif

.PHONY : pre-build-compiler_options
pre-build-compiler_options :
ifdef COMPILER_OPTIONS
	@echo Building with COMPILER_OPTIONS flag set to $(COMPILER_OPTIONS) ...
$(eval CFLAGS += $(COMPILER_OPTIONS))
else
	@echo Building with COMPILER_OPTIONS flag NOT set ...
endif


.PHONY : target
target : \
		felics_check.elf \
		$(LSTS)

.PHONY : target1
target1 : \
		felics_bench.elf \
		$(LSTS)

felics_check.elf : \
		$(OBJS) \
		felics_main_check.o \
		felics_common.o
	$(CC) $(LDFLAGS) $(addprefix $(BUILDDIR)/, $^) $(LDLIBS) -o $(BUILDDIR)/$@

felics_bench.elf : \
		$(OBJS) \
		felics_main_bench.o \
		felics_common.o
	$(CC) $(LDFLAGS) $(addprefix $(BUILDDIR)/, $^) $(LDLIBS) -o $(BUILDDIR)/$@

%.bin: $(BUILDDIR)/%.elf
	$(OBJCOPY) -O binary $< $@

%.hex: $(BUILDDIR)/%.elf
	$(OBJCOPY) -O ihex $< $@

%.o : \
		%.c \
		$(COMMONSOURCEDIR)/felics/cipher.h \
		$(COMMONSOURCEDIR)/felics/common.h \
		$(SOURCEDIR)/api.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@

%.o : \
		%.S \
		$(COMMONSOURCEDIR)/felics/cipher.h \
		$(COMMONSOURCEDIR)/felics/common.h \
		$(SOURCEDIR)/api.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@

felics_%.o: $(COMMONSOURCEDIR)/felics/%.c \
            $(COMMONSOURCEDIR)/felics/cipher.h \
            $(COMMONSOURCEDIR)/felics/common.h \
            $(SOURCEDIR)/api.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@

felics_check.lst felics_bench.lst: %.lst: %.elf
	$(OBJDUMP) $(OBJDUMPFLAGS) $(BUILDDIR)/$< > $(BUILDDIR)/$@

%.lst : %.o
	$(OBJDUMP) $(OBJDUMPFLAGS) $(BUILDDIR)/$< > $(BUILDDIR)/$@


clean :
	@echo $(DELIMITER) Begin cleaning: $(CIPHERNAME) $(DELIMITER)
	rm -f $(filter-out %.log,$(wildcard $(BUILDDIR)/*))
	@echo $(DELIMITER) End cleaning: $(CIPHERNAME) $(DELIMITER)


help:
	@echo ""
	@echo -n "Call this makefile from a cipher source directory or build "
	@echo 		"directory to build the given cipher:"
	@echo -n "	make -f ./../../../common/cipher.mk "
	@echo -n		"[ARCHITECTURE=[AVR|MSP|ARM|PC|NRF52840|STM32L053]] [DEBUG=[0|1|3|7]] "
	@echo -n		"[MEASURE_CYCLE_COUNT=[0|1]] [SCENARIO=[0|1]] "
	@echo -n		"[COMPILER_OPTIONS='...'] [all|clean|help]"
	@echo ""
	@echo ""
	@echo " 	Examples: "
	@echo "		make -f ./../../../common/cipher.mk"
	@echo "		make -f ./../../../common/cipher.mk ARCHITECTURE=PC"
	@echo "		make -f ./../../../common/cipher.mk clean"
	@echo ""
