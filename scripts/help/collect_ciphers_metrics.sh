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


# Display help information
function display_help()
{
	echo ""
	echo " Call this script to collect the ciphers metrics"
	echo " 	./collect_ciphers_metrics.sh [{-h|--help}] [{-a|--architectures}=['PC AVR MSP ARM']] [{-c|--ciphers}=['Cipher1 Cipher2 ...']] [{-co|--compiler_options}='...']"
	echo ""
	echo "	Options:"
	echo "		-h, --help"
	echo "			Display help information"
	echo "		-a, --architectures"
	echo "			Specifies for which archiectures to collect ciphers metrics"
	echo "				List of values: 'PC AVR MSP ARM NRF52840 STM32L053'"
	echo "				Default: all architectures"
	echo "		-c, --ciphers"
	echo "			Specifies for which ciphers to collect the metrics"
	echo "				List of values: 'CipherName_BlockSizeInBits_KeySizeInBits_v01 ...'"
	echo "				Default: all ciphers"
	echo "		-co,--compiler_options"
	echo "			Specifies the compiler options"
	echo "				List of values: '-O3 --param max-unroll-times=5 --param max-unrolled-insns=100 ...'"
	echo "				Default: all compiler options"
	echo ""
	echo "	Examples:"
	echo "		./collect_ciphers_metrics.sh -f=0"
	echo "		./collect_ciphers_metrics.sh --format=1"
	echo "		./collect_ciphers_metrics.sh -a='PC AVR'"
	echo ""

	exit
}
