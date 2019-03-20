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
# Functions to generate CSV data table
#


# Add CSV table header
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
# 	$3 - the architecture
function add_csv_table_header()
{
	local output_file=$1
	local scenario=$2
	local architecture=$3
	

	# Clear output
	echo -n "" > $output_file

	case $scenario in
		$SCRIPT_SCENARIO_0)
			printf "Cipher Info,,,Implementation Info,,,Code Size,,,,,RAM,,,,,,,,,,Execution Time,,," >> $output_file
			printf "\n" >> $output_file
			printf ",,,,,,,,,,,Stack,,,,Data,,,," >> $output_file
			printf "\n" >> $output_file
			printf "Cipher,Block Size (bits),Key Size (bits),Version,Language,Options,EKS (bytes),E (bytes),DKS (bytes),D(bytes),EKS + E + DKS + D (bytes),EKS (bytes),E (bytes),DKS (bytes),D (bytes),EKS (bytes),E (bytes),DKS (bytes),D (bytes),Common (bytes),Total (bytes),EKS (cycles),E (cycles),DKS (cycles),D (cycles)" >> $output_file
			printf "\n" >> $output_file
			;;
		$SCRIPT_SCENARIO_1)
			printf "Cipher Info,,,Implementation Info,,,Code Size,,,,,RAM,,,,,,,,,,Execution Time,,," >> $output_file
			printf "\n" >> $output_file
			printf ",,,,,,,,,,,Stack,,,,Data,,,," >> $output_file
			printf "\n" >> $output_file
			printf "Cipher,Block Size (bits),Key Size (bits),Version,Language,Options,EKS (bytes),E (bytes),DKS (bytes),D(bytes),EKS + E + DKS + D (bytes),EKS (bytes),E (bytes),DKS (bytes),D (bytes),EKS (bytes),E (bytes),DKS (bytes),D (bytes),Common (bytes),Total (bytes),EKS (cycles),E (cycles),DKS (cycles),D (cycles)" >> $output_file
			printf "\n" >> $output_file
			;;
		$SCRIPT_SCENARIO_2)
			printf "Cipher Info,,,Implementation Info,,,Code Size,RAM,,Execution Time" >> $output_file
			printf "\n" >> $output_file
			printf ",,,,,,,Stack,Data," >> $output_file
			printf "\n" >> $output_file
			printf "Cipher,Block Size (bits),Key Size (bits),Version,Options,Language,E (bytes),E (bytes),Data (bytes),E (cycles)" >> $output_file
			printf "\n" >> $output_file
			;;
	esac
}


# Add CVS table row
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
# 	$3 - the cipher name
#	$4 - the cipher block size
#	$5 - the cipher key size
#	$6 - the cipher implementation version
#	$7 - the cipher implementation language
#	$8 - the cipher implementation compiler options
#	$9 ... - cipher metrics values
function add_csv_table_row()
{
	local output_file=$1
	local scenario=$2
	local cipher_name=$3
	local cipher_block_size=$4
	local cipher_key_size=$5
	local cipher_implementation_version=$6
	local cipher_implementation_language=$7
	local cipher_implementation_compiler_options=$8
	local cipher_metrics_values=( ${@:9} )


	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "$cipher_name" >> $output_file
	printf "$CSV_FIELD_DELIMITER$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" $cipher_block_size >> $output_file
	printf "$CSV_FIELD_DELIMITER$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" $cipher_key_size >> $output_file
	printf "$CSV_FIELD_DELIMITER$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" $cipher_implementation_version >> $output_file
	printf "$CSV_FIELD_DELIMITER$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" $cipher_implementation_language >> $output_file
	printf "$CSV_FIELD_DELIMITER$CSV_EQUAL_DELIMITER$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "$cipher_implementation_compiler_options" >> $output_file

	
	for value in ${cipher_metrics_values[@]}
	do
		printf "$CSV_FIELD_DELIMITER$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" $value >> $output_file
	done
	printf "\n" >> $output_file
}


# Add CSV table footer
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
function add_csv_table_footer()
{
	local output_file=$1
	local scenario=$2
	

	case $scenario in
		$SCRIPT_SCENARIO_0)
			;;
		$SCRIPT_SCENARIO_1)
			;;
		$SCRIPT_SCENARIO_2)
			;;
	esac
}
