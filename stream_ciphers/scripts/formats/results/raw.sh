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
# Functions to generate raw data table
#


# Add raw table header
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
# 	$3 - the architecture
function add_raw_table_header()
{
	local output_file=$1
	local scenario=$2
	local architecture=$3
	

	# Clear output
	echo -n "" > $output_file

	case $scenario in
		$SCRIPT_SCENARIO_0)
			# Table title
			title_position=$(($SCENARIO_0_TABLE_HORIZONTAL_LINE_LENGTH / 2 + 15))	
			printf " %"$title_position"s " "Architecture: $architecture; Scenario: $scenario" >> $output_file
			printf "\n" >> $output_file

			# Table header
			printf "%0.s-" $(seq 1 $SCENARIO_0_TABLE_HORIZONTAL_LINE_LENGTH) >> $output_file
			printf "\n" >> $output_file
			printf "| %53s | %39s | %39s | %81s | %25s |\n" "Cipher Info" "Implementation Info" "Code Size" "RAM" "Execution Time" >> $output_file
			printf "%0.s-" $(seq 1 $SCENARIO_0_TABLE_HORIZONTAL_LINE_LENGTH) >> $output_file
			printf "\n" >> $output_file
			printf "| %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s |\n" "Cipher" "State Size" "Key Size" "IV Size" "Version" "Language" "Options" "S" "E" "S+E" "S Stack" "E Stack" "S Data" "E Data" "Common Data" "Total Data" "S" "E" >> $output_file
			printf "%0.s-" $(seq 1 $SCENARIO_0_TABLE_HORIZONTAL_LINE_LENGTH) >> $output_file
			;;
		$SCRIPT_SCENARIO_1)
			# Table title
			title_position=$(($SCENARIO_1_TABLE_HORIZONTAL_LINE_LENGTH / 2 + 15))
			printf " %"$title_position"s " "Architecture: $architecture; Scenario: $scenario" >> $output_file
			printf "\n" >> $output_file

			# Table header
			printf "%0.s-" $(seq 1 $SCENARIO_1_TABLE_HORIZONTAL_LINE_LENGTH) >> $output_file
			printf "\n" >> $output_file
			printf "| %53s | %39s | %39s | %81s | %25s |\n" "Cipher Info" "Implementation Info" "Code Size" "RAM" "Execution Time" >> $output_file
			printf "%0.s-" $(seq 1 $SCENARIO_1_TABLE_HORIZONTAL_LINE_LENGTH) >> $output_file
			printf "\n" >> $output_file
			printf "| %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s | %11s |\n" "Cipher" "State Size" "Key Size" "IV Size" "Version" "Language" "Options" "S" "E" "S+E" "S Stack" "E Stack" "S Data" "E Data" "Common Data" "Total Data" "S" "E" >> $output_file
			printf "%0.s-" $(seq 1 $SCENARIO_1_TABLE_HORIZONTAL_LINE_LENGTH) >> $output_file
			;;
	esac

	printf "\n" >> $output_file
}


# Add raw table row
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
# 	$3 - the cipher name
#	$4 - the cipher state size
#	$5 - the cipher key size
#	$6 - the cipher IV size
#	$7 - the cipher implementation version
#	$8 - the cipher implementation language
#	$9 - the cipher implementation compiler options
#	$10 ... - cipher metrics values
function add_raw_table_row()
{
	local output_file=$1
	local scenario=$2
	local cipher_name=$3
	local cipher_state_size=$4
	local cipher_key_size=$5
	local cipher_iv_size=$6
	local cipher_implementation_version=$7
	local cipher_implementation_language=$8
	local cipher_implementation_compiler_options=$9
	local cipher_metrics_values=( ${@:10} )
	
	
	local column_length=0

	case $scenario in
		$SCRIPT_SCENARIO_0)
			column_length=11
			;;
		$SCRIPT_SCENARIO_1)
			column_length=11
			;;
	esac

	# Table line
	printf "| %"$column_length"s " "$cipher_name" >> $output_file
	printf "| %"$column_length"s " "$cipher_state_size" >> $output_file
	printf "| %"$column_length"s " "$cipher_key_size" >> $output_file
	printf "| %"$column_length"s " "$cipher_iv_size" >> $output_file
	printf "| %"$column_length"s " "$cipher_implementation_version" >> $output_file
	printf "| %"$column_length"s " "$cipher_implementation_language" >> $output_file
	printf "| %"$column_length"s " "$cipher_implementation_compiler_options" >> $output_file

	for value in ${cipher_metrics_values[@]}
	do
		printf "| %"$column_length"s " $value >> $output_file
	done
	printf "|\n" >> $output_file
}


# Add raw table footer
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
function add_raw_table_footer()
{
	local output_file=$1
	local scenario=$2

	
	local horizontal_line_length=0
	
	case $scenario in
		$SCRIPT_SCENARIO_0)
			horizontal_line_length=$SCENARIO_0_TABLE_HORIZONTAL_LINE_LENGTH
			;;
		$SCRIPT_SCENARIO_1)
			horizontal_line_length=$SCENARIO_1_TABLE_HORIZONTAL_LINE_LENGTH
			;;
	esac

	# Table footer
	printf "%0.s-" $(seq 1 $horizontal_line_length) >> $output_file
	printf "\n" >> $output_file
}
