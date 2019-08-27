#!/bin/bash

set -e

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
# Call this script to extract the cipher RAM consumption
# 	./cipher_ram.sh [{-h|--help}] [--version] [{-a|--architecture}=[PC|AVR|MSP|ARM]] [{-o|--output}=[...]]
#
#	To call from a cipher build folder use:
#		./../../../../scripts/cipher/cipher_ram.sh [options]
#
#	Options:
#		-h, --help
#			Display help information
#		--version
#			Display version information
#		-a, --architecture
#			Specifies which architecture to build for
#				Default: PC
#		-o, --output
#			Specifies where to output the results. The relative path is computed from the directory where script was called
#				Default: /dev/tty
#
#	Examples:
#		./../../../../scripts/cipher/cipher_ram.sh
#		./../../../../scripts/cipher/cipher_ram.sh --architecture=MSP
#  		./../../../../scripts/cipher/cipher_ram.sh -o=results.txt
#


# Get current script path
script_path=$(dirname $0)

# Include configuration file
source $script_path/../config/config.sh

# Include constants files
source $script_path/../constants/constants.sh
source $script_path/../constants/cipher/cipher_ram.sh

# Include help file
source $script_path/../help/cipher/cipher_ram.sh

# Include validation functions
source $script_path/../common/validate.sh

# Include version file
source $script_path/../common/version.sh


# Default values
SCRIPT_SCENARIO=$SCRIPT_SCENARIO_1
SCRIPT_ARCHITECTURE=$SCRIPT_ARCHITECTURE_PC
SCRIPT_OUTPUT=$DEFAULT_SCRIPT_OUTPUT


# Parse script arguments
for i in "$@"
do
	case $i in
		-h|--help)
			display_help
			shift
			;;
		--version)
			display_version
			shift
			;;
		-a=*|--architecture=*)
			SCRIPT_ARCHITECTURE="${i#*=}"
			shift
			;;
		-o=*|--output=*)
			if [[ "${i#*=}" ]] ; then
				SCRIPT_OUTPUT="${i#*=}"
			fi
			shift
			;;
		*)
			# Unknown option
			;;
	esac
done


echo "Script settings:"
echo -e "\t SCRIPT_ARCHITECTURE \t\t = $SCRIPT_ARCHITECTURE"
echo -e "\t SCRIPT_OUTPUT \t\t\t = $SCRIPT_OUTPUT"


# Validate inputs
validate_architecture $SCRIPT_ARCHITECTURE


# Simulate the given binary file execution
# Parameters:
# 	$1 - the gdb command file
# 	$2 - the gdb target binary file
# 	$3 - the gdb output file
# 	$4 - the simulator output file
# 	$5 - the make log file
function simulate()
{
	echo "SIMULATING"

	local command_file=$1
	local target_file=$2
	local gdb_output_file=$3
	local simulator_output_file=$4
	local make_log_file=$5


	case $SCRIPT_ARCHITECTURE in
		$SCRIPT_ARCHITECTURE_PC)
			$PC_GDB -x $command_file $target_file &> $gdb_output_file &
			;;
		$SCRIPT_ARCHITECTURE_AVR)
			$SIMAVR_SIMULATOR -g -m atmega128 $target_file &> $simulator_output_file &
			$AVR_GDB -x $command_file &> $gdb_output_file

			jobs -l %'$SIMAVR_SIMULATOR'
			kill -PIPE %'$SIMAVR_SIMULATOR'
			;;
		$SCRIPT_ARCHITECTURE_MSP)
			$MSPDEBUG_SIMULATOR -n sim "prog $target_file" gdb &> $simulator_output_file &
			$MSP_GDB -x $command_file &> $gdb_output_file
			;;
		$SCRIPT_ARCHITECTURE_ARM)
			# Upload the program to the board
			make -f ./../../../common/cipher.mk ARCHITECTURE=$SCRIPT_ARCHITECTURE $target_file &> $make_log_file

			$JLINK_GDB_SERVER -USB -device cortex-m3 &> $simulator_output_file &
			$NRF52840_GDB -x $command_file &> $gdb_output_file

			jlink_gdb_server_pid=$(ps aux | grep "JLinkGDBServer" | grep -v "grep" | tr -s ' ' | cut -d ' ' -f 2)
			for pid in $jlink_gdb_server_pid
			do
				kill -PIPE $pid
			done
			;;
		$SCRIPT_ARCHITECTURE_NRF52840)
			# Upload the program to the board
			make -f ./../../../common/cipher.mk ARCHITECTURE=$SCRIPT_ARCHITECTURE $target_file &> $make_log_file

			$JLINK_GDB_SERVER -device NRF52840_XXAA -if SWD -speed 4000 &> $simulator_output_file &
			$NRF52840_GDB -x $command_file &> $gdb_output_file

			jlink_gdb_server_pid=$(ps aux | grep "JLinkGDBServer" | grep -v "grep" | tr -s ' ' | cut -d ' ' -f 2)
			for pid in $jlink_gdb_server_pid
			do
				kill -PIPE $pid
			done
			;;
		$SCRIPT_ARCHITECTURE_STM32L053)
			# Upload the program to the board
			make -f ./../../../common/cipher.mk ARCHITECTURE=$SCRIPT_ARCHITECTURE $target_file &> $make_log_file

			$STLINK_GDB_SERVER &> $simulator_output_file &
			$STM32L053_GDB -x $command_file &> $gdb_output_file

			stlink_gdb_server_pid=$(ps aux | grep "st-util" | grep -v "grep" | tr -s ' ' | cut -d ' ' -f 2)
			for pid in $stlink_gdb_server_pid
			do
				kill -PIPE $pid
			done
			;;
	esac

	# Wait for the debug session to finish
	sleep 1
}


# Compute the stack usage
# Parameters:
# 	$1 - the gdb output file
# 	$2 - the gdb printed variable name
function compute_stack_usage()
{
	local output_file=$1
	local variable_name=$2


	# Get the stack content array
	local stack_content=( $(cat $output_file | nawk '/\$'$variable_name' = {/,/}/' | tr -d '\r' | cut -d '{' -f 2 | cut -d '}' -f 1 | tr -d ',') ) 

	local count=0
	while [ $((${stack_content[$count]})) -eq $((${MEMORY_PATTERN[$(($count % $memory_patern_length))]})) ]
	do
		count=$(($count + 1));
	done

	local used_stack=$(($MEMORY_SIZE - $count))
	
	echo $used_stack
}


echo "Begin cipher RAM - $(pwd)"


# Get the state, key, round keys size
solve-define ()
(
    prog=/tmp/felics-$1
    gcc -I../../../common/ -I../source -x c -o $prog - <<EOF
#include <stdio.h>
#include <stdint.h>

#define PC 1
#define SCENARIO 1
#define SCENARIO_1 1

#include "constants.h"

int main()
{
    printf("%d\n", $1);
}
EOF
    $prog
    rm $prog
)

block_size=$(solve-define BLOCK_SIZE)
key_size=$(solve-define KEY_SIZE)

# Set the searched files pattern
pattern='*.o'

# Get the number of files matching the pattern
files_number=$(find . -maxdepth 1 -type f -name "$pattern" | wc -l)

if [ 0 -eq $files_number ] ; then
	echo "There is no file matching the pattern: '$pattern' for cipher '$cipher_name'!"
	exit 1
fi

# Get the files matching the pattern
files=$(ls $pattern)


files="felics_bench.elf $files"


# Set the size command depending on the architecture
case $SCRIPT_ARCHITECTURE in
	$SCRIPT_ARCHITECTURE_PC)
		script_size=$PC_SIZE	
		;;

	$SCRIPT_ARCHITECTURE_AVR)
		script_size=$AVR_SIZE
		;;

	$SCRIPT_ARCHITECTURE_MSP)
		script_size=$MSP_SIZE
		;;

	$SCRIPT_ARCHITECTURE_ARM)
		script_size=$ARM_SIZE
		;;

	$SCRIPT_ARCHITECTURE_NRF52840)
		script_size=$NRF52840_SIZE
		;;

	$SCRIPT_ARCHITECTURE_STM32L053)
		script_size=$STM32L053_SIZE
		;;
esac


for file in $files
do
	# Get the section sizes line for current file
	if [ -e $file ] ; then
		size=$($script_size $file | grep $file)
	else
		continue
	fi

	# Get the section data size
	data=$(echo $size | cut -d ' ' -f 2)
	
	# Get the component name (file name without the extension)
	component=${file%.*}

	declare $component"_data"=$data
done


shared_constants_e=0
shared_constants_d=0
shared_constants_total=0

# Read and process constants implementation information
declare -a shared_parts
for constants_section in ${CONSTANTS_SECTIONS[@]}
do
	shared_files=$(cat $IMPLEMENTATION_INFO_FILE | grep $constants_section$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 | tr ',' ' ')

	for shared_file in $shared_files
	do
		shared_name=$shared_file"_data"

		shared_value=${!shared_name}
		if [ "" == "$shared_value" ] ; then
			shared_value=0
		fi


		# Test if the shared file RAM was added to the total
		used_part=$FALSE
		for shared_part in ${shared_parts[@]}
		do
			if [ "$shared_part" == "$shared_file" ] ; then
				used_part=$TRUE
				break
			fi
		done

	
		# Add the shared file ROM to total
		if [ $FALSE -eq $used_part ]; then
			shared_constants_total=$(($shared_constants_total + $shared_value))
			shared_parts+=($shared_file) 
		fi
	
	
		case $constants_section in
			$CONSTANTS_SECTION_E)
				shared_constants_e=$(($shared_constants_e + $shared_value))
				;;
			$CONSTANTS_SECTION_D)
				shared_constants_d=$(($shared_constants_d + $shared_value))
				;;
		esac
	done
done


# Compute the data RAM
data_ram_e=$shared_constants_e
data_ram_d=$shared_constants_d

grep-define ()
{
    local var=$1
    local src=../../../common/felics/main_bench.c
    grep -E "^#define +${var} +[0-9]+$" ${src} | grep -Eo '[0-9]+'
}

data_size=$(grep-define DATA_SIZE)
associated_data_size=$(grep-define ASSOCIATED_DATA_SIZE)
data_ram_common=$(($key_size + $data_size + $associated_data_size))
data_ram_total=$(($data_ram_common + $shared_constants_total))


# Get the memory pattern length
memory_patern_length=$((${#MEMORY_PATTERN[@]}))

# Generate the memory file
memory_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MEMORY_FILE
echo "Generate the memory file: '$memory_file'"
echo -n "" > $memory_file

for ((i=0; i<$MEMORY_SIZE/$memory_patern_length; i++))
do
	echo -ne "$(printf '\\x%x\\x%x\\x%x\\x%x\\x%x\\x%x\\x%x\\x%x\\x%x\\x%x' ${MEMORY_PATTERN[*]})" >> $memory_file
done


# Get the cipher name
cipher_name=$(basename -- "$(dirname -- "$(pwd)")")


# Set the searched file pattern
file=felics_bench.elf
# Get the number of files matching the pattern
files_number=$(find . -maxdepth 1 -type f -name "$file" | wc -l)

if [ 0 -eq $files_number ] ; then
	echo "There is no file matching the pattern: '$file' for cipher '$cipher_name'!"
	exit 1
fi


gdb_stack_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$GDB_STACK_LOG_FILE
gdb_stack_sections_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$GDB_STACK_SECTIONS_LOG_FILE

# Debug the executable
case $SCRIPT_ARCHITECTURE in
	$SCRIPT_ARCHITECTURE_PC)

		simulate $PC_SCENARIO1_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file
		simulate $PC_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file
		;;

	$SCRIPT_ARCHITECTURE_AVR)

		simavr_stack_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$SIMAVR_STACK_LOG_FILE
		simavr_stack_sections_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$SIMAVR_STACK_SECTIONS_LOG_FILE

		simulate $AVR_SCENARIO1_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $simavr_stack_log_file
		simulate $AVR_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $simavr_stack_sections_log_file

		;;
	
	$SCRIPT_ARCHITECTURE_MSP)

		mspdebug_stack_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MSPDEBUG_STACK_LOG_FILE
		mspdebug_stack_sections_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MSPDEBUG_STACK_SECTIONS_LOG_FILE

		simulate $MSP_SCENARIO1_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $mspdebug_stack_log_file
		simulate $MSP_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $mspdebug_stack_sections_log_file
		;;

	$SCRIPT_ARCHITECTURE_ARM)

		make_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MAKE_LOG_FILE
		jlink_gdb_server_stack_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$JLINK_GDB_SERVER_STACK_LOG_FILE
		jlink_gdb_server_stack_sections_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$JLINK_GDB_SERVER_STACK_SECTIONS_LOG_FILE

		simulate $ARM_SCENARIO1_GDB_STACK_COMMANDS_FILE upload-bench $gdb_stack_log_file $jlink_gdb_server_stack_log_file $make_log_file
		simulate $ARM_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE upload-bench $gdb_stack_sections_log_file $jlink_gdb_server_stack_sections_log_file $make_log_file
		;;

	$SCRIPT_ARCHITECTURE_NRF52840)

		make_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MAKE_LOG_FILE
		jlink_gdb_server_stack_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$JLINK_GDB_SERVER_STACK_LOG_FILE
		jlink_gdb_server_stack_sections_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$JLINK_GDB_SERVER_STACK_SECTIONS_LOG_FILE

		simulate $NRF52840_SCENARIO1_GDB_STACK_COMMANDS_FILE upload-bench $gdb_stack_log_file $jlink_gdb_server_stack_log_file $make_log_file
		simulate $NRF52840_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE upload-bench $gdb_stack_sections_log_file $jlink_gdb_server_stack_sections_log_file $make_log_file
		;;

	$SCRIPT_ARCHITECTURE_STM32L053)

		make_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MAKE_LOG_FILE
		stlink_gdb_server_stack_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$STLINK_GDB_SERVER_STACK_LOG_FILE
		stlink_gdb_server_stack_sections_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$STLINK_GDB_SERVER_STACK_SECTIONS_LOG_FILE

		simulate $STM32L053_SCENARIO1_GDB_STACK_COMMANDS_FILE upload-bench $gdb_stack_log_file $stlink_gdb_server_stack_log_file $make_log_file
		simulate $STM32L053_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE upload-bench $gdb_stack_sections_log_file $stlink_gdb_server_stack_sections_log_file $make_log_file
		;;
esac


e_stack=0
d_stack=0
total_stack=0

if [ -f $gdb_stack_log_file ] ; then
	total_stack=$(compute_stack_usage $gdb_stack_log_file 1)
fi

if [ -f $gdb_stack_sections_log_file ] ; then
	e_stack=$(compute_stack_usage $gdb_stack_sections_log_file 1)
	d_stack=$(compute_stack_usage $gdb_stack_sections_log_file 2)
fi


# Display results
printf "%s %s %s %s %s %s" $e_stack $d_stack $data_ram_e $data_ram_d $data_ram_common $data_ram_total > $SCRIPT_OUTPUT
	

echo ""
echo "End cipher RAM - $(pwd)"
