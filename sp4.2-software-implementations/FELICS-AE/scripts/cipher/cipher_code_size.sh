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
# Call this script to extract the cipher code size
# 	./cipher_code_size.sh [{-h|--help}] [--version] [{-a|--architecture}=[PC|AVR|MSP|ARM]] [{-o|--output}=[...]]
#
#	To call from a cipher build folder use:
#		./../../../../scripts/cipher/cipher_code_size.sh [options]
#
#	Options:
#		-h, --help
#			Display help information
#		--version
#			Display version information
#		-a, --architecture
#			Specifies which architecture is used
#				PC - binary files are build for PC
#				AVR - binary files are build for AVR device
#				MSP - binary file are build for MSP device
#				ARM - binary files are build for ARM device
#				NRF52840 - binary files are build for NRF52840 device
#				Default: PC
#		-o, --output
#			Specifies where to output the results. The relative path is computed from the directory where script was called
#				Default: /dev/tty
#
#	Examples:
#		./../../../../scripts/cipher/cipher_code_size.sh0
#		./../../../../scripts/cipher/cipher_code_size.sh --architecture=MSP
#  		./../../../../scripts/cipher/cipher_code_size.sh -o=results.txt
#


# Get current script path
script_path=$(dirname $0)

# Include configuration file
source $script_path/../config/config.sh

# Include constants files
source $script_path/../constants/constants.sh

# Include help file
source $script_path/../help/cipher/cipher_code_size.sh

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


echo "Begin cipher code size - $(pwd)"


# Get the cipher name
cipher_name=$(basename -- "$(dirname -- "$(pwd)")")


# Set the searched files pattern
pattern=$ALL_FILES$OBJECT_FILE_EXTENSION 

# Get the number of files matching the pattern
files_number=$(find . -maxdepth 1 -type f -name "$pattern" | wc -l)

if [ 0 -eq $files_number ] ; then
	echo "There is no file matching the pattern: '$pattern' for cipher '$cipher_name'!"
	exit 1
fi

# Get the files matching the pattern
files=$(ls $pattern)


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
esac


for file in $files
do
	size=$($script_size $file | grep $file)

	# Get the section sizes
	text=$(echo $size | cut -d ' ' -f 1)
	data=$(echo $size | cut -d ' ' -f 2)

	# Compute the ROM requirement	
	rom=$(($text + $data))

	# Get the component name (file name without the extension)
	component=${file%$OBJECT_FILE_EXTENSION}

	# Set the component ROM requirement
	declare $component"_rom"=$rom
done


shared_code_e=0
shared_code_d=0
shared_code_total=0

# Read and process code implementation information
declare -a shared_parts
for code_section in ${CODE_SECTIONS[@]}
do
    shared_files=$(cat $IMPLEMENTATION_INFO_FILE | grep $code_section$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 | tr ',' ' ')

    for shared_file in $shared_files
    do
	shared_name=$shared_file"_rom"

	shared_value=${!shared_name}
	if [ "" == "$shared_value" ] ; then
	    echo "Error: unknown component $shared_file"
	    exit 1
	fi


	# Test if the shared file ROM was added to the total
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
	    shared_code_total=$(($shared_code_total + $shared_value))
	    shared_parts+=($shared_file) 
	fi
	
	
	case $code_section in
	    $CODE_SECTION_E)
		shared_code_e=$(($shared_code_e + $shared_value))
		;;
	    $CODE_SECTION_D)
		shared_code_d=$(($shared_code_d + $shared_value))
		;;
	esac
    done
done


# Cipher
cipher_e=$(($encrypt_rom + $shared_code_e))
cipher_d=$(($decrypt_rom + $shared_code_d))
cipher_total=$(($encrypt_rom + $decrypt_rom + $shared_code_total))

# Scenario 1
scenario1_e=$(($cipher_e))
scenario1_d=$(($cipher_d))
scenario1_total=$(($cipher_total))


# Display results
printf "%s %s %s" $scenario1_e $scenario1_d $scenario1_total > $SCRIPT_OUTPUT


echo ""
echo "End cipher code size - $(pwd)"
