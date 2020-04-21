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
# Call this script to extract the cipher code size
# 	./cipher_code_size.sh [{-a|--architecture}=[PC|AVR|MSP|ARM]] [{-o|--output}=[...]]
#
#	To call from a cipher build folder use:
#		./../../../../scripts/cipher/cipher_code_size.sh [options]
#
#	Options:
#		-a, --architecture
#			Specifies which architecture to build for
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

set -eu

# Get current script path
script_path=$(dirname $0)

# Include constants files
source $script_path/../constants/constants.sh


# Default values
SCRIPT_ARCHITECTURE=$SCRIPT_ARCHITECTURE_PC
SCRIPT_OUTPUT=$DEFAULT_SCRIPT_OUTPUT


# Parse script arguments
for i in "$@"
do
	case $i in
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


echo "Begin cipher code size - $(pwd)"


# Get the cipher name
cipher_name=$(basename -- "$(dirname -- "$(pwd)")")


# Set the searched files pattern
pattern='*.o'

# Get the number of files matching the pattern
files_number=$(find . -maxdepth 1 -type f -name "$pattern" | wc -l)

if [ 0 -eq $files_number ] ; then
	echo "There is no file matching the pattern: '$pattern' for cipher '$cipher_name'!"
	exit 1
fi

for file in ${pattern}
do
	size=$(size $file | grep $file)

	# Get the section sizes
	text=$(echo $size | cut -d ' ' -f 1)
	data=$(echo $size | cut -d ' ' -f 2)

	# Compute the ROM requirement	
	rom=$(($text + $data))

	# Get the component name (file name without the extension)
	component=${file%.o}

	# Set the component ROM requirement
	declare $component"_rom"=$rom
done


cipher_e=0
cipher_d=0
cipher_total=0

# Read and process code implementation information
declare -a shared_parts
for code_section in EncryptCode DecryptCode
do
    shared_files=$(cat ../source/implementation.info | grep "$code_section:" | cut -d ':' -f 2 | tr ',' ' ')

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
	    cipher_total=$(($cipher_total + $shared_value))
	    shared_parts+=($shared_file) 
	fi
	
	
	case $code_section in
	    EncryptCode)
		cipher_e=$(($cipher_e + $shared_value))
		;;
	    DecryptCode)
		cipher_d=$(($cipher_d + $shared_value))
		;;
	esac
    done
done


printf "%s %s %s" $cipher_e $cipher_d $cipher_total > $SCRIPT_OUTPUT


echo ""
echo "End cipher code size - $(pwd)"
