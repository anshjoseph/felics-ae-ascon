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
# Call this script to collect the ciphers metrics
# 	./collect_ciphers_metrics.sh [{-h|--help}] [{-a|--architectures}=['PC AVR MSP ARM']] [{-c|--ciphers}=['Cipher1 Cipher2 ...']] [{-co|--compiler_options}='...']
#
#	Options:
#		-h, --help
#			Display help information
#		-a, --architectures
#			Specifies for which archiectures to collect ciphers metrics
#				List of values: 'PC AVR MSP ARM'
#				Default: all architectures
#		-c, --ciphers
#			Specifies for which ciphers to collect the metrics
#				List of values: 'CipherName_BlockSizeInBits_KeySizeInBits_v01 ...'
#				Default: all ciphers
#		-co,--compiler_options
#			Specifies the compiler options
#				List of values: '-O3 --param max-unroll-times=5 --param max-unrolled-insns=100 ...'
#				Default: all compiler options
#
#	Examples:
#		./collect_ciphers_metrics.sh -a='PC AVR'
#

set -e

# Get current script path
script_path=$(dirname $0)

# Include constants files
source $script_path/constants/constants.sh

# Include help file
source $script_path/help/collect_ciphers_metrics.sh


# Parse script arguments
for i in "$@"
do
	case $i in
		-h|--help)
			display_help
			shift
			;;
		-a=*|--architectures=*)
			SCRIPT_USER_ARCHITECTURES="${i#*=}"
			shift
			;;
		-c=*|--ciphers=*)
			SCRIPT_USER_CIPHERS="${i#*=}"
			shift
			;;
		-co=*|--compiler_options=*)
			SCRIPT_USER_COMPILER_OPTIONS="${i#*=}"
			shift
			;;
		-j=*|--json-output=*)
			SCRIPT_JSON_OUTPUT="${i#*=}"
			shift
			;;
		*)
			# Unknown option
			;;
	esac
done


# Include output format
source ${script_path}/formats/json.sh


# Change current directory to script source path directory
if [ '.' != $script_path ] ; then
	cd $script_path
fi


# Set the current working directory
current_directory=$(pwd)
echo "Begin collect ciphers metrics - $current_directory"


# Change current working directory
cd "${current_directory}"/../source/ciphers
echo "Changed working directory: $(pwd)"
echo ""


# Get the number of directories
directories_number=$(find . -maxdepth 1 -type d | wc -l)

if [ 0 -eq $directories_number ] ; then
	echo "There is no directory here: '$(pwd)'!"
	echo "Exit!"
	exit
fi

# Get the files matching the pattern
ciphers_directories=$(ls -d *)


# If user architectures are not set, use all architectures
if [ -n "$SCRIPT_USER_ARCHITECTURES" ]; then
	architectures=$SCRIPT_USER_ARCHITECTURES
else
	architectures=(${SCRIPT_ARCHITECTURES[@]})
fi

# If user ciphers are not set, use all ciphers
if [ -n "$SCRIPT_USER_CIPHERS" ]; then
	declare -a directories
	for cipher in $SCRIPT_USER_CIPHERS
	do
		cipher_found=$FALSE
		for cipher_directory in $ciphers_directories
		do
			if [ $cipher == $cipher_directory ] ; then
				directories+=($cipher_directory)
				cipher_found=$TRUE
				break
			fi
		done
		if [ $FALSE == $cipher_found ] ; then
			echo "Unknown cipher '$cipher'!"
			exit 1
		fi
	done
else
	directories=$ciphers_directories
fi

# If user compiler options are not set, use all compiler options
if [ -n "$SCRIPT_USER_COMPILER_OPTIONS" ]; then
	user_compiler_options="${SCRIPT_USER_COMPILER_OPTIONS[@]}"
	compiler_options=()

	OLD_IFS=$IFS
	IFS=";"
	for user_compiler_option in ${user_compiler_options[@]}
	do
		compiler_option=$(echo -e "${user_compiler_option}" | sed -e 's/^[[:space:]]*//')
		compiler_options+=("$compiler_option")
	done
	IFS=$OLD_IFS
else
	compiler_options=("${SCRIPT_COMPILER_OPTIONS[@]}")
fi


results_dir="${current_directory}"/../results
script_json_output="${results_dir}/${SCRIPT_JSON_OUTPUT}"

add_json_table_header "${script_json_output}"


skip-setup ()
{
	local implem_info=$1
	local key=$2
	local value=$3

	if ! grep -q "^${key}:" ${implem_info}
	then
		# No restriction for this implementation. Do not skip.
		return 1
	fi

	# Skip if the value is not listed explicitly.
	! grep -q "^${key}:.*${value}" ${implem_info}
}

needs-cycle-count-instrumentation ()
{
    local arch=$1
    test ${arch} = ARM -o                       \
         ${arch} = PC -o                        \
         ${arch} = NRF52840 -o                  \
         ${arch} = STM32L053
}

make-bench ()
{
    local log_file=$1
    shift

    if ! make -f ${CIPHER_MAKEFILE} clean &> ${log_file}
    then
        cat ${log_file}
        return 1
    fi

    if ! make -f ${CIPHER_MAKEFILE} SCENARIO=1 "$@" &> ${log_file}
    then
        cat ${log_file}
        return 1
    fi
}

run-benchmark ()
{
    local cipher_name=$1
    local version=$2
    local architecture=$3
    local options=$4

    echo "Run for cipher '${cipher_name}':"
    echo -e "\t IMPLEMENTATION_VERSION = ${version}"
    echo -e "\t ARCHITECTURE = ${architecture}"
    echo -e "\t COMPILER_OPTIONS = ${options}"
    echo ""

    timeout 120 ${script_path}/cipher/check_cipher.sh \
            -a=${architecture} -co="${options}"

    local options_part=${options// /_}
    local output_base="${architecture}_bench_${options// /_}"
    local code_size_output=${output_base}_code_size.log
    local code_ram_output=${output_base}_code_ram.log
    local code_time_output=${output_base}_code_time.log

    make-bench ${output_base}_make_bench.log    \
               ARCHITECTURE=${architecture}     \
               COMPILER_OPTIONS="${options}"

    timeout 120 ${script_path}/cipher/cipher_code_size.sh \
            "-a=$architecture" -o=$code_size_output

    timeout 120 ${script_path}/cipher/cipher_ram.sh \
            "-a=$architecture" -o=$code_ram_output

    if needs-cycle-count-instrumentation ${architecture}
    then
        make-bench ${output_base}_make_bench_time.log   \
                   MEASURE_CYCLE_COUNT=1                \
                   ARCHITECTURE=${architecture}         \
                   COMPILER_OPTIONS="${options}" 
    fi

    timeout 120 ${script_path}/cipher/cipher_execution_time.sh \
            "-a=$architecture" -o=$code_time_output

    add_json_table_row "${script_json_output}" ${architecture} ${cipher_name}                                               \
                       ${version} "${options}"                                                                              \
                       "${code_size_output}" "${code_ram_output}" "${code_time_output}"

}


for architecture in ${architectures[@]}
do
	echo -e "\t\t\t ---> Architecture: $architecture"

		for directory in ${directories[@]}
		do
			if skip-setup ${directory}/source/implementation.info Platforms ${architecture}
			then
				echo "${directory}: skipping for ${architecture}..."
				continue
			fi

			cd $directory/build

			echo -e "\t\t\t\t\t ---> Cipher: $directory"

			# Get the cipher name
			cipher_directory_name=$(basename -- "$(dirname -- "$(pwd)")")

			cipher_name=$(echo $cipher_directory_name | cut -d $DIRECTORY_NAME_SEPARATOR -f 1)
			cipher_implementation_version=$(echo $cipher_directory_name | cut -d $DIRECTORY_NAME_SEPARATOR -f 2)
			cipher_implementation_version=${cipher_implementation_version:1:${#cipher_implementation_version}-1}

			if [ $EXAMPLE_CIPHER_NAME == $cipher_name ] ; then
				cd ./../../
				continue
			fi

			for compiler_option in "${compiler_options[@]}"
			do
				if skip-setup ../source/implementation.info Options "${compiler_option}"
				then
					echo "${directory}: skipping for ${compiler_option}..."
					continue
				fi

				run-benchmark "${cipher_name}" "${cipher_implementation_version}" "${architecture}" "${compiler_option}"
			done

			cd ./../../
		done

done


add_json_table_footer "${script_json_output}"


# Change current working directory
cd $current_directory
echo "End collect ciphers metrics - $(pwd)"
