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
# Call this script to collect the ciphers metrics
# 	./collect_ciphers_metrics.sh [{-h|--help}] [--version] [{-a|--architectures}=['PC AVR MSP ARM']] [{-c|--ciphers}=['Cipher1 Cipher2 ...']] [{-co|--compiler_options}='...']
#
#	Options:
#		-h, --help
#			Display help information
#		--version
#			Display version information
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


# Get current script path
script_path=$(dirname $0)

# Include constants files
source $script_path/constants/constants.sh
source $script_path/constants/collect_ciphers_metrics.sh

# Include help file
source $script_path/help/collect_ciphers_metrics.sh

# Include validation functions
source $script_path/common/validate.sh

# Include check status function
source $script_path/common/check_status.sh

# Include version file
source $script_path/common/version.sh


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
cd $current_directory/$CIPHERS_PATH
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

# TODO: remove scenario management from other scripts
scenario=1

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


# Validate architectures
for architecture in $architectures
do
	validate_architecture $architecture
done


results_dir="${current_directory}/${SCRIPT_OUTPUT_PATH}"
script_json_output="${results_dir}${SCRIPT_JSON_OUTPUT}"

add_json_table_header "${script_json_output}"


for architecture in ${architectures[@]}
do
	echo -e "\t\t\t ---> Architecture: $architecture"

	if [ ${architecture} = PC ] && [ $(cat /sys/devices/system/cpu/cpu$PC_EXECUTION_TIME_CPU/cpufreq/scaling_governor) = powersave ]
	then
		echo '"powersave" CPU governor yields unreliable results.'
		exit 1
	fi

		for directory in ${directories[@]}
		do
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
				echo "Run for cipher '$cipher_name':"
				echo -e "\t IMPLEMENTATION_VERSION = $cipher_implementation_version"
				echo -e "\t ARCHITECTURE = $architecture"
				echo -e "\t COMPILER_OPTIONS = $compiler_option"
				echo ""


				compiler_option_name=${compiler_option// /_}

				check_cipher_output_file=$architecture$COMPILER_OPTIONS_NAME_PART$compiler_option_name$FILE_NAME_SEPARATOR$CHECK_CIPHER_OUTPUT_FILE
				check_cipher_error_file=$architecture$COMPILER_OPTIONS_NAME_PART$compiler_option_name$FILE_NAME_SEPARATOR$CHECK_CIPHER_ERROR_FILE

				# Remove log file
				rm -f $check_cipher_output_file

				# Clear error file
				echo "" > $check_cipher_error_file

				# Check cipher
				timeout $CHECK_CIPHER_TIMEOUT ./../../../../scripts/cipher/check_cipher.sh -a=$architecture -c=$cipher_directory_name "-co=$compiler_option" -m=$CIPHER_SCRIPT_MODE -o=$check_cipher_output_file 2> $check_cipher_error_file
				if [ ! -f $check_cipher_output_file ] ; then
					echo "missing output file $check_cipher_output_file"
					exit 1
				fi
				if [ -f $check_cipher_error_file ] ; then
					check_cipher_errors=$(cat $check_cipher_error_file)
				fi
				if [ "" != "$check_cipher_errors" ] ; then
					echo "$check_cipher_errors"
					exit 1
				fi

				check_cipher_result=$(cat $check_cipher_output_file)
				if [ $FALSE -eq $check_cipher_result ] ; then
					echo "check_cipher failed"
					exit 1
				fi


				cipher_code_size_output_file=$architecture$SCENARIO_NAME_PART$scenario$COMPILER_OPTIONS_NAME_PART$compiler_option_name$FILE_NAME_SEPARATOR$CIPHER_CODE_SIZE_OUTPUT_FILE
				cipher_ram_output_file=$architecture$SCENARIO_NAME_PART$scenario$COMPILER_OPTIONS_NAME_PART$compiler_option_name$FILE_NAME_SEPARATOR$CIPHER_RAM_OUTPUT_FILE
				cipher_execution_time_output_file=$architecture$SCENARIO_NAME_PART$scenario$COMPILER_OPTIONS_NAME_PART$compiler_option_name$FILE_NAME_SEPARATOR$CIPHER_EXECUTION_TIME_OUTPUT_FILE

				cipher_code_size_error_file=$architecture$SCENARIO_NAME_PART$scenario$COMPILER_OPTIONS_NAME_PART$compiler_option_name$FILE_NAME_SEPARATOR$CIPHER_CODE_SIZE_ERROR_FILE
				cipher_ram_error_file=$architecture$SCENARIO_NAME_PART$scenario$COMPILER_OPTIONS_NAME_PART$compiler_option_name$FILE_NAME_SEPARATOR$CIPHER_RAM_ERROR_FILE
				cipher_execution_time_error_file=$architecture$SCENARIO_NAME_PART$scenario$COMPILER_OPTIONS_NAME_PART$compiler_option_name$FILE_NAME_SEPARATOR$CIPHER_EXECUTION_TIME_ERROR_FILE

				# Remove log files
				rm -f $cipher_code_size_output_file
				rm -f $cipher_ram_output_file
				rm -f $cipher_execution_time_output_file

				# Clear error files
				echo "" > $cipher_code_size_error_file
				echo "" > $cipher_ram_error_file
				echo "" > $cipher_execution_time_error_file


				# Code size
				timeout $CIPHER_CODE_SIZE_TIMEOUT ./../../../../scripts/cipher/cipher_code_size.sh "-s=$scenario" "-a=$architecture" "-m=$CIPHER_SCRIPT_MODE" "-co=$compiler_option" -o=$cipher_code_size_output_file 2> $cipher_code_size_error_file
				if [ ! -f $cipher_code_size_output_file ] ; then
					continue
				fi
				if [ -f $cipher_code_size_error_file ] ; then
					cipher_code_size_errors=$(cat $cipher_code_size_error_file)
				fi
				if [ "" != "$cipher_code_size_errors" ] ; then
					echo "$cipher_code_size_errors"
					exit 1
				fi


				# RAM
				timeout $CIPHER_RAM_TIMEOUT ./../../../../scripts/cipher/cipher_ram.sh "-s=$scenario" "-a=$architecture" "-m=$CIPHER_SCRIPT_MODE" "-co=$compiler_option" -o=$cipher_ram_output_file 2> $cipher_ram_error_file
				if [ ! -f $cipher_ram_output_file ] ; then
					echo "NO OUTPUT $cipher_ram_output_file"
					continue
				fi
				if [ -f $cipher_ram_error_file ] ; then
					cipher_ram_errors=$(cat $cipher_ram_error_file)
				fi
				if [ "" != "$cipher_ram_errors" ] ; then
					echo "CIPHER RAM ERRORS: $cipher_ram_error_file ; $cipher_ram_errors"
					exit 1
				fi


				# Execution time
				timeout $CIPHER_EXECUTION_TIME_TIMEOUT ./../../../../scripts/cipher/cipher_execution_time.sh "-s=$scenario" "-a=$architecture" "-m=$CIPHER_SCRIPT_MODE" "-co=$compiler_option" -o=$cipher_execution_time_output_file 2> $cipher_execution_time_error_file
				if [ ! -f $cipher_execution_time_output_file ] ; then
					continue
				fi
				if [ -f $cipher_execution_time_error_file ] ; then
					cipher_execution_time_errors=$(cat $cipher_execution_time_error_file)
				fi
				if [ "" != "$cipher_execution_time_errors" ] ; then
					echo "$cipher_execution_time_errors"
					exit 1
				fi

				add_json_table_row "${script_json_output}" ${architecture} ${cipher_name} ${cipher_implementation_version} "${compiler_option}" \
					"${cipher_code_size_output_file}" "${cipher_ram_output_file}" "${cipher_execution_time_output_file}"

				if [ $FALSE -eq $KEEP_GENERATED_FILES ] ; then
					# Remove generated files
					rm -f $check_cipher_output_file
					rm -f $cipher_code_size_output_file
					rm -f $cipher_ram_output_file
					rm -f $cipher_execution_time_output_file

					rm -f $check_cipher_error_file
					rm -f $cipher_code_size_error_file
					rm -f $cipher_ram_error_file
					rm -f $cipher_execution_time_error_file
				fi
			done


			cd ./../../
		done

done


add_json_table_footer "${script_json_output}"


# Change current working directory
cd $current_directory
echo "End collect ciphers metrics - $(pwd)"
