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
# Call this script to extract the cipher execution time
# 	./cipher_execution_time.sh [{-a|--architecture}=[PC|AVR|MSP|ARM]] [{-o|--output}=[...]]
#
#	To call from a cipher build folder use:
#		./../../../../scripts/cipher/cipher_execution_time.sh [options]
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
#		./../../../../scripts/cipher_execution_time.sh
#		./../../../../scripts/cipher_execution_time.sh --architecture=MSP
#  		./../../../../scripts/cipher_execution_time.sh -o=results.txt
#

set -e

# Get current script path
script_path=$(dirname $0)

# Include configuration file
source $script_path/../config.sh

# Include constants files
source $script_path/../constants/constants.sh
source $script_path/../constants/cipher/cipher_execution_time.sh


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


function mean ()
{
    let total=0
    let n=0

    while read i
    do
        let total+=i
        let n++
    done

    echo $((total/n))
}

function median ()
{
    local n=$1

    if ((n%2 == 1))
    then
        head -$((n/2+1)) | tail -1
    else
        head -$((n/2+1)) | tail -2 | mean
    fi
}

compute-file-median ()
{
    local samples_file=$1
    local medians_file=$2

    local keys=(
        EncryptCycleCount
        DecryptCycleCount
    )

    local samples_nb=$(grep -c ${keys[0]} ${samples_file})
    local key

    > ${medians_file}

    for key in ${keys[@]}
    do
        median=$(
            grep ${key} ${samples_file} |
            cut -d' ' -f2               |
            sort -n                     |
            median ${samples_nb}
        )

        echo "${key}: ${median}" >> ${medians_file}
    done
}

try-cpufreq-set ()
{
    local governor=$1

    if ! command -v cpufreq-set > /dev/null
    then
        return 1
    fi

    sudo -n cpufreq-set -c ${PC_EXECUTION_TIME_CPU} -g ${governor}
}

set-cpu-governor ()
{
    local governor=$1

    if ! try-cpufreq-set ${governor} && [ ${governor} = performance ]
    then
        cat <<EOF
Cannot set CPU governor to "performance".
Execution time measurements may suffer from increased jitter.
See documentation/setup.md for instructions on setting up cpufrequtils.
EOF
    fi
}


# Simulate the given binary file execution
# Parameters:
# 	$1 - the target binary file or the commands file
#	$2 - the simulator output file
#	$3 - the make log file
#	$4 - the make target
function simulate()
{
	local target_file=$1
	local output_file=$2
	local make_log_file=$3
	local make_target=$4


	case $SCRIPT_ARCHITECTURE in
		$SCRIPT_ARCHITECTURE_PC)
            local samples=$output_file.samples
            > $samples

            set-cpu-governor performance

            for i in {1..1000}
            do
                taskset -c $PC_EXECUTION_TIME_CPU $target_file >> $samples
            done

            set-cpu-governor powersave

            compute-file-median $samples $output_file
			;;
		$SCRIPT_ARCHITECTURE_AVR)
			$AVRORA_SIMULATOR -arch=avr -mcmu=atmega128 -input=elf -monitors=calls -seconds=5 -colors=false $target_file > $output_file
			;;
		$SCRIPT_ARCHITECTURE_MSP)
			$MSPDEBUG_SIMULATOR -n sim < $target_file &> $output_file
			;;
		$SCRIPT_ARCHITECTURE_ARM)
			make -f $CIPHER_MAKEFILE ARCHITECTURE=$SCRIPT_ARCHITECTURE $make_target &> $make_log_file
			# Run the program stored in the flash memory of the board
			$ARM_SERIAL_TERMINAL > $output_file
			;;
		$SCRIPT_ARCHITECTURE_NRF52840)
			make -f $CIPHER_MAKEFILE ARCHITECTURE=$SCRIPT_ARCHITECTURE $make_target &> $make_log_file
			# Run the program stored in the flash memory of the board
			make -f $CIPHER_MAKEFILE ARCHITECTURE=$SCRIPT_ARCHITECTURE run > $output_file
			;;
		$SCRIPT_ARCHITECTURE_STM32L053)
			make -f $CIPHER_MAKEFILE ARCHITECTURE=$SCRIPT_ARCHITECTURE $make_target &> $make_log_file
			# Run the program stored in the flash memory of the board
			make -f $CIPHER_MAKEFILE ARCHITECTURE=$SCRIPT_ARCHITECTURE run > $output_file
			;;
	esac
}


# Compute the execution time
# Parameters:
# 	$1 - the simulator output file
# 	$2 - the execution time (cycle count) first row identifier
# 	$3 - the execution time (cycle count) second row identifier
function compute_execution_time()
{
	local output_file=$1
	local first_row_identifier=$2
	local second_row_identifier=$3


	case $SCRIPT_ARCHITECTURE in
		$SCRIPT_ARCHITECTURE_PC)
			local cycle_count=$(cat $output_file | grep $first_row_identifier | tr -d '\r' | cut -d ':' -f 2)
			echo $cycle_count
			;;
		$SCRIPT_ARCHITECTURE_AVR)
			local initial_value=$(cat $output_file | grep -e "--(CALL)-> $first_row_identifier" | grep "$first_row_identifier$" | tr -d '\r' | tr -s ' ' | cut -d ' ' -f 3)

			local final_value
			if [ -z $second_row_identifier ] ; then
				final_value=$(cat $output_file | grep -e "<-(RET )--" | tail -1 | tr -d '\r' | tr -s ' ' | cut -d ' ' -f 3)
			else
				final_value=$(cat $output_file | grep -e "--(CALL)-> $second_row_identifier" | grep "$second_row_identifier$" | tr -d '\r' | tr -s ' ' | cut -d ' ' -f 3)
			fi

			if [ -z $final_value ] ; then
				final_value=$(cat $output_file | grep -e "<-(RET )--" | tail -1 | tr -d '\r' | tr -s ' ' | cut -d ' ' -f 3)
			fi

			local cycle_count=$(($final_value - $initial_value))
			echo $cycle_count
			;;
		$SCRIPT_ARCHITECTURE_MSP)
			local mclk_initial_value=$(cat $output_file | grep "MCLK:" | head -n $first_row_identifier | tail -n 1 | tr -d '\r' | cut -d ':' -f 2)
			local mclk_final_value=$(cat $output_file | grep "MCLK:" | head -n $(($first_row_identifier + 1)) | tail -n 1 | tr -d '\r' | cut -d ':' -f 2)

			local cycle_count=$(($mclk_final_value - $mclk_initial_value))
			echo $cycle_count
			;;
		$SCRIPT_ARCHITECTURE_ARM)
			local cycle_count=$(cat $output_file | grep $first_row_identifier | tr -d '\r' | cut -d ':' -f 2)
			echo $cycle_count
			;;
		$SCRIPT_ARCHITECTURE_NRF52840)
			local cycle_count=$(cat $output_file | grep -a $first_row_identifier | tr -d '\r' | cut -d ':' -f 2)
			echo $cycle_count
			;;
		$SCRIPT_ARCHITECTURE_STM32L053)
			local cycle_count=$(cat $output_file | grep -a $first_row_identifier | tr -d '\r' | cut -d ':' -f 2)
			echo $cycle_count
			;;
	esac
}


echo "Begin cipher execution time - $(pwd)"


# Get the cipher name
cipher_name=$(basename -- "$(dirname -- "$(pwd)")")


file=./felics_bench.elf

if ! test -f ${file}
then
    echo "Cannot find ${file} for cipher '${cipher_name}."
    exit 1
fi


eks_execution_time=0
e_execution_time=0
dks_execution_time=0
d_execution_time=0
total_execution_time=0

# Debug the executable
case $SCRIPT_ARCHITECTURE in
	$SCRIPT_ARCHITECTURE_PC)

		make_log_file=$SCRIPT_ARCHITECTURE$FILE_NAME_SEPARATOR$MAKE_LOG_FILE
		pc_output_file=$SCRIPT_ARCHITECTURE$FILE_NAME_SEPARATOR$PC_OUTPUT_FILE

		simulate $file $pc_output_file $make_log_file

		if [ -f $pc_output_file ] ; then
			e_execution_time=$(compute_execution_time $pc_output_file 'EncryptCycleCount')
			d_execution_time=$(compute_execution_time $pc_output_file 'DecryptCycleCount')
		fi
		;;

	$SCRIPT_ARCHITECTURE_AVR)

		avr_execution_time_log_file=$SCRIPT_ARCHITECTURE$FILE_NAME_SEPARATOR$AVR_EXECUTION_TIME_LOG_FILE		

		simulate $file $avr_execution_time_log_file

		if [ -f $avr_execution_time_log_file ] ; then
			e_execution_time=$(compute_execution_time $avr_execution_time_log_file 'crypto_aead_encrypt' 'EndEncryption')
			d_execution_time=$(compute_execution_time $avr_execution_time_log_file 'crypto_aead_decrypt' 'EndDecryption')
		fi
	
		if [ -f $avr_execution_time_log_file ] ; then
			total_execution_time=$(compute_execution_time $avr_execution_time_log_file 'main')
		fi
		;;

	$SCRIPT_ARCHITECTURE_MSP)

		mspdebug_execution_time_log_file=$SCRIPT_ARCHITECTURE$FILE_NAME_SEPARATOR$MSPDEBUG_EXECUTION_TIME_LOG_FILE
		mspdebug_execution_time_sections_log_file=$SCRIPT_ARCHITECTURE$FILE_NAME_SEPARATOR$MSPDEBUG_EXECUTION_TIME_SECTIONS_LOG_FILE

		commands_dir=../../../../scripts/plumbing/cipher/execution_time

		simulate ${commands_dir}/msp_execution_time.cmd $mspdebug_execution_time_log_file
		simulate ${commands_dir}/msp_execution_time_sections.cmd $mspdebug_execution_time_sections_log_file

		if [ -f $mspdebug_execution_time_log_file ] ; then
			e_execution_time=$(compute_execution_time $mspdebug_execution_time_sections_log_file 1)
			d_execution_time=$(compute_execution_time $mspdebug_execution_time_sections_log_file 3)
		fi

		if [ -f $mspdebug_execution_time_log_file ] ; then
			total_execution_time=$(compute_execution_time $mspdebug_execution_time_log_file 1)
		fi
		;;

	$SCRIPT_ARCHITECTURE_ARM)

		make_log_file=$SCRIPT_ARCHITECTURE$FILE_NAME_SEPARATOR$MAKE_LOG_FILE
		arm_serial_terminal_output_file=$SCRIPT_ARCHITECTURE$FILE_NAME_SEPARATOR$ARM_SERIAL_TERMINAL_OUTPUT_FILE

		simulate $file $arm_serial_terminal_output_file $make_log_file upload-bench

		if [ -f $arm_serial_terminal_output_file ] ; then
			e_execution_time=$(compute_execution_time $arm_serial_terminal_output_file 'EncryptCycleCount')
			d_execution_time=$(compute_execution_time $arm_serial_terminal_output_file 'DecryptCycleCount')
		fi
		;;

	$SCRIPT_ARCHITECTURE_NRF52840)

		make_log_file=$SCRIPT_ARCHITECTURE$FILE_NAME_SEPARATOR$MAKE_LOG_FILE
		nrf52840_serial_terminal_output_file=$SCRIPT_ARCHITECTURE$FILE_NAME_SEPARATOR$NRF52840_SERIAL_TERMINAL_OUTPUT_FILE

		simulate $file $nrf52840_serial_terminal_output_file $make_log_file upload-bench

		if [ -f $nrf52840_serial_terminal_output_file ] ; then
			e_execution_time=$(compute_execution_time $nrf52840_serial_terminal_output_file 'EncryptCycleCount')
			d_execution_time=$(compute_execution_time $nrf52840_serial_terminal_output_file 'DecryptCycleCount')
		fi
		;;

	$SCRIPT_ARCHITECTURE_STM32L053)

		make_log_file=$SCRIPT_ARCHITECTURE$FILE_NAME_SEPARATOR$MAKE_LOG_FILE
		stm32l053_serial_terminal_output_file=$SCRIPT_ARCHITECTURE$FILE_NAME_SEPARATOR$STM32L053_SERIAL_TERMINAL_OUTPUT_FILE

		simulate $file $stm32l053_serial_terminal_output_file $make_log_file upload-bench

		if [ -f $stm32l053_serial_terminal_output_file ] ; then
			e_execution_time=$(compute_execution_time $stm32l053_serial_terminal_output_file 'EncryptCycleCount')
			d_execution_time=$(compute_execution_time $stm32l053_serial_terminal_output_file 'DecryptCycleCount')
		fi
		;;
esac


# Dipslay results
printf "%s %s" $e_execution_time $d_execution_time > $SCRIPT_OUTPUT


echo ""
echo "End cipher execution time - $(pwd)"
