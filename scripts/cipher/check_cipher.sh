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
# Call this script to check if the cipher implementation is compliant with the framework
#     ./check_cipher.sh [{-h|--help}] [--version] [{-a|--architecture}=[PC|AVR|MSP|ARM|NRF52840]] [{-co|--compiler_options}='...']
#
#    To call from a cipher build folder use:
#        ./../../../../scripts/cipher/check_cipher.sh [options]
#
#    Options:
#        -h, --help
#            Display help information
#        --version
#            Display version information
#        -a, --architecture
#            Specifies which architecture to build for
#                Default: PC
#        -co,--compiler_options
#            Specifies the compiler options
#                List of values: '-O3 --param max-unroll-times=5 --param max-unrolled-insns=100 ...'
#                Default: -O3
#
#    Examples:
#        ./../../../../scripts/cipher/check_cipher.sh0
#        ./../../../../scripts/cipher/check_cipher.sh --architecture=MSP
#          ./../../../../scripts/cipher/check_cipher.sh -o=results.txt
#

set -e

# Get current script path
script_path=$(dirname $0)

# Include configuration file
source $script_path/../config/config.sh

# Include constants files
source $script_path/../constants/constants.sh
source $script_path/../constants/cipher/check_cipher.sh

# Include help file
source $script_path/../help/cipher/check_cipher.sh

# Include version file
source $script_path/../common/version.sh


# Default values
SCRIPT_ARCHITECTURE=$SCRIPT_ARCHITECTURE_PC
SCRIPT_COMPILER_OPTIONS=$SCRIPT_COMPILER_OPTION_OPTIMIZE_3


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
        -co=*|--compiler_options=*)
            SCRIPT_COMPILER_OPTIONS="${i#*=}"
            shift
            ;;
        *)
            # Unknown option
            ;;
    esac
done


echo "Script settings:"
echo -e "\t SCRIPT_ARCHITECTURE \t\t = $SCRIPT_ARCHITECTURE"
echo -e "\t SCRIPT_COMPILER_OPTIONS \t = $SCRIPT_COMPILER_OPTIONS"


# Set the current working directory
echo "Begin check cipher - $(pwd)"


fail ()
{
    local error_log=$1
    echo "${error_log}:"
    cat ${error_log}

    exit 1
}


# Clean
if ! make -f $CIPHER_MAKEFILE clean &> $MAKE_FILE_LOG
then
    fail $MAKE_FILE_LOG
fi

# Build
if ! make -f $CIPHER_MAKEFILE ARCHITECTURE=$SCRIPT_ARCHITECTURE SCENARIO=0 COMPILER_OPTIONS="$SCRIPT_COMPILER_OPTIONS" DEBUG=7 &>> $MAKE_FILE_LOG
then
    fail $MAKE_FILE_LOG
fi

program=felics_check.elf

# Run
case $SCRIPT_ARCHITECTURE in
    $SCRIPT_ARCHITECTURE_PC)
        if ! ./${program} > $RESULT_FILE
        then
            fail <(echo "Error! Run the executable to see the error: '$(pwd)/${program}'")
        fi
        ;;

    $SCRIPT_ARCHITECTURE_AVR)
        if ! $SIMAVR_SIMULATOR -m atmega128 ${program} &> $RESULT_FILE
        then
            fail <(echo "Error! Run the executable to see the error: '$(pwd)/${program}'")
        fi
        ;;

    $SCRIPT_ARCHITECTURE_MSP)
        if ! $MSPDEBUG_SIMULATOR -n sim < $MSPDEBUG_CHECK_CIPHER_COMMANDS_FILE &> $RESULT_FILE
        then
            fail <(echo "Error! Run the executable to see the error: '$(pwd)/${program}'")
        fi
        ;;

    $SCRIPT_ARCHITECTURE_ARM)
        # Upload the program to the board
        if ! make -f $CIPHER_MAKEFILE ARCHITECTURE=$SCRIPT_ARCHITECTURE upload-check &>> $MAKE_FILE_LOG
        then
            fail ${MAKE_FILE_LOG}
        fi

        # Run the program stored in the flash memory of the board
        $ARM_SERIAL_TERMINAL > $RESULT_FILE
        ;;

    $SCRIPT_ARCHITECTURE_NRF52840|$SCRIPT_ARCHITECTURE_STM32L053)
        # Upload the program to the board
        if ! make -f $CIPHER_MAKEFILE ARCHITECTURE=$SCRIPT_ARCHITECTURE upload-check &>> $MAKE_FILE_LOG
        then
            fail ${MAKE_FILE_LOG}
        fi

        # Run the program stored in the flash memory of the board
        make -f $CIPHER_MAKEFILE ARCHITECTURE=$SCRIPT_ARCHITECTURE run > $RESULT_FILE
        ;;

esac

check-count ()
{
    grep -c "$1" ${RESULT_FILE} || (($?==1))
}

correct_count=$(check-count "CORRECT!")
wrong_count=$(check-count "WRONG!")

if [ $EXPECTED_CORRECT_COUNT -ne $correct_count ] || [ $EXPECTED_WRONG_COUNT -ne $wrong_count ] ; then
    fail <(echo "Error! Test vectors do not check!" ; echo "correct = $correct_count, wrong = $wrong_count")
fi


echo "End check cipher - $(pwd)"
