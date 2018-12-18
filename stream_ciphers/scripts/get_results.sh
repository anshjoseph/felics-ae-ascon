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
# Call this script to get the results
# 	./get_results.sh [{-h|--help}] [--version] [{-f|--format}=[0|1|2|3|4|5]] [{-a|--architectures}=['PC AVR MSP ARM']] [{-s|--scenarios}=['0 1']] [{-c|--ciphers}=['Cipher1 Cipher2 ...']] [{-p|--prefix}='...'] [{-co|--compiler_options}='...']
#
#	Options:
#		-h, --help
#			Display help information
#		--version
#			Display version information
#		-f, --format
#			Specifies which output format to use
#				0 - use all output formats below
#				1 - raw table
#				2 - MediaWiki table
#				3 - XML table
#				4 - LaTeX table
#				5 - CSV table
#				Default: 0
#		-a, --architectures
#			Specifies for which archiectures to get the results
#				List of values: 'PC AVR MSP ARM'
#				Default: all architectures
#		-s, --scenarios
#			Specifies for which scenarios to get the results
#				List of values: '0 1'
#				Default: all scenarios
#		-c, --ciphers
#			Specifies for which ciphers to get the results
#				List of values: 'CipherName_StateSizeInBits_KeySizeInBits_IVSizeInBits_v01 ...'
#				Default: all ciphers
#		-p, --prefix
#			Specifies the results file prefix
#				Default: current date in 'YYYY_mm_dd' format
#		-co,--compiler_options
#			Specifies the compiler options
#				List of values: '-O3 --param max-unroll-times=5 --param max-unrolled-insns=100 ...'
#				Default: all compiler options
#
#	Examples:
#		./get_results.sh -f=0
#		./get_results.sh --format=1
#		./get_results.sh -a='PC AVR' --scenarios="0 1"
#


# Get current script path
script_path=$(dirname $0)

# Include constants files
source $script_path/constants/constants.sh
source $script_path/constants/get_results.sh

# Include help file
source $script_path/help/get_results.sh

# Include validation functions
source $script_path/common/validate.sh

# Include version file
source $script_path/common/version.sh


# Default values
SCRIPT_FORMAT=$SCRIPT_FORMAT_0


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
		-f=*|--format=*)
			SCRIPT_FORMAT="${i#*=}"
			shift
			;;
		-a=*|--architectures=*)
			SCRIPT_USER_ARCHITECTURES="${i#*=}"
			shift
			;;
		-s=*|--scenarios=*)
			SCRIPT_USER_SCENARIOS="${i#*=}"
			shift
			;;
		-c=*|--ciphers=*)
			SCRIPT_USER_CIPHERS="${i#*=}"
			shift
			;;
		-p=*|--prefix=*)
			SCRIPT_USER_PREFIX="${i#*=}"
			shift
			;;
		-co=*|--compiler_options=*)
			SCRIPT_USER_COMPILER_OPTIONS="${i#*=}"
			shift
			;;
		*)
			# Unknown option
			;;
	esac
done


echo "Script settings:"
echo -e "\t SCRIPT_FORMAT \t = $SCRIPT_FORMAT"


# Validate format
validate_format $SCRIPT_FORMAT


# Change current directory to script source path directory
if [ '.' != $script_path ] ; then
	cd $script_path
fi


# Set the current working directory
current_directory=$(pwd)
echo "Begin get results - $current_directory"


# Change current working directory
cd $CIPHERS_PATH
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


# User did not select architectures
user_architectures=$FALSE

# If user architectures are not set, use all architectures
if [ -n "$SCRIPT_USER_ARCHITECTURES" ]; then
	architectures=$SCRIPT_USER_ARCHITECTURES
	user_architectures=$TRUE
else
	architectures=(${SCRIPT_ARCHITECTURES[@]}) 
fi


# User did not select scenarios
user_scenarios=$FALSE

# If user scenarios are not set, use all scenarios
if [ -n "$SCRIPT_USER_SCENARIOS" ]; then
	scenarios=$SCRIPT_USER_SCENARIOS
	user_scenarios=$TRUE
else
	scenarios=(${SCRIPT_SCENARIOS[@]}) 
fi


# User did not select ciphers
user_ciphers=$FALSE

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
			exit
		fi
	done
	user_ciphers=$TRUE
else
	directories=$ciphers_directories
fi


# User did not select compiler options
user_compiler_options=$FALSE

# If user compiler options are not set, use all compiler options
if [ -n "$SCRIPT_USER_COMPILER_OPTIONS" ]; then
	compiler_options="${SCRIPT_USER_COMPILER_OPTIONS[@]}"
	user_compiler_options=$TRUE
else
	compiler_options=("${SCRIPT_COMPILER_OPTIONS[@]}")
fi


# Validate architectures
for architecture in $architectures
do
	validate_architecture $architecture
done

# Validate scenarios
for scenario in $scenarios
do
	validate_scenario $scenario
done


cd $current_directory


# Set file prefix
if [ -n "$SCRIPT_USER_PREFIX" ] ; then
	file_prefix=$SCRIPT_USER_PREFIX$FILE_NAME_SEPARATOR	
	file_prefix=$(echo $file_prefix | tr -d ' ')
else
	file_prefix=$(date -u +"%Y_%m_%d")$FILE_NAME_SEPARATOR
fi


# Prepare script parameters
if [ $TRUE -eq $user_architectures ] ; then
	script_architectures_parameter="-a=${architectures[@]}"
else
	script_architectures_parameter=""
fi

if [ $TRUE -eq $user_scenarios ] ; then
	script_scenarios_parameter="-s=${scenarios[@]}"
else
	script_scenarios_parameter=""
fi

if [ $TRUE -eq $user_ciphers ] ; then
	script_ciphers_parameter="-c=${directories[@]}"
else
	script_ciphers_parameter=""
fi

if [ $TRUE -eq $user_compiler_options ] ; then
	script_compiler_options_parameter="-co=${compiler_options[@]}"
else
	script_compiler_options_parameter=""
fi

# Get ciphers info
./get_ciphers_info.sh -f=$SCRIPT_FORMAT "$script_ciphers_parameter"


# Collect ciphers metrics
./collect_ciphers_metrics.sh -f=$SCRIPT_FORMAT "$script_architectures_parameter" "$script_scenarios_parameter" "$script_ciphers_parameter" "$script_compiler_options_parameter"


# Create directory structure
mkdir -p $SCRIPT_RESULTS_DIR_PATH

mkdir -p $SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME

for architecture in ${architectures[@]}
do
	mkdir -p $SCRIPT_RESULTS_DIR_PATH$architecture
done


# Move files to new location
case $SCRIPT_FORMAT in
	$SCRIPT_FORMAT_0)
		raw_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_RAW_OUTPUT_EXTENSION
		source_file=$SCRIPT_OUTPUT_PATH/$raw_file
		destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$raw_file
		if [ -f $source_file ] ; then
			mv $source_file $destination_file
		fi

		mediawiki_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION
		source_file=$SCRIPT_OUTPUT_PATH/$mediawiki_file
		destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$mediawiki_file
		if [ -f $source_file ] ; then
			mv $source_file $destination_file
		fi

		xml_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_XML_OUTPUT_EXTENSION
		source_file=$SCRIPT_OUTPUT_PATH/$xml_file
		destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$xml_file
		if [ -f $source_file ] ; then
			mv $source_file $destination_file
		fi

		latex_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_LATEX_OUTPUT_EXTENSION
		source_file=$SCRIPT_OUTPUT_PATH/$latex_file
		destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$latex_file
		if [ -f $source_file ] ; then
			mv $source_file $destination_file
		fi

		csv_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_CSV_OUTPUT_EXTENSION
		source_file=$SCRIPT_OUTPUT_PATH/$csv_file
		destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$csv_file
		if [ -f $source_file ] ; then
			mv $source_file $destination_file
		fi
		;;
	$SCRIPT_FORMAT_1)
		raw_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_RAW_OUTPUT_EXTENSION
		source_file=$SCRIPT_OUTPUT_PATH/$raw_file
		destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$raw_file
		if [ -f $source_file ] ; then
			mv $source_file $destination_file
		fi
		;;
	$SCRIPT_FORMAT_2)
		mediawiki_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION
		source_file=$SCRIPT_OUTPUT_PATH/$mediawiki_file
		destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$mediawiki_file
		if [ -f $source_file ] ; then
			mv $source_file $destination_file
		fi
		;;
	$SCRIPT_FORMAT_3)
		xml_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_XML_OUTPUT_EXTENSION
		source_file=$SCRIPT_OUTPUT_PATH/$xml_file
		destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$xml_file
		if [ -f $source_file ] ; then
			mv $source_file $destination_file
		fi
		;;
	$SCRIPT_FORMAT_4)
		latex_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_LATEX_OUTPUT_EXTENSION
		source_file=$SCRIPT_OUTPUT_PATH/$latex_file
		destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$latex_file
		if [ -f $source_file ] ; then
			mv $source_file $destination_file
		fi
		;;
	$SCRIPT_FORMAT_5)
		csv_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_CSV_OUTPUT_EXTENSION
		source_file=$SCRIPT_OUTPUT_PATH/$csv_file
		destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$csv_file
		if [ -f $source_file ] ; then
			mv $source_file $destination_file
		fi
		;;
esac


for architecture in ${architectures[@]}
do
	for scenario in ${scenarios[@]}
	do
		case $SCRIPT_FORMAT in
			$SCRIPT_FORMAT_0)
				raw_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_RAW_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$raw_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$raw_file
				if [ -f $source_file ] ; then
					mv $SCRIPT_OUTPUT_PATH/$source_file $destination_file
				fi

				mediawiki_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$mediawiki_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$mediawiki_file
				if [ -f $source_file ] ; then
					mv $source_file $destination_file
				fi

				xml_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_XML_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$xml_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$xml_file
				if [ -f $source_file ] ; then
					mv $source_file $destination_file
				fi
		
				latex_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_LATEX_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$latex_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$latex_file
				if [ -f $source_file ] ; then
					mv $source_file $destination_file
				fi

				csv_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_CSV_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$csv_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$csv_file
				if [ -f $source_file ] ; then
					mv $source_file $destination_file
				fi
				;;
			$SCRIPT_FORMAT_1)
				raw_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_RAW_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$raw_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$raw_file
				if [ -f $source_file ] ; then
					mv $SCRIPT_OUTPUT_PATH/$source_file $destination_file
				fi
				;;
			$SCRIPT_FORMAT_2)
				mediawiki_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$mediawiki_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$mediawiki_file
				if [ -f $source_file ] ; then
					mv $source_file $destination_file
				fi
				;;
			$SCRIPT_FORMAT_3)
				xml_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_XML_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$xml_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$xml_file
				if [ -f $source_file ] ; then
					mv $source_file $destination_file
				fi
				;;
			$SCRIPT_FORMAT_4)
				latex_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_LATEX_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$latex_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$latex_file
				if [ -f $source_file ] ; then
					mv $source_file $destination_file
				fi
				;;
			$SCRIPT_FORMAT_5)
				csv_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_CSV_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$csv_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$csv_file
				if [ -f $source_file ] ; then
					mv $source_file $destination_file
				fi
				;;
		esac
	done
done


# Create the archive
cd $SCRIPT_OUTPUT_PATH
zip -r $SCRIPT_OUTPUT_PATH/$file_prefix$RESULTS_FILE_NAME$ZIP_FILE_EXTENSION $RESULTS_DIR_NAME
cd $current_directory


# Create MediWiki page
if [ $SCRIPT_FORMAT_0 -eq $SCRIPT_FORMAT ] || [ $SCRIPT_FORMAT_2 -eq $SCRIPT_FORMAT ] ; then
	mediawiki_results_file=$SCRIPT_OUTPUT_PATH$RESULTS_FILE_NAME$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION

	#echo "=Stream Ciphers=" > $mediawiki_results_file
	#echo "" >> $mediawiki_results_file
	echo "" > $mediawiki_results_file

	mediawiki_file=$file_prefix$INFO_OUTPUT_FILE_NAME$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION
	content=$(cat $SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$mediawiki_file)

	echo "==Implementation Info==" >> $mediawiki_results_file
	echo "$content" >> $mediawiki_results_file
	echo "" >> $mediawiki_results_file

	for scenario in ${scenarios[@]} 
	do
		echo "==Scenario $scenario==" >> $mediawiki_results_file
		echo "" >> $mediawiki_results_file

		for architecture in ${architectures[@]}
		do
			mediawiki_file=$file_prefix$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION
			content=$(cat $SCRIPT_RESULTS_DIR_PATH$architecture/$mediawiki_file)

			echo "===$architecture===" >> $mediawiki_results_file
			echo "$content" >> $mediawiki_results_file
			echo "" >> $mediawiki_results_file
		done
	done

	echo "==Files==" >> $mediawiki_results_file
	echo "* All results: [[ Media:$file_prefix$RESULTS_FILE_NAME$ZIP_FILE_EXTENSION | [ZIP] ]]" >> $mediawiki_results_file

	echo "[[Category:ACRYPT]]" >> $mediawiki_results_file
fi


# Change current working directory
cd $current_directory
echo "End get results - $(pwd)"
