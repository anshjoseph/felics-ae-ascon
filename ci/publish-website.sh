#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

set -eux

CI_DIR=$(dirname $0)
FELICS_AE_DIR=${CI_DIR}/..
FELICS_PUBLISH=${FELICS_AE_DIR}/scripts/felics-publish
FELICS_RESULTS=${FELICS_AE_DIR}/results
OUTPUT=${CI_DIR}/results/implementation.md

mkdir -p ${CI_DIR}/results

PLATFORMS=(AVR MSP ARM PC)

declare -A PLATFORM_NAMES=(
    [AVR]="AVR ATmega128"
    [MSP]=MSP430F1611
    [ARM]="ARM Cortex-M3"
    [PC]=PC
)


publish-platform ()
{
    local platform=$1

    ${FELICS_PUBLISH}                                                   \
        ${FELICS_RESULTS}/all.json                                      \
        -f "cipher_name=.+128.?,architecture=${platform}"               \
        -c 'Performance results for 128-bit key algorithms on {arch}.'  \
        -l 'table:bench-soft-128-{arch}'                                \
        -o ${OUTPUT}-128-${platform}.html

    ${FELICS_PUBLISH}                                           \
        ${FELICS_RESULTS}/all.json                              \
        -f "cipher_name=Lilliput.+,architecture=${platform}"    \
        -c 'Performance of Lilliput-AE on {arch}.'              \
        -l 'table:bench-soft-lilliput-{arch}'                   \
        -o ${OUTPUT}-lilliput-${platform}.html

    echo "### Performance results on ${PLATFORM_NAMES[${platform}]}" >> ${OUTPUT}
    echo >> ${OUTPUT}

    cat ${OUTPUT}-{128,lilliput}-${platform}.html >> ${OUTPUT}

    echo >> ${OUTPUT}
}


> ${OUTPUT}

for p in ${PLATFORMS[@]}
do
    publish-platform ${p}
done
