#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

set -eux

CI_DIR=$(dirname $0)
FELICS_AE_DIR=${CI_DIR}/..
FELICS_PUBLISH=${FELICS_AE_DIR}/scripts/felics-publish
FELICS_RESULTS=${FELICS_AE_DIR}/results

mkdir -p ${CI_DIR}/results

versions_128='8bitfast|opt.*|.*ref'
${FELICS_PUBLISH}                                                           \
    ${FELICS_RESULTS}/all.json                                              \
    -f "cipher_name=(Ascon|ACORN|Lilliput.+128),version=${versions_128}"    \
    -c 'Performance results for 128-bit key algorithms on {arch}.'          \
    -l 'table:bench-soft-128-{arch}'                                        \
    -o ${CI_DIR}/results/implem-soft-128.tex

${FELICS_PUBLISH}                                           \
    ${FELICS_RESULTS}/all.json                              \
    -f 'cipher_name=Lilliput.+,version=felicsref'           \
    -c 'Performance of \textsc{{Lilliput-AE}} on {arch}.'   \
    -l 'table:bench-soft-lilliput-{arch}'                   \
    -i='-version'                                           \
    -o ${CI_DIR}/results/implem-soft-lilliput.tex

${CI_DIR}/publish-nist-ti.py                    \
    ${FELICS_RESULTS}/all.json                  \
    ${CI_DIR}/results/implem-soft-ti.tex
