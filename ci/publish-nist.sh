#!/bin/bash

set -eux

CI_DIR=$(dirname $0)
FELICS_AE_DIR=${CI_DIR}/../FELICS-AE/authenticated_block_ciphers
FELICS_PUBLISH=${FELICS_AE_DIR}/scripts/felics-publish
FELICS_RESULTS=${FELICS_AE_DIR}/results

mkdir -p ${CI_DIR}/results

${FELICS_PUBLISH}                                                   \
    ${FELICS_RESULTS}/lilliput-vs-caesar-usecase-1.json             \
    -f 'cipher_name=.+128.?'                                        \
    -c 'Performance results for 128-bit key algorithms on {arch}.'  \
    -l 'table:bench-soft-128-{arch}'                                \
    -o ${CI_DIR}/results/implem-soft-128.tex

${FELICS_PUBLISH}                                           \
    ${FELICS_RESULTS}/lilliput-vs-caesar-usecase-1.json     \
    -f 'cipher_name=Lilliput.+'                             \
    -c 'Performance of \textsc{{Lilliput-AE}} on {arch}.'   \
    -l 'table:bench-soft-lilliput-{arch}'                   \
    -i='-version'                                           \
    -o ${CI_DIR}/results/implem-soft-lilliput.tex

${CI_DIR}/publish-nist-ti.py                    \
    ${FELICS_RESULTS}/lilliput-ref-vs-ti.json   \
    ${CI_DIR}/results/implem-soft-ti.tex
