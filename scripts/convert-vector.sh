#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2021 Kévin Le Gouguec

# Read a LWC_AEAD_KAT test vector on stdin, print a FELICS-AE test
# vector to stdout.

set -eu

read-field ()
{
    local -r field=$1

    local line
    read line
    [[ ${line} =~ ${field}\ =\ ([[:xdigit:]]+) ]]
    echo ${BASH_REMATCH[1]}
}

dump-field ()
{
    local -r value=$1
    local -r n=${#value}

    local i
    for ((i=0; i<n; i+=2))
    do
        echo -n 0x${value:${i}:2}
        if ((i<n-2))
        then
            echo -n ', '
        fi
    done
}

key=$(read-field "Key")
nonce=$(read-field "Nonce")
plaintext=$(read-field "PT")
adata=$(read-field "AD")
ciphertext=$(read-field "CT")

cat <<EOF
#include <stdint.h>

#include "felics/test_vectors.h"
#include "api.h"

const uint8_t expectedKey[CRYPTO_KEYBYTES] = {
    $(dump-field ${key})
};
const uint8_t expectedNonce[CRYPTO_NPUBBYTES] = {
    $(dump-field ${nonce})
};
const uint8_t expectedPlaintext[MAXTEST_BYTES_M] = {
    $(dump-field ${plaintext})
};
const uint8_t expectedAssociated[MAXTEST_BYTES_AD] = {
    $(dump-field ${adata})
};

const uint8_t expectedCiphertext[MAXTEST_BYTES_M+CRYPTO_ABYTES] = {
    $(dump-field ${ciphertext})
};
EOF
