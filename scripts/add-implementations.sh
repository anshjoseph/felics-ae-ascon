#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2021 Kévin Le Gouguec

set -eux

if (($# < 2))
then
    cat <<EOF
Usage: $0 NAME crypto_aead/CIPHER/IMPLEM...

Add a new cipher to FELICS-AE.

Each implementation will be added to source/ciphers/\$NAME_v\$IMPLEM.
EOF
    exit 1
fi

name=$1
shift

scripts_dir=$(realpath $(dirname $0))
ciphers_dir="${scripts_dir}"/../source/ciphers
integrator=$(getent passwd "${USER}" | cut -d':' -f5)

for d
do
    version=$(basename "$d")
    dst="${ciphers_dir}/${name}_v${version}"

    mkdir -p "${dst}"/source
    cp "$d"/* "${dst}"/source

    cat <<EOF > "${dst}"/source/implementation.info
ImplementationDescription: Reference implementation of ${name} integrated by ${integrator}
ImplementationAuthors: TODO

EncryptCode: encrypt!crypto_aead_decrypt
DecryptCode: encrypt!crypto_aead_encrypt
EOF

    if test "$d" = ref
    then
        kat=$(dirname "$d")/LWC_AEAD_KAT_128_128.txt
        vector_file="${dst}"/source/test_vectors.c

        grep -A5 "Count = 545" "${kat}" |
            tail -n5 |
            "${scripts_dir}"/convert-vector.sh > "${vector_file}"
    else
        (
            cd "${dst}"/source
            ln -s ../../"${name}_vref"/source/test_vectors.c .
        )
    fi
done
