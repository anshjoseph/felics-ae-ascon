#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

set -eu

for arg
do
    case ${arg} in
        --from=*)
            ref=${arg#*=}
            ;;
        --to=*)
            new=${arg#*=}
    esac
done

scripts_dir=$(dirname $(realpath $0))
root_dir=${scripts_dir}/..
ciphers_dir=${root_dir}/source/ciphers

mkdir -p ${ciphers_dir}/.templates/Lilliput_v${new}/{i,ii}

(
    cd ${ciphers_dir}/.templates/Lilliput_v${new}
    ln -s ../Lilliput_v${ref}/*.[chS] .
    for mode in i ii
    do
        (
            cd ${mode}
            ln -s ../../Lilliput_v${ref}/${mode}/*.[chS] .
            cp ../../Lilliput_v${ref}/${mode}/implementation.info .
        )
    done
)

mkdir -p ${ciphers_dir}/Lilliput-{I,II}-{128,192,256}_v${new}/{source,build}

for mode in i ii
do
    for keylen in 128 192 256
    do
        new_dir=Lilliput-${mode^^}-${keylen}_v${new}
        ref_dir=Lilliput-${mode^^}-${keylen}_v${ref}

        cp ${ciphers_dir}/${ref_dir}/build/.gitignore \
           ${ciphers_dir}/${new_dir}/build
        (
            cd ${ciphers_dir}/${new_dir}/source
            ln -s ../../${ref_dir}/source/{test_vectors.c,_parameters.h} .
            ln -s ../../.templates/Lilliput_v${new}/*.[chS] .
            ln -s ../../.templates/Lilliput_v${new}/${mode}/* .
        )
    done
done

ref_dir=$(realpath --relative-to=. ${ciphers_dir}/.templates/Lilliput_v${ref})
new_dir=$(realpath --relative-to=. ${ciphers_dir}/.templates/Lilliput_v${new})

cat <<EOF
Created ${new_dir}
from ${ref_dir}.

You may now:

- edit ${new_dir}/{i,ii}/implementation.info
  to explain the specifics of your implementation,

- copy files from ${ref_dir}
  over symlinks in ${new_dir}
  and start editing these copies.

EOF
