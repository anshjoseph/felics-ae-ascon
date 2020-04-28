#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

set -eu
shopt -s extglob

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

templates_dir=$(dirname $(realpath $0))
ciphers_dir=${templates_dir}/..

mkdir -p ${templates_dir}/Lilliput_v${new}/{i,ii}

(
    cd ${templates_dir}/Lilliput_v${new}
    ln -s ../Lilliput_v${ref}/!(api).[chS] .
    for mode in i ii
    do
        (
            cd ${mode}
            ln -s ../../Lilliput_v${ref}/${mode}/*.[chS] .
            cp ../../Lilliput_v${ref}/${mode}/implementation.info .
        )
    done
)

mkdir -p ${ciphers_dir}/Lilliput-{I,II}-{128,192,256}_v${new}/source

for mode in i ii
do
    for keylen in 128 192 256
    do
        variant=Lilliput-${mode^^}-${keylen}
        new_dir=${variant}_v${new}
        ref_dir=${variant}_v${ref}

        (
            cd ${ciphers_dir}/${new_dir}/source
            # Implementation-indepdendent files.
            ln -s ../../.templates/Lilliput_vfelicsref/api.h .
            ln -s ../../${variant}_vfelicsref/source/{test_vectors.c,parameters.h} .
            # Other files.
            ln -s ../../.templates/Lilliput_v${new}/!(api).[chS] .
            ln -s ../../.templates/Lilliput_v${new}/${mode}/* .
        )
    done
done

ref_dir=$(realpath --relative-to=. ${templates_dir}/Lilliput_v${ref})
new_dir=$(realpath --relative-to=. ${templates_dir}/Lilliput_v${new})

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
