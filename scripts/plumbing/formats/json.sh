# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

get_code_size ()
{
    local results=$1

    # Layout:
    # E D TOTAL
    cut -d' ' -f1 ${results}
}

get_code_ram ()
{
    local results=$1

    # Layout:
    # STACK     DATA
    # E D       E D COMMON TOTAL
    local stack=$(cut -d' ' -f1 ${results})
    local e_data=$(cut -d' ' -f3 ${results})
    local c_data=$(cut -d' ' -f5 ${results})

    echo $((stack+e_data+c_data))
}

get_code_time ()
{
    local results=$1

    # Layout:
    # E D
    cut -d' ' -f1 ${results}
}

felics-version ()
{
    formats_dir=$(dirname ${BASH_SOURCE})
    scripts_dir=${formats_dir}/../..

    PYTHONPATH=${scripts_dir} python3 -m felics.version "{$1}"
}

add_json_table_header ()
{
    local output_file=$1

    cat <<EOF > ${output_file}
{
    "commit": "$(felics-version commit)",
    "branch": "$(felics-version branch)",
    "data": [
EOF
}

add_json_table_row ()
{
    local output_file=$1
    local architecture=$2
    local cipher_name=$3
    local cipher_implementation_version=$4
    local cipher_implementation_compiler_options=$5

    local code_size_file=$6
    local code_ram_file=$7
    local code_time_file=$8

    cat <<EOF >> ${output_file}
        {
            "cipher_name": "${cipher_name}",
            "architecture": "${architecture}",
            "version": "${cipher_implementation_version}",
            "compiler_options": "${cipher_implementation_compiler_options}",
            "code_size": $(get_code_size ${code_size_file}),
            "code_ram": $(get_code_ram ${code_ram_file}),
            "code_time": $(get_code_time ${code_time_file})
        },
EOF
}

add_json_table_footer ()
{
    local output_file=$1

    sed -i '$ s/,$//' ${output_file} # Remove trailing comma.
    cat <<EOF >> ${output_file}
    ]
}
EOF
}
