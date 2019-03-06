#!/bin/bash

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
    local data=$(cut -d' ' -f6 ${results})

    echo $((stack+data))
}

get_code_time ()
{
    local results=$1

    # Layout:
    # EKS E DKS D
    cut -d' ' -f2 ${results}
}

describe-revision ()
{
    if ! git symbolic-ref --short HEAD 2>/dev/null
    then
        git branch --contains HEAD |
            grep -v '^*' |
            tr -d ' ' |
            paste -sd , |
            sed -r 's/(.*)/DETACHED:\1/'
    fi
}

add_json_table_header ()
{
    local output_file=$1
    local commit=$(git rev-parse --short HEAD)
    local branch=$(describe-revision)

    cat <<-EOF > ${output_file}
	{
	    "commit": "${commit}",
	    "branch": "${branch}",
	    "data": [
	EOF
}

add_json_table_row ()
{
    local output_file=$1
    local architecture=$2
    local cipher_name=$3
    local cipher_block_size=$4
    local cipher_key_size=$5
    local cipher_implementation_version=$6
    local cipher_implementation_language=$7
    local cipher_implementation_compiler_options=$8

    local code_size_file=${9}
    local code_ram_file=${10}
    local code_time_file=${11}

    cat <<-EOF >> ${output_file}
	{
	    "cipher_name": "${cipher_name}",
	    "architecture": "${architecture}",
	    "block_size": ${cipher_block_size},
	    "key_size": ${cipher_key_size},
	    "version": "${cipher_implementation_version}",
	    "language": "${cipher_implementation_language}",
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
    cat <<-EOF >> ${output_file}
	    ]
	}
	EOF
}
