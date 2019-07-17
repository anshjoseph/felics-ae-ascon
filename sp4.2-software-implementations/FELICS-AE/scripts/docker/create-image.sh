#!/bin/bash

set -eux

docker_dir=$(dirname $(realpath $0))
scripts_dir=${docker_dir}/..

./download-dependencies.sh

options=(
    --force-rm
    --tag=felics-ae:$("${scripts_dir}"/version.sh)
    --file ./Dockerfile
    ./
)

"${scripts_dir}"/felics-archive .resources
docker build "${options[@]}"
