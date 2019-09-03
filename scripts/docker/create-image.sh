#!/bin/bash

set -eux

docker_dir=$(dirname $(realpath $0))
scripts_dir=${docker_dir}/..

mkdir -p "${docker_dir}"/.resources
"${docker_dir}"/download-dependencies.sh "${docker_dir}"/.resources

options=(
    --force-rm
    --tag=felics-ae:$("${scripts_dir}"/version.sh)
    --file "${docker_dir}"/Dockerfile
    "${docker_dir}"
)

"${scripts_dir}"/felics-archive "${docker_dir}"/.resources
docker build "${options[@]}"
