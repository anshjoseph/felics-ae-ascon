#!/bin/bash

set -eux

docker_dir=$(dirname $(realpath $0))
felics_dir=${docker_dir}/../..

./download-dependencies.sh

options=(
    --force-rm
    --tag=felics-ae
    --file ./Dockerfile
    ./
)

${felics_dir}/scripts/felics-archive .resources
docker build "${options[@]}"
