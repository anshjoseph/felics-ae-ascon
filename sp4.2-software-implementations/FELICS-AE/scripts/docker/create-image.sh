#!/bin/bash

set -eux

./download-dependencies.sh

options=(
    --force-rm
    --tag=felics-ae
    --file ./Dockerfile
    ./
)

docker_dir=$(dirname $(realpath $0))
felics_dir=${docker_dir}/../..

mount=$(paste -sd, <<EOF
type=bind
src=${felics_dir}
dst=/home/felics/FELICS-AE
EOF
)

docker build "${options[@]}"
docker create --mount="${mount}" --name felics-ae -it felics-ae
docker start felics-ae
