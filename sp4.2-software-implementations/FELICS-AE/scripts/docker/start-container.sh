#!/bin/bash

set -eux

docker_dir=$(dirname $(realpath $0))
felics_dir=${docker_dir}/../..

options=(
    --mount=type=bind,src="${felics_dir}",dst=/home/felics/FELICS-AE
    --name felics-ae
    -it
)

docker create "${options[@]}" felics-ae
docker start felics-ae
