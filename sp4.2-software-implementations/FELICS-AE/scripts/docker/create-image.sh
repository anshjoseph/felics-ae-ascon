#!/bin/bash

set -eux

./download-dependencies.sh

options=(
    --force-rm
    --tag=felics-ae
    --file ./Dockerfile
    ./
)

docker build "${options[@]}"
docker create --name felics-ae -it felics-ae
docker start felics-ae
