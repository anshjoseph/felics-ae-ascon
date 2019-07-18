#!/bin/bash

set -eux

docker_dir=$(dirname $(realpath $0))
scripts_dir=${docker_dir}/..

usb_devices=($(
    find /dev/bus/usb/ -type c |
    while read d ; do printf "%s\n" "--device=${d}" ; done
))

options=(
    --device=/dev/ttyACM0
    "${usb_devices[@]}"
    --name felics-ae
    -it
)

version=$(
    docker images felics-ae --format "{{.Tag}}" |
    sort -r                                     |
    head -n1
)
docker create "${options[@]}" felics-ae:${version}
docker start felics-ae
