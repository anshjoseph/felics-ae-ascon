#!/bin/bash

set -eux

docker_dir=$(dirname $(realpath $0))
felics_dir=${docker_dir}/../..

usb_devices=($(
    find /dev/bus/usb/ -type c |
    while read d ; do printf "%s\n" "--device=${d}" ; done
))

options=(
    --mount=type=bind,src="${felics_dir}",dst=/home/felics/FELICS-AE
    --device=/dev/ttyACM0
    "${usb_devices[@]}"
    --name felics-ae
    -it
)

docker create "${options[@]}" felics-ae
docker start felics-ae
