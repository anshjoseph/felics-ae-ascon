#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2021 Kévin Le Gouguec

set -eu

CONTAINER=$1

run-guest ()
{
    docker exec "${CONTAINER}" "$@"
}

host_gid=$(getent group dialout | cut -d: -f3)
guest_gid=$(run-guest getent group dialout | cut -d: -f3)

if ((host_gid != guest_gid))
then
    echo "Changing guest GID for dialout from ${guest_gid} to ${host_gid}."
    run-guest groupmod -g ${host_gid} dialout
fi
