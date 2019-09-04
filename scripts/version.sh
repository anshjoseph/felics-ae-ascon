#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

scripts_dir=$(realpath $(dirname $0))
PYTHONPATH="${scripts_dir}" python3 -m felics.version
