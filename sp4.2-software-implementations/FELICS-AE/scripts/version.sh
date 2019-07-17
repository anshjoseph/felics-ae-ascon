#!/bin/bash

scripts_dir=$(realpath $(dirname $0))
PYTHONPATH="${scripts_dir}" python3 -m felics.version
