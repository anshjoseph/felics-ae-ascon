#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2021 Kévin Le Gouguec

# We can't just grep "#define $1", as this definition might refer to
# another macro.  Instead, let the preprocessor and the compiler
# compute the value for us.

set -eu

cipher_dir=$1
constant=$2

prog=$(mktemp)
gcc -I"${cipher_dir}"/source -x c -o $prog - <<EOF
#include <stdio.h>
#include "api.h"

int main(void)
{
    printf("%d", ${constant});
    return 0;
}
EOF

$prog
rm $prog
