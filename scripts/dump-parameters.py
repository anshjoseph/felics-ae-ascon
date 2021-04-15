#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2021 Kévin Le Gouguec

import json
from os import path
from subprocess import run
from sys import argv


_SCRIPTS_DIR = path.dirname(path.realpath(argv[0]))
_ROOT_DIR = path.join(_SCRIPTS_DIR, path.pardir)
_CIPHERS_DIR = path.join(_ROOT_DIR, 'source', 'ciphers')


def cipher_dir(result):
    return f'{result["cipher_name"]}_v{result["version"]}'

def read_ciphers(results_file):
    with open(results_file) as res:
        data = json.load(res)['data']
    return {
        # NB: this will only keep one version of each cipher;
        # presumably we don't care, since we expect all versions of a
        # cipher to use the same parameters.
        # We need at least one folder per cipher; if all ciphers had a
        # known version (e.g. "ref"), we could just use that; alas…
        result['cipher_name']: cipher_dir(result) for result in data
    }

def get_constant(cipher, constant):
    source_dir = path.join(_CIPHERS_DIR, cipher)
    script = path.join(
        _SCRIPTS_DIR, 'plumbing', 'cipher', 'cipher_constant.sh'
    )

    p = run((script, source_dir, constant),
            check=True, capture_output=True, text=True)
    return str(8*int(p.stdout))


def find_parameters(cipher):
    return {
        param: get_constant(cipher, param)
        for param in ('CRYPTO_KEYBYTES', 'CRYPTO_NPUBBYTES', 'CRYPTO_ABYTES')
    }


TABLE_TEMPLATE = r'''
\begin{{table}}[H]
  \centering
  \begin{{tabular}}{{l|r|r|r}}
  \textbf{{}} & \textbf{{$k$}} & \textbf{{$n$}} & \textbf{{$\tau$}} \\
{rows}
  \end{{tabular}}
  \caption{{Key, nonce and tag sizes for algorithms benchmarked with FELICS-AE.}}
  \label{{tab:felics-parameters}}
\end{{table}}
'''[1:]


def main(results_file):
    ciphers = read_ciphers(results_file)

    parameters = {
        c_name: find_parameters(c_dir) for c_name, c_dir in ciphers.items()
    }

    rows = (
        ' & '.join((name, params['CRYPTO_KEYBYTES'], params['CRYPTO_NPUBBYTES'],
                    params['CRYPTO_ABYTES']))
        + r' \\'
        for name, params in parameters.items()
    )

    print(TABLE_TEMPLATE.format(
        rows='\n'.join(sorted(rows))
    ))

if __name__ == '__main__':
    main(argv[1])
