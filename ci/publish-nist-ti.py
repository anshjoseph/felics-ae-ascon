#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from collections import defaultdict, OrderedDict
import json
from sys import argv


_METRICS = ('code_size', 'code_ram', 'code_time')
_ARCHITECTURES = ('AVR', 'MSP', 'ARM', 'PC')


_VERSION1 = 'felicsref'
_VERSION2 = 'threshold'
_CIPHER = 'Lilliput'
_CFLAGS = '-O3'


_TABLE_TEMPLATE = r'''
\begin{{table}}[H]
  \centering
  \begin{{tabular}}{{l|l||r|r|r}}
{header} \\
    \hline
{body}
  \end{{tabular}}
  \caption{{Performance impact of the thresholding scheme.}}
  \label{{table:bench-soft-ti}}
\end{{table}}
'''[1:]                         # Remove first newline.


def _group_setups(filename):
    with open(filename) as f:
        results = json.load(f)

    grouped = {a: defaultdict(dict) for a in _ARCHITECTURES}

    versions = {_VERSION1, _VERSION2}

    for setup in results['data']:
        name = setup['cipher_name']
        version = setup['version']
        cflags = setup['compiler_options']
        arch = setup['architecture']

        if (
            not name.startswith(_CIPHER)
            or version not in versions
            or cflags != _CFLAGS
        ):
            continue

        grouped[arch][name][version] = setup

    return OrderedDict((
        (a, grouped[a])
        for a in sorted(grouped, key=_ARCHITECTURES.index)
    ))


def _compute_differences(data1, data2):
    return {
        m: data2[m]/data1[m]
        for m in _METRICS
    }


def _smallcaps(text):
    return r'\textsc{{{txt}}}'.format(txt=text)


def _format_ratios(setups, v1, v2):
    header = r'    & {cipher:<{pad}}'
    metrics = r'{code_size:.2f} & {code_ram:.2f} & {code_time:.2f} \\'
    line = '{header} & {metrics}'

    ciphers = setups.keys()
    pad = len(_smallcaps(max(ciphers, key=len)))

    for cipher, values in sorted(setups.items()):
        ratios = _compute_differences(values[v1], values[v2])

        yield line.format(
            header=header.format(cipher=_smallcaps(cipher), pad=pad),
            metrics=metrics.format_map(ratios)
        )


def _indent(text, indent):
    return '\n'.join(indent*' ' + line for line in text.splitlines())


def _format_header(v1, v2):
    fields = (
        r'\textbf{Platform}',
        r'\textbf{Member}'
    ) + tuple(
        r'$\frac{{{m}_{{{v2}}}}}{{{m}_{{{v1}}}}}$'.format(m=m, v1=v1, v2=v2)
        for m in ('ROM', 'RAM', 'cycles')
    )

    return _indent(' & '.join(fields), 4)


def _arch_table(arch, setups, v1, v2):
    header = r'\multirow{{{n}}}{{*}}{{{a}}}'.format(a=arch, n=len(setups))
    footer = r'\hline'
    content = '\n'.join(line for line in _format_ratios(setups, v1, v2))

    return '\n'.join((header, content, footer))


def _format_body(setups, v1, v2):
    tables = (
        _arch_table(arch, setups, v1, v2) for arch, setups in setups.items()
    )

    return _indent('\n'.join(tables), 4)


def _main(results_filename, output_filename):
    setups = _group_setups(results_filename)

    table = _TABLE_TEMPLATE.format(
        header=_format_header(_VERSION1, _VERSION2),
        body=_format_body(setups, _VERSION1, _VERSION2),
    )

    with open(output_filename, 'w') as out:
        out.write(table)


if __name__ == '__main__':
    _main(argv[1], argv[2])
