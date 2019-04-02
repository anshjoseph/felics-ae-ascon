#!/usr/bin/env python3

from collections import defaultdict, OrderedDict
import json
from os import path


_CI_DIR = path.dirname(__file__)
_FELICS_AE_DIR = path.join(
    _CI_DIR, '..', 'FELICS-AE', 'authenticated_block_ciphers'
)
_RESULTS_FILENAME = path.join(_FELICS_AE_DIR, 'results', 'lilliput-ref-vs-ti.json')


_METRICS = ('code_size', 'code_ram', 'code_time')
_ARCHITECTURES = ('AVR', 'MSP', 'ARM', 'PC')


def _group_setups(filename):
    with open(filename) as f:
        results = json.load(f)

    grouped = {a: defaultdict(dict) for a in _ARCHITECTURES}

    for setup in results['data']:
        grouped[setup['architecture']][setup['cipher_name']][setup['version']] = setup

    return OrderedDict((
        (a, grouped[a])
        for a in sorted(grouped, key=_ARCHITECTURES.index)
    ))


def _compute_differences(data1, data2):
    return {
        m: data2[m]/data1[m]
        for m in _METRICS
    }


def _print_ratios(setups):
    v1 = 'felicsref'
    v2 = 'threshold'

    template = r'    \textsc{{{cipher:<{pad}}}} & {code_size:.2f} & {code_ram:.2f} & {code_time:.2f} \\'
    pad = max(len(cipher) for cipher in setups)

    for cipher, metrics in sorted(setups.items()):
        arguments = dict(
            cipher=cipher,
            pad=pad,
            **_compute_differences(metrics[v1], metrics[v2])
        )

        print(template.format_map(arguments))


def _print_header(architecture, lines_nb):
    print(r'\multirow{{{n}}}{{*}}{{{a}}}'.format(a=architecture, n=lines_nb))


def _print_footer():
    print(r'\hline')


def _print_table(setups):
    for arch, arch_setups in setups.items():
        _print_header(arch, len(arch_setups))
        _print_ratios(arch_setups)
        _print_footer()


if __name__ == '__main__':
    _print_table(_group_setups(_RESULTS_FILENAME))
