# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from felics import METRICS


def _format_diff(diff, value1, value2):
    red = '\N{ESCAPE}[01;31m'
    green = '\N{ESCAPE}[01;32m'
    reset = '\N{ESCAPE}[0m'

    template = '{color}{diff:+.2%}{reset} ({v1} {arrow} {v2})'
    arguments = {'diff': diff, 'v1': value1, 'v2': value2, 'reset': reset}

    if diff < 0:
        arguments['color'] = green
        arguments['arrow'] = '↘'
    else:
        arguments['color'] = red
        arguments['arrow'] = '↗'

    return template.format_map(arguments)


def _compute_diffs(data1, data2, threshold=0):
    differences = (
        (m, (data2[m]-data1[m]) / data1[m])
        for m in METRICS
    )

    return {
        m: _format_diff(diff, data1[m], data2[m])
        for m, diff in differences
        if abs(diff) > threshold
    }


def _format_lines(diffs):
    return '\n'.join(
        '    {m}: {d}'.format(m=m, d=diffs[m])
        for m in sorted(diffs, key=METRICS.index)
    )


def format_differences(pairs, formatter, threshold=0):
    diff_gen = (
        (setup1, setup2, _compute_diffs(setup1, setup2, threshold))
        for setup1, setup2 in pairs
    )

    return tuple(
        formatter(setup1, setup2, _format_lines(diffs))
        for setup1, setup2, diffs in diff_gen
        if diffs
    )
