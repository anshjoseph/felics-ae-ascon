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


def _compute_differences(data1, data2, threshold):
    differences = (
        (m, (data2[m]-data1[m]) / data1[m])
        for m in METRICS
    )

    return {m: diff for m, diff in differences if abs(diff) > threshold}


def format_differences(data1, data2, threshold=0):
    differences = _compute_differences(data1, data2, threshold)

    return tuple(
        _format_diff(differences[m], data1[m], data2[m])
        for m in METRICS
        if m in differences
    )
