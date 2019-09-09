# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from collections import defaultdict, namedtuple

from felics import ARCHITECTURES_BY_NAME, METRICS


def setup_key(setup, keys):
    fields = setup.copy()
    fields['architecture'] = ARCHITECTURES_BY_NAME[setup['architecture']]
    kwargs = {k: fields[k] for k in keys}
    return namedtuple('SetupKey', keys)(**kwargs)


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


def _format_diffs(diffs):
    return '\n'.join(
        '    {m}: {d}'.format(m=m, d=diffs[m])
        for m in sorted(diffs, key=METRICS.index)
    )


def _format_table(arch, diffs):
    return '\n\n'.join((arch.codename, '\n\n'.join(diffs))) + '\n'


def format_differences(pairs, setup_format, threshold=0):
    # Sort differences by architecture.
    differences = defaultdict(list)

    for setup1, setup2 in pairs:
        diffs = _compute_diffs(setup1, setup2, threshold)

        if not diffs:
            continue

        text = '{setup}\n{diffs}'.format(
            setup=setup_format.format_map(setup1),
            diffs=_format_diffs(diffs)
        )

        differences[ARCHITECTURES_BY_NAME[setup1['architecture']]].append(text)

    tables = (
        _format_table(arch, differences[arch])
        for arch in sorted(differences)
    )

    return '\n'.join(tables)
