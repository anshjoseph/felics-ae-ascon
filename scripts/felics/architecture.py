# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from collections import namedtuple


Architecture = namedtuple(
    'Architecture',
    (
        'codename',
        'name',
        'size',
    )
)
