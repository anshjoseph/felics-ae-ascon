# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from collections import namedtuple


_Architecture = namedtuple(
    'Architecture',
    (
        'size',
        'codename',
        'name'
    )
)

class Architecture(_Architecture):
    def __str__(self):
        return self.codename
