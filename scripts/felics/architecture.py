# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from collections import namedtuple


class Architecture(namedtuple('Architecture',
                              ('size', 'codename', 'name'))):
    def __str__(self):
        return self.codename
