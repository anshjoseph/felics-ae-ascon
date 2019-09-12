# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from .architecture import Architecture


class Pc(Architecture):

    @property
    def codename(self):
        return 'PC'

    @property
    def name(self):
        return 'PC'

    @property
    def size(self):
        return 64

    def check_setup(self): pass
