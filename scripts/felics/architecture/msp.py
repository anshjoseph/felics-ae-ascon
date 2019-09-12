# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from .architecture import Architecture


class Msp(Architecture):

    @property
    def codename(self):
        return 'MSP'

    @property
    def name(self):
        return 'MSP430F1611'

    @property
    def size(self):
        return 16

    def check_setup(self): pass
