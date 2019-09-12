# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from .architecture import Architecture


class Avr(Architecture):

    @property
    def codename(self):
        return 'AVR'

    @property
    def name(self):
        return 'AVR ATmega128'

    @property
    def size(self):
        return 8

    def check_setup(): pass
