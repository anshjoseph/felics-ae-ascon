# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from .architecture import Architecture


class Nrf52840(Architecture):

    @property
    def codename(self):
        return 'NRF52840'

    @property
    def name(self):
        return 'NRF52840 Cortex-M4'

    @property
    def size(self):
        return 32

    def check_setup(self): pass
