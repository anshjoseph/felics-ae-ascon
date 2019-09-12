# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from .architecture import Architecture


class Stm32l053(Architecture):

    @property
    def codename(self):
        return 'STM32L053'

    @property
    def name(self):
        return 'STM32L053 Cortex-M0+'

    @property
    def size(self):
        return 32

    def check_setup(self): pass
