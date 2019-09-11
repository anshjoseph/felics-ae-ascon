# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from .architecture import Architecture


class Arm(Architecture):

    @property
    def codename(self):
        return 'ARM'

    @property
    def name(self):
        return 'ARM Cortex-M3'

    @property
    def size(self):
        return 32
