# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from getpass import getuser
import os
from os import path

from ..errors import FelicsError
from .architecture import Architecture


_DEVICE = '/dev/ttyACM0'


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

    def check_setup(self):
        if not path.exists(_DEVICE):
            raise FelicsError(
                'Cannot find {dev}; is your ARM device plugged in?'.format(dev=_DEVICE)
            )

        if not os.access(_DEVICE, os.W_OK):
            raise FelicsError((
                'Cannot write to {dev}; are you in the "dialout" group? '
                'Cf. documentation/setup.md § ARM-specific.'
            ).format(dev=_DEVICE))
