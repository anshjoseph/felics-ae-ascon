# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from felics.architecture import Architecture


ARCHITECTURES = (
    Architecture(8, 'AVR', 'AVR ATmega128'),
    Architecture(16, 'MSP', 'MSP430F1611'),
    Architecture(32, 'ARM', 'ARM Cortex-M3'),
    Architecture(32, 'NRF52840', 'NRF52840 Cortex-M4'),
    Architecture(32, 'STM32L053', 'STM32L053 Cortex-M0+'),
    Architecture(64, 'PC', 'PC')
)

METRICS = ('code_size', 'code_ram', 'code_time')
