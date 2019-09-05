# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from felics.architecture import Architecture


ARCHITECTURES = (
    Architecture('AVR', 'AVR ATmega128', 8),
    Architecture('MSP', 'MSP430F1611', 16),
    Architecture('ARM', 'ARM Cortex-M3', 32),
    Architecture('NRF52840', 'NRF52840 Cortex-M4', 32),
    Architecture('STM32L053', 'STM32L053 Cortex-M0+', 32),
    Architecture('PC', 'PC', 64)
)
