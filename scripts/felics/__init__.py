# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from collections import OrderedDict

from felics.architecture import avr, msp, arm, nrf52840, stm32l053, pc


AVR = avr.Avr()
MSP = msp.Msp()
ARM = arm.Arm()
NRF52840 = nrf52840.Nrf52840()
STM32L053 = stm32l053.Stm32l053()
PC = pc.Pc()

ARCHITECTURES = (AVR, MSP, ARM, NRF52840, STM32L053, PC)
ARCHITECTURES_BY_NAME = OrderedDict((a.codename, a) for a in ARCHITECTURES)

METRICS = ('code_size', 'code_ram', 'code_time')
