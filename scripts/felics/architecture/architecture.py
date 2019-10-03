# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from abc import ABC, abstractmethod


class Architecture(ABC):
    """Interface for microcontroller architecture.

    This class exists to provide some genericity over architectures,
    as well as handle some basic properties such as

    - using the codename when formatted into strings,
    - sorting according to word size.
    """

    def __lt__(self, other):
        sortable = lambda a: (a.size, a.codename)
        return sortable(self) < sortable(other)

    def __str__(self):
        return self.codename

    def __repr__(self):
        return self.codename

    @property
    @abstractmethod
    def codename(self): pass

    @property
    @abstractmethod
    def name(self): pass

    @property
    @abstractmethod
    def size(self): pass

    @abstractmethod
    def check_setup(self): pass
