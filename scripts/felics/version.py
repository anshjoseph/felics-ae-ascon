# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2019 Airbus Cybersecurity SAS

from os import path
from sys import argv
from warnings import warn


_REPO = None
_VERSION = 'unknown'
_VERSION_FILE = path.join(
    path.dirname(path.realpath(__file__)),
    path.pardir,
    path.pardir,
    'VERSION'
)


class UnknownVersionWarning(Warning):
    def __str__(self):
        return '''\
Cannot determine version.

If you are using the Git repository, perhaps install python3-git
(Ubuntu) or GitPython (PyPI)?

Otherwise, your distribution of FELICS-AE should include a top-level
VERSION file.
'''


try:
    import git
    _REPO = git.Repo(path=__file__, search_parent_directories=True)

except:
    if not path.exists(_VERSION_FILE):
        warn(UnknownVersionWarning())

    else:
        with open(_VERSION_FILE) as v:
            _VERSION = v.read()


def version():
    if _REPO is None:
        return _VERSION

    return _REPO.git.describe(always=True)


def branch():
    if _REPO is None:
        return 'release'

    try:
        return _REPO.git.symbolic_ref('HEAD', short=True)
    except git.GitCommandError:
        return 'DETACHED'


def commit():
    if _REPO is None:
        return version()

    return _REPO.git.show(format='format:%h', no_patch=True)


def _main(arguments):
    template = '{version}'
    if arguments:
       template = arguments[0]

    info = {
        'commit': commit(),
        'branch': branch(),
        'version': version()
    }

    print(template.format_map(info))


if __name__ == '__main__':
    _main(argv[1:])
