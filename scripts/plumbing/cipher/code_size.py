#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2021 Kévin Le Gouguec

from argparse import ArgumentParser
from pathlib import Path
import re
from subprocess import run, PIPE

from felics.errors import FelicsError


def parse_arguments():
    parser = ArgumentParser()
    parser.add_argument('-o', '--output', type=Path)
    return parser.parse_args()


class ImplementationInfo:
    def __init__(self, path):
        lines = Path(path).read_text().splitlines()
        kv_pairs = (
            l.split(':', maxsplit=1)
            for l in lines
            if l and not l.isspace() and not l.startswith('#')
        )
        self._fields = {
            k.strip(): v.strip() for k, v in kv_pairs
        }

    def _code_size_specs(self, field):
        # The section has the form: FILESPEC[, FILESPEC…].
        files = (f.strip() for f in self._fields[field].split(','))

        # Each file spec has the form: NAME[!EXCEPTION[!EXCEPTION…]].
        # Split each spec into [NAME, EXCEPTION, EXCEPTION…].
        specs = (f.split('!') for f in files)

        return {f: exceptions for f, *exceptions in specs}

    @property
    def encryption_files(self):
        return self._code_size_specs('EncryptCode')

    @property
    def decryption_files(self):
        return self._code_size_specs('DecryptCode')


SYSV_TEXT_SECTIONS = (
    'text', 'data', 'rodata', 'progmem.data', 'eh_frame', 'note'
)

SYSV_SIZE_RE = (
    '^'
    r'(?P<section>\.(?:{section_re}))'
    r'(?:\.(?P<symbol>[\w.]+))?'
    ' +'
    r'(?P<size>\d+)'
    ' +'
    r'(?P<addr>\d+)'
    '$'
).format(section_re='|'.join(SYSV_TEXT_SECTIONS))

SYSV_SIZE_PATTERN = re.compile(SYSV_SIZE_RE, flags=re.MULTILINE)


class InvalidCodeSize(FelicsError):

    def __init__(self, file, actual, expected):
        super().__init__()
        self._file = file
        self._actual = actual
        self._expected = expected

    def __str__(self):
        template = '''
Adding the text and data sections from {s._file} yields {s._expected}
bytes, but only {s._actual} bytes were found by iterating over these
subsections:
- {sections}
It is likely that this list of subsections must be appended.'''
        return template.format(
            s=self,
            sections='\n- '.join(SYSV_TEXT_SECTIONS)
        )


def size(*args):
    return run(
        ('size',)+args, stdout=PIPE, universal_newlines=True, check=True
    ).stdout


def expected_size(elf_file):
    header_line, values_line = size(elf_file).splitlines()
    header = header_line.split()
    values = values_line.split()
    return sum(
        int(values[i]) for i, name in enumerate(header)
        if name in {'text', 'data'}
    )


def section_name(match):
    # Assume there are no symbol collisions across sections, e.g. no
    # file contains both .text.foo and .rodata.foo.
    if match['symbol'] is not None:
        return match['symbol']
    return match['section']


def parse_sizes(elf_file):
    matches = (
        m.groupdict() for m in SYSV_SIZE_PATTERN.finditer(size('-A', elf_file))
    )

    section_sizes = {
        section_name(m): int(m['size']) for m in matches
    }

    # Sanity check: our list of subsections might not be exhaustive.
    # Check that our sum is at least equal to text+data as reported by
    # plain `size`.
    # Allow EXPECTED < ACTUAL because plain `size` does not seem to
    # account for every RO section listed by `size -A`.

    expected = expected_size(elf_file)
    actual = sum(section_sizes.values())
    if actual < expected:
        raise InvalidCodeSize(elf_file, actual, expected)

    # Some compiler optimizations (e.g. constant propagation, SRA)
    # generate specialized clones of some sections (e.g. for a section
    # .text.foo: .text.foo.constprop.0, .text.foo.isra.42).  Remove
    # the clones and add their sizes to the original section.

    for name in section_sizes.copy():
        dot = name.find('.')
        if dot == -1:
            continue

        original_name = name[:dot]
        original_size = section_sizes.get(original_name, 0)

        subsection_size = section_sizes.pop(name)
        section_sizes[original_name] = original_size + subsection_size

    return section_sizes


def sum_files(sizes, files):
    return sum(
        value
        for f, exceptions in files.items()
        for section, value in sizes[f].items()
        if section not in exceptions
    )


def main(arguments):
    # Assume we are running from the "build" directory.
    implem_info = ImplementationInfo('../source/implementation.info')

    encryption_files = implem_info.encryption_files
    decryption_files = implem_info.decryption_files
    all_files = set(encryption_files) | set(decryption_files)

    file_sizes = {
        f: parse_sizes('{f}.o'.format(f=f)) for f in all_files
    }

    encryption_sum = sum_files(file_sizes, encryption_files)
    decryption_sum = sum_files(file_sizes, decryption_files)
    total_sum = sum_files(file_sizes, dict.fromkeys(all_files, ()))

    serialized_sums = '{encryption} {decryption} {total}'.format(
        encryption=encryption_sum,
        decryption=decryption_sum,
        total=total_sum,
    )

    arguments.output.write_text(serialized_sums)


if __name__ == '__main__':
    main(parse_arguments())
