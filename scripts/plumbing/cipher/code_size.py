#!/usr/bin/env python3

from argparse import ArgumentParser
from pathlib import Path
import re
from subprocess import run, PIPE
from sys import argv

from felics.errors import FelicsError


def parse_arguments():
    parser = ArgumentParser()
    parser.add_argument('-o', '--output', type=Path)
    return parser.parse_args()


class ImplementationInfo:
    def __init__(self, path):
        content = Path(path).read_text()
        kv_pairs = (
            l.split(':', maxsplit=1)
            for l in content.splitlines()
            if l and not l.isspace()
        )
        self._fields = {
            k.strip(): v.strip() for k, v in kv_pairs
        }

    def _split(self, field, sep):
        return tuple(i.strip() for i in self._fields[field].split(sep))

    @property
    def encryption_files(self):
        return self._split('EncryptCode', ',')

    @property
    def decryption_files(self):
        return self._split('DecryptCode', ',')


SYSV_TEXT_SECTIONS = (
    'text', 'data', 'rodata', 'progmem.data', 'eh_frame'
)

SYSV_SIZE_RE = (
    '^'
    r'(?P<section>\.(?:{section_re}))'
    r'(?:\.(?P<symbol>[\w.]+))?'
    ' +'
    '(?P<size>\d+)'
    ' +'
    '(?P<addr>\d+)'
    '$'
).format(section_re='|'.join(SYSV_TEXT_SECTIONS))

SYSV_SIZE_PATTERN = re.compile(SYSV_SIZE_RE, flags=re.MULTILINE)


class InvalidCodeSize(FelicsError):

    def __init__(self, file, actual, expected):
        self._file = file
        self._actual = actual
        self._expected = expected

    def __str__(self):
        return '''
Adding the text and data sections from {s._file} yields {s._expected}
bytes, but only {s._actual} bytes were found by iterating over these
subsections:
- {sections}
It is likely that this list of subsections must be appended.'''.format(
            s=self,
            sections = '\n- '.join(SYSV_TEXT_SECTIONS)
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
    expected = expected_size(elf_file)
    actual = sum(section_sizes.values())
    if actual != expected:
        raise InvalidCodeSize(elf_file, actual, expected)

    return section_sizes


def sum_files(sizes, files):
    return sum(value for f in files for value in sizes[f].values())


def main(arguments):
    # Assume we are running from the "build" directory.
    implem_info = ImplementationInfo('../source/implementation.info')

    encryption_files = implem_info.encryption_files
    decryption_files = implem_info.decryption_files
    all_files = set(encryption_files+decryption_files)

    file_sizes = {
        f: parse_sizes('{f}.o'.format(f=f)) for f in all_files
    }

    serialized_sums = '{encryption} {decryption} {total}'.format(
        encryption=sum_files(file_sizes, encryption_files),
        decryption=sum_files(file_sizes, decryption_files),
        total=sum_files(file_sizes, all_files)
    )

    arguments.output.write_text(serialized_sums)


if __name__ == '__main__':
    main(parse_arguments())
