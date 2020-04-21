#!/usr/bin/env python3

from argparse import ArgumentParser
from pathlib import Path
import re
from subprocess import run, PIPE
from sys import argv


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


_sysv_text_sections_re = '|'.join((
    'text', 'data', 'rodata', 'progmem.data', 'eh_frame'
))

_sysv_size_re = (
    '^'
    r'(?P<section>\.(?:{section_re}))'
    r'(?:\.(?P<symbol>[\w.]+))?'
    ' +'
    '(?P<size>\d+)'
    ' +'
    '(?P<addr>\d+)'
    '$'
).format(section_re=_sysv_text_sections_re)

SYSV_SIZE_PATTERN = re.compile(_sysv_size_re, flags=re.MULTILINE)

def section_name(match):
    if match['symbol'] is not None:
        return match['symbol']
    return match['section']

def parse_sizes(elf_file):
    size_output = run(
        ('size', '-A', elf_file),
        stdout=PIPE, universal_newlines=True, check=True
    ).stdout

    matches = (
        m.groupdict() for m in SYSV_SIZE_PATTERN.finditer(size_output)
    )

    # Assume that no .text and .rodata symbols share the same name.
    return {
        section_name(m): int(m['size'])
        for m in matches
    }


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
