#!/usr/bin/env python3

from collections import defaultdict
from sys import argv
from statistics import median


samples_filename = argv[1]
output_filename = argv[2]


with open(samples_filename) as samples_file:
    samples_content = samples_file.read()


results = defaultdict(list)

for line in samples_content.splitlines():
    key, value = line.split(':')
    results[key].append(int(value))

medians = {key: int(median(values)) for key, values in results.items()}

with open(output_filename, 'w') as output_file:
    for key, median in medians.items():
        output_file.write('{k}: {v}\n'.format(k=key, v=median))
