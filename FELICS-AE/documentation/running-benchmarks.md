Running benchmarks
==================

The `scripts` folder provides several programs that help with running
benchmarks and analyzing their results.

The documentation for these scripts can be consulted by running them
with `--help`.

`felics-run`
------------

This script runs ROM, RAM and cycle count measurements for every
requested cipher, on every requested architecture.

The results are stored as JSON files in the `results` folder. These
files contain:

- some metadata about the circumstances of the benchmark:
    - abbreviated commit ID,
    - branch,
- the actual benchmark data, organized as a list of "setups". Each
  setup is defined by:
    - the algorithm's name,
    - the hardware platform,
    - the implementation version,
    - compiler options,
    - the measurements (ROM size, RAM size, cycle count).

These JSON files can then be analyzed or exported into other formats
by other scripts.
