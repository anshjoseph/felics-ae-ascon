FELICS-AE
=========

An adaptation of the [FELICS framework] for Authenticated Encryption.

[FELICS framework]: https://www.cryptolux.org/index.php/FELICS "Fair Evaluation of Lightweight Cryptographic Systems"

Copyright
---------

FELICS is distributed under the GNU General Public License, version 3
or later.

Project Structure
-----------------

### `documentation`

This folder contains instructions for

- setting up the framework: `setup.md`,
- running measurement campaigns and analyzing the results:
  `running-benchmarks.md`,
- adding new algorithms, or new implementations for these algorithms:
  `adding-ciphers.md`.

### `source`

This folder contains both support code (`architecture` and `common`
subfolders) and the source for the evaluated ciphers (`ciphers`
subfolder).

### `scripts`

This folder provides the scripts which compile and run the evaluted
ciphers, measure their performance, and display the measured data.

### `results`

This folder is where measurement scripts store their results by
default.
