# Cipher implementations

## Use `crypto_aead` API as entry point

Instead of the `Encrypt`/`Decrypt` functions.

## Remove `constants.c` files

They are relics of FELICS's previous code-size measuring logic, and
they add noise when diff'ing a cipher's reference implementation
vs. its FELICS integration.

Done for Lilliput-AE.

## Remove `encrypt.c` and `decrypt.c` files

They force the integrator to make gratuitious changes to the reference
implementation.

`cipher.mk` makes no assumption on how C files are named; it just
compiles all `.c` and `.S` files it finds in the `source` folder.

`cipher_code_size.sh` includes some special-casing to measure the ROM
of `encrypt.o` and `decrypt.o`; removing the assumption that these
files exist should simplify the code.

## Add `felics-` prefix to headers required by FELICS-AE

So that the integrator does not have to rename files that happen to be
named "cipher.h" or "constants.h" in the reference implementation.

## Add support for multiple revisions of an algorithm

Possible solutions:

1. Put the version number in the algorithm's folder name,
   e.g. `Lilliput-I-128-v1_vfelicsref`.

2. Have subfolders under the algorithm's folder,
   e.g. `Lilliput-I-128_vfelicsref/v1`.

# Scripts & tooling

## Port more scripts to Python

Advantages over Bash:

- better error-reporting (immediate, loud and precise failures)
- automatic script usage documentation

## Convert `implementation.info` to JSON

So that hypothetical Python scripts can simply `json.load()` them into
native types instead of parsing them manually.

## Move some constants away from constants.sh

Constants that are used in a single script belong in that script;
keeping them anywhere else complicates inspection and maintenance.

## Simplify AVR cycle measurements

Stop using the "second identifier; use the `<-(RET )` line.

# Miscellaneous

## Update copyright statements

From University of Luxembourg, 2015, to PACLIDO consortium, 2019.
