# Changelog

## [Unreleased]

### Added

- The new `scripts/dump-parameters.py` script generates a LaTeX table
  enumerating the bit sizes of every parameter of every algorithm
  tested in a result file.
- Provide instructions and utility script to setup J-Link and dialout group
  for ARM benchmarks in Docker containers.
- Provide instructions and utility script to setup sudoers and
  cpupower for PC benchmarks in Docker containers.

## [0.3.0] – 2021-04-14

### Algorithms

- Implementations of the following NIST round 2 candidates have been
  added:
    - ForkAE
    - GIFT-COFB
    - Grain
    - LOCUS
    - LOTUS
    - Pyjamask
    - Romulus
    - SKINNY-AEAD
    - SUNDAE-GIFT
    - Saturnin
    - SPARKLE
    - Subterranean
    - Xoodyak

### Fixed

- Source filenames with hyphens are no longer a problem.
- Restore the correct CPU governor; do not assume "powersave".

## [0.2.0] – 2020-05-15

### Added

- `felics-update OLD-RESULTS NEW-RESULTS` no longer ignores setups
  exclusively found in `NEW-RESULTS`.

- Fields in the `EncryptCode` and `DecryptCode` sections of
  `implementation.info` can now be completed with one or more
  `!symbol` suffixes: each `symbol` will be subtracted from the ELF
  file's code size for this specific operation.  This can be used to
  discount e.g. decryption-specific code in a source file used for
  both encryption and decryption.

  This mechanism is meant to make it easier to integrate
  implementations: instead of requiring that encryption, decryption
  and common code be isolated in dedicated files, algorithm sources
  can now be integrated as-is; functions and variables irrelevant to
  encryption (resp. decryption) can now simply be blacklisted in
  `implementation.info`'s `EncryptCode` field (resp. `DecryptCode`).

  See `documentation/adding-ciphers.md` for more information.

- `felics-compare` can now filter compilation options.

#### Algorithms

- Implementations of Lilliput-Ⅱ have been rid of Lilliput-TBC's
  decryption code.

- Implementations of AES-128-GCM have been ported from SUPERCOP:
    - `ref`: cross-platform software implementation,
    - `aes-ni`: x86-exclusive implementation relying on the AES-NI
      processor instructions.

### Fixed

- RAM measurement could sometimes fail on PC, especially with a cold
  cache, because we used to spawn an asynchronous GDB script, wait one
  second, and assume that GDB was done. The script is now run
  synchronously.

### Changed

- The data section of the object files named in implementation.info's
  EncryptCode and DecryptCode fields now contribute to the RAM
  footprint.

### Removed

- `build` folders have been removed from the repository. They are
  still generated during the benchmark process, but it is no longer
  necessary to add them when adding implementations.

- It is no longer necessary to define `BlockSize` in
  `implementation.info`.

  This "block size" information was used by the original FELICS
  framework as part of the RAM footprint measurement process; it is
  not obvious that this information is meaningful in the case of AEAD
  ciphers which process inputs of arbitrary lengths.  Furthermore,
  FELICS's memory-spraying mechanism should be enough to measure the
  stack consumption accurately.

## [0.1.0] – 2019-10-03

### Added

- The nRF52840 (ARM Cortex-M4) and STM32L053 (ARM Cortex-M0+) 32-bit
  microcontrollers are now supported. As with the ARM Cortex-M3,
  physical devices plugged in `/dev/ttyACM0` are required.

- Documents recounting the adaptation process from FELICS to FELICS-AE
  have been added in `documentation/nist-lwc-workshop-2019`, and
  presented at the [NIST LWC workshop 2019].

- In `scripts/docker`, a turnkey Docker image can now be generated
  with `create-image.sh`, and deployed with `scripts/docker/`.
  Alternately, you may prefer using the lower-level
  `*-dependencies.sh` scripts to fetch and install FELICS-AE's
  numerous software dependencies.

- `felics-publish` can now translate column headers in other
  languages; so far only English and French are supported.

[NIST LWC workshop 2019]: https://csrc.nist.gov/Events/2019/Lightweight-Cryptography-Workshop-2019

#### Algorithms

- Implementations of Lilliput-AE now match version 1.1 of the
  specification.

### Changed

- AEAD implementations are now expected to follow the SUPERCOP
  conventions (also used for the CAESAR competition and the NIST LWC
  standardization process).  The top-level `Encrypt` and `Decrypt`
  functions are no longer required; instead FELICS-AE will look for:

    - the `crypto_aead_encrypt` and `crypto_aead_decrypt` functions;
      in order to make the API more precise and improve performance on
      low-end platforms, their signature has been adapted as follows:
        - `unsigned char*` parameters are now `uint8_t*`;
          `unsigned long long` parameters are now `size_t`;
        - the unused `nsec` parameter has been removed;

    - a file named `api.h` where the following constants are defined:
        - `CRYPTO_KEYBYTES`,
        - `CRYPTO_ABYTES`,
        - `CRYPTO_NPUBBYTES`.

- Implementations no longer need to include files named `encrypt.c`
  and `decrypt.c`.

- Implementations must now define their own nonce in `test_vectors.c`;
  FELICS-AE no longer hardcodes it to $0^{|N|}$.

- The list of source file basenames reserved by FELICS-AE has shrunk
  down to "`test_vectors`" and "`felics_*`". AEAD implementations can
  now have files named e.g. `cipher.[ch]`, `common.[ch]` or
  `constants.h`.

- Implementations no longer have to define `KEY_SIZE` and `BLOCK_SIZE`
  in `constants.h`; it is still required to define `BlockSize` in
  `implementation.info`

### Removed

- Algorithms COLM, MORUS, AES-OCB and Deoxys have been removed, in
  order to lighten the maintenance burden and increase the focus on
  lightweight algorithms.

## [0.0.1] – 2019-07-03

### Added

- This changelog, following conventions from
  <https://keepachangelog.com>.

[Unreleased]: https://gitlab.inria.fr/minier/felics-ae/compare/0.3.0...master
[0.3.0]: https://gitlab.inria.fr/minier/felics-ae/compare/0.2.0...0.3.0
[0.2.0]: https://gitlab.inria.fr/minier/felics-ae/compare/0.1.0...0.2.0
[0.1.0]: https://gitlab.inria.fr/minier/felics-ae/compare/0.0.1...0.1.0
[0.0.1]: https://gitlab.inria.fr/minier/felics-ae/tags/0.0.1
