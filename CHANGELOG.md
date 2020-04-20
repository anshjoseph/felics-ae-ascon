# Changelog

## [Unreleased]

### Added

- The nRF52840 (ARM Cortex-M4) and STM32L053 (ARM Cortex-M0+) 32-bit
  microcontrollers are now supported. As with the ARM Cortex-M3,
  physical devices plugged in `/dev/ttyACM0` are required.

- Documents recounting the adaptation process from FELICS to FELICS-AE
  have been added to `documentation/nist-lwc-workshop-2019`, and
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

- Implementations of AES-128-GCM have been ported from SUPERCOP:
    - `ref`: cross-platform software implementation,
    - `aes-ni`: x86-exclusive implementation relying on the AES-NI
      processor instructions.

### Changed

- AEAD implementations no longer need to define additional `Encrypt`
  and `Decrypt` functions; FELICS-AE will call their `crypto_aead_…`
  functions directly.

  In order to make the API more precise and improve performance on
  low-end platforms,
    - the signature of the `crypto_aead_…` functions has been adapted
      to use `uint8_t` (resp. `size_t`) instead of `unsigned char`
      (resp. `unsigned long long`),
    - the unused `nsec` parameter has been removed.

- The list of source file basenames reserved by FELICS-AE has shrunk
  down to "`test_vectors`" and "`felics_*`". AEAD implementations can
  now have files named e.g. `cipher.[ch]` or `common.[ch]`.

- Implementations no longer need to include files named `encrypt.c`
  and `decrypt.c`.

- Implementations must now define their own nonce in `test_vectors.c`;
  FELICS-AE no longer hardcodes it to $0^{|N|}$.

- The data section of the object files named in implementation.info's
  EncryptCode field now contribute to the RAM footprint.

### Removed

- Algorithms COLM, MORUS, AES-OCB and Deoxys have been removed, in
  order to lighten the maintenance burden and increase the focus on
  lightweight algorithms.

- `build` folders have been removed from the repository. They are
  still generated during the benchmark process, but it is no longer
  necessary to add them when adding implementations.

## [0.1.0]

### Added

- This changelog, following conventions from
  <https://keepachangelog.com>.

[Unreleased]: https://gitlab.inria.fr/minier/felics-ae/compare/0.1.0...master
[0.1.0]: https://gitlab.inria.fr/minier/felics-ae/tags/0.1.0
