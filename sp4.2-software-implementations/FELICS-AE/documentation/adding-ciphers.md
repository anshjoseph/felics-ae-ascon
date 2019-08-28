Adding cipher implementations
=============================

To add a new cipher implementation:

1. Create a new folder under `source/ciphers`, named according to this
   convention: `${cipher_name}_v{version}`
    - `cipher_name`: a string identifying the algorithm
    - `version`: a string identifying the implementation's purpose
      (e.g. `ref` for the reference version, `msp` for an
      implementation optimized for the MSP430 microcontroller)

2. Add the following files, using the templates provided in
   `source/ciphers/CipherName_v01`:
    - `api.h`: header which defines sizes for keys, nonces and tags
    - one file for encryption (e.g. `encrypt.c`), and another for
      decryption (e.g. `decrypt.c`); the former must define
      `crypto_aead_encrypt()` and the latter `crypto_aead_decrypt()`
    - `implementation.info`: metadata used by the framework's scripts
    - `test_vectors.c`: contains byte arrays for plaintext, associated
      data, key, nonce and ciphertext

3. To ensure code size is measured accurately,
    - use different files for functions that are used only during
      encryption or only during decryption,
    - add these files to `implementation.info`'s `EncryptCode` and
      `DecryptCode` sections (comma-separated, without extension).

4. To make your implementation portable across all four platforms, use
   the types defined in `felics/cipher.h`. These types provide uniform
   macros for platform-specific types, memory access functions, and
   alignment.

5. Optionally, to reduce duplication across versions, you may want to
   use symbolic links; the `source/ciphers/.templates` folder stores
   version-independent files, which can be linked to.
