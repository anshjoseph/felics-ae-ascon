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
    - `data_types.h`: platform-specific declarations for integer types
    - `encrypt.c`, `decrypt.c`: entry points defining the functions
      `crypto_aead_encrypt()` and `crypto_aead_decrypt()`, which will
      be called by the framework
    - `implementation.info`: metadata used by the framework's scripts
    - `test_vectors.c`: contains static byte arrays for plaintext,
      associated data, key and ciphertext (the nonce is set to
      all-zero bytes)

3. To ensure code size is measured accurately,
    - use different files for functions that are used only during
      encryption or only during decryption,
    - add these files to `implementation.info`'s `EncryptCode` and
      `DecryptCode` sections (comma-separated, without extension).

4. To make your implementation portable across all four platforms, use
   the types defined in `cipher.h` (included by `data_types.h`). These
   types provide uniform macros for platform-specific types, memory
   access functions, and alignment.

5. Optionally, to reduce duplication across versions, you may want to
   use symbolic links; the `source/ciphers/.templates` folder stores
   version-independent files, which can be linked to.
