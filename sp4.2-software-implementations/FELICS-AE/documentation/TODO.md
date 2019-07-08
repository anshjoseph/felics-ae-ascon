# Remove `constants.c` files

Done for Lilliput-AE.

# Remove `upload-*` target from Makefiles

Use dedicated script; no use cluttering makefiles. Used by
`cipher_execution_time.sh` and `check_cipher.sh`.

# Port more scripts to Python

Advantages over Bash:

- better error-reporting (fast, loud and precise failures)
- automatic script usage documentation

# Convert `implementation.info` to JSON

So that hypothetical Python scripts can simply `json.load()` them into
native types instead of parsing them manually.

# Use `crypto_aead` API as entry point

Instead of the `Encrypt`/`Decrypt` functions.

# Add support for multiple revisions of an algorithm

Possible solutions:

1. Put the version number in the algorithm's folder name,
   e.g. `Lilliput-I-128-v1_vfelicsref`.

2. Have subfolders under the algorithm's folder,
   e.g. `Lilliput-I-128_vfelicsref/v1`.
