# Remove `upload-*` target from Makefiles

Use dedicated script; no use cluttering makefiles. Used by
`cipher_execution_time.sh` and `check_cipher.sh`.

# Remove "output" argument to measurement scripts

And assorted default constant.

# Port more scripts to Python

Advantages over Bash:

- better error-reporting (fast, loud and precise failures)
- automatic script usage documentation
