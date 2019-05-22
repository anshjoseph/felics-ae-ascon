# Remove `upload-*` target from Makefiles

Use dedicated script; no use cluttering makefiles. Used by
`cipher_execution_time.sh` and `check_cipher.sh`.

# Simplify measurement scripts

- replace `if [ ! -f $some_output_file ]` and `if [ -f
  $some_error_file ]` in `collect_ciphers_metrics.sh` with `set -e` in
  relevant scripts

Once scripts have become simple enough…

# Port more scripts to Python

Advantages over Bash:

- better error-reporting (fast, loud and precise failures)
- automatic script usage documentation
