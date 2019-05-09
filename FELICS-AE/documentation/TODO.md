# Remove scenario 0

As long as scenarios come with their own test vectors, I do not see
the point of having a "test" scenario.

If all benchmark runs end with sanity checks on their vectors, and
fail loudly if the output is incorrect, then scenario 0 is redundant.

# Port more scripts to Python

Advantages over Bash:

- better error-reporting (fast, loud and precise failures)
- automatic script usage documentation
