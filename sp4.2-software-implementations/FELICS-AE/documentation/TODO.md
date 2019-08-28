# Cipher implementations

## Limit differences with reference implementations

The more FELICS-AE requires manual tweaks to integrate an algorithm's
implementation (reference or optimized), the more work it represents
for an integrator. It also complicates the job of an auditor checking
for differences between the original code and the FELICS version.

### Add support for finer-grained code-size measurement

As things stand, if some files in reference implementations happen to
contain both encryption and decryption code, they must be split.

`size`, `nm` and `readelf` can all display the code size for specific
functions, so it should be possible to keep encryption and decryption
functions together in a single file, and specify which to include (or
remove) from the code-size tally in the implementation metadata file.

## Add support for multiple revisions of an algorithm

Possible solutions:

1. Put the version number in the algorithm's folder name,
   e.g. `Lilliput-I-128-v1_vfelicsref`.

2. Have subfolders under the algorithm's folder,
   e.g. `Lilliput-I-128_vfelicsref/v1`.

## Support multiple test vectors

With a single vector we have as many blind spots as code branches.

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

## Add a script to identify versions of dependencies

Then add this information to the JSON results file, for better
traceability.

## Bring back scenarios

E.g. add a couple of `--mlen=LIST` and `--alen=LIST` parameters to
`felics-run` (and `collect_ciphers_metrics.sh`).

## Implement profiling

So that implementers can identify bottlenecks.

# Miscellaneous

## Update copyright statements

From University of Luxembourg, 2015, to PACLIDO consortium, 2019.
