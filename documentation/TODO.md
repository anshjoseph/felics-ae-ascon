# Cipher implementations

## Limit differences with reference implementations

The more FELICS-AE requires manual tweaks to integrate an algorithm's
implementation, the more work it represents for an integrator. It also
complicates the job of an auditor checking for differences between the
original code and the FELICS version.

## Support multiple revisions of an algorithm

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

## Convert `implementation.info` to JSON or YAML

So that we can leverage libraries to translate these files to native
data structures such as sequences and mappings.  JSON is included in
Python's standard library; YAML needs a third-party package but it
allows comments.

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

## Improve handling of ARM devices

- Stop duplicating `/dev/ttyACM0` everywhere (e.g. have one constant
  in a Python module).
- Use `udevadm info -q property` to find relevant devices.
- Stop attaching every USB device on the system to the Docker
  container.
