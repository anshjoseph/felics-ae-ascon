Running benchmarks
==================

The `scripts` folder provides several programs that help with running
benchmarks and analyzing their results.

The documentation for these scripts can be consulted by running them
with `--help`.

`felics-run`
------------

This script runs ROM, RAM and cycle count measurements for every
requested cipher, on every requested architecture.

The results are stored as JSON files in the `results` folder. These
files contain:

- some metadata about the circumstances of the benchmark:
    - abbreviated commit ID,
    - branch,
- the actual benchmark data, organized as a list of "setups". Each
  setup is defined by:
    - the algorithm's name,
    - the hardware platform,
    - the implementation version,
    - compiler options,
    - the measurements (ROM size, RAM size, cycle count).

These JSON files can then be analyzed or exported into other formats
by other scripts.

`felics-publish`
----------------

This script parses the setups in a JSON file, and either displays them
to the console, or exports them to another format, such as:

- HTML tables,
- LaTeX tables,
- XLSX or OpenDocument spreadsheet (requires the `pyexcel-xlsx` and
  `pyexcel-ods` packages, respectively).

Various options allow the user to filter or sort setups, or pick the
information to display. For example:

``` sh
options=(
    # Only show results for the reference version of cipher Foobar.
    --filter='cipher_name=Foobar.+,version=ref'
    # Sort by CFLAGS, then by performance in terms of execution time.
    --sort-by='compiler_options,code_time'
    # Remove the "version" column.
    --info='-version'
    # Convert to spreadsheet.
    --out=foobar-ref.ods
)

./felics-publish some-results.json ${options[@]}
```

`felics-compare`
----------------

This script computes and displays the evolution between two sets of
performance metrics, with an optional threshold to hide evolutions
that one may not find significant. Results are highlighted (green for
reduced figures, red for increased ones) so that performance
regressions can be identified at a glance.

`felics-compare-revisions`
--------------------------

This script automatically checks out two Git revisions, runs the
requested benchmarks, then compares the results.
