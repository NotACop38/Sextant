# Workflows

Sextant has four subcommands: `infer`, `inspect`, `export`, and `bench`. This
page documents each one and the options that matter day to day. The typical flow
is `infer` to produce a report, then `inspect` to read samples through it and
`export` to generate parsers from it.

## `infer`: from samples to a verified report

```
sextant infer <inputs...> [options]
```

`infer` ingests one or more files, directories, or glob patterns, runs inference,
and prints a scored field map. With `--out` it writes a machine-readable JSON
report that `inspect` and `export` consume.

### Options

| Option | Meaning |
|---|---|
| `<inputs...>` | One or more files, directories, or glob patterns to analyze. Required. |
| `-r`, `--recursive` | Descend into subdirectories when an input is a directory. |
| `--max-bytes-per-sample <N>` | Cap the bytes read from any single sample. |
| `--max-total-bytes <N>` | Cap the total bytes read across all samples. |
| `--no-llm` | Statistics-only, with no language model and zero network egress. |
| `--timeout <SECONDS>` | Wall-clock cap for executing the structure against each sample. |
| `--transport <tcp\|udp>` | Treat inputs as packet captures and extract this transport's payloads. Requires `--port`. |
| `--port <N>` | The port that identifies the protocol in a capture. Requires `--transport`. |
| `--out <FILE>` | Write the JSON report to this path. |

### Examples

```bash
# A directory of samples, offline, writing a report.
sextant infer ./samples --no-llm --out report.json

# A glob, with a per-sample byte cap.
sextant infer './captures/*.bin' --max-bytes-per-sample 65536 --out report.json

# A protocol from a packet capture (see "Protocols" below).
sextant infer capture.pcap --transport tcp --port 502 --out modbus.json
```

### Reading the output

The summary reports the chosen hypothesis and its fit score, broken into three
dimensions:

- **coverage**: how much of each sample the structure accounts for.
- **consistency**: whether internal relationships hold, such as a length field
  matching the bytes it governs, a count matching the number of records, or a
  checksum verifying over its covered range.
- **generality**: whether the same structure fits across all samples, not just
  one.

Each field carries a heuristic confidence value and evidence. High confidence
does not prove semantic meaning or correctness on unseen data. The field map
is honest about what was checked and what was assumed. See
[How it works](how-it-works.md).

### Protocols

To infer a protocol from a packet capture, pass a `.pcap` or `.pcapng` file with
`--transport` and `--port`. Sextant extracts the payloads carried by that
transport and port, clusters them into message types, and infers structure over
them. The Wireshark Lua exporter is the natural output for this track.

## `inspect`: read a sample through the field map

```
sextant inspect <report.json> --sample <file> [--color]
```

`inspect` renders a single sample as an annotated hex view: a table of fields
with offset, size, name, role, type, value, and confidence, followed by a hex
dump. It is how you read raw bytes through the inferred structure.

| Option | Meaning |
|---|---|
| `<report.json>` | A report produced by `infer --out`. Required. |
| `--sample <file>` | The sample to render through the report. Required. |
| `--color` | Color each field's bytes in the hex dump and its name in the table. |

```bash
sextant inspect report.json --sample ./samples/sample_01.bin --color
```

## `export`: generate a parser specification

```
sextant export <report.json> --format <fmt> [--out <file>] [--cross-validate <dir>]
```

`export` validates the report IR and translates its supported structure into
editable parser source. Imported scores and labels are untrusted metadata. Ordinary
export does not rerun the original samples or execute the generated parser.
Unsupported target layouts return an error. Output goes to standard output
unless you pass `--out`.

| Option | Meaning |
|---|---|
| `<report.json>` | A report produced by `infer`. Required. |
| `--format <fmt>` | Target parser format: `kaitai`, `imhex`, `wireshark`, or `010`. Required. |
| `--out <FILE>` | Write the generated parser here. Defaults to standard output. |
| `--cross-validate <DIR>` | Kaitai only: compile the spec and parse the samples in `DIR` through it as an independent check. Optional. |

The four formats:

| Format | Flag value | Extension | Use it for |
|---|---|---|---|
| Kaitai Struct | `kaitai` | `.ksy` | A portable spec that compiles to parsers in many languages. |
| ImHex pattern | `imhex` | `.hexpat` | Interactive visual analysis in the ImHex editor. |
| Wireshark dissector | `wireshark` | `.lua` | Decoding a protocol live in Wireshark. |
| 010 Editor template | `010` | `.bt` | Templated hex inspection in 010 Editor. |

```bash
sextant export report.json --format kaitai    --out format.ksy
sextant export report.json --format wireshark --out dissector.lua
```

### Optional Kaitai cross-validation

The `--cross-validate` option is an independent second opinion. It compiles the
generated `.ksy` with the Kaitai Struct compiler and parses your samples through
the compiled parser. This needs the `kaitai-struct-compiler` (and a JVM) on your
`PATH`. It is never required: a missing compiler is reported as skipped, not
failed, and the core export works without it.

```bash
sextant export report.json --format kaitai --out format.ksy \
  --cross-validate ./samples
```

## `bench`: measure accuracy against ground truth

```
sextant bench [--corpus <dir>] [--out <results.json>]
```

`bench` runs statistics-only inference over the ground-truth corpus and reports
field-boundary precision, recall, and F1, exact-boundary recovery, role and type
accuracy, and native IR validity. The same samples are used for inference and
evaluation; no external parser or held-out generalization is measured. It is fully offline. With `--out` it writes
machine-readable results. It exits non-zero if any configured accuracy target is
missed, which is how CI guards against regressions.

| Option | Meaning |
|---|---|
| `--corpus <DIR>` | The corpus directory to evaluate. Defaults to the repository corpus. |
| `--out <FILE>` | Write machine-readable JSON results to this path. |

```bash
sextant bench
```

The numbers published in the project README are generated by this command, not
written by hand.

## Exit codes

Sextant uses the exit codes defined in PRD Section 14: `0` success, `1` usage
error, `2` input error, `3` inference produced no usable hypothesis, `4` export
error, `5` internal error. These make Sextant easy to drive from scripts and CI.

## Limits and success status

Inference exits successfully only when the native IR fully covers every retained
sample, all constraints pass, and there are no gaps, overlaps, or trailing bytes.
A diagnostic report is still written when verification fails (exit code 3).
`--timeout` limits each execution, not the entire inference pipeline. TCP capture
analysis currently uses segment payloads without stream reassembly.

Without `--force`, output creation refuses existing files and symlinks. The
benchmark rejects manifests above 1 MiB, more than 256 samples, samples above
64 MiB, more than 256 MiB retained bytes per format, or more than 100,000 expanded
ground-truth fields. Sample paths must remain within their format directory and
actual sizes must match the manifest. Oversized samples are rejected, not clipped.
