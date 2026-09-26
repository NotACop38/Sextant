# Workflows

Sextant has four subcommands: `infer`, `inspect`, `export`, and `bench`. This
page documents each one and its options. The typical flow is `infer` to
produce a report, then `inspect` to read samples through it and `export` to
generate parser specs from it.

## `infer`: from samples to a scored report

```
sextant infer <inputs...> [options]
```

`infer` ingests one or more files, directories, or glob patterns, runs
inference, and prints the chosen hypothesis with its score and field map. With
`--out` it writes the JSON report that `inspect` and `export` read.

### Options

| Option | Meaning |
|---|---|
| `<inputs...>` | One or more files, directories, or glob patterns to analyze. Required. |
| `-r`, `--recursive` | Descend into subdirectories when an input is a directory. |
| `--max-bytes-per-sample <N>` | Cap the bytes read from any single sample. Default 64 MiB. |
| `--max-total-bytes <N>` | Cap the total bytes read across all samples. Default 1 GiB. |
| `--no-llm` | Run statistics-only with zero network egress. This is already the behavior without `--provider`; the flag states the intent and refuses to combine with `--provider`. |
| `--provider <NAME>` | Opt in to the model pass with `anthropic`, `openai`, or `ollama`. Needs a build with the `llm` feature. See [The model pass](#the-model-pass). |
| `--model <ID>` | The model to ask. Defaults to the provider's default model. Requires `--provider`. |
| `--max-llm-calls <N>` | Cap the model calls this run may make. Default 8. Requires `--provider`. |
| `--timeout <SECONDS>` | Wall-clock cap for executing a hypothesis against each sample. Default 5 seconds. It does not bound the whole run. |
| `--transport <tcp\|udp>` | Treat the inputs as packet captures and extract this transport's payloads. Requires `--port`. |
| `--port <N>` | The port that identifies the protocol in a capture. Requires `--transport`. |
| `--max-messages <N>` | Cap the protocol messages extracted across all captures. Default 10,000. |
| `--out <FILE>` | Write the JSON report to this path. |
| `--force` | Allow `--out` to overwrite an existing file or write outside the current working directory. |

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

The summary names the chosen hypothesis and its fit score, which combines
three dimensions:

- **coverage**: how much of each sample the fields explain, without overruns
  or overlaps.
- **consistency**: how many of the constraints the hypothesis claims hold,
  such as a constant signature or a checksum over its covered range.
- **generality**: the fraction of samples that parse to a clean end, so a
  structure that fits one sample but not the others scores low.

Two further lines put the fit in context:

- **structure** estimates how much of the samples the hypothesis explains, as
  one minus the bits it still needs to reproduce them relative to storing them
  raw. A single opaque field can fit perfectly and still scores zero here.
- **N of M sample(s) fully verified** counts the samples that were consumed
  exactly, with no gap, overlap, trailing bytes, or failed constraint, and how
  many checksum checks passed.

Each field carries a confidence and the evidence behind it. Confidence
describes evidence from these samples; it does not prove a field's meaning or
correctness on unseen data. See [How it works](how-it-works.md).

### Exit status

`infer` exits 0 only when the chosen hypothesis fully verifies every retained
sample. When it does not, the report is still printed and written, and `infer`
exits 3 so scripts can tell a partial result from a verified one.

### The model pass

A binary built with the `llm` feature can consult a language model after
statistical inference:

```bash
export ANTHROPIC_API_KEY=...   # or put it in the Sextant config file
sextant infer ./samples --provider anthropic --out report.json
```

The model proposes field names, roles, types, enum meanings, size rules, and a
format-family guess, as structured output. Sextant applies each proposal
through the native executor and keeps it only when the fit over the full
sample set does not drop and no sample loses a check it passed before. The
request holds the candidate field layout and at most 256 bytes from each of
the first four samples.

- The summary reports the mode, the provider and model, the calls and tokens
  used, and how many proposals were accepted and rejected. The same
  information is in the report's `metadata.model`.
- When the call fails or its answer is unusable, the run keeps the
  statistics-only result, prints why on standard error, and records the
  reason in the report.
- Credentials come only from the environment or the config file, never from a
  flag. A missing credential fails before any input is read.
- Setting `SEXTANT_MODEL_CACHE_DIR` caches responses on disk, so repeating a
  run makes no provider call.

[Model data handling](model-data-handling.md) documents exactly what is sent,
the provider settings, and the config file.

### Protocols

To infer a protocol from packet captures, pass `.pcap` or `.pcapng` files with
`--transport` and `--port`. Sextant extracts the payloads carried by that
transport and port, clusters them into message types, associates requests
with responses, and infers structure over the messages. The Wireshark Lua
exporter is the natural output for this track.

Capture inputs are resolved like sample inputs: files, directories (with `-r`
to recurse), and glob patterns, with the same byte caps, and a capture named
twice is read once. A file that a directory or glob sweeps in and that is not
a capture is skipped with a note; a file named explicitly must be a capture.
`--max-messages` caps the messages extracted across all captures, and its note
appears only when messages were actually left out. Sextant notes, per capture,
packets the capture cut short (they are skipped, not treated as complete
messages), TCP keep-alive probes and exact retransmissions it dropped, and any
truncated or corrupt block where reading stopped. When both endpoints use the
selected port, the side that sent first is treated as the client. TCP payloads
are analyzed per segment; streams are not reassembled.

## `inspect`: read a sample through the field map

```
sextant inspect <report.json> --sample <file> [--color]
```

`inspect` renders one sample as an annotated hex view: a table of fields with
offset, size, name, role, type, value, and confidence, followed by a hex dump.

| Option | Meaning |
|---|---|
| `<report.json>` | A report produced by `infer --out`. Required. |
| `--sample <FILE>` | The sample to render through the report. Required. |
| `--color` | Color each field's bytes in the hex dump and its name in the table. |
| `--max-bytes-per-sample <N>` | Cap the bytes read from the sample. Default 64 MiB. |

```bash
sextant inspect report.json --sample ./samples/sample_01.bin --color
```

## `export`: generate a parser specification

```
sextant export <report.json> --format <fmt> [--out <file>] [--cross-validate <dir>]
```

`export` validates the report's IR and translates it into editable parser
source. It does not rerun the samples or execute the generated parser, and it
treats the report's scores and labels as untrusted metadata. A layout the
target cannot express faithfully is refused with an explanation rather than
approximated. Output goes to standard output unless you pass `--out`.

| Option | Meaning |
|---|---|
| `<report.json>` | A report produced by `infer`. Required. |
| `--format <FMT>` | The target: `kaitai`, `imhex`, `wireshark`, or `010`. Required. |
| `--out <FILE>` | Write the generated parser here. Defaults to standard output. |
| `--cross-validate <DIR>` | Kaitai only: compile the spec and parse the samples in `DIR` through it. Optional. |
| `--force` | Allow `--out` to overwrite an existing file or write outside the current working directory. |

The four targets:

| Target | Flag value | Extension | Use it for | Runtime-tested |
|---|---|---|---|---|
| Kaitai Struct | `kaitai` | `.ksy` | A portable spec that compiles to parsers in many languages. | Yes, compiled and run through the Python runtime. |
| Wireshark dissector | `wireshark` | `.lua` | Decoding a protocol in Wireshark. | Yes, run under Lua 5.4. |
| ImHex pattern | `imhex` | `.hexpat` | Interactive analysis in the ImHex editor. | Not yet. |
| 010 Editor template | `010` | `.bt` | Templated hex inspection in 010 Editor. | Not yet. |

The runtime tests execute generated parsers and compare the field ranges they
produce with the native executor's. The ImHex and 010 exporters cannot express
a struct with a size rule and refuse such layouts.

```bash
sextant export report.json --format kaitai    --out format.ksy
sextant export report.json --format wireshark --out dissector.lua
```

### Optional Kaitai cross-validation

`--cross-validate` is an independent second opinion on a Kaitai export. It
compiles the generated `.ksy` with the Kaitai Struct compiler and parses every
sample in the directory through the compiled Python parser. It needs
`kaitai-struct-compiler` (which needs a JVM) on `PATH`, or named by
`SEXTANT_KAITAI_COMPILER`, and `python3` with the `kaitaistruct` package. A
missing tool is reported as skipped, not failed, and export works without it.

```bash
sextant export report.json --format kaitai --out format.ksy \
  --cross-validate ./samples
```

The generated spec states at its top that checksum and range constraints are
not verified at run time: Kaitai checks the structure, not every constraint
the native executor checks.

## `bench`: measure accuracy against ground truth

```
sextant bench [--corpus <dir>] [--out <results.json>]
```

`bench` runs statistics-only inference over the ground-truth corpus and, per
format and per tier, reports field-boundary precision, recall, and F1, exact
recovery, role and type accuracy, native validity, and the structure measure.
The tiers separate formats inference was tuned against (development) from
formats held out of tuning (validation and held-out); see
[`corpus/README.md`](../corpus/README.md). It runs fully offline.

The output ends with two checklists. The regression floors sit just below the
current results, and `bench` exits 3 when any metric falls below its floor,
which is how CI catches regressions. The PRD Section 15 targets are reported
as met or not met and do not affect the exit status.

| Option | Meaning |
|---|---|
| `--corpus <DIR>` | The corpus directory to evaluate. Defaults to the repository corpus. |
| `--out <FILE>` | Write machine-readable JSON results to this path. |
| `--force` | Allow `--out` to overwrite an existing file or write outside the current working directory. |

The benchmark numbers in the project README are generated by the harness, not
written by hand.

## Exit codes

Sextant uses the exit codes defined in PRD Section 14.

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Usage error, including contradictory flags and an unusable model provider. |
| 2 | Input error: unreadable, missing, or oversized input, or a report that does not parse. |
| 3 | No fully verified hypothesis (`infer`), or a benchmark regression (`bench`). |
| 4 | Export error, including a layout the target cannot express. |
| 5 | Internal error. |

## Limits and output files

- Every command caps what it reads. Ingestion clips a sample at the
  per-sample cap, stops at the total-byte, file, and directory-entry caps, and
  notes each cap it hits. It never follows a symlink found while walking a
  directory or glob, and it skips FIFOs, sockets, and devices.
- Without `--force`, a command refuses to overwrite an existing file, to
  follow a symlink at the output path, or to write outside the current working
  directory.
- The benchmark rejects manifests above 1 MiB, more than 256 samples, samples
  above 64 MiB, more than 256 MiB of retained bytes per format, and more than
  100,000 expanded ground-truth fields. Sample paths must stay within their
  format directory, and sizes must match the manifest. Oversized samples are
  rejected, not clipped.
