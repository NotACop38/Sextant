<div align="center">

# Sextant

**Infer the structure of unknown binary formats from samples, verify it by execution, and export editable parsers.**

[![CI](https://github.com/NotACop38/Sextant/actions/workflows/ci.yml/badge.svg)](https://github.com/NotACop38/Sextant/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![MSRV: 1.85](https://img.shields.io/badge/MSRV-1.85-orange?logo=rust)](rust-toolchain.toml)

</div>

Sextant is a command-line tool for reverse engineering binary file formats and
network protocols. Given samples of an unknown format, it infers a field
layout, executes that layout natively against every sample to measure how well
it fits, and exports the result as a Kaitai Struct, Wireshark Lua, ImHex, or
010 Editor parser specification, with a per-field confidence report.

> [!NOTE]
> **Status: pre-release.** No binaries or crates have been published yet;
> [build from source](#installation). Accuracy is measured on a tiered
> ground-truth corpus and [published below](#benchmarks), including where it
> falls short of the project's targets.

## Contents

- [What it does](#what-it-does)
- [Example](#example)
- [How it works](#how-it-works)
- [Benchmarks](#benchmarks)
- [Installation](#installation)
- [Usage](#usage)
- [The optional model pass](#the-optional-model-pass)
- [Scope and limitations](#scope-and-limitations)
- [Security](#security)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## What it does

Sextant takes a set of samples of one format (files, directories, or globs),
or packet captures with a transport and port, and produces:

- **a field map**: offsets, sizes, types, and roles (magic, version, length,
  count, offset, checksum, timestamp, flags, enum, payload), each with a
  confidence and the evidence behind it;
- **a JSON report**: the chosen hypothesis as an executable intermediate
  representation (IR), the score breakdown, per-sample results, and the
  refinement history;
- **an annotated hex view** of any sample, read through the report; and
- **parser specifications** for Kaitai Struct, Wireshark Lua, ImHex, and 010
  Editor, generated from the same checked IR.

It targets structured, uncompressed data with observable constants, lengths,
counts, offsets, or checksums: file headers, container and chunk formats,
record streams, and simple binary protocols. It marks high-entropy regions as
opaque and does not decompress, decrypt, or deobfuscate them.

## Example

Three PNG files, with nothing telling Sextant they are PNG:

```console
$ sextant infer corpus/png/samples --out png.json
Ingested 3 samples (235 bytes total).
  corpus/png/samples/sample_01.png: 69 bytes
  corpus/png/samples/sample_02.png: 75 bytes
  corpus/png/samples/sample_03.png: 91 bytes

Best hypothesis: candidate-chunked (fit score 1.000)
  coverage 1.000  consistency 1.000  generality 1.000  structure 0.322
  3 of 3 sample(s) fully verified; 9 checksum check(s) passed
  mode: statistics-only (no language model, no network egress)
Field map:
  magic: magic, bytes, 8 bytes (confidence 1.00)
  records: unknown, array, to end (confidence 0.85)
    record: unknown, struct, from fields (confidence 0.75)
      length: length, u32 big-endian, 4 bytes (confidence 0.90)
      type: enum, string, 4 bytes (confidence 0.60)
      data: payload, bytes, derived from length (confidence 0.60)
      checksum: checksum, u32 big-endian, 4 bytes (confidence 0.95)
  (confidence describes evidence from these samples, not certainty about field meaning; per-field evidence is in the report JSON)
Refinement: no improving change was found (already converged).

Wrote report to png.json
```

Sextant recovered the 8-byte signature and the chunk stream: a big-endian
length, a four-character type, the data that length governs, and a CRC-32. The
checksum line means the CRC-32 of every chunk in every sample verified, from
the end of `length` to the end of `data`, which is exactly PNG's rule. The
same report exports to a parser, and the optional cross-check compiles it and
runs every sample through it:

```console
$ sextant export png.json --format kaitai --out png.ksy --cross-validate corpus/png/samples
Wrote kaitai parser to png.ksy
Cross-validation: the Kaitai spec compiled and parsed all 3 samples.
```

The [quick start](docs/quickstart.md) walks through the full flow, including
`inspect`, and the [demo](docs/demo.cast) is an asciinema recording of it
(`asciinema play docs/demo.cast`), generated from real command output.

## How it works

```
samples -> ingest -> statistical inference -> candidate IRs -> execute and score each
                                                                        |
parser specs <- export <- chosen IR <- refine: heuristics, optional model <--+
                                       (every change re-executed, kept only if the fit holds)
```

1. **Inference.** Sextant looks for evidence that holds in every sample:
   invariant signatures, integers that equal the sample length, a region
   length, or a record count, pointers to invariant markers, and checksums
   that verify. It segments headers with a minimum description length code
   and builds candidates from several families, such as fixed layouts,
   length-governed bodies, counted records, and length-prefixed chunk streams.
2. **Execution.** Each candidate is an IR: fields with kinds, size and count
   rules, offsets, roles, and constraints. A native Rust executor runs it
   against every sample under hard limits on depth, array length, work,
   memory, and time, and reports either concrete field instances or a
   localized failure.
3. **Scoring.** The *fit* score (0 to 1) combines coverage, constraint
   consistency, and generality across samples. Fit alone cannot distinguish
   a recovered format from one opaque field that swallows every sample, so a
   separate *structure* measure estimates how much of the samples the
   hypothesis actually explains, as a description-length saving over the raw
   bytes.
4. **Selection and refinement.** Candidates are ranked by full verification,
   fit, passing checksums, encoded relationships, and structure. Refinement
   then tries local changes (boundaries, byte order, integer widths) and keeps
   a change only when it improves the fit over the full sample set without
   costing any sample its parse or its full verification.

The rule that holds everything together: **the model proposes; the executor
disposes.** No heuristic or model change is accepted if it lowers the verified
fit on the full sample set. Verification establishes that the chosen IR parses
the retained samples as scored. It does not establish what fields mean, that
the structure holds for samples you did not supply, or that an exported parser
behaves identically in its own runtime; those need separate evidence.
[How it works](docs/how-it-works.md) covers the details.

## Benchmarks

`sextant bench` runs statistics-only inference over a ground-truth corpus of 16
file formats and compares the result with hand-verified layouts. The formats
are split into three tiers so that no number is quoted from data the
heuristics were tuned on without saying so:

- **Development** (TLV and three other purpose-built formats, PNG, BMP, WAV,
  ZIP): inference is tuned against these, so they measure fit to known data.
- **Validation** (GIF, ELF64, TAR, pcap): held out, then evaluated once. That
  first run scored a mean boundary F1 of 0.460 and exposed one generic defect,
  zero padding misread as a stream of empty records, which was fixed. These
  numbers are therefore no longer blind.
- **Held-out** (gzip, MIDI, QOI, ICO): never examined before their first
  evaluation, which produced the numbers below; nothing has been tuned
  against them since.

<!-- BENCH:START -->
| Tier | Format | Samples | Boundary F1 | Exact | Role | Type | Valid | Structure |
|---|---|--:|--:|:-:|--:|--:|--:|--:|
| development | tlv | 3 | 1.00 | yes | 1.00 | 1.00 | 100% | 0.22 |
| development | scma | 5 | 1.00 | yes | 0.33 | 1.00 | 100% | 0.11 |
| development | stot | 5 | 1.00 | yes | 1.00 | 1.00 | 100% | 0.37 |
| development | sdlp | 5 | 1.00 | yes | 1.00 | 1.00 | 100% | 0.38 |
| development | png | 3 | 1.00 | yes | 1.00 | 1.00 | 100% | 0.32 |
| development | bmp | 5 | 0.87 | no | 0.47 | 0.65 | 100% | 0.57 |
| development | wav | 5 | 1.00 | yes | 0.71 | 1.00 | 100% | 0.30 |
| development | zip | 5 | 0.79 | no | 0.19 | 0.42 | 100% | 0.54 |
| **development** | **mean** | **36** | **0.96** | **6/8** | **0.71** | **0.88** | **100%** | |
| validation | gif | 5 | 0.41 | no | 0.16 | 0.16 | 100% | 0.09 |
| validation | elf | 5 | 0.57 | no | 0.09 | 0.31 | 100% | 0.60 |
| validation | tar | 4 | 0.55 | no | 0.05 | 0.16 | 100% | 0.23 |
| validation | pcapfile | 4 | 0.85 | no | 0.36 | 0.72 | 100% | 0.22 |
| **validation** | **mean** | **18** | **0.60** | **0/4** | **0.17** | **0.34** | **100%** | |
| held-out | gzip | 5 | 0.55 | no | 0.11 | 0.11 | 100% | 0.02 |
| held-out | midi | 5 | 1.00 | yes | 0.81 | 1.00 | 100% | 0.23 |
| held-out | qoi | 5 | 0.73 | no | 0.43 | 0.57 | 100% | 0.10 |
| held-out | ico | 5 | 0.87 | no | 0.54 | 0.67 | 100% | 0.08 |
| **held-out** | **mean** | **20** | **0.79** | **1/4** | **0.47** | **0.59** | **100%** | |
<!-- BENCH:END -->

Columns: **Boundary F1** compares inferred field boundaries with the ground
truth, excluding the trivial sample start and end. **Exact** is whether every
boundary of every sample matched. **Role** and **Type** are the fractions of
ground-truth fields whose exact byte span was recovered with the right role,
or the right storage type (for integers, the right width and byte order).
**Valid** is the fraction of samples the chosen IR parses completely with
every constraint passing. **Structure** is the description-length measure
above.

How to read it:

- The PRD's statistics-only targets (boundary F1 at least 0.85, at least half
  the formats exact, full validity) are all met on the development tier. On
  the validation and held-out tiers only validity is met.
- On held-out formats, inferred boundaries are usually right (precision 0.95)
  but often incomplete (recall 0.70). Formats with an opaque body, such as
  gzip, lose the most.
- Semantic roles are the weakest area without a model. Role accuracy is 0.47
  on the held-out tier and 0.17 on the validation tier.
- Validity is 100% by construction: the fallback candidates always parse, and
  ranking puts fully verified hypotheses first. It says nothing about semantic
  accuracy.
- The model pass is not benchmarked, and no academic baseline has been run on
  this corpus, so no comparison is claimed.

CI fails if any tier drops below its regression floor. The table is generated
by the harness (`cargo run -p sextant-bench -- --write-readme`) and checked by
a test, so it cannot drift from the code. Statistics-only inference is fast
enough for interactive use: 100 one-MiB samples take about a second, and 20
one-MiB samples holding about 10,000 records each take about three seconds
(release build, 4-core cloud VM).

## Installation

Building needs a Rust toolchain from [rustup](https://rustup.rs/). The
repository pins Rust 1.85.0, its minimum supported version, in
`rust-toolchain.toml`, and rustup selects it automatically.

```bash
git clone https://github.com/NotACop38/Sextant
cd Sextant
cargo build --release -p sextant-re                 # statistics-only, no network code
cargo build --release -p sextant-re --features llm  # adds the optional model pass
./target/release/sextant --help
```

The core needs no JVM, network service, or model account. Kaitai
cross-validation additionally needs the Kaitai Struct compiler (and a JVM) and
Python with the `kaitaistruct` package. See [installation](docs/installation.md)
for details and for what the first release will add (prebuilt archives with
checksums, install scripts, and the `sextant-re` crate).

## Usage

```bash
# Infer a structure from samples and write a report.
sextant infer ./samples --out report.json

# Read one sample through the inferred field map.
sextant inspect report.json --sample ./samples/first.bin --color

# Export a parser specification: kaitai, wireshark, imhex, or 010.
sextant export report.json --format kaitai --out format.ksy
sextant export report.json --format wireshark --out dissector.lua

# Infer a protocol from packet captures.
sextant infer capture.pcapng --transport tcp --port 502 --out modbus.json

# Measure accuracy against the ground-truth corpus.
sextant bench
```

`infer` exits 0 only when the chosen hypothesis fully verifies every sample,
and 3 otherwise, while still writing the report for diagnosis. Output files
are never overwritten, and never written outside the working directory,
without `--force`. The [workflows guide](docs/workflows.md) documents every
command, option, and exit code.

| Export target | Flag | Runtime-tested |
|---|---|---|
| Kaitai Struct (`.ksy`) | `--format kaitai` | Yes: compiled and run through the Python runtime, and compared with the native executor |
| Wireshark dissector (`.lua`) | `--format wireshark` | Yes: run under Lua 5.4 and compared with the native executor |
| ImHex pattern (`.hexpat`) | `--format imhex` | Not yet |
| 010 Editor template (`.bt`) | `--format 010` | Not yet |

Each exporter refuses a layout its target cannot express faithfully rather
than approximating it, and sanitizes every identifier and comment derived from
the input.

## The optional model pass

A binary built with the `llm` feature can ask a language model (Anthropic,
OpenAI, or a local Ollama server) to propose field names, roles, types, and
size rules:

```bash
export ANTHROPIC_API_KEY=...
sextant infer ./samples --provider anthropic --out report.json
```

Every proposal is applied through the native executor and kept only if the fit
does not drop and no sample loses a check it passed. It is strictly opt-in:
nothing is sent without `--provider`, a credential in the environment never
enables it, and `--no-llm` rejects `--provider` outright. The request holds
the candidate field layout and at most 256 bytes from each of the first four
samples. API keys come only from the environment or a config file, never from
a flag. `--max-llm-calls` caps calls, the report records calls and tokens, and
`SEXTANT_MODEL_CACHE_DIR` enables an on-disk response cache.
[Model data handling](docs/model-data-handling.md) documents exactly what is
sent and every setting.

## Scope and limitations

- **Semantics are suggestions.** Names and roles come from heuristics or a
  model. A perfect fit shows the layout parses the samples, not that a field
  means what its name says.
- **Samples bound the result.** A structure inferred from a few similar
  samples can miss variants they do not contain. Varied samples give better
  results.
- **Alignment is positional.** Samples are compared at fixed offsets from the
  start or from recovered boundaries; there is no gap-aware sequence
  alignment yet.
- **Protocols are per message.** TCP payloads are analyzed per segment,
  without stream reassembly.
- **Time limits are per execution.** `--timeout` bounds each execution of a
  hypothesis against a sample, not the whole run.
- **Exports are translations.** ImHex and 010 Editor output is not yet
  runtime-tested, and Kaitai specs do not check checksum or range constraints
  at run time.

The [PRD status section](docs/PRD.md#implementation-and-qualification-status-2026-09-26)
lists every known gap against the requirements.

## Security

Sextant is built to parse hostile input: the parsing core is safe Rust
(`unsafe` is denied workspace-wide), every input-facing path enforces resource
limits, and ingestion, the executor, inference, capture parsing, and each
exporter have fuzz targets. It never executes input. Untrusted text, including
file names, report contents, and model output, is escaped before it reaches
the terminal. Still, analyze potentially malicious samples in an isolated
environment, and review generated parsers before running them. Report
vulnerabilities privately as described in [SECURITY.md](SECURITY.md); the
[threat model](docs/threat-model.md) lists the trust boundaries.

## Documentation

- [User guide](docs/index.md): [installation](docs/installation.md),
  [quick start](docs/quickstart.md), [workflows](docs/workflows.md),
  [how it works](docs/how-it-works.md), [privacy](docs/privacy.md),
  [model data handling](docs/model-data-handling.md), and
  [examples](docs/examples.md).
- [Product requirements](docs/PRD.md): what Sextant does and why, with its
  current status.
- [Ground-truth corpus](corpus/README.md): the formats, tiers, and provenance.
- [Changelog](CHANGELOG.md) and [release process](docs/RELEASING.md).

## Contributing

Contributions are welcome, especially formats and protocols you would like to
reverse and public, redistributable sample corpora: they directly shape the
benchmark. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[agent guide](AGENTS.md) first; they describe the local gate and the
verification invariant every change must respect. Use
[GitHub issues](https://github.com/NotACop38/Sextant/issues) for bugs, format
requests, and questions.

Sextant builds on prior work: the protocol reverse-engineering literature
(Netzob, NetPlier, NEMESYS, BinaryInferno, DynPRE, BinPRE) for its statistical
techniques, and [Kaitai Struct](https://kaitai.io/),
[ImHex](https://imhex.werwolv.net/), Wireshark, and 010 Editor as the formats
analysts already use.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you state otherwise, any
contribution you submit is dual licensed the same way, with no additional
terms.

Sextant is intended for defensive security research, interoperability, malware
analysis, and reverse engineering of formats you are authorized to analyze. You
are responsible for ensuring your use complies with applicable law and with
the terms governing any software or data you analyze.
