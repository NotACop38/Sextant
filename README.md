<div align="center">

# Sextant

**Infer binary structure, test it against samples, and export editable parsers.**

*A sextant fixes an unknown position from known references. Sextant fixes unknown structure from observed bytes.*

Sextant proposes a structure for binary samples, executes it locally, and reports how well it fits. Export that structure to Kaitai, ImHex, Wireshark, or 010 Editor for further analysis. Native verification and external parser validation are reported separately.

[![CI](https://github.com/NotACop38/Sextant/actions/workflows/ci.yml/badge.svg)](https://github.com/NotACop38/Sextant/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)

</div>

-----

> [!NOTE]
> **Project status: pre-release development.** The CLI runs statistics-only and offline by default. The optional model path is available through the engine API. Current accuracy measurements cover 21 development samples in five formats; broader inference accuracy, held-out generalization, and all export runtimes are not yet qualified. Build from source; no GitHub release is currently published. See the [benchmarks](#benchmarks) and [review record](docs/REVIEW_2026-09-12.md).

-----

## Contents

- [What is Sextant?](#what-is-sextant)
- [The problem](#the-problem)
- [How it works](#how-it-works)
- [Demo](#demo)
- [Documentation](#documentation)
- [How Sextant is positioned](#how-sextant-is-positioned)
- [Output formats](#output-formats)
- [Usage](#usage)
- [Installation](#installation)
- [Design principles](#design-principles)
- [Roadmap](#roadmap)
- [Project documents](#project-documents)
- [Prior art and acknowledgements](#prior-art-and-acknowledgements)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## What is Sextant?

Reverse engineers constantly hit binary blobs with no documentation: proprietary file formats, game save files, firmware payloads, IoT and industrial-control protocols, malware command-and-control traffic and config files. Working out the layout by hand (staring at hex, guessing at field boundaries, testing length prefixes) is slow, error-prone work.

Sextant takes a handful of **samples** of an unknown format (a directory of files, or a packet capture) and produces:

- a **field map**: boundaries, types, and inferred roles (magic, version, length, count, offset, checksum, timestamp, enum, payload);
- an **editable parser specification** in the format of your choice (Kaitai Struct, ImHex pattern, Wireshark Lua dissector, 010 Editor template);
- an **annotated hex view** for any sample, so you can read the bytes through the inferred structure;
- a **confidence report** describing what was verified, what is uncertain, and why.

Use the result as a starting hypothesis for analysis. A structure can consume every byte without recovering its meaning: an opaque payload alone can earn a perfect fit score. Inspect the evidence, vary the samples, and validate exported code in its target runtime before relying on it.

## The problem

Manual parser authoring requires repeated guesses about boundaries, lengths, and repetition. Sextant makes those guesses executable and compares them against all retained samples. Its useful scope today is simple structured data with observable constants, lengths, counts, or delimiters.

The project combines established inference techniques with a native verification loop and editable exports. It does not establish a novelty or accuracy advantage over existing research tools; those comparisons require common data and independently reproduced results.

## How it works

```
                 ┌──────────────┐
  samples ─────► │  Ingest      │  files or pcap → normalized records
                 └──────┬───────┘
                        ▼
                 ┌──────────────┐
                 │ Statistical  │  entropy, byte-frequency, n-gram boundaries,
                 │ inference    │  multi-sample alignment, length/offset/CRC heuristics
                 └──────┬───────┘
                        ▼
                 ┌──────────────┐
                 │ Optional     │  name fields, infer field roles & types,
                 │ semantic pass│  recognize the format family, resolve ambiguity
                 └──────┬───────┘
                        ▼
                 ┌──────────────┐
                 │ Format       │  a structured, executable description of
                 │ Hypothesis   │  "what we think this format is" (the IR)
                 │ IR           │
                 └──────┬───────┘
                        ▼
                 ┌──────────────┐      does it parse every sample,
                 │ Executor &   │ ───► without contradiction, with no
                 │ scorer       │      leftover bytes? score the fit.
                 └──────┬───────┘
                        │  ▲
              refine    │  │  feedback: failures localize the wrong assumption
                        ▼  │
                 ┌──────────────┐
                 │ Exporters    │  Kaitai · ImHex · Wireshark Lua · 010 · hex view
                 └──────────────┘
```

The heart of Sextant is the **Format Hypothesis IR** and its **native executor**. Every hypothesis about a format is compiled to a structured intermediate representation and then *executed directly against the raw bytes* and scored on how well it fits. This is what separates Sextant from a model that simply emits a guess: hypotheses are **falsifiable and tested**, and parse failures feed back into the next round of refinement, localizing exactly which assumption was wrong. The exporters translate this IR into target source. That translation has its own correctness boundary: native fit alone does not prove the exported code behaves identically.

A note on the alignment step: comparing many samples to discover where fields begin and end is related to sequence alignment, and the PRD keeps gap-aware alignment as the target. The current v0.1.0 implementation uses a bounded positional alignment over normalized samples; adding gap-aware alignment is planned future work.

The language-model path is **optional** and never weakens verification. The statistical engine and IR executor run entirely offline. In v0.1.0 the public CLI always runs statistics-only; the engine contains a provider-agnostic semantic pass for library use and tests, and CLI provider flags are planned for a later release.

## Demo

The demo shows offline inference, inspection, and export on bundled samples. The demo is recorded as an [asciinema cast](docs/demo.cast). Play it locally with:

```bash
asciinema play docs/demo.cast
```

The cast is generated from genuine command output by [`examples/record_demo.py`](examples/record_demo.py), not hand-written. To run the same flow yourself, see the [quick start](docs/quickstart.md) or run [`examples/quickstart.sh`](examples/quickstart.sh).

## Documentation

Full user documentation lives in [`docs/`](docs/index.md):

- [Installation](docs/installation.md): build Sextant from source.
- [Quick start](docs/quickstart.md): infer, inspect, and export a parser end to end.
- [Workflows](docs/workflows.md): the `infer`, `inspect`, `export`, and `bench` commands in detail.
- [How it works](docs/how-it-works.md): the Format Hypothesis IR and the verification loop.
- [Privacy and the `--no-llm` story](docs/privacy.md): what is and is not transmitted.
- [Model data handling](docs/model-data-handling.md): what the optional engine model path sends when enabled by an integrator.
- [Examples](docs/examples.md): runnable examples against the corpus and the recorded demo.

## How Sextant is positioned

| Capability | Current boundary |
|---|---|
| Native inference and verification | Offline, tested against the retained input samples |
| Semantic names and roles | Heuristic or model suggestions; fit does not prove meaning |
| Sample alignment | Bounded positional alignment; gap-aware alignment is planned |
| Protocol input | Captured UDP payloads and TCP segment payloads; no TCP stream reassembly |
| Parser export | Supported IR subset per target; unsupported layouts return errors |
| External runtime checks | Kaitai compiler/Python and Lua tests; ImHex and 010 runtime qualification remains open |
| Accuracy evidence | Development corpus only; no held-out or competitor evaluation |

## Benchmarks

Accuracy is measured against a ground-truth corpus by `sextant bench` (PRD Section 15). Run it yourself with `sextant bench` or `cargo run -p sextant-bench`.

<!-- BENCH:START -->
These numbers are produced by `sextant bench` over the ground-truth corpus and are regenerated by the harness, not written by hand. The run is statistics-only (`--no-llm`), so it reflects the verified core with no language model involved.

| Format | Samples | Boundary F1 | Exact boundaries | Role acc. | Type acc. | Native validity |
|---|--:|--:|:-:|--:|--:|--:|
| tlv | 3 | 0.943 | no | 0.778 | 0.556 | 100% |
| scma | 5 | 0.834 | no | 0.333 | 0.333 | 100% |
| stot | 5 | 1.000 | yes | 1.000 | 1.000 | 100% |
| sdlp | 5 | 1.000 | yes | 1.000 | 1.000 | 100% |
| png | 3 | 1.000 | yes | 0.923 | 0.692 | 100% |
| **corpus** | **21** | **0.956** | **60%** | **0.807** | **0.716** | **100%** |

Regression targets for this development corpus: field-boundary F1 at least 0.85, exact-boundary rate at least 0.50, native validity 100%. Measured: F1 0.956, exact boundaries 60%, native validity 100%.

These are development-set results: inference and evaluation use the same samples, including four synthetic formats and three PNG files. Exact boundaries do not imply correct field types or semantics. Native validity measures complete native parsing with passing constraints; it does not execute exported parsers. The broader PRD corpus and held-out accuracy targets remain unqualified. No competing tool was run.
<!-- BENCH:END -->

## Output formats

|Format                      |Flag                |Use it for                                                                       |
|----------------------------|--------------------|---------------------------------------------------------------------------------|
|Kaitai Struct (`.ksy`)      |`--format kaitai`   |A portable spec that compiles to parsers in C++, Python, Java, Go, Rust, and more|
|ImHex pattern (`.hexpat`)   |`--format imhex`    |Interactive visual analysis in the ImHex editor                                  |
|Wireshark dissector (`.lua`)|`--format wireshark`|Decoding a protocol live in Wireshark                                            |
|010 Editor template (`.bt`) |`--format 010`      |Templated hex inspection in 010 Editor                                           |
|Annotated hex (terminal)    |`sextant inspect`   |Reading a single sample through the inferred structure                           |

## Usage

> These commands work today against the bundled corpus. The protocol example needs a packet capture; see the [workflows guide](docs/workflows.md) for the full reference.

```bash
# Infer structure from a directory of sample files
sextant infer ./samples/*.sav --out report.json

# Read a sample through the inferred field map (annotated hex)
sextant inspect report.json --sample ./samples/save_01.sav

# Export a parser specification
sextant export report.json --format kaitai    --out save_format.ksy
sextant export report.json --format imhex     --out save_format.hexpat
sextant export report.json --format wireshark --out save_dissector.lua

# Fully offline, statistics-only inference (no model involved)
sextant infer ./samples/*.bin --no-llm --out report.json

# Protocol capture example
sextant infer capture.pcap --transport tcp --port 9000 --out proto.json
```

Example of the inferred field map (illustrative):

```
sextant inspect report.json --sample save_01.sav

offset  size  field          role        type     value           confidence
0x0000  4     magic          MAGIC       bytes    "SAVE"           high
0x0004  2     version        VERSION     u16le    3                high
0x0006  2     entry_count    COUNT       u16le    7                high   ── drives loop below
0x0008  4     payload_len    LENGTH      u32le    412              high   ── matches remaining bytes
0x000c  …     entries[7]     ARRAY                                 medium
0x01a4  4     checksum       CHECKSUM    u32le    0x8f3a21bc        medium ── CRC32 over 0x00..0x1a4 ✓ verified
```

## Installation

Build from source with the pinned Rust toolchain:

```bash
git clone https://github.com/NotACop38/Sextant
cd Sextant
cargo build --release
./target/release/sextant --help
```

The binary is named `sextant`. The repository contains release workflows, install scripts, and a Homebrew formula template, but no tagged GitHub release is currently published. Registry publication is not verified here. Use the source build until distribution artifacts are available and tested.

Ordinary inference, inspection, and export need no JVM or model account. Optional Kaitai cross-validation requires the Kaitai Struct compiler, a JVM, Python, and the `kaitaistruct` runtime. The engine model API reads API keys from the environment or config only.

See [installation](docs/installation.md) and the [release process](docs/RELEASING.md).

## Design principles

- **Memory safety for hostile input.** Sextant parses untrusted, potentially adversarial binary data: malware traffic, malformed files. The core is written in Rust precisely because writing parsers for hostile input in a memory-safe systems language is the correct engineering choice for a security tool.
- **Falsifiable over plausible.** A confident-sounding guess is worthless if it doesn’t parse the bytes. Every hypothesis is executed and scored against real samples; unverified conclusions are labeled as such.
- **Honest confidence.** Sextant distinguishes what it verified from what it inferred. The field map and report make uncertainty visible rather than hiding it behind a tidy answer.
- **The model is an accelerant, not a dependency.** The statistical engine stands on its own and runs offline. The semantic pass can add labels and refinements only after executor verification, and the public CLI remains statistics-only in v0.1.0.
- **Editable, standard outputs.** Sextant hands you a Kaitai spec or a Wireshark dissector (open formats you can read, correct, and own), not a black box.

## Roadmap

The native pipeline, optional model API, protocol ingestion, and four exporters are implemented. The next priorities are evidence and fidelity:

- Complete the PRD corpus and add held-out samples before claiming general accuracy.
- Qualify generated code in each actual target runtime and extend supported layouts.
- Add gap-aware alignment and TCP stream reassembly where evidence supports them.
- Expose model configuration only with clear data handling and cost controls.
- Publish and smoke-test release artifacts before advertising installation channels.

The [engineering checklist](docs/ENGINEERING_CHECKLIST.md) distinguishes implementation from outstanding acceptance criteria.

## Project documents

- [Product Requirements Document](docs/PRD.md): the source of truth for what Sextant does and why.
- [Engineering Checklist](docs/ENGINEERING_CHECKLIST.md): the step-by-step build plan.
- [Agent guide](AGENTS.md): how contributors and AI coding agents work in this repository.

## Prior art and acknowledgements

Sextant stands on a great deal of prior work. The academic protocol-reverse-engineering literature (Netzob, NetPlier, NEMESYS, BinaryInferno, DynPRE, BinPRE) defined the statistical techniques this project builds on. [Kaitai Struct](https://kaitai.io/) is both an inspiration and a primary export target, and [ImHex](https://imhex.werwolv.net/) and 010 Editor shaped how analysts expect to read binary structure. Sextant connects sample-based inference, optional language-model semantics, native fit testing, and parser export in one workflow.

## Contributing

Contributions are welcome. Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) and the [agent guide](AGENTS.md), which together describe how the project is built one checklist step at a time and the verification invariant every change must respect. The maintainers triage incoming issues against the labels and process in [`docs/TRIAGE.md`](docs/TRIAGE.md).

Use [GitHub issues](https://github.com/NotACop38/Sextant/issues) for format requests and corpus suggestions. Issues describing **formats or protocols you would like to be able to reverse**, or **public sample corpora** suitable for benchmarking, are especially valuable: they directly shape the test suite. Report security vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option, the standard dual license in the Rust ecosystem. Unless you state otherwise, any contribution you submit is dual licensed the same way, with no additional terms.

## Disclaimer

Sextant is a tool for defensive security research, interoperability, malware analysis, and the reverse engineering of formats you are authorized to analyze. It parses untrusted binary input; run it in an appropriately isolated environment when analyzing potentially malicious samples. You are responsible for ensuring your use complies with applicable law and with the terms governing any software or data you analyze.
