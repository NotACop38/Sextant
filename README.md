<div align="center">

# Sextant

**Reverse engineering for unknown binary formats and protocols, with parsers you can trust.**

*A sextant fixes an unknown position from known references. Sextant fixes unknown structure from observed bytes.*

Sextant infers the structure of unknown binary file formats and network protocols from sample data, then generates a parser it has **verified against your samples**: a tested artifact, not an unchecked guess.

[![CI](https://github.com/NotACop38/Sextant/actions/workflows/ci.yml/badge.svg)](https://github.com/NotACop38/Sextant/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/sextant-re.svg)](https://crates.io/crates/sextant-re)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)

</div>

-----

> [!NOTE]
> **Project status: v0.1.0, ready for the first public release.** Sextant infers simple binary file formats and protocols end to end today, and the verified core runs fully offline under `--no-llm`. The public CLI is statistics-only in this release; the model semantic path exists in the engine and test suite, but provider flags are not wired into the CLI yet. It is pre-1.0, so interfaces may still change before v1.0. See the [roadmap](#roadmap), the [changelog](CHANGELOG.md), and the [benchmarks](#benchmarks) for what is verified.

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
- a **runnable parser** in the format of your choice (Kaitai Struct, ImHex pattern, Wireshark Lua dissector, 010 Editor template);
- an **annotated hex view** for any sample, so you can read the bytes through the inferred structure;
- a **confidence report** describing what was verified, what is uncertain, and why.

The point is not to replace the reverse engineer. It is to get you ~70% of the way to a working parser in minutes, with the uncertain parts clearly flagged, so your time goes to the genuinely hard 30%.

## The problem

Tooling for unknown binary structure is split across three groups that don’t talk to each other:

- **Practical tools** (Kaitai Struct, ImHex, 010 Editor, PolyFile) are either *fully manual* (a human writes the spec) or only *recognize already-known formats*. The hard inference is left entirely to the analyst.
- **Academic protocol-reverse-engineering tools** (Netzob, NetPlier, NEMESYS, BinaryInferno, DynPRE, BinPRE) *do* infer structure, but they’re research prototypes with modest real-world accuracy, they often require expert hints (known delimiters, key fields), they tend to struggle with packed fields, and they emit raw field boundaries rather than a usable parser.
- **LLM reverse-engineering tools** (GhidraMCP, ida-pro-mcp, Gepetto, ReverserAI) have converged almost entirely on *disassembly*: renaming functions and commenting decompiled code. None of them address format or protocol structure.

Nobody is sitting in the middle. Sextant is built for that gap: statistical inference for the boundaries, a verification-gated semantic layer, and (the part everyone is missing) **verification that the result actually parses the input**.

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

The heart of Sextant is the **Format Hypothesis IR** and its **native executor**. Every hypothesis about a format is compiled to a structured intermediate representation and then *executed directly against the raw bytes* and scored on how well it fits. This is what separates Sextant from a model that simply emits a guess: hypotheses are **falsifiable and tested**, and parse failures feed back into the next round of refinement, localizing exactly which assumption was wrong. Real parsers (Kaitai, ImHex, Wireshark, 010) are just **exporters** off that verified IR at the very end.

A note on the alignment step: comparing many samples to discover where fields begin and end is related to sequence alignment, and the PRD keeps gap-aware alignment as the target. The current v0.1.0 implementation uses a bounded positional alignment over normalized samples; adding gap-aware alignment is planned future work.

The language-model path is **optional** and never weakens verification. The statistical engine and IR executor run entirely offline. In v0.1.0 the public CLI always runs statistics-only; the engine contains a provider-agnostic semantic pass for library use and tests, and CLI provider flags are planned for a later release.

## Demo

An unknown binary blob goes in; a verified field map and a working parser come out, fully offline. The demo is recorded as an [asciinema cast](docs/demo.cast). Play it locally with:

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

The table reflects design goals for v1.

|                                            |Manual tools<br>(Kaitai, ImHex, 010)|Academic PRE<br>(Netzob, BinaryInferno…)|LLM-disasm bridges<br>(GhidraMCP, Gepetto)|**Sextant**       |
|--------------------------------------------|:----------------------------------:|:--------------------------------------:|:----------------------------------------:|:----------------:|
|Infers unknown structure from samples       |✗ *(you write the spec)*            |✓                                       |✗ *(works on disassembly)*                |**✓**             |
|Semantic field meaning (names, roles, types)|manual                              |limited                                 |✓                                         |**partial today** |
|Produces a runnable parser                  |✓ *(after manual work)*             |✗                                       |✗                                         |**✓**             |
|Verifies output against the input           |n/a                                 |✗                                       |✗                                         |**✓ (core loop)** |
|Handles packed flags and bit evidence       |✓                                   |often ✗                                 |n/a                                       |**partial today** |
|Runs without sending data to a model        |✓                                   |✓                                       |✗                                         |**✓ (`--no-llm`)**|

## Benchmarks

Accuracy is measured against a ground-truth corpus by `sextant bench` (PRD Section 15). Run it yourself with `sextant bench` or `cargo run -p sextant-bench`.

<!-- BENCH:START -->
These numbers are produced by `sextant bench` over the ground-truth corpus and are regenerated by the harness, not written by hand. The run is statistics-only (`--no-llm`), so it reflects the verified core with no language model involved.

| Format | Samples | Boundary F1 | Perfect | Role acc. | Type acc. | Parser validity |
|---|--:|--:|:-:|--:|--:|--:|
| tlv | 3 | 0.943 | no | 0.778 | 0.556 | 100% |
| scma | 5 | 0.834 | no | 0.333 | 0.333 | 100% |
| stot | 5 | 1.000 | yes | 1.000 | 1.000 | 100% |
| sdlp | 5 | 1.000 | yes | 1.000 | 1.000 | 100% |
| png | 3 | 1.000 | yes | 0.923 | 0.692 | 100% |
| **corpus** | **21** | **0.956** | **60%** | **0.807** | **0.716** | **100%** |

Targets (PRD Section 15): field-boundary F1 at least 0.85, perfection rate at least 0.50, parser validity 100%. The corpus run meets them: F1 0.956, perfection 60%, validity 100%.

How to read this against academic baselines: compare numbers only within the same corpus and methodology. The important property here is not just the score, but that every number above is verified: the chosen IR parses every sample by construction, and the same IR exports a Kaitai, Wireshark, ImHex, or 010 parser.
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

# Export a verified parser
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

Sextant ships a single binary named `sextant` for Linux, macOS, and Windows
once a tagged release is published. Pick whichever method suits you.

### Prebuilt binaries (install script)

After the GitHub Release is published, the scripts download the release archive
for your platform, verify its SHA-256 checksum, and install the `sextant` binary.
No compiler required.

```bash
# Linux and macOS
curl -fsSL https://raw.githubusercontent.com/NotACop38/Sextant/main/scripts/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/NotACop38/Sextant/main/scripts/install.ps1 | iex
```

You can also download an archive and its `.sha256` directly from the
[Releases page](https://github.com/NotACop38/Sextant/releases) and verify it
against the published `SHA256SUMS`.

### From crates.io

The crates.io name `sextant` belongs to an unrelated project, so the CLI package
is `sextant-re`. After publication, it installs a binary called `sextant`.

```bash
cargo install sextant-re
```

### Homebrew

A formula template is provided in `packaging/homebrew/sextant.rb` for a Homebrew
tap. Once published:

```bash
brew install NotACop38/tap/sextant
```

### From source

```bash
git clone https://github.com/NotACop38/Sextant
cd Sextant
cargo build --release
# binary at ./target/release/sextant
```

See [docs/RELEASING.md](docs/RELEASING.md) for the versioning policy, the
release process, and how artifacts are built and checksummed.

Sextant ships as a single static binary. Optional dependencies:

- **Kaitai export** shells out to the Kaitai Struct compiler (`kaitai-struct-compiler`), which requires a JVM. Other export formats have no external dependency.
- **The model semantic pass** exists in the engine and reads API keys from the environment or config only. The v0.1.0 CLI does not expose provider flags yet, so CLI inference remains statistics-only and offline.

## Design principles

- **Memory safety for hostile input.** Sextant parses untrusted, potentially adversarial binary data: malware traffic, malformed files. The core is written in Rust precisely because writing parsers for hostile input in a memory-safe systems language is the correct engineering choice for a security tool.
- **Falsifiable over plausible.** A confident-sounding guess is worthless if it doesn’t parse the bytes. Every hypothesis is executed and scored against real samples; unverified conclusions are labeled as such.
- **Honest confidence.** Sextant distinguishes what it verified from what it inferred. The field map and report make uncertainty visible rather than hiding it behind a tidy answer.
- **The model is an accelerant, not a dependency.** The statistical engine stands on its own and runs offline. The semantic pass can add labels and refinements only after executor verification, and the public CLI remains statistics-only in v0.1.0.
- **Editable, standard outputs.** Sextant hands you a Kaitai spec or a Wireshark dissector (open formats you can read, correct, and own), not a black box.

The v0.1.0 core below is implemented. Product work that remains, including CLI provider flags and gap-aware alignment, should be tracked in [issues](https://github.com/NotACop38/Sextant/issues) and [discussions](https://github.com/NotACop38/Sextant/discussions).

- [x] **Phase 0: Scaffold.** CLI skeleton, sample-corpus harness, the IR type definitions, and a suite of *known* formats with hand-verified ground truth for measuring accuracy from day one.
- [x] **Phase 1: MVP engine (no model).** Statistical inference + IR executor + accuracy scoring against the known-format suite.
- [x] **Phase 2: The novel core.** Provider-agnostic semantic pass in the engine and the generate-test-refine loop. CLI provider flags remain future work.
- [x] **Phase 3: Exporters.** Kaitai, ImHex, Wireshark, 010, and the annotated hex view.
- [x] **Phase 4: Protocols and showcases.** pcap ingestion, an industrial/IoT protocol case study (Modbus/TCP), and published benchmarks against the academic baselines.

## Project documents

- [Product Requirements Document](docs/PRD.md): the source of truth for what Sextant does and why.
- [Engineering Checklist](docs/ENGINEERING_CHECKLIST.md): the step-by-step build plan.
- [Agent guide](AGENTS.md): how contributors and AI coding agents work in this repository.

## Prior art and acknowledgements

Sextant stands on a great deal of prior work. The academic protocol-reverse-engineering literature (Netzob, NetPlier, NEMESYS, BinaryInferno, DynPRE, BinPRE) defined the statistical techniques this project builds on. [Kaitai Struct](https://kaitai.io/) is both an inspiration and a primary export target, and [ImHex](https://imhex.werwolv.net/) and 010 Editor shaped how analysts expect to read binary structure. Sextant’s contribution is to connect sample-based inference, language-model semantics, and **round-trip verification** into a single tool that emits a tested parser.

## Contributing

Contributions are welcome. Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) and the [agent guide](AGENTS.md), which together describe how the project is built one checklist step at a time and the verification invariant every change must respect. The maintainers triage incoming issues against the labels and process in [`docs/TRIAGE.md`](docs/TRIAGE.md).

Open-ended questions, format requests, and corpus suggestions are best raised in [GitHub Discussions](https://github.com/NotACop38/Sextant/discussions). Issues describing **formats or protocols you would like to be able to reverse**, or **public sample corpora** suitable for benchmarking, are especially valuable: they directly shape the test suite. Report security vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option, the standard dual license in the Rust ecosystem. Unless you state otherwise, any contribution you submit is dual licensed the same way, with no additional terms.

## Disclaimer

Sextant is a tool for defensive security research, interoperability, malware analysis, and the reverse engineering of formats you are authorized to analyze. It parses untrusted binary input; run it in an appropriately isolated environment when analyzing potentially malicious samples. You are responsible for ensuring your use complies with applicable law and with the terms governing any software or data you analyze.
