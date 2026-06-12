# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A fuzz target (`ir_json`) for the two JSON deserializers that face hostile
  input directly: the Format Hypothesis IR and the report, including a
  round-trip losslessness check (FR-19, NFR-2).
- Deterministic malformed-capture tests for the pcap reader (truncated
  headers, oversized record lengths, byte-flipped real captures), corrupt
  report JSON tests for `inspect` and `export`, and score-bounds assertions
  over every breakdown dimension.
- The release pipeline smoke test now runs `infer`, `inspect`, and `export`
  end to end on the committed corpus, so a binary with a broken pipeline can
  never ship.

### Changed

- `sextant infer` no longer prints a warning on default runs that provider
  flags are unavailable. The field map's mode line already states that the
  run is statistics-only with no network egress.
- PRD Section 14 now documents the implemented `--recursive` and
  `--max-total-bytes` flags and names the v1 flags that v0.1.0 omits.

### Fixed

- A pcapng input too short to hold a single block header is reported as
  truncated instead of reading as an empty capture.
- The bench harness generates the same benchmark prose the README commits, so
  the README guard test passes again.
- The reserved-filler naming regression test exercises a reachable scenario;
  the previous one placed its length field beyond the detector's header scan
  bound and silently asserted nothing.

## [0.1.0] - 2026-06-05

### Added

- Initial Cargo workspace scaffolding: the `sextant-ir`, `sextant-engine`,
  `sextant-llm`, `sextant-export`, and `sextant-cli` crates, plus the `bench`
  evaluation harness.
- The `sextant` command-line skeleton with `infer`, `inspect`, `export`, and
  `bench` subcommands stubbed out, plus working `--version` and `--help`.
- Development tooling: a pinned Rust 1.85.0 toolchain on edition 2024, rustfmt
  and clippy configuration, a `cargo-deny` policy, and a Linux CI workflow that
  runs build, test, clippy, format check, and `cargo-deny`.
- Dual MIT or Apache-2.0 license, plus contributor, security, and
  code-of-conduct documentation and issue and pull-request templates.
- A seed ground-truth corpus: a custom TLV format with three samples and a
  ground-truth description, plus a corpus loader and tests.
- The Format Hypothesis IR in `sextant-ir`: format, structure, field, kind,
  size and count rules, offsets, roles, constraints, evidence, and confidence
  types, modeled close to Kaitai Struct semantics (PRD Section 10, FR-13 to
  FR-19).
- Lossless JSON serialization for the IR, so any hypothesis round-trips to an
  equal value (FR-19).
- Semantic IR validation that rejects dangling length, count, offset, and
  checksum references, overlapping fixed fields, and sizes, widths, ranges, and
  confidences that are not sane, each with a clear, located error.
- A hand-authored ground-truth IR for PNG, committed as a fixture for later
  steps.
- Sample ingestion in `sextant-engine`: files, directories, and glob patterns
  are normalized into an ordered sample set with per-sample provenance (path,
  retained length, full size, and source offset), with configurable per-sample
  and total byte caps that bound memory and are surfaced to the user (FR-1,
  FR-3, FR-4, FR-5).
- `sextant infer <inputs>` now ingests its inputs and reports the sample count
  and sizes, with `--recursive`, `--max-bytes-per-sample`, and
  `--max-total-bytes` options. Pathological inputs (empty, single-byte, very
  large, identical, and single-sample) are handled without error.
- End-to-end statistics-only inference orchestration in `sextant-engine`:
  `infer` ingests, generates and scores candidate hypotheses, selects the best,
  refines it, and assembles a draft report with a scored field map (milestone
  M1, FR-25 to FR-28, NFR-3, NFR-4).
- A repeating length-prefixed record detector that recovers chunked and
  tag-length-value layouts (such as PNG chunks and the corpus TLV records),
  including per-record checksums (FR-9, FR-10).
- A heuristic-only refinement loop (endianness swaps, integer width swaps, and
  fixed-size boundary nudges) that applies a change only when the native scorer
  confirms the verified fit does not regress (the non-regression invariant,
  FR-26), records its accepted steps, and always terminates (FR-27, FR-28).
- `sextant infer <dir> --no-llm` now prints a scored field map with a fit-score
  breakdown and the refinement history, with a `--timeout` option. The
  statistics-only path is fully offline and links no network crate (NFR-4).
- Field-boundary accuracy metrics (precision, recall, F1, and perfection rate)
  in the `bench` crate, with a test confirming the statistics-only pipeline
  clears the PRD Section 15 file-format targets (F1 at least 0.85, perfection at
  least 0.5).
- A machine-readable JSON report (FR-34): the chosen IR, per-field confidence
  and evidence, the fit-score breakdown, the per-sample breakdown, the
  refinement history, and run metadata, with a versioned JSON Schema committed
  at `schemas/report.schema.json` that every emitted report validates against.
  `sextant infer --out <file>` writes the report.
- `sextant inspect <report.json> --sample <file>` (FR-35): an annotated hex view
  that renders a sample through a report, showing each field's offset, size,
  name, role, type, decoded value, and confidence, followed by a hex dump, with
  optional `--color` highlighting per field.
- Packet-capture ingestion in `sextant-engine` (FR-2): a native, dependency-free
  reader for classic pcap (microsecond and nanosecond, either byte order) and
  pcapng, extracting transport payloads by transport and port over Ethernet, raw
  IP, BSD loopback, and Linux cooked-capture link layers carrying IPv4 or IPv6
  and TCP or UDP, each payload carrying its direction, flow, timestamp, and
  capture offset.
- Protocol inference: message clustering that separates message types by the most
  discriminating byte, request and response association on a flow, and detection
  of the protocol-oriented field semantics (message type, sequence or transaction
  id, and remaining length). The assembled hypothesis is verified against every
  message and is never chosen over the statistics-only baseline when it scores
  lower (the non-regression invariant, FR-26). New `message_type` and `sequence`
  field roles back these semantics.
- `sextant infer <capture> --transport <tcp|udp> --port <N>` reads packet
  captures, prints the clustered field map and request/response pairing, and
  writes a report whose Wireshark dissector binds to the capture's port, the
  primary output for the protocol track.
- Modbus/TCP (the protocol showcase) and a custom toy request/response protocol
  added to the corpus, each with a generated capture, a `generate.py` source, and
  a hand-verified ground truth.
- `sextant bench` runs statistics-only inference over the ground-truth corpus and
  reports the PRD Section 15 metrics: field-boundary precision, recall, and F1;
  the perfection rate; semantic role and type accuracy; and parser validity. It
  prints a results table, writes machine-readable JSON with `--out`, accepts a
  `--corpus <dir>` override, and exits non-zero when a metric falls below its
  configured threshold.
- The benchmark harness (`bench` crate) computes those metrics and assembles a
  machine-readable report; the README benchmark block is generated from it with
  `cargo run -p sextant-bench -- --write-readme` (and a test fails if the block drifts),
  so the published numbers are never hand-written.
- A benchmark regression guard in CI (`cargo run -p sextant-bench -- --check`) and in the
  test suite that fails the build if field-boundary F1, perfection rate, parser
  validity, or role and type accuracy drop below their thresholds. The
  statistics-only corpus run clears the PRD Section 15 targets (field-boundary F1
  at least 0.85, perfection at least 0.5, parser validity 100%).
- Robustness and security hardening (Step 13, NFR-1, NFR-2, FR-24): `cargo-fuzz`
  targets for every input-facing component, namely ingestion, the executor, the
  statistical inference pass, capture parsing, and each of the four exporters
  (Kaitai, ImHex, Wireshark, and 010), sharing an arbitrary IR generator that
  stresses hostile field names, unusual widths, dangling references, and
  oversized sizes. Each target ran its budget with zero crashes or hangs.
- `proptest`-based property tests for the parse invariants (a parse never
  overruns the sample; a length or count field always matches what it governs in
  a valid parse) and for the resource bounds (recursion depth, array length,
  total field count, total work, and the wall-clock timeout each stop a runaway
  parse with a localized failure rather than a crash, hang, or unbounded
  allocation).
- A scheduled `Fuzz` CI workflow that runs every fuzz target on a nightly cron
  (with a shorter smoke run on pull requests that touch the fuzzed crates) and
  fails on any recorded crash artifact, plus a `cargo-audit` job that checks the
  workspace and fuzz lockfiles against the RustSec advisory database (NFR-10).
- User documentation (Step 14, NFR-7) under `docs/`: an installation guide, a
  quick start, a workflows reference for `infer`, `inspect`, `export`, and
  `bench`, a "how it works" explanation of the Format Hypothesis IR and the
  verification loop, a privacy and `--no-llm` page, and a model data-handling
  note describing exactly what the optional model pass transmits.
- Runnable examples against the bundled corpus: `examples/quickstart.sh` (the
  infer, inspect, export flow) and a `sextant-engine` `infer_corpus` library
  example, with an index in `examples/README.md`.
- A recorded asciinema demo at `docs/demo.cast`, generated from genuine command
  output by `examples/record_demo.py` and linked from the README.
- A `docs_build` test in the `bench` crate that fails CI if any relative link in
  `docs/` or `examples/` is broken or if any Markdown file contains an em dash or
  an en dash.
- Packaging and distribution (Step 15, NFR-5, NFR-10): CI now builds, lints, and
  tests on Linux, macOS, and Windows via a platform matrix, and a `.gitattributes`
  normalizes text to LF so cross-platform builds and output comparisons stay
  stable.
- A tag-driven `Release` workflow (the cargo-dist equivalent) that verifies the
  tag matches the workspace version, builds the `sextant` binary natively for
  `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, and
  `x86_64-pc-windows-msvc`, packages each build with the licenses and changelog,
  writes a per-archive SHA-256 checksum and an aggregate `SHA256SUMS` manifest,
  and publishes them to a GitHub Release with notes drawn from this changelog.
- crates.io publication metadata for every publishable crate. Because the bare
  name `sextant` is already taken, the CLI is published as `sextant-re` (it still
  installs a binary named `sextant`) and the benchmark harness is published as
  `sextant-bench` (its library name stays `bench`). The shared workspace version
  keeps all crates consistent. `docs/RELEASING.md` documents the SemVer policy,
  the changelog flow, the crate names, and the publish order.
- Install scripts: `scripts/install.sh` (Linux and macOS) and
  `scripts/install.ps1` (Windows) download the release archive for the host
  platform, verify its checksum, and install the `sextant` binary without
  requiring a compiler. A Homebrew formula template lives at
  `packaging/homebrew/sextant.rb`.
- Public-launch readiness (Step 16, milestone M6): the README now carries live
  badges (CI status, crates.io version, and license) in place of the
  placeholders, and its status note, roadmap, contributing, and license sections
  reflect the first release. Issue labels are defined in `.github/labels.yml` and
  applied with `scripts/setup-labels.sh`; the triage and contribution flow is
  documented in `docs/TRIAGE.md`, and the issue templates apply a `triage` label.
  `docs/LAUNCH.md` is the maintainer checklist with the exact commands to flip the
  repository public, enable Discussions, apply the labels, cut the tagged release,
  and publish to crates.io, and `docs/ANNOUNCEMENT.md` is a launch write-up of the
  IR and the verification loop.

[Unreleased]: https://github.com/NotACop38/Sextant/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/NotACop38/Sextant/releases/tag/v0.1.0
