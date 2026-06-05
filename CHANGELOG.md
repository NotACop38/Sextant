# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  `cargo run -p bench -- --write-readme` (and a test fails if the block drifts),
  so the published numbers are never hand-written.
- A benchmark regression guard in CI (`cargo run -p bench -- --check`) and in the
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
