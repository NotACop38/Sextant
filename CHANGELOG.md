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
