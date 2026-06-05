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
