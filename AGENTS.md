# Sextant: agent guide

This file is the operating manual for AI coding agents working in this repository. It is read automatically by Codex (`AGENTS.md`) and, through `CLAUDE.md`, by Claude Code. Read it before doing anything.

## The project

Sextant is a command-line reverse-engineering tool that infers the structure of unknown binary file formats and network protocols from sample data, then exports parser specifications (Kaitai, ImHex, Wireshark, 010), with an honest per-field confidence report. Native fit and target runtime verification are separate evidence; never claim the latter from the former. The defining property is verification: every structural hypothesis is executed natively against the bytes and scored, and a language model may propose semantics and refinements, but its proposals are accepted only when the executor confirms they improve the fit. Protect that property above all.

## Authoritative documents (read these first)

- `docs/PRD.md` is the source of truth for what Sextant does and why. Requirement tags `FR-###` and `NFR-###` refer to it. Its status section lists where the current version falls short.
- `docs/ENGINEERING_CHECKLIST.md` is the build plan that produced the current version. Its steps are implemented; the boxes left open are qualification gaps, closed there when met.

If this file and the PRD ever disagree, the PRD wins.

## How to work

1. Work from an issue or a clearly scoped request, and do only that. Keep one branch and one pull request per change so reviews and the verification invariant stay auditable.
2. A change is done only when the Global Definition of Done (below) is satisfied and verifiable, not when the code merely compiles. When a change closes a qualification gap, check its box in `docs/ENGINEERING_CHECKLIST.md` and update the PRD status section.
3. When you finish, run the checks below, report the results, then stop and wait for review.
4. Ask before guessing. Resolved decisions are in PRD Section 20. If a genuinely new, hard-to-reverse decision arises, surface it instead of assuming.

## Non-negotiable invariants

- The model proposes; the executor disposes. Never accept a model or heuristic change that lowers the verified parse score on the full sample set (PRD FR-26, FR-31). This is the heart of the tool.
- The executor and scorer are native Rust. They must not depend on a JVM, the Kaitai compiler, or any network service, and they must run under `--no-llm` and offline (FR-21).
- No input may cause a panic, a hang, or unbounded allocation. Enforce recursion-depth, array-length, and wall-clock limits (FR-24, NFR-2).
- `--no-llm` must always work and produce zero network egress (NFR-4). The model pass runs only when `--provider` names a provider, never because a credential is present, and the CLI's network code stays behind the off-by-default `llm` feature.
- Never tune inference against the held-out benchmark tier. Examining a held-out format's results to guide a change moves that format to the validation tier in the same change (see `corpus/README.md`).
- Secrets (API keys) come only from the environment or a config file, never from command-line flags (FR-40).

## Project conventions

- No em dashes or en dashes anywhere: prose, code comments, generated docs, and CLI output. Use hyphens, colons, or commas.
- Rust 2024 edition, MSRV 1.85.0 (pinned in `rust-toolchain.toml`).
- Safe Rust. No new `unsafe` without a written justification comment and a covering test.
- Dual licensed under MIT or Apache-2.0.
- Keep everything provider-agnostic. This repository is built by both Claude Code and Codex; nothing should assume a specific agent.

## Workspace layout

- `sextant-ir`: the Format Hypothesis IR types, serialization, and validation.
- `sextant-engine`: ingestion, statistical inference, the executor, the scorer, and the refinement loop. Depends on `sextant-ir`.
- `sextant-llm`: the provider-agnostic model interface and its implementations (Anthropic and OpenAI first-class, Ollama optional). Optional dependency.
- `sextant-export`: exporters for Kaitai, ImHex, Wireshark, and 010.
- `sextant-cli` (published as `sextant-re`): the `sextant` binary that wires the above together. Its model providers are behind the `llm` feature, off by default.
- `bench` (published as `sextant-bench`): the evaluation and benchmark harness, with the tiered corpus under `corpus/`.
- `fuzz`: the `cargo-fuzz` targets, excluded from the workspace because they need nightly.

Put new code in the crate that owns its responsibility. Do not create cross-crate shortcuts that bypass the IR or the executor.

## Global Definition of Done (every change)

- [ ] The full local gate in [Commands](#commands) passes, including debug and release builds, all-feature tests, Clippy with warnings as errors, formatting, supply-chain checks, and the benchmark regression guard.
- [ ] No new `unsafe` without a justification comment and a test.
- [ ] Public items have doc comments; behavior changes update the relevant docs.
- [ ] Input-facing code paths have at least one negative or malformed-input test.
- [ ] No em dashes or en dashes were introduced anywhere.
- [ ] CI is green.

## Commands

Use focused crate and test checks, and `cargo fmt --all`, during development. Run this full local gate from the repository root before declaring any change done:

```bash
cargo fmt --all --check
cargo build --all-targets --all-features --verbose
cargo build --release
cargo test --workspace --all-features --verbose
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check
cargo audit
cargo audit --file fuzz/Cargo.lock
cargo run -p sextant-bench -- --check
```

Keep these commands aligned with [the CI workflow](.github/workflows/ci.yml). They cover its checks on the current host and include the release build required by the Global Definition of Done. CI additionally verifies build, test, Clippy, and benchmark results on Linux, macOS, and Windows, and runs two checks that need external tools:

- The exporter runtime tests, with the Kaitai Struct compiler 0.11 on `PATH`, `python3` with `kaitaistruct`, and Lua 5.4: `SEXTANT_REQUIRE_KAITAI=1 SEXTANT_REQUIRE_LUA=1 cargo test -p sextant-export`. Without the variables, tests that need a missing tool are skipped.
- The examples against the release build: `./examples/quickstart.sh` and `python3 examples/record_demo.py`.

Run them locally when you touch exporters or CLI output. When a change moves the benchmark numbers, regenerate the README block with `cargo run -p sextant-bench -- --write-readme`. When a change touches fuzzed code, also run the relevant `cargo fuzz run <target>` for its configured budget.

## Testing expectations

- Negative and malformed-input tests for anything that reads bytes.
- `cargo-fuzz` targets for ingestion, the executor, and each exporter, maintained with the code they cover.
- Property tests for parse invariants (a parse never overruns; a length field always matches what it governs in a valid parse).
- Snapshot tests for report output and `inspect` output.
- Runtime tests that execute generated Kaitai and Lua parsers and compare them with the native executor, for any exporter change.

## Security posture

Sextant parses untrusted, potentially hostile input. Keep the parsing core in safe Rust, enforce resource limits, and never execute input. Documentation must instruct users to analyze potentially malicious samples in an isolated environment.

## Do not

- Do partial work and call it done.
- Overwrite `README.md`, `docs/PRD.md`, or `docs/ENGINEERING_CHECKLIST.md` without an explicit instruction.
- Make the core depend on the JVM, the Kaitai compiler, or the network.
- Let the language model override verification, or send any bytes off the machine when `--no-llm` is set.
- Commit secrets, API keys, or large binary corpora that are not part of the intended test set.
- Introduce em dashes or en dashes.
