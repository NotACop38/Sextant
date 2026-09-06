# Sextant: agent guide

This file is the operating manual for AI coding agents working in this repository. It is read automatically by Codex (`AGENTS.md`) and, through `CLAUDE.md`, by Claude Code. Read it before doing anything.

## The project

Sextant is a command-line reverse-engineering tool that infers the structure of unknown binary file formats and network protocols from sample data, then generates parsers it has verified against those samples (Kaitai, ImHex, Wireshark, 010), with an honest per-field confidence report. The defining property is verification: every structural hypothesis is executed natively against the bytes and scored, and a language model may propose semantics and refinements, but its proposals are accepted only when the executor confirms they improve the fit. Protect that property above all.

## Authoritative documents (read these first)

- `docs/PRD.md` is the source of truth for what Sextant does and why. Requirement tags `FR-###` and `NFR-###` refer to it.
- `docs/ENGINEERING_CHECKLIST.md` is the step-by-step build plan. Each step has a Tasks list and an Acceptance criteria block.

If this file and the PRD ever disagree, the PRD wins.

## How to work

1. Work one checklist step at a time. Do only the step you were asked to do. Do not start any later step.
2. A step is done only when every box under its Acceptance criteria and the Global Definition of Done (below) is satisfied and verifiable, not when the code merely compiles.
3. Check off the boxes you complete in `docs/ENGINEERING_CHECKLIST.md`.
4. Prefer one branch per step (for example `step-03-executor`) so reviews and the verification invariant stay auditable.
5. When you finish a step, run the checks below, report results and which acceptance criteria now pass, then stop and wait for review.
6. Ask before guessing. Resolved decisions are in PRD Section 20. If a genuinely new, hard-to-reverse decision arises, surface it instead of assuming.

## Non-negotiable invariants

- The model proposes; the executor disposes. Never accept a model or heuristic change that lowers the verified parse score on the full sample set (PRD FR-26, FR-31). This is the heart of the tool.
- The executor and scorer are native Rust. They must not depend on a JVM, the Kaitai compiler, or any network service, and they must run under `--no-llm` and offline (FR-21).
- No input may cause a panic, a hang, or unbounded allocation. Enforce recursion-depth, array-length, and wall-clock limits (FR-24, NFR-2).
- `--no-llm` must always work and produce zero network egress (NFR-4).
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
- `sextant-cli`: the `sextant` binary that wires the above together.
- `bench` (or `xtask`): the evaluation and benchmark harness.

Put new code in the crate that owns its responsibility. Do not create cross-crate shortcuts that bypass the IR or the executor.

## Global Definition of Done (every step)

- [ ] The full local gate in [Commands](#commands) passes, including debug and release builds, all-feature tests, Clippy with warnings as errors, formatting, supply-chain checks, and the benchmark regression guard.
- [ ] No new `unsafe` without a justification comment and a test.
- [ ] Public items have doc comments; behavior changes update the relevant docs.
- [ ] Input-facing code paths have at least one negative or malformed-input test.
- [ ] No em dashes or en dashes were introduced anywhere.
- [ ] CI is green.

## Commands

Use focused crate and test checks, and `cargo fmt --all`, during development. Run this full local gate from the repository root before declaring any step done:

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

Keep these commands aligned with [the CI workflow](.github/workflows/ci.yml). They cover its checks on the current host and include the release build required by the Global Definition of Done. CI additionally verifies build, test, Clippy, and benchmark results on Linux, macOS, and Windows.

Where a step involves fuzzing, also run the relevant `cargo fuzz run <target>` for its configured budget.

## Testing expectations

- Negative and malformed-input tests for anything that reads bytes.
- `cargo-fuzz` targets for ingestion, the executor, and each exporter, added and maintained from Step 3 onward.
- Property tests for parse invariants (a parse never overruns; a length field always matches what it governs in a valid parse).
- Snapshot tests for report output and `inspect` output.

## Security posture

Sextant parses untrusted, potentially hostile input. Keep the parsing core in safe Rust, enforce resource limits, and never execute input. Documentation must instruct users to analyze potentially malicious samples in an isolated environment.

## Do not

- Skip steps, or do partial work and call a step done.
- Overwrite `README.md`, `docs/PRD.md`, or `docs/ENGINEERING_CHECKLIST.md` without an explicit instruction.
- Make the core depend on the JVM, the Kaitai compiler, or the network.
- Let the language model override verification, or send any bytes off the machine when `--no-llm` is set.
- Commit secrets, API keys, or large binary corpora that are not part of the intended test set.
- Introduce em dashes or en dashes.
