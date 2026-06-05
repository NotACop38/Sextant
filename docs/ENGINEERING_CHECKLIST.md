# Sextant: Engineering Checklist

| Field | Value |
|---|---|
| Project | Sextant |
| Document | Engineering Checklist (build plan) |
| Status | Draft v0.1 (proposed) |
| Owner | `<you>` |
| Last updated | 2026-06-04 |
| Related documents | `docs/PRD.md`, `README.md` |

## How to use this checklist with a coding agent

This checklist is written to be executed by interchangeable AI coding agents (for example Claude Code or Codex), one step at a time. Every step is self-contained and provider-agnostic, so either agent can pick up any step given the repository and these documents. Steps are order-dependent, so run them in sequence.

1. **Work step by step.** Do not start a step until the previous step's acceptance criteria all pass. Each step is sized to be a coherent unit of work with a clear definition of done.
2. **Treat acceptance criteria as the definition of done.** A step is complete only when every box under "Acceptance criteria" is checked and verifiable, not when the code merely compiles.
3. **The PRD is the source of truth.** Requirement tags (FR-n, NFR-n) reference `docs/PRD.md`. If a conflict appears, follow the PRD and fix this checklist.
4. **Keep the tree green.** The Global Definition of Done below applies to every step in addition to its specific criteria.
5. **Update as you go.** Check boxes off in this file as work lands, and open follow-up issues for anything deferred.
6. **Ask before guessing.** The PRD records its resolved decisions in Section 20. If a genuinely new decision arises that is hard to reverse, confirm it with the maintainer before implementing.

## Global Definition of Done (applies to every step)

- [ ] `cargo build` and `cargo build --release` succeed.
- [ ] `cargo test` passes.
- [ ] `cargo clippy --all-targets --all-features` is clean (warnings treated as errors in CI).
- [ ] `cargo fmt --all --check` passes.
- [ ] No new `unsafe` without a written justification comment and a covering test (NFR-1).
- [ ] Public items have doc comments; user-facing behavior changes update the relevant docs.
- [ ] CI is green on the change.
- [ ] New input-facing code paths have at least one negative or malformed-input test.
- [ ] All prose, comments, and generated documentation use no em dashes or en dashes (use hyphens, colons, or commas).

---

## Step 1: Project scaffolding and documents

**Goal.** Create the repository skeleton, development tooling, CI, and place the planning documents. After this step, the project builds, lints, tests, and runs a trivial CLI, and the PRD and this checklist live in the repo.

### Tasks

- [x] Initialize the Git repository (private for now; public flip is Step 16).
- [x] Create a Cargo workspace with the adopted crates: `sextant-ir`, `sextant-engine`, `sextant-llm`, `sextant-export`, `sextant-cli`, plus an `xtask` or `bench` harness.
- [x] Add `rust-toolchain.toml` pinning Rust 2024 edition and MSRV 1.85.0.
- [x] Add `Cargo.toml` workspace metadata: description, repository URL, keywords, categories, and license fields.
- [x] Commit `README.md` (already drafted).
- [x] Commit `docs/PRD.md` and `docs/ENGINEERING_CHECKLIST.md` (this file).
- [x] Add `LICENSE-MIT` and `LICENSE-APACHE` (dual license).
- [x] Add `.gitignore` for Rust (`/target`, caches, editor files, local secrets).
- [x] Add `rustfmt.toml` and `clippy` configuration; enable warnings-as-errors in CI.
- [x] Add `deny.toml` for `cargo-deny` (licenses and advisories).
- [x] Add a minimal `sextant-cli` binary that supports `--version` and `--help` via `clap`, with `infer`, `inspect`, `export`, and `bench` subcommands stubbed to a not-yet-implemented message.
- [x] Add the test-corpus directory structure (for example `corpus/<format>/samples/` and `corpus/<format>/ground_truth.json`) with a short `corpus/README.md` describing the format and provenance fields. Seed it with one trivial controlled format (a custom TLV) including two or three samples and a ground-truth file.
- [x] Add a GitHub Actions CI workflow: build, test, clippy, fmt check, and `cargo-deny`, on Linux at minimum (macOS and Windows can be added in Step 15).
- [x] Add `CONTRIBUTING.md` (brief), `SECURITY.md`, `CODE_OF_CONDUCT.md`, and issue and pull-request templates.
- [x] Add a `CHANGELOG.md` seeded with an Unreleased section.

### Acceptance criteria

- [x] `cargo build` and `cargo test` succeed on a clean checkout.
- [x] `sextant --version` and `sextant --help` work and list the four subcommands.
- [x] `docs/PRD.md` and `docs/ENGINEERING_CHECKLIST.md` are committed and linked from the README.
- [x] CI runs and passes build, test, clippy, fmt, and `cargo-deny` on Linux.
- [x] The seed corpus format loads: a test reads its samples and ground-truth file without error.

---

## Step 2: The Format Hypothesis IR

**Goal.** Define the core data model (PRD Section 10, FR-13 to FR-19) and prove it can represent a real format by hand.

### Tasks

- [x] Implement the IR types in `sextant-ir`: Format, Structure, Field, Kind, size rules, count rules, Role, Constraint, Evidence, and confidence.
- [x] Implement `serde` serialization and deserialization to and from JSON (FR-19).
- [x] Implement IR validation (well-formed references, no dangling length or count targets, sane sizes).
- [x] Author by hand a ground-truth IR for at least one corpus format (for example PNG or the TLV) as a fixture.
- [x] Add unit tests for serialization round-trips and validation.

### Acceptance criteria

- [x] Any IR serializes to JSON and deserializes back to an equal value (round-trip test passes).
- [x] Validation rejects malformed IRs (dangling references, overlapping fixed fields) with clear errors.
- [x] The hand-authored IR for the chosen format is committed and used by later steps.

---

## Step 3: The executor and scorer (verification substrate)

**Goal.** Implement native execution and scoring of an IR against samples (FR-20 to FR-24, PRD Section 11). No inference yet. This is the heart of the project and must be JVM-free and panic-free.

### Tasks

- [x] Implement the executor: run an IR against one sample, producing field instances with concrete byte ranges and values, or a localized failure (offset and reason).
- [x] Implement resource limits: recursion depth, maximum array length, total work or wall-clock cap (FR-24).
- [x] Implement the scorer: coverage, consistency (length, count, offset, checksum relationships), and generality across the sample set, returning a 0 to 1 score and a structured breakdown (FR-22, FR-23).
- [x] Implement checksum verification for at least CRC32, CRC16, additive, and XOR over a specified covered range.
- [x] Add property tests and at least one `cargo-fuzz` target that feeds random bytes to the executor.

### Acceptance criteria

- [x] The hand-authored IR from Step 2 parses its corpus samples and scores at or near 1.0.
- [x] A deliberately wrong IR scores low, and the breakdown points at the failing dimension.
- [x] The fuzz target runs for a defined iteration count with no panics, hangs, or unbounded allocation.
- [x] Checksum verification passes on a format that has a checksum (for example PNG CRC32).

---

## Step 4: Sample ingestion

**Goal.** Turn user inputs into a normalized sample set (FR-1, FR-3 to FR-5). pcap is deferred to Step 11.

### Tasks

- [x] Implement file and directory and glob ingestion into an ordered sample set with provenance.
- [x] Enforce per-sample and total byte caps (FR-5).
- [x] Handle empty files, single-byte files, very large files, identical files, and a single-sample set without error (FR-4).
- [x] Add tests covering each pathological case.

### Acceptance criteria

- [x] `sextant infer <dir>` ingests a directory and reports the sample count and sizes.
- [x] All pathological-input tests pass.
- [x] Byte caps are enforced and surfaced to the user.

---

## Step 5: Statistical inference pass

**Goal.** Produce candidate IR trees from samples using classical techniques (FR-6 to FR-12).

### Tasks

- [x] Implement entropy, byte-frequency, and n-gram statistics across the sample set.
- [x] Implement multi-sample sequence alignment to find invariant and variable regions and candidate boundaries.
- [x] Implement magic or signature detection (FR-8).
- [x] Implement length, count, and offset field detection across endianness and width hypotheses (FR-9).
- [x] Implement checksum field detection over plausible ranges (FR-10).
- [x] Implement sub-byte field detection for flags and packed integers (FR-11, using `bitvec`).
- [x] Emit one or more candidate IRs with preliminary scores (FR-12).

### Acceptance criteria

- [x] On at least three corpus formats, the statistical pass recovers the magic and at least one length or count relationship, expressed as a candidate IR.
- [x] Candidate IRs are valid (pass Step 2 validation) and executable by the Step 3 executor.
- [x] Detected boundaries on the corpus meet an initial field-boundary recall bar (set a starting number, refine later).

---

## Step 6: Inference orchestration (statistics-only MVP)

**Goal.** Wire ingestion, statistical inference, and the executor and scorer into an end-to-end `infer --no-llm` that selects the best candidate (this realizes milestone M1, PRD Section 18).

### Tasks

- [x] Implement orchestration: ingest, generate candidates, execute and score each, select the best.
- [x] Implement a heuristic-only refinement loop (boundary nudges, endianness and width swaps) that respects the non-regression invariant (FR-26).
- [x] Wire the result into a draft report object.
- [x] Add end-to-end tests on corpus formats.

### Acceptance criteria

- [x] `sextant infer <dir> --no-llm` produces a scored field map for the corpus formats.
- [x] No network egress occurs in `--no-llm` mode (assert in a test or document the verification method) (NFR-4).
- [x] The statistics-only pipeline meets the accuracy targets in PRD Section 15 on the file-format corpus (field-boundary F1 at least 0.85, perfection at least 0.5).

---

## Step 7: Report and annotated hex output

**Goal.** Define the machine-readable report and the `inspect` view (FR-34, FR-35).

### Tasks

- [x] Define the report JSON structure and commit a JSON Schema for it.
- [x] Serialize the chosen IR, per-field confidence and evidence, the score breakdown, the refinement history, and run metadata into the report.
- [x] Implement `sextant inspect <report.json> --sample <file>`: an annotated hex view with offsets, sizes, names, roles, types, values, and confidence, with optional color.
- [x] Add tests validating reports against the schema and snapshot tests for `inspect` output.

### Acceptance criteria

- [x] Reports validate against the committed schema.
- [x] `inspect` renders a readable annotated hex view for a corpus sample.
- [x] Snapshot tests cover the report and the `inspect` rendering.

---

## Step 8: LLM provider abstraction

**Goal.** A provider-agnostic model interface with at least one working implementation, fully optional (FR-33, FR-40, PRD Section 12). No inference behavior change yet.

### Tasks

- [ ] Define the `LlmProvider` trait: a completion call and a JSON or structured call.
- [ ] Implement the reference providers, Anthropic Messages API and OpenAI, behind feature flags. Auto-detect the active provider from available credentials and use `--provider` to disambiguate.
- [ ] Optionally implement a local Ollama provider, feature-gated.
- [ ] Read API keys from environment or config only, never from flags (FR-40).
- [ ] Implement retries with backoff, a maximum call count, an optional budget, and on-disk response caching keyed by request hash (NFR-6, NFR-9).
- [ ] Provide a mock provider for tests so no network is required in CI.

### Acceptance criteria

- [ ] Unit tests exercise the trait using the mock provider with no network access.
- [ ] `--no-llm` bypasses the provider entirely and remains the default-safe path.
- [ ] The cache returns a stored response for an identical request without a network call (test with the mock).
- [ ] Secrets are never accepted via command-line flags.

---

## Step 9: LLM semantic pass and refinement loop

**Goal.** Use the model to add semantics and propose verified refinements (FR-29 to FR-32, FR-25 to FR-28). This realizes milestone M2.

### Tasks

- [ ] Implement the semantic pass: send candidate structure plus a bounded byte view, receive JSON field annotations (names, roles, types, enum meanings, format-family guess).
- [ ] Implement model-proposed refinement operations expressed against the IR (FR-30).
- [ ] Integrate proposals into the generate, test, refine loop. Apply a proposal only if the executor confirms the verified score does not regress (FR-26, FR-31).
- [ ] Enforce byte caps on what is sent in prompts (NFR-4) and cost guardrails (NFR-9).
- [ ] Add tests using the mock provider with canned proposals, including a bad proposal that must be rejected by the executor.

### Acceptance criteria

- [ ] With a canned good proposal, role and type annotations improve on a held-out format.
- [ ] With a canned bad proposal, the loop rejects it and the verified score does not drop (the non-regression invariant holds in test).
- [ ] The refine loop always terminates (convergence, max iterations, or target score).
- [ ] Enabling the model never lowers the verified parse score below the statistics-only baseline on the corpus.

---

## Step 10: Exporters

**Goal.** Generate editable parsers from the IR (FR-36 to FR-38).

### Tasks

- [ ] Implement the Kaitai `.ksy` exporter (primary).
- [ ] Implement the ImHex `.hexpat`, Wireshark `.lua`, and 010 `.bt` exporters.
- [ ] Implement optional Kaitai cross-validation: compile the generated spec with the Kaitai compiler and parse all samples, reported separately and never required by the core (FR-38, NFR-5).
- [ ] Add round-trip tests: for each corpus format, the exported parser parses every sample.

### Acceptance criteria

- [ ] The generated Kaitai spec for a corpus format compiles with the Kaitai compiler and parses all samples (when the optional cross-check is enabled).
- [ ] Each exporter produces output that correctly parses corpus samples for at least one format.
- [ ] `sextant export <report.json> --format <fmt> --out <file>` works for all four formats.

---

## Step 11: Protocols and pcap ingestion

**Goal.** Extend inference to captured binary protocols (FR-2, PRD Section 6.2). This realizes the first half of milestone M4.

### Tasks

- [ ] Implement pcap and pcapng reading and payload extraction by transport and port (FR-2).
- [ ] Implement message clustering and request and response association.
- [ ] Add protocol-oriented field semantics (message type, sequence number, length).
- [ ] Add Modbus/TCP (the protocol showcase) and a custom toy protocol to the corpus, each with captures and ground truth.
- [ ] Wire the Wireshark exporter as the primary output for this track.

### Acceptance criteria

- [ ] `sextant infer capture.pcap --transport tcp --port <N>` produces a field map for the Modbus/TCP and toy protocol captures.
- [ ] A generated Wireshark dissector decodes the Modbus/TCP and toy protocol captures.
- [ ] Message clustering separates distinct message types on the toy protocol.

---

## Step 12: Evaluation harness and benchmarks

**Goal.** Automate accuracy measurement against ground truth and produce publishable numbers (PRD Section 15). This completes milestone M4.

### Tasks

- [ ] Implement `sextant bench`: run inference over the corpus and compute field-boundary precision, recall, and F1; perfection rate; role and type accuracy; and parser validity.
- [ ] Emit a results table (and machine-readable results) suitable for the README.
- [ ] Add a regression guard so CI fails if metrics drop below configured thresholds.
- [ ] Frame results against the academic baselines on comparable metrics.

### Acceptance criteria

- [ ] `sextant bench` runs over the corpus and prints a metrics table.
- [ ] Metrics meet the targets in PRD Section 15.
- [ ] A metrics regression below threshold fails CI.
- [ ] README benchmark numbers are generated from this harness, not hand-written.

---

## Step 13: Robustness, fuzzing, and security hardening

**Goal.** Make the tool safe on hostile input at scale (NFR-1, NFR-2, FR-24, PRD Section 16). This is part of milestone M5.

### Tasks

- [ ] Add `cargo-fuzz` targets for ingestion, the executor, and each exporter.
- [ ] Add property tests for invariants (a parse never overruns; a length always matches what it governs in a valid parse).
- [ ] Verify and tighten resource limits (timeouts, memory caps, recursion and array bounds).
- [ ] Run fuzzers in CI on a schedule (for example nightly) with a crash-corpus check.
- [ ] Add `cargo-audit` to CI.

### Acceptance criteria

- [ ] All fuzz targets run for the configured budget with zero crashes or hangs.
- [ ] Resource limits are enforced and covered by tests.
- [ ] CI includes scheduled fuzzing and a clean `cargo-audit`.

---

## Step 14: Documentation, examples, and demo

**Goal.** Make the project understandable and adoptable (NFR-7, PRD Sections 13 and 16). Part of milestone M5 and M6.

### Tasks

- [ ] Write user documentation: install, quick start, the `infer`, `inspect`, and `export` workflows, the `--no-llm` and privacy story, and a short "how it works" explanation of the IR and the verification loop.
- [ ] Add runnable examples against the corpus.
- [ ] Record an asciinema demo: unknown blob in, field map and working parser out.
- [ ] Finalize `CONTRIBUTING.md`, `SECURITY.md`, and the data-handling note for the model pass.
- [ ] Ensure the documentation site or `docs/` builds cleanly.

### Acceptance criteria

- [ ] Documentation builds and the quick start works end to end on a fresh machine.
- [ ] At least one example runs successfully against the corpus.
- [ ] The demo is recorded and linked from the README.

---

## Step 15: Packaging and distribution

**Goal.** Ship installable artifacts on all supported platforms (NFR-5, PRD Section 18). Completes milestone M5.

### Tasks

- [ ] Extend CI to build and test on Linux, macOS, and Windows.
- [ ] Configure `cargo-dist` (or equivalent) to produce prebuilt binaries for tagged releases.
- [ ] Prepare crates.io publication metadata for all publishable crates; verify the `sextant` name is available before first publish.
- [ ] Add an install script and, optionally, a Homebrew tap.
- [ ] Adopt SemVer and wire the `CHANGELOG.md` into the release process.
- [ ] Ensure release artifacts are checksummed (and signed if feasible) (NFR-10).

### Acceptance criteria

- [ ] A tagged release produces working binaries for Linux, macOS, and Windows.
- [ ] `cargo install sextant` (after publish) installs a working binary.
- [ ] The changelog is updated for the release and the version is consistent across crates.

---

## Step 16: Public launch

**Goal.** Make the repository public and announce a first release (milestone M6).

### Tasks

- [ ] Final review of README, docs, license headers, and the security and responsible-use notes.
- [ ] Replace placeholder badges with live ones (a real CI status badge, crates.io version, license).
- [ ] Flip the repository to public.
- [ ] Enable Discussions and set up issue labels and a triage process.
- [ ] Cut and publish the first tagged release.
- [ ] Optional: prepare a short write-up of the IR and the verification loop for sharing.

### Acceptance criteria

- [ ] The repository is public with accurate, non-placeholder badges and a green CI.
- [ ] A versioned release is published with downloadable binaries.
- [ ] Issue labels and a contribution and triage flow are in place.

---

## Appendix: per-step requirement coverage

| Step | Primary PRD requirements |
|---|---|
| 1 Scaffolding and docs | NFR-5, NFR-10 |
| 2 IR | FR-13 to FR-19 |
| 3 Executor and scorer | FR-20 to FR-24, NFR-1, NFR-2 |
| 4 Ingestion | FR-1, FR-3, FR-4, FR-5 |
| 5 Statistical inference | FR-6 to FR-12 |
| 6 Orchestration (no model) | FR-25 to FR-28, NFR-3, NFR-4 |
| 7 Report and inspect | FR-34, FR-35 |
| 8 LLM abstraction | FR-33, FR-40, NFR-6, NFR-9 |
| 9 Semantic pass and refine | FR-29 to FR-32, FR-26, FR-31 |
| 10 Exporters | FR-36 to FR-38 |
| 11 Protocols and pcap | FR-2 |
| 12 Evaluation | PRD Section 15 |
| 13 Robustness and fuzzing | FR-24, NFR-1, NFR-2 |
| 14 Documentation | NFR-7 |
| 15 Packaging | NFR-5, NFR-10 |
| 16 Public launch | PRD Section 18 (M6) |
