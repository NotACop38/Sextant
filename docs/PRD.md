# Sextant: Product Requirements Document (PRD)

| Field | Value |
|---|---|
| Project | Sextant |
| Document | Product Requirements Document |
| Status | Draft v0.2. Open decisions resolved (see Section 20). |
| Owner | `<you>` |
| Last updated | 2026-06-04 |
| Related documents | `README.md`, `docs/ENGINEERING_CHECKLIST.md` |

> **How to read this document.** This PRD is the source of truth for *what* Sextant does and *why*. The companion `ENGINEERING_CHECKLIST.md` describes *how* and *in what order* to build it. When the two disagree, the PRD wins and the checklist should be corrected. Requirements are numbered (FR for functional, NFR for non-functional) so the checklist and code reviews can reference them directly.

---

## 1. Summary

Sextant is a command-line reverse-engineering tool that infers the structure of unknown binary file formats and network protocols from sample data, then generates parsers that it has verified against those samples. The output is a field map plus an editable parser (Kaitai Struct, ImHex pattern, Wireshark dissector, or 010 Editor template), each accompanied by an honest, per-field confidence report.

The defining idea is verification. Every structural hypothesis is compiled to an internal representation, the Format Hypothesis IR, then executed natively against the raw bytes and scored on how well it fits every sample. A language model proposes field semantics and refinements, but its proposals are accepted only when the native executor confirms they improve the fit. The result is a tested artifact, not an unverified guess. This is also the property that differentiates Sextant from existing tools and the property that must never be compromised during development.

## 2. Problem statement

Tooling for unknown binary structure is split across three groups that do not work together:

1. **Practical tools** (Kaitai Struct, ImHex, 010 Editor, PolyFile) are either fully manual, requiring a human to author the spec, or only recognize already-known formats. The hard inference is left to the analyst.
2. **Academic protocol-reverse-engineering tools** (Netzob, NetPlier, NEMESYS, BinaryInferno, DynPRE, BinPRE) do infer structure but are research prototypes: modest real-world accuracy, frequent need for expert hints, weak handling of sub-byte fields, and output limited to raw field boundaries rather than a usable parser.
3. **LLM reverse-engineering tools** (GhidraMCP, ida-pro-mcp, Gepetto, ReverserAI) have converged on disassembly: renaming functions and commenting decompiled code. None address format or protocol structure.

No tool sits in the middle: statistical inference for the boundaries, a language model for the semantics, and verification that the result actually parses the input. Sextant fills that gap.

## 3. Goals and non-goals

### 3.1 Goals

1. Infer the layout of an unknown binary format from a set of samples with minimal human input.
2. Produce a parser that has been mechanically verified to parse every supplied sample.
3. Report confidence honestly, distinguishing what was verified from what was inferred.
4. Run fully offline when required; the language model is an accelerant, never a dependency.
5. Be fast and memory-safe enough to point at untrusted, potentially adversarial input.
6. Emit open, editable outputs that an analyst can read, correct, and own.

### 3.2 Non-goals (v1)

1. Decompressing or decrypting payloads. High-entropy regions are detected and marked opaque, not unpacked.
2. Deobfuscation, packer unpacking, or anti-analysis defeat.
3. Replacing a disassembler or decompiler. Sextant reasons about data layout, not code.
4. A graphical user interface. v1 is CLI-first.
5. Guaranteeing correct inference of arbitrarily complex formats. Sextant targets structured, length- and tag-delimited binary data and reports low confidence where it cannot do better.
6. Real-time or streaming protocol inference. v1 works from captured samples.

## 4. Target users

| Persona | Needs |
|---|---|
| Independent security researcher / RE hobbyist | A fast way to bootstrap a parser for an undocumented file or save format. |
| Malware analyst / threat intelligence | Structure of C2 messages and config blobs; a Wireshark dissector for live triage. |
| Vulnerability researcher | Field boundaries and length or offset relationships as inputs to fuzzing and bug hunting. |
| Protocol / IoT / ICS researcher | Inference of proprietary binary protocols from captures, with a usable dissector. |
| Interoperability / data-recovery engineer | A working parser for a legacy or proprietary format with no public spec. |

## 5. Use cases and user stories

- **US-1.** As a researcher, I want to point Sextant at a directory of sample files and receive a field map, so that I do not have to hand-trace the layout in a hex editor.
- **US-2.** As a malware analyst, I want a generated Wireshark dissector for an unknown protocol capture, so that I can read sessions live.
- **US-3.** As a privacy-conscious user, I want to run inference fully offline, so that no sample bytes leave my machine.
- **US-4.** As a vulnerability researcher, I want length, count, offset, and checksum fields identified and cross-checked, so that I can target a fuzzer at the right structure.
- **US-5.** As a contributor, I want an accuracy benchmark against a known-format corpus, so that I can tell whether a change improved or regressed inference.
- **US-6.** As an analyst, I want the tool to tell me which fields it is unsure about, so that I know where to spend my own effort.

## 6. Scope

### 6.1 v1 (MVP): file formats

- Ingest a set of files of one unknown format.
- Statistical inference pass producing one or more candidate hypotheses.
- Native IR executor and scorer (the verification substrate).
- Optional language-model semantic and refinement pass with a generate, test, refine loop.
- Field map and machine-readable report.
- Exporters: Kaitai Struct first, then ImHex, Wireshark, 010 Editor.
- Annotated hex inspection of any sample.
- Accuracy evaluation harness against a curated ground-truth corpus.

### 6.2 v1.x: protocols

- pcap and pcapng ingestion.
- Message clustering and request/response association.
- Protocol-oriented field semantics (message type, sequence numbers, lengths).
- Wireshark dissector as the primary export for this track.

### 6.3 Future (post v1.x)

- State-machine inference for protocols.
- A library API and optional MCP server so other tools can drive Sextant.
- Plugin or rule packs for known field encodings (timestamps, GUIDs, IP addresses).
- A minimal local model option tuned for field-naming.

## 7. Functional requirements

### 7.1 Ingestion

- **FR-1.** Accept one or more input files or a directory; expand globs; ignore directories recursively only when asked.
- **FR-2.** Accept a packet capture (`.pcap`, `.pcapng`) and a transport and port selector to extract message payloads (v1.x).
- **FR-3.** Normalize inputs into an internal sample set: an ordered list of byte buffers with provenance (path, length, offset within capture).
- **FR-4.** Handle pathological inputs without crashing: empty files, single-byte files, very large files, identical files, and a set of size one.
- **FR-5.** Enforce a configurable per-sample byte cap and a total-input cap to bound memory.

### 7.2 Statistical inference

- **FR-6.** Compute per-offset and windowed Shannon entropy, byte-value frequency, and n-gram statistics across the sample set.
- **FR-7.** Align samples using sequence alignment to discover invariant regions, variable regions, and likely field boundaries.
- **FR-8.** Detect candidate magic or signature fields (invariant prefixes and constants).
- **FR-9.** Detect candidate length, count, and offset fields by correlating integer-valued regions with sample sizes, repetition counts, and intra-sample offsets, across multiple endianness and width hypotheses.
- **FR-10.** Detect candidate checksum or hash fields by testing common algorithms (at minimum CRC32, CRC16, additive and XOR checksums) over plausible covered ranges.
- **FR-11.** Detect sub-byte fields (bit flags and packed integers); the engine must not assume byte-aligned fields only.
- **FR-12.** Emit one or more candidate Format Hypothesis IR trees ranked by a preliminary score.

### 7.3 Format Hypothesis IR

- **FR-13.** Represent a format as an ordered structure of fields and nested structures (see Section 10).
- **FR-14.** Represent fixed-size, length-derived, delimited, and to-end fields.
- **FR-15.** Represent arrays whose element count is fixed, derived from a count field, derived from a length field, or runs to end.
- **FR-16.** Represent integer fields with explicit width, endianness, and signedness; byte fields; string fields with an encoding; enums; and opaque or high-entropy blobs.
- **FR-17.** Represent cross-field relationships: a length, count, or offset field that governs another field, and a checksum field with an algorithm and a covered byte range.
- **FR-18.** Attach to every field a confidence value and an evidence record describing what supports the hypothesis.
- **FR-19.** Be fully serializable to and from JSON for inspection, caching, and reproducibility.

### 7.4 Executor and scorer (verification)

- **FR-20.** Execute an IR against a single sample, producing either a structured parse (field instances with concrete values and byte ranges) or a localized failure (offset and reason).
- **FR-21.** The executor must be implemented in native Rust and must not depend on any external compiler, runtime, or network service. It must run in `--no-llm` mode and in offline environments.
- **FR-22.** Score the fit of an IR against the entire sample set on at least: byte coverage (explained vs unexplained bytes, no overruns), cross-field consistency (length, count, offset, and checksum relationships hold on every sample), and generality (the same IR parses all samples without contradiction).
- **FR-23.** Penalize unexplained gaps, overlapping fields, parse failures, and constraint violations. Produce an overall fit score in the range 0 to 1 plus a structured breakdown.
- **FR-24.** Be robust to adversarial input: no panics, no unbounded memory or time. Enforce recursion-depth, array-length, and wall-clock limits.

### 7.5 Refinement loop

- **FR-25.** Starting from the best candidate, iteratively propose and test refinements (boundary moves, type or endianness changes, adding a length dependency, recognizing an array, identifying a checksum).
- **FR-26.** Each proposed change is accepted only if the executor confirms it does not reduce the verified fit score on the full sample set and does not break generality. This non-regression invariant is mandatory.
- **FR-27.** Terminate on convergence (no accepted improvement), a configurable maximum iteration count, or a target score.
- **FR-28.** Record the refinement history for explainability.

### 7.6 Language-model pass (optional)

- **FR-29.** Given candidate structure and a bounded view of sample bytes, request semantic annotations: field names, roles, types, enum value meanings, and a guess at the format family.
- **FR-30.** Request concrete, testable refinement proposals expressed against the IR, not free text.
- **FR-31.** All model proposals pass through the executor and scorer (FR-26). The model never has final authority over the output.
- **FR-32.** Be fully bypassable with `--no-llm`. When bypassed, no bytes are transmitted off the machine.
- **FR-33.** Support multiple providers behind one interface (see Section 12), selected by flag or config.

### 7.7 Output and exporters

- **FR-34.** Produce a machine-readable report (JSON) containing the chosen IR, per-field confidence and evidence, the fit-score breakdown, and run metadata.
- **FR-35.** Render an annotated hex view of any sample using the report (`sextant inspect`).
- **FR-36.** Export the chosen IR to Kaitai Struct (`.ksy`). Kaitai is the primary export and the cross-validation target.
- **FR-37.** Export to ImHex pattern (`.hexpat`), Wireshark Lua dissector (`.lua`), and 010 Editor template (`.bt`).
- **FR-38.** For Kaitai export, optionally compile the generated spec with the Kaitai compiler and parse all samples through it as an independent cross-check, reported separately. The core pipeline must not require this step.

### 7.8 CLI and configuration

- **FR-39.** Provide the commands in Section 14 with consistent flags, helpful `--help`, and stable exit codes.
- **FR-40.** Read configuration from flags, then environment variables, then an optional config file, in that precedence. Secrets (API keys) come only from the environment or config file, never from flags.
- **FR-41.** Provide structured logging at selectable verbosity, with an optional JSON log format.

## 8. Non-functional requirements

- **NFR-1. Memory safety.** Core parsing of untrusted input is written in safe Rust. `unsafe` is forbidden by default and every exception requires a written justification and a test.
- **NFR-2. Robustness.** All input-facing components (ingestion, executor, exporters) are fuzzed. No input may cause a panic, hang, or unbounded allocation.
- **NFR-3. Performance.** On a typical laptop, statistics-only inference over 100 samples of up to 1 MB each completes in seconds, not minutes. Specific budgets are set in the checklist and tracked by benchmarks.
- **NFR-4. Privacy.** With `--no-llm`, zero network egress. With the model enabled, the tool documents exactly what is transmitted and supports limiting how many sample bytes are sent.
- **NFR-5. Portability.** Builds and runs on Linux, macOS, and Windows. Ships as a single static binary with no required runtime. Optional features (Kaitai compilation) are clearly gated.
- **NFR-6. Determinism and reproducibility.** Given the same inputs and configuration, statistics-only runs are deterministic. Model responses are cached by input hash so that runs are reproducible and inexpensive to repeat.
- **NFR-7. Observability.** Every run can emit a trace of decisions sufficient to explain why a field was assigned a given type, role, and confidence.
- **NFR-8. Extensibility.** New field detectors, new exporters, and new model providers can be added without changing the core engine, via well-defined traits.
- **NFR-9. Cost control.** Model usage is bounded by a maximum call count and an optional budget; caching prevents repeated spend.
- **NFR-10. Supply-chain hygiene.** Dependencies are license- and advisory-checked in CI; releases are reproducible and the dependency set is auditable.

## 9. System architecture

```
inputs (files or pcap)
        |
        v
[ Ingestion ]  normalize into a sample set (byte buffers + provenance)
        |
        v
[ Statistical inference ]  entropy, frequency, alignment, length/offset/checksum heuristics
        |                  -> one or more candidate IR trees
        v
[ LLM semantic pass ]  (optional) names, roles, types, refinement proposals
        |
        v
[ Format Hypothesis IR ]  the structured, executable hypothesis
        |
        v
[ Executor + scorer ] <----+  native Rust; parse every sample, score the fit
        |                   |
        | refine            |  feedback: failures localize the wrong assumption;
        +-------------------+  accept a change only if the verified score holds (FR-26)
        |
        v
[ Report + exporters ]  field map, JSON report, Kaitai / ImHex / Wireshark / 010, hex view
```

Crate layout (Cargo workspace). Decision: the multi-crate workspace below is adopted.

- `sextant-ir`: the Format Hypothesis IR types, serialization, and validation.
- `sextant-engine`: ingestion, statistical inference, executor, scorer, refinement loop. Depends on `sextant-ir`.
- `sextant-llm`: provider-agnostic model interface and implementations. Optional dependency.
- `sextant-export`: exporters for Kaitai, ImHex, Wireshark, 010.
- `sextant-cli`: the `sextant` binary; wires the above together.
- `xtask` or a `bench` binary: the evaluation and benchmark harness.

## 10. The Format Hypothesis IR

The IR is intentionally close to Kaitai Struct semantics so that export is faithful, with added confidence and evidence metadata. Representative model (final field names are an implementation detail):

- **Format**: a name, a default endianness, a root structure, optional named enums, and global metadata.
- **Structure**: an ordered list of fields.
- **Field**: a name (optional, may be model-supplied), a kind, a size rule, an optional role, optional constraints, a confidence value, and an evidence record.
- **Kind**: one of integer (with width, endianness override, signedness), bytes, string (with encoding), enum (referencing a named enum), struct (nested), array (with an element kind and a count rule), or opaque (high-entropy or unknown).
- **Size rule**: fixed N bytes, derived from a referenced length field, delimited by a terminator, or to end of buffer or parent.
- **Count rule** (arrays): fixed N, from a referenced count field, bounded by a referenced length field, or to end.
- **Role**: magic, version, length, count, offset, checksum, timestamp, flags, enum, reserved or padding, payload, or unknown.
- **Constraint**: an expected constant (for magic), an expected value range, or a checksum specification (algorithm plus covered byte range expressed relative to fields).
- **Evidence**: which detector proposed the field, the cross-sample support (for example, how many samples agree), and any model rationale.

The IR must round-trip losslessly through JSON (FR-19) and be the single object that the executor consumes and the exporters read.

## 11. Verification and scoring model

**Fit score** of an IR over the sample set combines:

1. **Coverage**: fraction of bytes in each sample that are explained, with no overruns and no overlaps. Unexplained trailing bytes and gaps are penalized.
2. **Consistency**: for every sample, derived relationships hold. A length field equals the size of what it governs; a count field equals the number of array elements; an offset field points where the structure expects; a checksum field verifies over its covered range.
3. **Generality**: a single IR parses all samples. An IR that fits one sample but fails others is penalized heavily to avoid overfitting.

The score is a value in 0 to 1 with a structured breakdown so that the report and the refinement loop can act on specific weaknesses.

**Refinement** proceeds from the current best IR by proposing local changes, executing, and re-scoring. The mandatory invariant (FR-26): a change is accepted only if it does not reduce the verified score on the full sample set. The loop terminates on convergence, a maximum iteration count, or a target score, and records its history.

**Confidence** reported per field is derived from cross-sample agreement and from whether the field participates in a relationship that verifies (a checksum that checks out, a length that always matches). Verified relationships yield high confidence; single-sample guesses yield low confidence and are labeled as such.

## 12. LLM integration

- **Provider abstraction.** A single trait (for example `LlmProvider`) exposes a completion call and a structured or JSON-returning call. Decision: Anthropic and OpenAI are both first-class, feature-gated reference implementations; a local option via Ollama is optional. The active provider is auto-detected from whichever API credentials are present in the environment, and if more than one is available the user selects one with `--provider`. This keeps the runtime model layer aligned with a build executed by multiple coding agents.
- **Structured proposals.** The model is prompted to return JSON conforming to a schema: field annotations and refinement operations expressed against the IR. Free-form text is not accepted as output.
- **Grounding.** Proposals are applied only through the executor and scorer (FR-31, FR-26). The model accelerates search; it does not decide the result. This is the anti-hallucination guarantee and a hard requirement.
- **Determinism and caching.** Low temperature; responses cached on disk keyed by a hash of the exact request, for reproducibility and cost control (NFR-6, NFR-9).
- **Cost guardrails.** Maximum calls per run and an optional budget; the run degrades gracefully to the best verified statistics-only result if limits are hit.
- **Privacy.** `--no-llm` transmits nothing. When enabled, the tool documents what is sent and supports a cap on how many bytes per sample are included in prompts (NFR-4).

## 13. Output: field map, report, and exporters

- **Report (JSON).** Contains the chosen IR, per-field confidence and evidence, the fit-score breakdown, the refinement history, and run metadata (tool version, inputs, configuration, model usage). A JSON Schema for the report is maintained in the repository.
- **Annotated hex (`inspect`).** Renders a sample through the report: offset, size, field name, role, type, value, and confidence, with optional color.
- **Exporters.** Kaitai `.ksy` (primary, and the cross-validation target), ImHex `.hexpat`, Wireshark `.lua`, 010 `.bt`. Each exporter is verified by round-tripping the known-format corpus.

## 14. CLI specification

This section specifies the v1 command surface. v0.1.0 implements a subset: the
provider flags (`--provider`, `--model`, `--max-llm-calls`, `--budget`),
`--format-hint`, and the global verbosity and logging flags are not wired into
the CLI yet, and every release so far runs statistics-only.

```
sextant infer <inputs...> [options]
  --no-llm                      Statistics-only; no network egress.
  --provider <name>             LLM provider (default from config).
  --model <id>                  Model identifier.
  --max-llm-calls <N>           Cap model calls for this run.
  --budget <amount>             Optional spend cap.
  -r, --recursive               Descend into subdirectories.
  --max-bytes-per-sample <N>    Cap sample bytes used and sent.
  --max-total-bytes <N>         Cap the total bytes read across all samples.
  --format-hint <name>          Optional hint about the format family.
  --transport <tcp|udp> --port <N>   Protocol extraction from a capture (v1.x).
  --timeout <seconds>           Wall-clock cap for inference.
  --out <report.json>           Where to write the report.

sextant inspect <report.json> --sample <file> [--color]
sextant export <report.json> --format <kaitai|imhex|wireshark|010> --out <file>
sextant bench [--corpus <dir>] [--out <results.json>]

Global: -v/--verbose, -q/--quiet, --json-logs, --version, --help
```

**Exit codes (adopted).** 0 success; 1 usage error; 2 input error; 3 inference produced no usable hypothesis; 4 export error; 5 internal error.

## 15. Accuracy and evaluation methodology

**Ground-truth corpus (adopted).** Each entry includes real sample files, a hand-verified ground-truth structure, and provenance. The file-format set is the v1 evaluation target and the protocol set is the v1.x target. PNG is the file-format showcase and Modbus/TCP is the protocol showcase.

File formats (v1):

| Format | Exercises |
|---|---|
| PNG (showcase) | Magic, length-prefixed chunks, CRC32, chunked arrays, big-endian. |
| GIF | Magic, fixed header, little-endian, block structure. |
| BMP | Header with offsets and sizes, little-endian. |
| WAV (RIFF) | Chunked container, little-endian sizes. |
| ZIP local file header | Signatures, lengths, little-endian. |
| ELF64 header (subset) | Magic, enums, offsets, 64-bit fields. |
| TAR (ustar) header (subset) | Fixed-width ASCII octal numeric fields. |
| pcap file and record header | A self-referential meta test. |
| Custom TLV | Controlled difficulty for length and type fields. |

Protocols (v1.x):

| Protocol | Exercises |
|---|---|
| Modbus/TCP (showcase) | Real industrial protocol with public captures and a documented spec: transaction id, length, unit id, function code. |
| Custom toy binary protocol | Controlled: message type, sequence number, length. |
| DNS over UDP (stretch) | Aspirational probe: name compression and back-references; used to test limits, not a v1 target. |

**Metrics.**

- Field-boundary precision, recall, and F1 against ground-truth offsets.
- Perfection rate: fraction of formats parsed exactly correctly (a metric used in the PRE literature, included for comparability).
- Semantic role accuracy and type accuracy.
- Parser validity: the generated Kaitai compiles and parses all samples.

**Targets (adopted; starting bars, tracked by `sextant bench` and tuned upward over time).**

- Statistics-only MVP: field-boundary F1 at least 0.85 and perfection at least 0.5 on the file-format corpus.
- Parser validity: 100% on the corpus. The chosen IR parses every sample by construction of the verification loop, and the exported Kaitai must parse every sample in the optional cross-check.
- With the model pass: field role accuracy at least 0.8 on a held-out subset and a measurable improvement over statistics-only, with no regression in the verified parse score.

The benchmark is run by `sextant bench` and its numbers are published in the README. The framing positions Sextant against the academic baselines (Netzob, BinaryInferno, and similar) on comparable metrics.

## 16. Security, safety, and privacy

- **Untrusted input.** Sextant is built to parse hostile data. Safe Rust core (NFR-1), fuzzed parsers (NFR-2), and enforced resource limits (FR-24). Input is never executed.
- **Operational guidance.** Documentation instructs users to analyze potentially malicious samples in an isolated environment.
- **Model data handling.** Offline by default in `--no-llm`; explicit documentation of what is transmitted otherwise; byte caps on prompts.
- **Supply chain.** `cargo-deny` for licenses and advisories in CI; reproducible, checksummed release artifacts (NFR-10).
- **Responsible use.** The README disclaimer applies: Sextant is for defensive research, interoperability, malware analysis, and the reverse engineering of formats the user is authorized to analyze.

## 17. Dependencies and technology choices

Rust 2024 edition, MSRV 1.85.0 (pinned in `rust-toolchain.toml`). Indicative crates (final selection in the checklist):

- CLI and config: `clap`, a config loader, `serde`, `serde_json`.
- Errors and logging: `thiserror`, `anyhow`, `tracing`, `tracing-subscriber`.
- Inference: a sequence-alignment crate (for example `bio`), `bitvec` for sub-byte fields, `rayon` for parallel statistics where it helps.
- Model client: `reqwest`, `tokio` (Anthropic and OpenAI providers; Ollama optional).
- Protocols (v1.x): a pcap reader and packet-parsing crates.
- Testing: `insta` for snapshots, `proptest` for properties, `cargo-fuzz` for fuzzing, `criterion` for benchmarks.
- CI and release: GitHub Actions, `rustfmt`, `clippy`, `cargo-deny`, `cargo-audit`, `cargo-dist`.

## 18. Release plan and milestones

Aligned with the README roadmap and expanded in the checklist.

- **M0 Scaffold.** Repo, workspace, CI, docs, ground-truth corpus skeleton.
- **M1 Verified core, no model.** IR, executor, scorer, statistical inference, end-to-end `infer --no-llm` meeting initial accuracy targets.
- **M2 Model-augmented core.** Provider abstraction, semantic pass, refinement loop with the non-regression invariant.
- **M3 Exporters.** Kaitai, ImHex, Wireshark, 010, with corpus round-trip verification.
- **M4 Protocols and benchmarks.** pcap ingestion, a protocol case study, published benchmarks.
- **M5 Hardening and packaging.** Fuzzing in CI, resource limits, prebuilt binaries, crates.io.
- **M6 Public launch.** Repo public, docs and demo complete, first release announced.

## 19. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Inference accuracy is low on complex, compressed, or encrypted formats | Tool looks weak | Scope to structured data; detect and mark opaque regions; report low confidence honestly. |
| Model hallucination | Wrong output, lost trust | Core design: every proposal is verified by the executor (FR-26, FR-31); model can never lower the verified score. |
| Kaitai compiler and JVM friction | Install pain | Executor is native and JVM-free (FR-21); Kaitai compilation is optional and only for cross-checking and `--format kaitai` export. |
| Model cost | Spend and slowness | Caps, budget, and on-disk caching (NFR-9). |
| Scope creep | Slips and complexity | Phased plan, MVP discipline, acceptance criteria per step. |
| Overfitting an IR to a single sample | Misleading results | Generality term in the score (Section 11). |

## 20. Decisions (resolved)

1. **Crate split:** adopt the multi-crate workspace (`sextant-ir`, `sextant-engine`, `sextant-llm`, `sextant-export`, `sextant-cli`, plus a `bench` or `xtask` harness).
2. **LLM providers:** Anthropic and OpenAI are both first-class, feature-gated reference providers; Ollama is optional for local use. The active provider is auto-detected from available credentials, and `--provider` disambiguates when more than one is present.
3. **Ground-truth corpus:** finalized in Section 15. PNG is the file-format showcase, Modbus/TCP is the protocol showcase, and DNS is a stretch probe.
4. **Accuracy targets:** finalized in Section 15 (field-boundary F1 at least 0.85 and perfection at least 0.5 for the statistics-only MVP; parser validity 100%; field role accuracy at least 0.8 with the model pass).
5. **Exit codes:** adopted in Section 14.
6. **Toolchain:** Rust 2024 edition, MSRV 1.85.0, pinned in `rust-toolchain.toml` and raisable as needed.
7. **License:** dual MIT or Apache-2.0.
8. **Build agents:** the project is built by interchangeable AI coding agents (Claude Code and Codex). Every checklist step is self-contained and provider-agnostic so either agent can execute any step. Steps remain order-dependent.

## 21. Glossary

- **Field map**: the human-readable list of inferred fields with offsets, sizes, types, roles, values, and confidence.
- **Format Hypothesis IR**: the internal, executable representation of a hypothesized format.
- **Executor**: the native component that runs an IR against bytes and produces a parse or a localized failure.
- **Fit score**: a 0 to 1 measure of how well an IR explains the sample set.
- **Perfection rate**: the fraction of formats parsed exactly correctly, used for comparability with PRE research.
- **PRE**: protocol reverse engineering.

## 22. Appendix: prior art

Sextant builds on the statistical techniques defined by the protocol-reverse-engineering literature (Netzob, NetPlier, NEMESYS, BinaryInferno, DynPRE, BinPRE) and on the practical binary-description ecosystem (Kaitai Struct, ImHex, 010 Editor). Its contribution is to connect sample-based inference, language-model semantics, and round-trip verification into a single tool that emits a tested parser.
