# Sextant security review and remediation

> INTERNAL ARTIFACT. This file is the working record of a pre-disclosure
> security audit. It is not user documentation and not the public security
> policy (see `SECURITY.md` for that). Maintainers may choose to add this file
> to `.gitignore` once its findings are absorbed into the changelog and the
> tracked issues. It is committed here so the remediation trail is auditable in
> the pull request that performed the work.

## Executive summary

This was a single autonomous identify-fix pass over the whole source tree of
Sextant: a Rust CLI that infers binary-format and protocol structure from
untrusted samples and emits parsers (Kaitai, ImHex, Wireshark, 010) that users
run elsewhere. The review verified the PRD invariants against the actual code
(FR-21, FR-24, FR-26, FR-31, FR-40, NFR-1, NFR-2, NFR-4) and fixed the issues
found, with a regression test for each where one is feasible.

The codebase was already in strong shape: the parsing core is panic-averse and
resource-bounded, the executor and scorer are native and offline, and the
refinement and semantic passes enforce the non-regression invariant correctly.
The one genuinely serious issue was a code-injection path in the Wireshark Lua
exporter; it is fixed.

Recommendation: GO for public disclosure, after the standard CI gates
(`cargo deny`, `cargo audit`) run in the project CI environment, which is where
those two tools are installed. They were not runnable in the review container.

### Findings by severity

| Severity | Count | Fixed | Escalated |
|---|---|---|---|
| Critical | 1 | 1 | 0 |
| High | 0 | 0 | 0 |
| Medium | 2 | 2 | 0 |
| Low | 2 | 2 | 0 |
| Info | 0 | 0 | 0 |

All findings were fixed. No escalations.

## Threat model

### Assets

- The integrity of the verification guarantee: an accepted hypothesis must have
  been confirmed by the native executor against the samples (FR-26, FR-31).
- The user's machine and the user's other tools: Sextant emits parser code that
  the user loads into Wireshark, ImHex, 010, or the Kaitai toolchain.
- Sample confidentiality: with `--no-llm`, no bytes leave the machine (NFR-4);
  with the model enabled, only a bounded byte view is sent.
- Secrets: provider API keys.

### Entry points (trust boundaries)

1. Untrusted sample files and directories (ingestion).
2. Untrusted packet captures, `.pcap` and `.pcapng` (pcap reader).
3. Untrusted serialized IR (JSON) fed to the validator and executor.
4. Hostile or malformed model responses (the LLM trust boundary).
5. The environment and config: provider selection and credentials.
6. The on-disk response cache.
7. The optional Kaitai compiler subprocess (cross-check only; not wired into the
   core and not invoked by the reviewed code paths).

### What the design already gets right (verified, not changed)

- The executor (`sextant-engine/src/executor.rs`) is bounded on every axis:
  recursion depth, array elements, total field count, a work-unit budget, and an
  optional wall-clock deadline that actually interrupts long work, including
  charging for delimiter scans and checksum ranges before doing them. It uses
  checked slicing, validated widths, and clamps integer decoding so no input
  panics (FR-24, NFR-2).
- Ingestion never reads a file whole; it caps per-sample and total bytes with a
  bounded reader (FR-5), and computes keep sizes in `u64` so a 32-bit target
  cannot wrap.
- The pcap reader uses `.get(..)` and `checked_add` throughout, advances the
  cursor by a positive minimum each block so it cannot loop, and skips
  fragmented or extension-header packets rather than misparsing them.
- The refinement loop and the LLM semantic pass both apply every proposal to a
  clone, re-validate it, re-score it with the native scorer, and accept it only
  when the verified score does not regress (FR-26, FR-31). The model response is
  parsed into a strict typed shape; structural kind changes are rejected.
- No code disables TLS verification. The HTTP client has a bounded timeout and
  bounded retries with backoff. Secrets are read only via an `EnvSource`
  (environment or config), never from a flag (FR-40).
- The Kaitai, ImHex, and 010 exporters route every identifier through the
  `snake`/`pascal` sanitizers (output restricted to `[a-z0-9_]` and PascalCase)
  and quote free text, so untrusted field names cannot break out.

## Findings (ordered by severity, security first)

### SEC-001 (Critical, code injection / code generation)

- Category: output and code-generation safety.
- Location: `sextant-export/src/wireshark.rs`, the array and struct element
  label sites in `emit_element`, `emit_array`, `emit_value`, `emit_integer`,
  `emit_delimited`, and the enum value-string table; the `lua_escape` helper.
- Impact: array and struct element display labels were interpolated raw into Lua
  double-quoted string literals (for example `:add(buffer(offset), "{label}")`
  and `ProtoField.bytes("proto.key", "{label}")`). Element names are not
  constrained to a safe character set by IR validation and can originate from a
  hostile model response (the semantic pass sets arbitrary field names) or a
  crafted sample. A name containing a double quote plus Lua source breaks out of
  the label and injects arbitrary code into the generated dissector, which the
  user loads into Wireshark. The top-level field path was safe (it ran labels
  through `snake`), but the element path was not. The previous `lua_escape` also
  did not neutralize newlines or control bytes, so a newline in an enum variant
  name produced broken or injectable Lua in the value-string table.
- Fix: hardened `lua_escape` to escape the backslash and quote and to render
  newlines, carriage returns, tabs, and all other control characters as numeric
  `\ddd` escapes, and applied it to every label interpolation in the exporter.
- Test: `wireshark::tests::malicious_array_element_name_cannot_inject_lua` and
  `wireshark::tests::malicious_enum_variant_name_is_escaped` (both fail before
  the fix: the raw breakout sequence and a raw newline appear in the output).

### SEC-002 (Medium, denial of service / path containment)

- Category: input handling, resource limits.
- Location: `sextant-engine/src/ingest.rs`, `collect_dir`.
- Impact: recursive directory ingestion used `fs::metadata`, which follows
  symlinks. A symlink that points back at an ancestor directory caused unbounded
  recursion (stack exhaustion, a DoS), and a symlink pointing outside the
  selected tree let ingestion read files the user did not choose.
- Fix: directory traversal now reads each entry with `fs::symlink_metadata` and
  skips any symlink, so the walk stays inside the selected tree and cannot loop.
  A symlink given explicitly as a top-level input is still honored.
- Test: `ingest::tests::recursive_ingest_does_not_follow_a_symlink_cycle`
  (Unix), which builds a real symlink cycle and asserts ingestion terminates and
  returns only the real file.

### SEC-003 (Medium, privacy / local information disclosure)

- Category: cache safety, privacy.
- Location: `sextant-llm/src/cache.rs`, `ResponseCache::put`.
- Impact: cached LLM request and response files can echo bytes drawn from the
  samples sent to the model. They were written with the process umask, typically
  world-readable, so on a shared machine another local user could read
  sample-derived data from the cache.
- Fix: on Unix the cache directory is set to `0700` and entries are created
  `0600` (owner only) via a private write helper. Non-Unix targets keep the
  ordinary write, since the mode bits are POSIX specific.
- Test: `cache::tests::cached_entries_are_owner_only` (Unix), asserting the
  entry mode is exactly `0600`.

### SEC-004 (Low, secret hygiene)

- Category: secrets, logging.
- Location: `sextant-llm/src/providers/anthropic.rs` and
  `sextant-llm/src/providers/openai.rs`.
- Impact: both provider structs derived `Debug` with an `api_key: String` field,
  so any accidental `{:?}` of a provider (a log line, an error chain) would print
  the credential in full.
- Fix: replaced the derived `Debug` with a manual implementation that prints the
  model and base URL and renders the key as `[redacted]`.
- Test: `debug_never_reveals_the_api_key` in each provider module (compiled with
  the provider feature), asserting the secret never appears and the redaction
  marker does.

### SEC-005 (Low, defense in depth) verified, no change needed

- Category: LLM trust boundary.
- Location: `sextant-llm/src/provider.rs`, `extract_json`.
- Finding: model output is parsed with `serde_json`, which enforces a recursion
  depth limit by default, and `slice_between` indexes only at char boundaries
  returned by `find`/`rfind`. The parsed value flows only into the strict
  `ModelProposal` shape and then through the executor's non-regression gate. No
  unsafe action, file write, or command execution is reachable from model text.
  No change required; recorded for completeness.

## Optimization notes

No optimization changes were made. The hot paths (alignment, statistics, the
executor over many samples) are already linear in the bytes scanned and bounded
by the input caps; no quadratic or adversarial-complexity blow-up was found in
`align.rs`, `detect.rs`, `chunk.rs`, or `candidate.rs`. Changing the release
profile or parallelism was judged out of scope for a security pass and not worth
the regression risk against the non-regression invariant.

## Functionality and coverage additions

- Added negative or adversarial regression tests for each fix (see above).
- The existing fuzz targets (ingest, pcap, executor, infer, and one per
  exporter) already cover the input-facing components; no input-facing component
  was found without a target.

## Final gate

Run in the review container (all passing):

- `cargo build --all-targets`: ok.
- `cargo build --release`: ok (see run log).
- `cargo test --all-features`: ok, every suite green.
- `cargo clippy --all-targets --all-features`: clean.
- `cargo fmt --all --check`: clean.
- `sextant bench`: corpus accuracy unchanged from baseline (see run log).

Not runnable in the review container (no tool installed); must be confirmed by
project CI, where they are gated:

- `cargo deny check`.
- `cargo audit`.

## Escalations: needs maintainer decision

None.
