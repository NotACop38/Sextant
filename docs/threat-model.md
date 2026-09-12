# Sextant threat model

This is a short, public threat model for Sextant. It records what Sextant
protects, where untrusted data enters, and the trust boundaries the design
relies on. The detailed privacy notes live in
[privacy.md](privacy.md) and [model-data-handling.md](model-data-handling.md).

## Assets

- Native verification evidence: successful inference requires full coverage and
  passing constraints on retained samples; failures can still produce diagnostic
  reports. Refinements preserve aggregate fit and previously successful samples.
  Semantic meaning and exported runtime behavior require separate evidence.
- The user's machine and the user's other tools, since Sextant emits parser code
  (Kaitai, ImHex, Wireshark Lua, 010) that the user runs elsewhere.
- Sample confidentiality. With `--no-llm`, no bytes leave the machine. With the
  model pass enabled, requests contain candidate metadata and bounded byte
  previews. Metadata can include additional sample-derived constants.
- Provider API keys.

## Entry points (untrusted input)

1. Sample files, directories, and globs (ingestion).
2. Packet captures, `.pcap` and `.pcapng` (the native pcap reader).
3. Serialized IR (JSON) handed to the validator and executor.
4. Model responses, which may be hostile or malformed (the LLM boundary).
5. Operator-controlled environment and config, which select trusted provider and
   executable endpoints and supply credentials.
6. The optional on-disk response cache.
7. External benchmark manifests, sample paths, and ground-truth record counts.

## Trust boundaries and protections

- The native parsing core uses safe Rust with recursion, field, work, owned-output,
  and per-execution deadline limits. IR validation checks depth before recursive
  helpers and bounds diagnostics. Inspection uses a range sweep and output caps.
  These controls are exercised with malformed-input tests and fuzzing; they are
  not a proof covering every possible input.
- Ingestion caps per-sample and total bytes and never reads a file whole.
  Traversal of a literal directory input does not follow symlinks, so it cannot
  loop on a cycle or read outside the selected tree. A recursive glob pattern
  (for example `root/**/*`) is expanded by the `glob` crate, which may traverse
  symlinked directories while matching; after expansion Sextant refuses symlink
  matches themselves and drops any path whose canonical form escapes the glob's
  literal prefix. Prefer a literal directory input when the tree may contain
  symlink cycles. The `inspect` and `export --cross-validate` paths apply the
  same per-sample and total byte caps, and report JSON is size-capped before
  parse.
- Optional Kaitai cross-validation (`export --cross-validate`) shells out to
  tools found on `PATH` (`kaitai-struct-compiler` / `ksc`, and `python3` with
  `kaitaistruct`). Pin a reviewed binary with `SEXTANT_KAITAI_COMPILER` when you
  do not want PATH lookup. Cross-validation requires trusting that installation.
  It uses private scratch storage, isolated Python, deadlines and output caps;
  those controls are not a sandbox for compromised executables. The native core
  remains independent of this toolchain.
- `--out` atomically refuses existing final path entries without `--force` and
  checks directory containment. This is not a filesystem sandbox against an
  attacker concurrently replacing parent directories in an otherwise writable tree.
- Benchmark manifests and retained samples have aggregate budgets, path checks,
  and checked ground-truth expansion; oversize or inconsistent inputs fail.
- Model responses are untrusted. JSON can be extracted from surrounding prose,
  then converted to typed operations, validated, and re-scored before acceptance.
- Generated identifiers, string literals, and checksum comments are escaped or
  sanitized. Unsupported target layouts are rejected, and generated Lua enforces
  progress and work limits. Regression coverage is distinct from qualification
  in every target runtime.
- Secrets come only from the environment or a config file (`SEXTANT_CONFIG` or
  `~/.config/sextant/config` as `KEY=VALUE` lines), never from a flag, are never
  logged, and the on-disk cache that can hold sample-derived bytes is written
  owner-only on Unix. Process environment values override file contents.
- `--no-llm` produces zero network egress, and the executor and scorer have no
  network, JVM, or external-runtime dependency.

## Out of scope

- Decompressing, decrypting, or deobfuscating payloads.
- Trusting the optional Kaitai compiler cross-check; it is never required by the
  core pipeline.
- Defending the host against parser code the user chooses to run in another
  tool without reviewing it first.
