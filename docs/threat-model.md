# Sextant threat model

This is a short, public threat model for Sextant. It records what Sextant
protects, where untrusted data enters, and the trust boundaries the design
relies on. The detailed privacy notes live in
[privacy.md](privacy.md) and [model-data-handling.md](model-data-handling.md).

## Assets

- The verification guarantee: a hypothesis is reported only when the native
  executor confirmed it parsed the samples. A model or heuristic may propose
  anything, but a proposal is accepted only if the verified parse score does not
  regress.
- The user's machine and the user's other tools, since Sextant emits parser code
  (Kaitai, ImHex, Wireshark Lua, 010) that the user runs elsewhere.
- Sample confidentiality. With `--no-llm`, no bytes leave the machine. With the
  model pass enabled, only a bounded byte view is sent, and the user controls
  the cap.
- Provider API keys.

## Entry points (untrusted input)

1. Sample files, directories, and globs (ingestion).
2. Packet captures, `.pcap` and `.pcapng` (the native pcap reader).
3. Serialized IR (JSON) handed to the validator and executor.
4. Model responses, which may be hostile or malformed (the LLM boundary).
5. The environment and config, which select the provider and supply credentials.
6. The on-disk response cache.

## Trust boundaries and protections

- Untrusted bytes never reach unsafe code. The parsing core is safe Rust with
  enforced limits on recursion depth, array and field counts, total work, and an
  optional wall-clock deadline, so no input causes a panic, hang, or unbounded
  allocation.
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
  do not want PATH lookup. Treat that toolchain as outside the trusted computing
  base: it is never required by the core pipeline.
- `--out` refuses to overwrite an existing file or write outside the current
  working directory unless `--force` is set.
- The model is never trusted. Its response is parsed into a strict, typed
  proposal shape (no free-form text), and every proposal is re-validated and
  re-scored by the native executor before it can be accepted.
- Generated output is sanitized. Identifiers are restricted to a safe character
  set and string literals are escaped, so a crafted sample or model response
  cannot inject executable content into a generated parser.
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
