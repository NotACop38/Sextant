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
- Sample confidentiality. Nothing leaves the machine unless `infer` is given
  `--provider`. With the model pass enabled, a request holds the candidate
  field layout and at most 256 bytes from each of the first four samples.
- Provider API keys.

## Entry points (untrusted input)

1. Sample files, directories, and globs (ingestion).
2. Packet captures, `.pcap` and `.pcapng` (the native pcap reader).
3. Reports and serialized IR (JSON) read by `inspect` and `export`, handed to
   the validator and executor.
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
  Directory inputs and glob patterns (for example `root/**/*`) are expanded by
  one bounded walker that never follows a symlink it finds, so it cannot loop on
  a cycle or read outside the selected tree; only a symlink named explicitly as
  an input, or as the literal leading directories of a glob, is honored. The
  walk stops with a notice after one million directory entries or 100,000
  resolved files. Only regular files become samples: FIFOs, sockets, and
  devices are skipped with a notice, and each file is checked again through its
  open handle, opened without blocking on Linux, macOS, and the BSDs, so a file
  swapped for a FIFO cannot hang a run. Capture inputs (`--transport` and
  `--port`) go through the same ingestion. The `inspect` and
  `export --cross-validate` paths apply the same per-sample and total byte caps
  and the same regular-file check, and report JSON is size-capped before parse.
- The pcap reader skips packets the capture cut short (captured length below
  the original length, or an IP or UDP length beyond the captured bytes) rather
  than treating a partial payload as a message, and reports how many it
  skipped. A truncated or corrupt later record or block ends reading with the
  earlier messages kept and a notice.
- The CLI escapes control characters and Unicode bidirectional and invisible
  controls in everything untrusted it prints: file names, patterns, arguments,
  report contents (including names quoted in validation errors), model output,
  and external tool output. A hostile name cannot inject terminal escape
  sequences.
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
  then converted to typed operations, validated, and re-scored before
  acceptance. Names must be ASCII identifiers of bounded length, free text is
  stripped of control characters and bounded, the number of entries and the
  re-scoring work are capped, and a rename is refused if it would change which
  field any reference binds to.
- Generated identifiers, string literals, and checksum comments are escaped or
  sanitized. Unsupported target layouts are rejected, and generated Lua enforces
  progress and work limits. Regression coverage is distinct from qualification
  in every target runtime.
- Secrets come only from the environment or a config file (`SEXTANT_CONFIG`, or
  by default `~/.config/sextant/config`, `%APPDATA%\sextant\config` on Windows,
  as `KEY=VALUE` lines), never from a flag, are never logged, and the on-disk
  cache that can hold sample-derived bytes is written owner-only on Unix. On
  Unix a config file that grants its group or others any access is refused.
  Process environment values override file contents.
- The model pass is opt-in: it runs only when `--provider` names a provider,
  never because a credential is present. `--no-llm` states the intent and
  rejects `--provider`, and a build without the `llm` feature links no network
  crate at all. The executor and scorer have no network, JVM, or
  external-runtime dependency in any build.

## Out of scope

- Decompressing, decrypting, or deobfuscating payloads.
- Trusting the optional Kaitai compiler cross-check; it is never required by the
  core pipeline.
- Defending the host against parser code the user chooses to run in another
  tool without reviewing it first.
