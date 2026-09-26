# Contributing to Sextant

Thank you for your interest in Sextant. Contributions of code, formats, and
sample corpora are welcome.

## Before you start

- Read [`AGENTS.md`](AGENTS.md). It is the operating manual for working in this
  repository and applies to humans and AI coding agents alike.
- The [Product Requirements Document](docs/PRD.md) is the source of truth for
  what Sextant does and why. Requirement tags such as `FR-26` refer to it. The
  [Engineering Checklist](docs/ENGINEERING_CHECKLIST.md) records the build plan
  that produced the current version.
- By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## How to work

- Work from an issue or a clearly scoped change, with one branch and one pull
  request per change.
- The verification invariant is non-negotiable: a model or heuristic change is
  never accepted if it lowers the verified parse score on the full sample set.
  The model proposes; the native executor disposes.
- Keep the parsing core in safe Rust. New `unsafe` requires a written
  justification comment and a covering test.
- Every public item carries a doc comment; the `missing_docs` lint enforces it.
- Use no em dashes or en dashes anywhere: prose, code comments, generated docs,
  or CLI output. Use hyphens, colons, or commas.
- Do not tune inference against the held-out benchmark tier. A format that has
  been consulted while developing a change leaves that tier (see
  [`corpus/README.md`](corpus/README.md)).

## Before you open a pull request

Run the [full local gate in `AGENTS.md`](AGENTS.md#commands) and make sure it
is clean. It matches what CI checks on the current host.

Two parts of CI need external tools and are worth running locally when you
touch the areas they cover:

- **Exporter runtimes.** With the Kaitai Struct compiler 0.11 on `PATH` (or
  named by `SEXTANT_KAITAI_COMPILER`), the `kaitaistruct` Python package, and
  Lua 5.4 installed, run
  `SEXTANT_REQUIRE_KAITAI=1 SEXTANT_REQUIRE_LUA=1 cargo test -p sextant-export`.
  Without the variables, tests that need a missing tool are skipped.
- **Examples.** After `cargo build --release`, run `./examples/quickstart.sh`
  and `python3 examples/record_demo.py`.

The CLI's model providers are behind the `llm` feature. The all-feature build
and test in the gate cover them; `cargo build -p sextant-re --features llm`
builds a binary that can use `--provider`.

A pull request is ready when the Global Definition of Done in
[`AGENTS.md`](AGENTS.md) is satisfied and CI is green.

## Documentation and examples

User documentation lives in [`docs/`](docs/index.md). When you change
user-facing behavior, update the relevant page in the same pull request.

- The documentation is checked in CI by the `docs_build` test in the
  `sextant-bench` crate: every relative link in `docs/` and `examples/` must
  resolve, and no Markdown file may contain an em dash or an en dash. Run it
  with `cargo test -p sextant-bench --test docs_build`.
- The benchmark block in the README is generated. After a change that moves
  the numbers, run `cargo run -p sextant-bench -- --write-readme`; a test fails
  when the block is stale.
- Runnable examples live in [`examples/`](examples/README.md) and work against
  the bundled corpus.
- The demo at [`docs/demo.cast`](docs/demo.cast) is generated from genuine
  command output by `python3 examples/record_demo.py`. Regenerate it whenever
  the demo flow changes rather than editing the cast by hand.

## Reporting issues

The most valuable issues describe formats or protocols you would like to
reverse, or point to public sample corpora suitable for benchmarking. They
directly shape the test suite. Report security vulnerabilities privately, as
described in [`SECURITY.md`](SECURITY.md).

## License

Unless you state otherwise, your contributions are dual licensed under
[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at the recipient's option,
matching the license of the project.
