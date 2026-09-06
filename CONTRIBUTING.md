# Contributing to Sextant

Thank you for your interest in Sextant. The project is in early development and
is built one checklist step at a time. Contributions are welcome.

## Before you start

- Read [`AGENTS.md`](AGENTS.md). It is the operating manual for working in this
  repository and applies to humans and AI coding agents alike.
- The [Product Requirements Document](docs/PRD.md) is the source of truth for
  what Sextant does and why. The [Engineering Checklist](docs/ENGINEERING_CHECKLIST.md)
  is the step-by-step build plan. Requirement tags such as `FR-26` refer to the
  PRD.
- By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## How to work

- Work one checklist step at a time, and prefer one branch per step.
- The verification invariant is non-negotiable: a model or heuristic change is
  never accepted if it lowers the verified parse score on the full sample set.
  The model proposes; the native executor disposes.
- Keep the parsing core in safe Rust. New `unsafe` requires a written
  justification comment and a covering test.
- Use no em dashes or en dashes anywhere: prose, code comments, generated docs,
  or CLI output. Use hyphens, colons, or commas.

## Before you open a pull request

Run the canonical [full local gate in `AGENTS.md`](AGENTS.md#commands) and make
sure it is clean. That list includes the release build and the current CI
checks; use it instead of maintaining a separate command list here.

A pull request is ready when its checklist step's acceptance criteria and the
Global Definition of Done in [`AGENTS.md`](AGENTS.md) are satisfied, and CI is
green.

## Documentation and examples

User documentation lives in [`docs/`](docs/index.md). When you change
user-facing behavior, update the relevant page in the same pull request.

- The documentation is checked in CI by the `docs_build` test in the `bench`
  crate: every relative link in `docs/` and `examples/` must resolve, and no
  Markdown file may contain an em dash or an en dash. Run it with
  `cargo test -p bench --test docs_build`.
- Runnable examples live in [`examples/`](examples/README.md) and work against
  the bundled corpus. Build the binary with `cargo build --release`, then run
  `./examples/quickstart.sh` or
  `cargo run -p sextant-engine --example infer_corpus`.
- The demo at [`docs/demo.cast`](docs/demo.cast) is generated from genuine
  command output by `python3 examples/record_demo.py`. Regenerate it whenever
  the demo flow changes rather than editing the cast by hand.

## Reporting issues

The most valuable issues right now describe formats or protocols you would like
to reverse, or point to public sample corpora suitable for benchmarking. They
directly shape the test suite. See [`SECURITY.md`](SECURITY.md) for reporting
security vulnerabilities privately.

## License

Unless you state otherwise, your contributions are dual licensed under
[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at the recipient's option,
matching the license of the project.
