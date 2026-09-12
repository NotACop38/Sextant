# Installation

Build Sextant from source today. As of 2026-09-12 no GitHub release is published,
and registry installation is not verified. Release workflows and packaging
templates are preparatory tooling.

## Prerequisites

- A Rust toolchain. Sextant pins Rust 2024 edition with a minimum supported
  version of 1.85.0 in `rust-toolchain.toml`, so a matching toolchain is
  selected automatically when you build inside the repository. Install Rust with
  [rustup](https://rustup.rs/) if you do not have it.
- Git, to clone the repository.

No JVM, no network service, and no language-model account are required to build
or to run the core. Those are optional and are described below.

## Prebuilt binaries

Once a tagged release is published and tested, download the
archive for your platform from the GitHub Releases page, verify it against the
published `SHA256SUMS`, and place the `sextant` binary on your `PATH`.

## From crates.io

The crates.io name `sextant` belongs to an unrelated project, so the CLI package
is configured for publication as `sextant-re`. After publication it should install
a binary named `sextant`; validate that path before relying on it.

```bash
cargo install sextant-re
```

## Build from source

```bash
git clone https://github.com/NotACop38/Sextant
cd Sextant
cargo build --release
```

The binary is written to `./target/release/sextant`. You can copy it onto your
`PATH` or run it in place.

Verify the build:

```bash
./target/release/sextant --version
./target/release/sextant --help
```

`--help` lists the four subcommands: `infer`, `inspect`, `export`, and `bench`.

## Optional components

Sextant runs fully offline with no extra components. Two capabilities are
optional and add external dependencies only when you choose to use them:

- **Kaitai cross-validation.** The `export --format kaitai --cross-validate`
  option can compile the generated spec and parse your samples through it as an
  independent check. That option shells out to the Kaitai Struct compiler
  (`kaitai-struct-compiler`), which requires a JVM, plus Python with the
  `kaitaistruct` package. The core never depends on
  it: if the compiler is absent the cross-check is reported as skipped, not
  failed, and every other command works without it.
- **The engine language-model path.** The optional semantic path reads API keys
  from the environment or a config file only. The v0.1.0 CLI does not expose
  provider flags, so CLI inference remains statistics-only and offline. See
  [Privacy and the `--no-llm` story](privacy.md).

## Running the test suite

To confirm the build is healthy, run the workspace checks:

```bash
cargo build --all-targets
cargo test
cargo clippy --all-targets --all-features
cargo fmt --all --check
```

All of these run in CI on every change. The benchmark regression guard
(`cargo run -p sextant-bench -- --check`) runs there too.

## Next steps

- [Quick start](quickstart.md): your first inference, inspection, and export.
- [Workflows](workflows.md): the full command reference.
