# Installation

No version of Sextant has been released yet, so build it from source.
Prebuilt binaries and a crates.io package are planned for the first release;
see [Releasing](RELEASING.md).

## Prerequisites

- A Rust toolchain, installed with [rustup](https://rustup.rs/). The repository
  pins Rust 1.85.0, the minimum supported version, in `rust-toolchain.toml`,
  and rustup selects it automatically inside the repository.
- Git, to clone the repository.

The core needs no JVM, no network service, and no model account.

## Build from source

```bash
git clone https://github.com/NotACop38/Sextant
cd Sextant
cargo build --release -p sextant-re
```

This builds a statistics-only `sextant` at `./target/release/sextant`. It
contains no network code. To build a binary that can also run the optional
model pass (`infer --provider`), enable the `llm` feature:

```bash
cargo build --release -p sextant-re --features llm
```

Copy the binary onto your `PATH`, or run it in place. Check that it works:

```bash
./target/release/sextant --version
./target/release/sextant --help
```

`--help` lists the four subcommands: `infer`, `inspect`, `export`, and `bench`.

## After the first release

- **Prebuilt binaries.** Each release is planned to publish archives for
  x86_64 Linux (a glibc build and a static musl build), macOS on Intel and
  Apple silicon, and x86_64 Windows, with SHA-256 checksums. The scripts
  `scripts/install.sh` and `scripts/install.ps1` download the archive for the
  host, verify its checksum, and install `sextant`. Release binaries include
  the model providers.
- **crates.io.** The crate name `sextant` belongs to an unrelated project, so
  the CLI is to be published as `sextant-re`, which installs a binary named
  `sextant`. `cargo install sextant-re` will install the statistics-only build
  and `cargo install sextant-re --features llm` one that can use `--provider`.

## Optional components

Sextant runs fully offline with no extra components. Two capabilities add
external dependencies, and only when you use them:

- **Kaitai cross-validation.** `export --format kaitai --cross-validate <dir>`
  compiles the generated spec with the Kaitai Struct compiler
  (`kaitai-struct-compiler`, which needs a JVM) and parses every sample in the
  directory through the Python runtime (`python3` with the `kaitaistruct`
  package). The compiler is taken from `SEXTANT_KAITAI_COMPILER` when set,
  otherwise from `PATH`. When a tool is missing, the cross-check is reported as
  skipped, not failed, and nothing else depends on it.
- **The model pass.** A binary built with the `llm` feature can consult
  Anthropic, OpenAI, or a local Ollama server with `infer --provider`. API keys
  are read from the environment or a config file, never from a flag. See
  [Model data handling](model-data-handling.md).

## Running the checks

To confirm a build is healthy, run the tests and the benchmark regression
guard:

```bash
cargo test --workspace --all-features
cargo run -p sextant-bench -- --check
```

The full gate that CI runs, including Clippy, formatting, and the supply-chain
checks, is listed in [`AGENTS.md`](../AGENTS.md#commands).

## Next steps

- [Quick start](quickstart.md): your first inference, inspection, and export.
- [Workflows](workflows.md): the full command reference.
