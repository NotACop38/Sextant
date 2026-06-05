# Releasing Sextant

This document describes how Sextant is versioned, packaged, and published. It is
the operating manual for cutting a release (PRD Section 18, NFR-5, NFR-10).

## Versioning policy (SemVer)

Sextant follows [Semantic Versioning](https://semver.org/). While the project is
pre-1.0, the minor version may include breaking changes, and the patch version
is reserved for backward-compatible fixes.

All workspace crates share one version. It is set once in the root `Cargo.toml`
under `[workspace.package]` and inherited by every member with
`version.workspace = true`, so the published crates never drift apart. The
release workflow verifies that the git tag matches this version before building
anything.

## Crate names

The bare name `sextant` was already taken on crates.io by an unrelated
celestial-navigation crate, so the published names are:

| Crate (directory)   | Published name   | Purpose                                  |
|---------------------|------------------|------------------------------------------|
| `sextant-ir`        | `sextant-ir`     | Format Hypothesis IR                     |
| `sextant-engine`    | `sextant-engine` | Ingestion, inference, executor, scorer   |
| `sextant-llm`       | `sextant-llm`    | Provider-agnostic model interface        |
| `sextant-export`    | `sextant-export` | Kaitai, ImHex, Wireshark, 010 exporters  |
| `bench`             | `sextant-bench`  | Evaluation and benchmark harness         |
| `sextant-cli`       | `sextant-re`     | The CLI; installs the `sextant` binary   |

The installed binary is always named `sextant`. Users install the CLI with
`cargo install sextant-re`. The `fuzz` crate is nightly-only tooling and is not
published.

## Changelog

The changelog follows [Keep a Changelog](https://keepachangelog.com/). Day-to-day
work is recorded under the `## [Unreleased]` heading. Cutting a release means:

1. Rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`.
2. Add a fresh, empty `## [Unreleased]` section above it.
3. Update the link references at the bottom of the file.

The release workflow extracts the body of the `## [X.Y.Z]` section and uses it as
the GitHub Release notes, so keep that section accurate.

## Cutting a release

1. Update `version` in the root `Cargo.toml` (`[workspace.package]`) and the
   matching `version` fields in `[workspace.dependencies]` for the internal
   crates.
2. Update `CHANGELOG.md` as described above.
3. Run the full local check (see `AGENTS.md`): `cargo fmt --all --check`,
   `cargo build --all-targets`, `cargo test`,
   `cargo clippy --all-targets --all-features`, and `cargo deny check`.
4. Commit, then tag: `git tag vX.Y.Z` and `git push origin vX.Y.Z`.
5. The `Release` workflow (`.github/workflows/release.yml`) verifies the tag,
   builds `sextant` on Linux, macOS (Intel and Apple Silicon), and Windows,
   packages each build with the licenses and changelog, writes a per-archive
   `.sha256` and an aggregate `SHA256SUMS`, and publishes them to a GitHub
   Release.

## Prebuilt binaries and checksums (cargo-dist equivalent)

Rather than vendor a generated cargo-dist workflow, Sextant ships an equivalent
hand-written pipeline in `.github/workflows/release.yml`. It produces:

- `sextant-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz`
- `sextant-vX.Y.Z-x86_64-apple-darwin.tar.gz`
- `sextant-vX.Y.Z-aarch64-apple-darwin.tar.gz`
- `sextant-vX.Y.Z-x86_64-pc-windows-msvc.zip`

Each archive has a companion `.sha256` file, and an aggregate `SHA256SUMS`
manifest covers them all (NFR-10). Adopting cargo-dist later is a drop-in
replacement: run `dist init` and let it own this workflow.

## Publishing to crates.io

Publish in dependency order so each crate's path dependencies already exist on
the registry:

```
cargo publish -p sextant-ir
cargo publish -p sextant-llm
cargo publish -p sextant-export
cargo publish -p sextant-engine
cargo publish -p sextant-bench
cargo publish -p sextant-re
```

Verify locally first without uploading:

```
cargo publish -p sextant-ir --dry-run
# dependent crates need their path deps on the registry to fully verify, so use
# --no-verify for a packaging-only check before the real publish:
cargo package -p sextant-engine --no-verify
```

After publishing, `cargo install sextant-re` installs a working `sextant`.

## Install script and Homebrew

- `scripts/install.sh` (Linux and macOS) and `scripts/install.ps1` (Windows)
  download the release archive for the host platform, verify its checksum, and
  install the `sextant` binary. They install released artifacts only.
- `packaging/homebrew/sextant.rb` is a formula template for a Homebrew tap.
  Update its `version`, URLs, and `sha256` values from the published archives on
  each release.
