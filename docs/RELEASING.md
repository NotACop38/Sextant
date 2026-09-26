# Releasing Sextant

This document describes how Sextant is versioned, packaged, and published
(PRD Section 18, NFR-5, NFR-10). No version has been released yet; the first
release is planned as 0.1.0.

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

The bare name `sextant` is taken on crates.io by an unrelated
celestial-navigation crate, so the published names are:

| Crate (directory) | Published name   | Purpose                                 |
|-------------------|------------------|-----------------------------------------|
| `sextant-ir`      | `sextant-ir`     | Format Hypothesis IR                    |
| `sextant-llm`     | `sextant-llm`    | Provider-agnostic model interface       |
| `sextant-engine`  | `sextant-engine` | Ingestion, inference, executor, scorer  |
| `sextant-export`  | `sextant-export` | Kaitai, ImHex, Wireshark, 010 exporters |
| `bench`           | `sextant-bench`  | Evaluation and benchmark harness        |
| `sextant-cli`     | `sextant-re`     | The CLI; installs the `sextant` binary  |

The installed binary is always named `sextant`. The model providers are behind
the CLI's `llm` feature, which is off by default; release binaries enable it.
The `fuzz` crate is nightly-only tooling and is not published.

## Before the first release: repository settings

These are one-time maintainer actions in the GitHub settings; nothing in the
repository can perform them.

- **Private vulnerability reporting.** Enable it under **Settings, Code
  security, Private vulnerability reporting**, so the "Report a vulnerability"
  button that [`SECURITY.md`](../SECURITY.md) describes exists.
- **Issue labels.** Apply the label set in `.github/labels.yml`, which
  [the triage guide](TRIAGE.md) relies on:
  `REPO=NotACop38/Sextant scripts/setup-labels.sh` (needs the GitHub CLI; safe
  to re-run).

## Changelog

The changelog follows [Keep a Changelog](https://keepachangelog.com/). Work is
recorded under the `## [Unreleased]` heading. Cutting a release means:

1. Rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` and remove its
   "not yet released" note.
2. Add a fresh, empty `## [Unreleased]` section above it.
3. Update the link references at the bottom of the file: `[Unreleased]`
   compares `vX.Y.Z...HEAD`, and `[X.Y.Z]` points at the release tag.

The release workflow extracts the body of the `## [X.Y.Z]` section and uses it
as the GitHub Release notes, so keep that section accurate.

## Cutting a release

1. Update `version` in the root `Cargo.toml` (`[workspace.package]`) and the
   matching `version` fields in `[workspace.dependencies]` for the internal
   crates.
2. Update `CHANGELOG.md` as described above.
3. Run the full local gate in [`AGENTS.md`](../AGENTS.md#commands) and confirm
   CI is green on the release commit.
4. Tag and push: `git tag vX.Y.Z` and `git push origin vX.Y.Z`. A tag with a
   SemVer prerelease suffix (for example `v0.2.0-rc.1`) is published as a
   GitHub prerelease, which install scripts that follow the latest release
   never pick up.
5. The `Release` workflow (`.github/workflows/release.yml`) verifies the tag,
   builds `sextant` with the `llm` feature for each target below, smoke-tests
   every binary against the committed corpus, packages it with the licenses and
   the changelog, and publishes the archives with their checksums to a GitHub
   Release.

## Prebuilt binaries and checksums

The workflow produces:

- `sextant-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz`, built on Ubuntu 22.04 so it
  needs glibc 2.34 or newer (the smoke test refuses a build that needs more);
- `sextant-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz`, a fully static build that
  runs on any x86_64 Linux, including musl distributions such as Alpine;
- `sextant-vX.Y.Z-x86_64-apple-darwin.tar.gz` and
  `sextant-vX.Y.Z-aarch64-apple-darwin.tar.gz`;
- `sextant-vX.Y.Z-x86_64-pc-windows-msvc.zip`.

Each archive has a companion `.sha256` file, and an aggregate `SHA256SUMS`
manifest covers them all (NFR-10). The workflow verifies the manifest with
`shasum -a 256 --strict -c` before publishing.

## Publishing to crates.io

Publish in dependency order so each crate's path dependencies already exist on
the registry:

```
cargo publish -p sextant-ir
cargo publish -p sextant-llm
cargo publish -p sextant-engine
cargo publish -p sextant-export
cargo publish -p sextant-bench
cargo publish -p sextant-re
```

Verify locally first without uploading:

```
cargo publish -p sextant-ir --dry-run
# Dependent crates need their path dependencies on the registry to fully
# verify, so use --no-verify for a packaging-only check before the real publish:
cargo package -p sextant-engine --no-verify
```

After publishing, `cargo install sextant-re --features llm` installs a
`sextant` that can use `--provider`, and `cargo install sextant-re` installs a
statistics-only build with no network code.

## Install scripts and Homebrew

- `scripts/install.sh` (Linux and macOS) and `scripts/install.ps1` (Windows)
  download the release archive for the host platform, verify its checksum, and
  install the `sextant` binary. On x86_64 Linux, `install.sh` picks the glibc
  build on glibc 2.34 or newer and the static musl build otherwise. They
  install released artifacts only, so they work once a release exists.
- `packaging/homebrew/sextant.rb` is a formula template for a Homebrew tap. On
  each release, update its `version` and its three `sha256` values (macOS arm64,
  macOS Intel, and the static Linux build) from the published archives.

## After a release

- The Releases page lists the version with all five archives, their `.sha256`
  files, and `SHA256SUMS`.
- `scripts/install.sh` installs a working `sextant` on a clean machine.
- After a crates.io publish, `cargo install sextant-re` produces a working
  binary.
