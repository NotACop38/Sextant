# Public launch checklist

This is the operating manual for taking Sextant public (Step 16 of the
engineering checklist, milestone M6). Everything that can be prepared in the
repository has been prepared. The remaining items are **maintainer actions**:
they change the repository's visibility, its GitHub settings, or publish
artifacts to external registries, none of which an agent or CI can or should do
on the maintainer's behalf. Run them in order.

Throughout, `OWNER/REPO` is `NotACop38/Sextant`.

## 0. Pre-flight (already done in the repository)

- README badges are live: CI status, crates.io version, and license.
- The roadmap, contributing, and license notes reflect the v0.1.0 release.
- `SECURITY.md`, the responsible-use disclaimer, and the data-handling notes are
  current.
- Issue labels are defined in `.github/labels.yml`; the triage process is in
  `docs/TRIAGE.md`; issue templates apply the `triage` label.
- The release pipeline (`.github/workflows/release.yml`) and `docs/RELEASING.md`
  are in place. `CHANGELOG.md` has a dated `## [0.1.0]` section ready to become
  the release notes.

Confirm the local checks are green before going further:

```sh
cargo fmt --all --check
cargo build --all-targets
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check
```

## 1. Flip the repository to public

This is a one-way-ish setting and a deliberate maintainer decision.

- GitHub UI: **Settings -> General -> Danger Zone -> Change visibility ->
  Make public**, or
- GitHub CLI:

  ```sh
  gh repo edit NotACop38/Sextant --visibility public --accept-visibility-change-consequences
  ```

After this, the CI badge in the README resolves against the public Actions runs.

## 2. Enable Discussions

- GitHub UI: **Settings -> General -> Features -> Discussions** (check the box),
  or
- GitHub CLI:

  ```sh
  gh repo edit NotACop38/Sextant --enable-discussions
  ```

Optionally seed an "Announcements" category and post the v0.1.0 note (a draft is
in `docs/ANNOUNCEMENT.md`).

## 3. Apply the issue labels

The label definitions live in the repository; GitHub cannot store them as files,
so apply them once with the helper script (idempotent; safe to re-run):

```sh
# Requires the GitHub CLI authenticated with repo access.
REPO=NotACop38/Sextant scripts/setup-labels.sh
```

Verify with `gh label list --repo NotACop38/Sextant`. Triage then follows
`docs/TRIAGE.md`.

## 4. Cut the first tagged release

The version is already `0.1.0` across the workspace and the changelog section is
dated. Tag from the default branch and push the tag:

```sh
git checkout main
git pull
git tag v0.1.0
git push origin v0.1.0
```

Pushing the tag triggers `.github/workflows/release.yml`, which verifies the tag
matches the workspace version, builds `sextant` for Linux, macOS (Intel and
Apple Silicon), and Windows, writes per-archive `.sha256` files and an aggregate
`SHA256SUMS`, and publishes a GitHub Release with the changelog body as the
notes. Watch it with:

```sh
gh run watch --repo NotACop38/Sextant
```

When it finishes, confirm the release has the four archives, their `.sha256`
files, and `SHA256SUMS`:

```sh
gh release view v0.1.0 --repo NotACop38/Sextant
```

## 5. Publish to crates.io

This uploads to an external registry and needs a crates.io token in the local
environment (`cargo login`). Publish in dependency order so each crate's path
dependencies already exist on the registry (see `docs/RELEASING.md`):

```sh
cargo publish -p sextant-ir
cargo publish -p sextant-llm
cargo publish -p sextant-export
cargo publish -p sextant-engine
cargo publish -p sextant-bench
cargo publish -p sextant-re
```

Once `sextant-re` is live, the crates.io badge resolves and
`cargo install sextant-re` installs a working `sextant` binary. Verify:

```sh
cargo install sextant-re
sextant --version
```

## 6. Optional: Homebrew tap

If you maintain a tap, update `packaging/homebrew/sextant.rb` with the published
archive URLs and their `sha256` values from the GitHub Release, then push it to
the tap repository.

## 7. Post-launch verification

- README badges render (CI green, crates.io version shows `0.1.0`).
- The Releases page lists v0.1.0 with downloadable, checksummed binaries.
- `gh label list` shows the full label set.
- Discussions is enabled and reachable.
- A fresh `cargo install sextant-re` produces a working `sextant`.

That completes the Step 16 acceptance criteria.
