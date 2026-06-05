#!/bin/sh
# Sextant installer for Linux and macOS.
#
# Downloads the prebuilt `sextant` binary for this platform from the GitHub
# Releases page, verifies its SHA-256 checksum, and installs it into a bin
# directory on your PATH. It does not require Rust or a compiler.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/NotACop38/Sextant/main/scripts/install.sh | sh
#
# Environment overrides:
#   SEXTANT_VERSION   Version to install, for example 0.1.0 (default: latest).
#   SEXTANT_BIN_DIR   Install directory (default: $HOME/.local/bin).
#   SEXTANT_REPO      GitHub owner/repo (default: NotACop38/Sextant).
#
# This script installs released artifacts only; to build from source use
# `cargo install sextant-re` or `cargo build --release`.

set -eu

REPO="${SEXTANT_REPO:-NotACop38/Sextant}"
BIN_NAME="sextant"
BIN_DIR="${SEXTANT_BIN_DIR:-$HOME/.local/bin}"

err() {
  echo "install.sh: error: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || err "required tool not found: $1"
}

need uname
need tar
need mkdir
# A downloader: curl preferred, wget accepted.
if command -v curl >/dev/null 2>&1; then
  DL="curl -fsSL"
  DL_O="curl -fsSL -o"
elif command -v wget >/dev/null 2>&1; then
  DL="wget -qO-"
  DL_O="wget -qO"
else
  err "need either curl or wget to download releases"
fi

# Detect the target triple from the host OS and architecture.
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Linux)
    case "$arch" in
      x86_64 | amd64) target="x86_64-unknown-linux-gnu" ;;
      *) err "unsupported Linux architecture: $arch (try cargo install sextant-re)" ;;
    esac
    ;;
  Darwin)
    case "$arch" in
      x86_64) target="x86_64-apple-darwin" ;;
      arm64 | aarch64) target="aarch64-apple-darwin" ;;
      *) err "unsupported macOS architecture: $arch" ;;
    esac
    ;;
  *)
    err "unsupported OS: $os (on Windows use scripts/install.ps1)"
    ;;
esac

# Resolve the version: explicit override, or the latest published release.
version="${SEXTANT_VERSION:-}"
if [ -z "$version" ]; then
  api="https://api.github.com/repos/${REPO}/releases/latest"
  tag="$($DL "$api" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\(.*\)".*/\1/p' | head -n1)"
  [ -n "$tag" ] || err "could not determine the latest release tag from $api"
  version="${tag#v}"
fi

archive="${BIN_NAME}-v${version}-${target}.tar.gz"
base="https://github.com/${REPO}/releases/download/v${version}"
url="${base}/${archive}"
sum_url="${url}.sha256"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading ${archive} ..."
$DL_O "$tmp/$archive" "$url" || err "download failed: $url"
$DL_O "$tmp/$archive.sha256" "$sum_url" || err "checksum download failed: $sum_url"

# Verify the checksum before trusting the archive.
echo "Verifying checksum ..."
expected="$(awk '{print $1}' "$tmp/$archive.sha256")"
[ -n "$expected" ] || err "empty checksum file"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$archive" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')"
else
  err "need sha256sum or shasum to verify the download"
fi
[ "$expected" = "$actual" ] || err "checksum mismatch: expected $expected, got $actual"

echo "Extracting ..."
tar -xzf "$tmp/$archive" -C "$tmp"
extracted="$tmp/${BIN_NAME}-v${version}-${target}/${BIN_NAME}"
[ -f "$extracted" ] || err "binary not found in archive"

mkdir -p "$BIN_DIR"
install -m 0755 "$extracted" "$BIN_DIR/$BIN_NAME" 2>/dev/null ||
  { cp "$extracted" "$BIN_DIR/$BIN_NAME" && chmod 0755 "$BIN_DIR/$BIN_NAME"; }

echo "Installed ${BIN_NAME} ${version} to ${BIN_DIR}/${BIN_NAME}"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "Note: ${BIN_DIR} is not on your PATH. Add it, for example:"
     echo "  export PATH=\"${BIN_DIR}:\$PATH\"" ;;
esac
echo "Run '${BIN_NAME} --help' to get started."
