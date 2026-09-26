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
# On x86_64 Linux it installs the glibc build when the system has glibc 2.34 or
# newer, and otherwise (musl distributions such as Alpine, an older glibc, or a
# C library it cannot identify) the fully static musl build, which runs on any
# x86_64 Linux.
#
# This script installs released artifacts only. To build from source, clone the
# repository and run `cargo build --release --locked -p sextant-re`; the binary
# is written to target/release/sextant. On a platform without a prebuilt
# binary, the script prints those commands.

set -eu

REPO="${SEXTANT_REPO:-NotACop38/Sextant}"
BIN_NAME="sextant"
BIN_DIR="${SEXTANT_BIN_DIR:-$HOME/.local/bin}"
# The oldest glibc the x86_64-unknown-linux-gnu build supports. The release
# workflow refuses to publish a glibc build that needs anything newer.
GLIBC_MIN="2.34"

err() {
  echo "install.sh: error: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || err "required tool not found: $1"
}

# No prebuilt binary exists for this platform: print the exact commands that
# build and install sextant from source, then stop. (The CLI crate is not on
# crates.io yet, so `cargo install` cannot fetch it.)
from_source() {
  clone_ref=""
  if [ -n "${SEXTANT_VERSION:-}" ]; then
    clone_ref=" --branch v${SEXTANT_VERSION}"
  fi
  cat >&2 <<EOF
install.sh: error: no prebuilt ${BIN_NAME} binary is published for $1.
Build it from source instead (needs git and Rust 1.85 or newer, see https://rustup.rs):

  git clone${clone_ref} https://github.com/${REPO}.git sextant-src
  cd sextant-src
  cargo build --release --locked -p sextant-re
  mkdir -p "${BIN_DIR}"
  install -m 0755 target/release/${BIN_NAME} "${BIN_DIR}/${BIN_NAME}"
EOF
  exit 1
}

# Succeed when the dotted version $1 is at least $2 (for example 2.35 >= 2.34).
version_at_least() {
  awk -v have="$1" -v need="$2" 'BEGIN {
    nh = split(have, h, "."); nn = split(need, n, ".")
    for (i = 1; i <= (nh > nn ? nh : nn); i++) {
      a = (i <= nh) ? h[i] + 0 : 0
      b = (i <= nn) ? n[i] + 0 : 0
      if (a > b) exit 0
      if (a < b) exit 1
    }
    exit 0
  }'
}

# Succeed on a musl-based system such as Alpine.
is_musl() {
  [ -f /etc/alpine-release ] && return 0
  for loader in /lib/ld-musl-*.so.1; do
    [ -e "$loader" ] && return 0
  done
  command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl
}

# Choose the x86_64 Linux artifact for this system's C library.
pick_linux_x86_64_target() {
  glibc="$(getconf GNU_LIBC_VERSION 2>/dev/null | sed -n 's/^glibc //p')"
  if [ -n "$glibc" ]; then
    if version_at_least "$glibc" "$GLIBC_MIN"; then
      target="x86_64-unknown-linux-gnu"
      return 0
    fi
    echo "Detected glibc ${glibc}, older than ${GLIBC_MIN}: using the static musl build."
  elif is_musl; then
    echo "Detected musl libc: using the static musl build."
  else
    echo "Could not identify the C library: using the static musl build."
  fi
  target="x86_64-unknown-linux-musl"
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
      x86_64 | amd64) pick_linux_x86_64_target ;;
      *) from_source "Linux on $arch" ;;
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
