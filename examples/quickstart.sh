#!/usr/bin/env bash
#
# Quick start example: infer, inspect, and export a verified parser end to end,
# fully offline, against the bundled TLV corpus.
#
# Run it from the repository root:
#
#   cargo build --release
#   ./examples/quickstart.sh
#
# Override the format (any directory under corpus/) with the first argument:
#
#   ./examples/quickstart.sh png
#
set -euo pipefail

# Resolve the repository root from this script's location, so it works from any
# working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

FORMAT="${1:-tlv}"
SAMPLES_DIR="corpus/${FORMAT}/samples"
SEXTANT="${SEXTANT:-./target/release/sextant}"

if [ ! -x "${SEXTANT}" ]; then
  echo "error: ${SEXTANT} not found. Build it first with: cargo build --release" >&2
  exit 1
fi

if [ ! -d "${SAMPLES_DIR}" ]; then
  echo "error: no samples directory at ${SAMPLES_DIR}" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT
REPORT="${WORK_DIR}/report.json"

echo "== 1. infer (statistics-only, offline) =="
"${SEXTANT}" infer "${SAMPLES_DIR}" --no-llm --out "${REPORT}"

# Pick the first sample to inspect.
FIRST_SAMPLE="$(find "${SAMPLES_DIR}" -type f | sort | head -n 1)"

echo
echo "== 2. inspect ${FIRST_SAMPLE} =="
"${SEXTANT}" inspect "${REPORT}" --sample "${FIRST_SAMPLE}"

echo
echo "== 3. export a Kaitai Struct parser =="
"${SEXTANT}" export "${REPORT}" --format kaitai --out "${WORK_DIR}/${FORMAT}.ksy"
echo "Wrote ${WORK_DIR}/${FORMAT}.ksy:"
echo "---"
head -n 20 "${WORK_DIR}/${FORMAT}.ksy"
echo "---"

echo
echo "Done. The exported parser was generated from a structure verified against every sample."
