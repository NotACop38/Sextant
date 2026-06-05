#!/usr/bin/env sh
# Create or update the repository's issue and pull-request labels from
# .github/labels.yml using the GitHub CLI.
#
# This is a maintainer convenience: GitHub has no way to commit labels, so they
# are applied out of band. The script is idempotent. It uses `gh label create
# --force`, which creates a label or updates its color and description if it
# already exists. It does not delete labels that are absent from the file; remove
# stale ones by hand with `gh label delete <name>`.
#
# Usage:
#   scripts/setup-labels.sh                 # uses the current repo (gh default)
#   REPO=NotACop38/Sextant scripts/setup-labels.sh
#
# Requirements: the GitHub CLI (`gh`) authenticated with repo access. No extra
# YAML tooling is needed; this parses the simple, fixed shape of labels.yml.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
labels_file="$here/../.github/labels.yml"

if [ ! -f "$labels_file" ]; then
  echo "error: cannot find $labels_file" >&2
  exit 1
fi

repo_args=""
if [ "${REPO:-}" != "" ]; then
  repo_args="--repo $REPO"
fi

name=""
color=""
desc=""

apply() {
  # Apply the currently buffered label, if any.
  if [ "$name" = "" ]; then
    return 0
  fi
  echo "label: $name"
  # shellcheck disable=SC2086
  gh label create "$name" --color "$color" --description "$desc" --force $repo_args
  name=""
  color=""
  desc=""
}

# Strip a leading 'key: ' and surrounding double quotes from a value.
strip_value() {
  # $1 is the raw text after the key.
  value=$1
  # Trim a single pair of wrapping double quotes if present.
  case "$value" in
    \"*\") value=${value#\"}; value=${value%\"} ;;
  esac
  printf '%s' "$value"
}

while IFS= read -r line || [ "$line" != "" ]; do
  case "$line" in
    "- name:"*)
      apply
      name=$(strip_value "$(printf '%s' "$line" | sed -e 's/^- name:[[:space:]]*//')")
      ;;
    *"color:"*)
      color=$(strip_value "$(printf '%s' "$line" | sed -e 's/^[[:space:]]*color:[[:space:]]*//')")
      ;;
    *"description:"*)
      desc=$(strip_value "$(printf '%s' "$line" | sed -e 's/^[[:space:]]*description:[[:space:]]*//')")
      ;;
    *) : ;;
  esac
done < "$labels_file"

apply

echo "done."
