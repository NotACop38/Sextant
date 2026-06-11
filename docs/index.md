# Sextant user guide

Sextant infers the structure of unknown binary file formats and network
protocols from sample data, then generates a parser it has verified against
those samples. This guide covers installing the tool, running it, and
understanding what it produces.

If you are new here, read the pages in order. If you are evaluating Sextant,
start with "How it works" to understand the verification property that sets it
apart.

## Contents

- [Installation](installation.md): build Sextant from source and check the
  binary works.
- [Quick start](quickstart.md): infer, inspect, and export a parser end to end
  in a few commands.
- [Workflows](workflows.md): the `infer`, `inspect`, and `export` commands in
  detail, plus `bench`.
- [How it works](how-it-works.md): the Format Hypothesis IR and the
  verification loop, the heart of the tool.
- [Privacy and the `--no-llm` story](privacy.md): what is and is not
  transmitted, and how to run fully offline.
- [Model data handling](model-data-handling.md): what the optional engine
  language-model path sends when an integrator enables it.
- [Examples](examples.md): runnable examples against the bundled corpus and the
  recorded demo.

## The short version

```bash
# Build the binary.
cargo build --release

# Infer structure from samples, fully offline.
./target/release/sextant infer corpus/tlv/samples --no-llm --out report.json

# Read a sample through the inferred field map.
./target/release/sextant inspect report.json --sample corpus/tlv/samples/sample_01.tlv

# Export a verified Kaitai Struct parser.
./target/release/sextant export report.json --format kaitai --out tlv.ksy
```

## Authoritative documents

This user guide is task-oriented. The project's authoritative documents live
beside it:

- [Product Requirements Document](PRD.md): the source of truth for what
  Sextant does and why. Requirement tags such as `FR-26` and `NFR-4` refer to
  it.
- [Engineering Checklist](ENGINEERING_CHECKLIST.md): the step-by-step build
  plan.
- [Agent guide](../AGENTS.md): how contributors and AI coding agents work in
  this repository.
- [Issue triage and contribution flow](TRIAGE.md): how issues and pull requests
  are labeled and handled.
- [Releasing](RELEASING.md): how Sextant is versioned, packaged, and published.
- [Public launch checklist](LAUNCH.md): the maintainer steps to take the project
  public and cut a release.

## A safety note

Sextant parses untrusted, potentially hostile binary input. Analyze
potentially malicious samples in an isolated environment, such as a disposable
virtual machine or container. Sextant never executes input; it only parses it.
See [SECURITY.md](../SECURITY.md) for the full security posture.
