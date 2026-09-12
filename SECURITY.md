# Security policy

Sextant is a tool for analyzing untrusted, potentially hostile binary input.
Security is a first-class concern for the project itself and for how it is used.

## Reporting a vulnerability

Please report security vulnerabilities privately. Do not open a public issue for
a security problem.

- Preferred: use GitHub's private vulnerability reporting for this repository
  (the "Report a vulnerability" button under the Security tab).
- Alternative: email the maintainer at tgraves38@protonmail.com.

Please include enough detail to reproduce the issue: the affected version or
commit, the input or command that triggers it, and the observed behavior. We
will acknowledge your report, work with you on a fix, and credit you unless you
prefer to remain anonymous.

## Supported versions

Sextant is pre-1.0 and under active development. Security fixes are applied to
the `main` branch. There are no long-term support branches yet.

## Using Sextant safely

Sextant parses untrusted binary data, including potentially malicious samples
such as malware configuration blobs and command-and-control captures.

- Analyze potentially malicious samples in an isolated environment, for example
  a disposable virtual machine or container with no sensitive data and limited
  network access.
- Sextant never executes input; it only parses it. The parsing core is written
  in safe Rust with enforced resource limits to bound memory and time.
- Run with `--no-llm` for fully offline analysis with zero network egress. When
  the language-model pass is enabled, review what is transmitted and use the
  per-sample byte caps to limit it.
- Treat generated parsers as you would any generated code: read them before
  running them against data you care about. Sextant sanitizes identifiers and
  escapes string literals derived from samples and from model output so a
  crafted name cannot inject executable content into a generated dissector or
  template, but reviewing generated code before running it remains good
  practice.

A short threat model, listing the assets, entry points, and trust boundaries,
is in [docs/threat-model.md](docs/threat-model.md).

## Data handling and privacy

Sextant runs fully offline by default. The native statistical engine, executor,
and scorer never touch the network, and `inspect`, `export`, and `bench` never
do either. The only component that can transmit data is the optional
language-model pass, and only when you opt into it.

- [Privacy and the `--no-llm` story](docs/privacy.md) explains what is and is
  not transmitted, and how to guarantee a fully offline run.
- [Model data handling](docs/model-data-handling.md) is the detailed note on
  exactly what the model pass sends, the byte-preview and call limits and the limitations of spend accounting, and how to turn it off. API keys are read
  only from the environment or a config file, never from a command-line flag.

The verification property is independent of mode: a hypothesis is accepted only
because the native executor confirmed it parsed your samples, so enabling the
model never lowers the verified parse score.

## Verification boundaries

Native fit is evidence about retained samples, not proof of semantic correctness,
all unseen inputs, or generated code in another runtime. Model and report labels
remain untrusted data. Ordinary exports are validated translations of a supported
IR subset; run external parser checks before relying on them.

Optional Kaitai cross-validation executes configured local tools. Private scratch
storage, Python isolated mode, process deadlines, and output caps reduce exposure,
but this is not a sandbox for a compromised compiler or Python installation.
Use trusted tools and isolate analysis of potentially malicious samples.
