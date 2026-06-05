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
  running them against data you care about.
