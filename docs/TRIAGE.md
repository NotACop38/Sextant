# Issue triage and contribution flow

This document describes how incoming issues and pull requests are handled in
Sextant. It is written for maintainers, but contributors may find it useful for
understanding what happens after they open something. The labels referenced here
are defined in [`.github/labels.yml`](../.github/labels.yml) and applied with
[`scripts/setup-labels.sh`](../scripts/setup-labels.sh).

## Where things go

- **Questions, format ideas, and open-ended discussion** belong in
  [GitHub Discussions](https://github.com/NotACop38/Sextant/discussions). If a
  question turns out to be a concrete defect or a scoped piece of work, it is
  promoted to an issue.
- **Defects and scoped work** belong in [issues](https://github.com/NotACop38/Sextant/issues),
  opened from the bug-report or feature-request template.
- **Security vulnerabilities** are reported privately, never as a public issue.
  See [`SECURITY.md`](../SECURITY.md).

## The triage flow

Every new issue starts with the `triage` label (the templates apply it
automatically). Triage aims to reach each new issue within a few days and do the
following:

1. **Confirm it is actionable.** Reproduce bugs where possible. If it needs more
   detail, apply `needs-info` and ask; close it later if the reporter does not
   respond and it cannot stand on its own.
2. **Classify the type.** Apply exactly one of `bug`, `enhancement`,
   `documentation`, `question`, `format-request`, or `corpus`. Add `security`
   if relevant (and move the conversation private if it is a real
   vulnerability).
3. **Classify the area.** Apply the `area: *` label for the crate or subsystem
   involved (`ir`, `engine`, `llm`, `export`, `cli`, `bench`, `ci`). More than
   one is fine when a change spans crates.
4. **Set a priority.** Apply one of `priority: high`, `priority: medium`, or
   `priority: low`. Correctness, memory-safety, and release-blocking issues are
   `priority: high`.
5. **Invite help where appropriate.** Apply `good first issue` to well-scoped
   starting points and `help wanted` where a contributor would be especially
   welcome.
6. **Remove `triage`** once the issue is classified. Its remaining labels now
   describe it.

Issues that are not actionable are closed with a short reason and the matching
label: `duplicate`, `wontfix`, or `invalid`. `blocked` marks work that is ready
but waiting on something else; note what it is blocked on.

## Pull requests

A pull request is ready to review when its checklist step's acceptance criteria
and the Global Definition of Done in [`AGENTS.md`](../AGENTS.md) are met and CI
is green. Reviewers check, above everything else, that the change respects the
**verification invariant**: no model or heuristic change may lower the verified
parse score on the full sample set. The model proposes; the native executor
disposes.

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the local check suite to run
before opening a pull request.

## Milestones and labels reference

The full label set, with colors and descriptions, lives in
[`.github/labels.yml`](../.github/labels.yml). To apply or update the labels on
the repository:

```sh
# Requires the GitHub CLI, authenticated with repo access.
REPO=NotACop38/Sextant scripts/setup-labels.sh
```
