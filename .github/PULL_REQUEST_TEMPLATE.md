## Summary

Describe what this change does and why.

## Related issue

Link the issue this change addresses, if there is one.

## Checklist

- [ ] The full local gate in [`AGENTS.md`](../AGENTS.md#commands) passes.
- [ ] New input-facing code paths have negative or malformed-input tests.
- [ ] No new `unsafe` without a written justification and a covering test.
- [ ] Public items have doc comments; affected docs are updated.
- [ ] If the benchmark numbers moved, the README block was regenerated with
      `cargo run -p sextant-bench -- --write-readme`.
- [ ] No em dashes or en dashes were introduced.

## Notes for reviewers

Anything reviewers should focus on. If this change touches the executor, the
scorer, inference ranking, or the refinement loop, confirm the verification
invariant still holds: no change may lower the verified parse score on the full
sample set.
