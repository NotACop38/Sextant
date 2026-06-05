## Summary

Describe what this change does and why.

## Related checklist step

Which step in [`docs/ENGINEERING_CHECKLIST.md`](../docs/ENGINEERING_CHECKLIST.md)
does this advance? Link any related issues.

## Checklist

- [ ] `cargo build` and `cargo build --release` succeed.
- [ ] `cargo test` passes.
- [ ] `cargo clippy --all-targets --all-features` is clean.
- [ ] `cargo fmt --all --check` passes.
- [ ] `cargo deny check` passes.
- [ ] New input-facing code paths have negative or malformed-input tests.
- [ ] No new `unsafe` without a written justification and a covering test.
- [ ] Public items have doc comments; affected docs are updated.
- [ ] No em dashes or en dashes were introduced.

## Notes for reviewers

Anything reviewers should focus on. If this change touches the executor, the
scorer, or the refinement loop, confirm the verification invariant still holds:
no change may lower the verified parse score on the full sample set.
