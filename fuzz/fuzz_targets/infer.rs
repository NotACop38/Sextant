#![no_main]
//! Fuzz target: feed arbitrary bytes to the statistical inference pass (FR-6 to
//! FR-12, FR-24, NFR-2).
//!
//! The inference pass reads untrusted samples, so it must never panic, hang, or
//! allocate without bound. This target splits the input into several samples on
//! a separator byte and runs `infer_candidates` under tight, deterministic
//! limits. Every candidate it returns must be valid IR and must execute on every
//! sample without overrunning. libFuzzer drives the byte stream; any panic,
//! abort, or out-of-memory is a finding. The in-tree tests in
//! `sextant-engine/tests/statistical_inference.rs` assert the same invariants on
//! stable.

use libfuzzer_sys::fuzz_target;
use sextant_engine::{execute, infer_candidates, Limits};

fuzz_target!(|data: &[u8]| {
    // Carve the input into samples on a separator byte so the pass sees a set,
    // not just one buffer. An empty input yields an empty set.
    let samples: Vec<&[u8]> = data.split(|&byte| byte == 0x00).collect();
    let limits = Limits::for_fuzzing();
    let candidates = infer_candidates(&samples, &limits);

    for candidate in &candidates {
        // Every emitted candidate must be valid IR (FR-12).
        assert!(candidate.format.validate().is_ok());
        // And it must execute on every sample without a leaf overrun (FR-24).
        for sample in &samples {
            let execution = execute(&candidate.format, sample, &limits);
            for &(start, end) in &execution.leaf_ranges {
                assert!(start <= end && end <= sample.len());
            }
        }
        assert!(candidate.score.overall.is_finite());
        assert!((0.0..=1.0).contains(&candidate.score.overall));
    }
});
