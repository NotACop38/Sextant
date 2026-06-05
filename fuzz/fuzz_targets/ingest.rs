#![no_main]
//! Fuzz target: drive sample ingestion with arbitrary bytes (FR-1, FR-4, FR-5,
//! NFR-2).
//!
//! Ingestion turns user inputs into a normalized sample set with provenance and
//! enforced byte caps. It must handle pathological inputs (empty files,
//! single-byte files, identical files, oversized files) without crashing, and it
//! must never retain more than the configured caps allow. This target carves the
//! fuzzer's bytes into several files in a throwaway directory, ingests it under
//! tight caps, and asserts the cap and provenance invariants on the result.
//! libFuzzer drives the byte stream; any panic is a finding. The in-tree tests
//! in `sextant-engine/tests/ingestion.rs` assert the same invariants on stable.

use libfuzzer_sys::fuzz_target;
use sextant_engine::{ingest, IngestOptions};

const MAX_BYTES_PER_SAMPLE: usize = 64;
const MAX_TOTAL_BYTES: usize = 256;

fuzz_target!(|data: &[u8]| {
    let Ok(dir) = tempfile::tempdir() else {
        return;
    };
    // Carve the input into up to a handful of files on a separator byte so the
    // multi-sample, identical-file, and total-cap paths are all exercised.
    let chunks: Vec<&[u8]> = data.split(|&byte| byte == 0xFF).take(16).collect();
    for (index, chunk) in chunks.iter().enumerate() {
        let path = dir.path().join(format!("sample_{index:02}.bin"));
        if std::fs::write(&path, chunk).is_err() {
            return;
        }
    }

    let options = IngestOptions::default()
        .with_max_bytes_per_sample(MAX_BYTES_PER_SAMPLE)
        .with_max_total_bytes(MAX_TOTAL_BYTES)
        .with_recursive(false);
    let input = dir.path().to_string_lossy().into_owned();
    let Ok(set) = ingest(std::slice::from_ref(&input), &options) else {
        return;
    };

    // The total-input cap is never exceeded (FR-5).
    assert!(set.total_bytes <= MAX_TOTAL_BYTES);
    let mut summed = 0usize;
    for sample in &set.samples {
        // No sample retains more than the per-sample cap (FR-5).
        assert!(sample.data.len() <= MAX_BYTES_PER_SAMPLE);
        // The retained length is consistent with provenance.
        assert_eq!(sample.data.len(), sample.provenance.length);
        assert!(sample.data.len() as u64 <= sample.provenance.original_length);
        summed += sample.data.len();
    }
    assert_eq!(summed, set.total_bytes);
});
