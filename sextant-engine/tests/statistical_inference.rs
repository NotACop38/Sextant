//! Step 5 acceptance (FR-6 to FR-12): the statistical inference pass recovers
//! the magic and at least one length or count relationship on three corpus
//! formats, every candidate it emits is valid and executable, and the detected
//! field boundaries clear an initial recall bar.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sextant_engine::align;
use sextant_engine::{
    Candidate, FieldInstance, Limits, Value, detect_magic, execute, infer_candidates,
};
use sextant_ir::{Constraint, Role};

/// The initial field-boundary recall bar for the statistical pass. This is a
/// starting number for the controlled corpus formats and is refined in later
/// steps as harder formats join the corpus.
const RECALL_BAR: f64 = 0.75;

/// Read every sample of a corpus format, sorted by file name for determinism.
fn read_samples(format: &str, extension: &str) -> Vec<Vec<u8>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the engine crate has a parent directory")
        .join("corpus")
        .join(format)
        .join("samples");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .map(|entry| entry.expect("a readable directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == extension))
        .collect();
    paths.sort();
    assert!(
        !paths.is_empty(),
        "no {extension} samples in {}",
        dir.display()
    );
    paths
        .into_iter()
        .map(|path| {
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        })
        .collect()
}

/// Whether the format has a top-level field with the magic role backed by a
/// constant constraint (FR-8).
fn has_magic(candidate: &Candidate) -> bool {
    candidate.format.root.fields.iter().any(|field| {
        field.role == Some(Role::Magic)
            && field
                .constraints
                .iter()
                .any(|c| matches!(c, Constraint::Constant { .. }))
    })
}

/// Whether the format recovered a length or count relationship (FR-9), anywhere
/// in the tree.
fn has_length_or_count(candidate: &Candidate) -> bool {
    fn walk(field: &sextant_ir::Field) -> bool {
        let here = matches!(field.role, Some(Role::Length) | Some(Role::Count));
        let nested = match &field.kind {
            sextant_ir::Kind::Struct { structure } => structure.fields.iter().any(walk),
            sextant_ir::Kind::Array { element, .. } => walk(element),
            _ => false,
        };
        here || nested
    }
    candidate.format.root.fields.iter().any(walk)
}

/// Collect the start offset of every parsed field instance, recursively, plus
/// the final consumed offset. These are the boundaries the candidate detected.
fn detected_boundaries(fields: &[FieldInstance], consumed: usize) -> BTreeSet<usize> {
    fn walk(field: &FieldInstance, out: &mut BTreeSet<usize>) {
        out.insert(field.start);
        match &field.value {
            Value::Struct(children) | Value::Array(children) => {
                for child in children {
                    walk(child, out);
                }
            }
            _ => {}
        }
    }
    let mut out = BTreeSet::new();
    for field in fields {
        walk(field, &mut out);
    }
    out.insert(consumed);
    out
}

/// The fraction of ground-truth boundaries the candidate recovered.
fn recall(truth: &BTreeSet<usize>, detected: &BTreeSet<usize>) -> f64 {
    if truth.is_empty() {
        return 1.0;
    }
    let hit = truth
        .iter()
        .filter(|offset| detected.contains(offset))
        .count();
    hit as f64 / truth.len() as f64
}

/// Run the pass over a corpus format and assert the acceptance criteria: the top
/// candidate recovers the magic and a length or count relationship, scores near
/// 1.0, parses every sample, and every emitted candidate is valid and
/// executable.
fn assert_recovers(format: &str, extension: &str, truth_for: impl Fn(&[u8]) -> BTreeSet<usize>) {
    let samples = read_samples(format, extension);
    let slices: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
    let limits = Limits::default();
    let candidates = infer_candidates(&slices, &limits);
    assert!(!candidates.is_empty(), "{format}: no candidates produced");

    // Every candidate validates and executes on every sample without failing.
    for candidate in &candidates {
        candidate
            .format
            .validate()
            .unwrap_or_else(|report| panic!("{format}: candidate invalid:\n{report}"));
        for sample in &slices {
            let execution = execute(&candidate.format, sample, &limits);
            assert!(
                execution
                    .leaf_ranges
                    .iter()
                    .all(|&(s, e)| s <= e && e <= sample.len()),
                "{format}: a leaf range overran the sample"
            );
        }
    }

    let best = &candidates[0];
    assert!(
        has_magic(best),
        "{format}: magic not recovered in best candidate"
    );
    assert!(
        has_length_or_count(best),
        "{format}: no length or count relationship recovered"
    );
    assert!(
        best.score.overall >= 0.99,
        "{format}: best score {} below 0.99",
        best.score.overall
    );
    assert!(
        (best.score.generality - 1.0).abs() < 1e-9,
        "{format}: best candidate does not parse every sample, generality {}",
        best.score.generality
    );

    // Field-boundary recall on the first sample must clear the initial bar.
    let execution = execute(&best.format, slices[0], &limits);
    assert!(
        execution.succeeded(),
        "{format}: best candidate failed to parse sample 0"
    );
    let detected = detected_boundaries(&execution.fields, execution.consumed);
    let truth = truth_for(slices[0]);
    let recall = recall(&truth, &detected);
    assert!(
        recall >= RECALL_BAR,
        "{format}: boundary recall {recall} below {RECALL_BAR}; truth {truth:?}, detected {detected:?}"
    );
}

#[test]
fn recovers_count_format_scma() {
    // magic[0,4) flags[4,5) count[5,6) then count records of four bytes.
    assert_recovers("scma", "scma", |sample| {
        let count = usize::from(sample[5]);
        let mut truth: BTreeSet<usize> = [0, 4, 5, 6].into_iter().collect();
        for index in 0..count {
            truth.insert(6 + index * 4);
        }
        truth.insert(6 + count * 4);
        truth
    });
}

#[test]
fn recovers_derived_length_format_sdlp() {
    // magic[0,4) length[4,6) payload[6,6+len) crc[end-4,end).
    assert_recovers("sdlp", "sdlp", |sample| {
        let len = u16::from_le_bytes([sample[4], sample[5]]) as usize;
        [0, 4, 6, 6 + len, sample.len()].into_iter().collect()
    });
}

#[test]
fn recovers_total_length_format_stot() {
    // magic[0,4) total_len[4,8) payload[8,end).
    assert_recovers("stot", "stot", |sample| {
        [0, 4, 8, sample.len()].into_iter().collect()
    });
}

#[test]
fn recovers_the_png_signature() {
    // PNG is not a clean fixed-offset length format, but its eight-byte
    // signature is an invariant prefix the magic detector must recover (FR-8).
    let samples = read_samples("png", "png");
    let slices: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
    let alignment = align(&slices);
    let magic = detect_magic(&slices, &alignment).expect("png magic recovered");
    const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    assert!(
        magic.bytes.starts_with(&PNG_SIGNATURE),
        "recovered magic should begin with the PNG signature, got {:02x?}",
        magic.bytes
    );

    // The pass as a whole still yields a valid, fully covering candidate.
    let candidates = infer_candidates(&slices, &Limits::default());
    assert!(candidates[0].format.validate().is_ok());
    assert!(candidates[0].score.coverage >= 0.99);
}

#[test]
fn garbage_input_never_panics_and_stays_valid() {
    // A spread of pathological sets: empty, single byte, identical, and noisy.
    let cases: Vec<Vec<Vec<u8>>> = vec![
        vec![],
        vec![vec![]],
        vec![vec![0x00], vec![0xFF]],
        vec![vec![1, 2, 3, 4, 5, 6, 7, 8], vec![1, 2, 3, 4, 5, 6, 7, 8]],
        vec![(0..50).collect(), (50..120).collect(), vec![7; 9]],
    ];
    for case in cases {
        let slices: Vec<&[u8]> = case.iter().map(Vec::as_slice).collect();
        let candidates = infer_candidates(&slices, &Limits::default());
        assert!(!candidates.is_empty());
        for candidate in &candidates {
            candidate
                .format
                .validate()
                .expect("every candidate from any input must be valid");
        }
    }
}
