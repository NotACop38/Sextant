//! Field-boundary accuracy metrics over the ground-truth corpus (PRD Section 15).
//!
//! This module measures how well the statistics-only inference pipeline recovers
//! the field structure of a known format. For each sample it compares the set of
//! byte offsets at which inferred fields begin against the same set derived from
//! the hand-verified ground truth, and reports field-boundary precision, recall,
//! and F1, plus the perfection rate (the fraction of formats recovered exactly).
//!
//! The full `sextant bench` command and its results table arrive in Step 12.
//! Step 6 needs these metrics to verify that the statistics-only pipeline clears
//! the PRD accuracy targets (field-boundary F1 at least 0.85 and perfection at
//! least 0.5 on the file-format corpus).

use std::collections::{BTreeSet, HashMap};

use sextant_engine::{FieldInstance, Limits, Value, execute, infer_candidates, refine};

use crate::{Field, GroundTruth, SizeRule, load_ground_truth, read_sample};

/// Accuracy metrics for a single sample.
#[derive(Debug, Clone)]
pub struct SampleMetrics {
    /// Field-boundary precision: inferred boundaries that are correct.
    pub precision: f64,
    /// Field-boundary recall: ground-truth boundaries that were recovered.
    pub recall: f64,
    /// Field-boundary F1 (the harmonic mean of precision and recall).
    pub f1: f64,
    /// Whether the inferred boundaries exactly match the ground truth.
    pub exact: bool,
}

/// Accuracy metrics for one format, aggregated over its samples.
#[derive(Debug, Clone)]
pub struct FormatMetrics {
    /// The format's machine name.
    pub format: String,
    /// Mean field-boundary F1 across the format's samples.
    pub f1: f64,
    /// Mean field-boundary precision across the format's samples.
    pub precision: f64,
    /// Mean field-boundary recall across the format's samples.
    pub recall: f64,
    /// Whether every sample of the format was recovered exactly.
    pub perfect: bool,
    /// Per-sample metrics, in corpus order.
    pub samples: Vec<SampleMetrics>,
}

/// Accuracy metrics across a set of formats (the corpus).
#[derive(Debug, Clone)]
pub struct CorpusMetrics {
    /// Per-format metrics, in the order evaluated.
    pub formats: Vec<FormatMetrics>,
    /// The macro-averaged field-boundary F1 across formats.
    pub macro_f1: f64,
    /// The perfection rate: the fraction of formats recovered exactly.
    pub perfection_rate: f64,
}

/// The integer width and byte order encoded by a ground-truth type string, when
/// it names a fixed-width integer.
fn int_type(ty: &str) -> Option<(usize, bool)> {
    match ty {
        "u8" => Some((1, false)),
        "u16le" => Some((2, false)),
        "u16be" => Some((2, true)),
        "u32le" => Some((4, false)),
        "u32be" => Some((4, true)),
        "u64le" => Some((8, false)),
        "u64be" => Some((8, true)),
        _ => None,
    }
}

/// Decode a ground-truth integer field's value at `offset`, when the field is an
/// integer type and the bytes are present.
fn decode_int(field: &Field, sample: &[u8], offset: usize) -> Option<u64> {
    let (width, big) = int_type(&field.ty)?;
    let end = offset.checked_add(width)?;
    if end > sample.len() {
        return None;
    }
    let mut value = 0u64;
    if big {
        for &byte in &sample[offset..end] {
            value = (value << 8) | u64::from(byte);
        }
    } else {
        for (index, &byte) in sample[offset..end].iter().enumerate() {
            value |= u64::from(byte) << (8 * index);
        }
    }
    Some(value)
}

/// The byte length of a ground-truth field at `cursor`, given the values decoded
/// so far. A derived size is clamped to the bytes remaining, so a length field
/// that names the whole file (as the STOT total-length field does) resolves to
/// "the rest of the buffer" rather than overrunning.
fn field_size(field: &Field, values: &HashMap<String, u64>, cursor: usize, len: usize) -> usize {
    match &field.size {
        SizeRule::Fixed(bytes) => *bytes as usize,
        SizeRule::Derived(name) => {
            let remaining = len.saturating_sub(cursor);
            values
                .get(name)
                .map_or(0, |&value| (value as usize).min(remaining))
        }
    }
}

/// Expand the ground truth into the set of field-boundary offsets for one
/// sample: the start offset of every header field, every field of every record,
/// and the final end offset.
fn ground_truth_boundaries(gt: &GroundTruth, sample: &[u8], record_count: u64) -> BTreeSet<usize> {
    let mut boundaries = BTreeSet::new();
    let mut values: HashMap<String, u64> = HashMap::new();
    let len = sample.len();
    let mut cursor = 0usize;
    boundaries.insert(0);

    for field in &gt.structure.header {
        if let Some(offset) = field.offset {
            cursor = offset as usize;
        }
        boundaries.insert(cursor.min(len));
        if let Some(value) = decode_int(field, sample, cursor) {
            values.insert(field.name.clone(), value);
        }
        cursor += field_size(field, &values, cursor, len);
    }

    for _ in 0..record_count {
        for field in &gt.structure.record {
            boundaries.insert(cursor.min(len));
            if let Some(value) = decode_int(field, sample, cursor) {
                values.insert(field.name.clone(), value);
            }
            cursor += field_size(field, &values, cursor, len);
        }
    }

    boundaries.insert(cursor.min(len));
    boundaries
}

/// Collect the start offset of every field instance (recursively into structs
/// and arrays), plus the final consumed offset: the boundaries the pipeline
/// inferred for one sample.
fn inferred_boundaries(fields: &[FieldInstance], consumed: usize) -> BTreeSet<usize> {
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
    out.insert(0);
    for field in fields {
        walk(field, &mut out);
    }
    out.insert(consumed);
    out
}

/// Precision, recall, and F1 of an inferred boundary set against the truth.
fn boundary_scores(truth: &BTreeSet<usize>, inferred: &BTreeSet<usize>) -> (f64, f64, f64) {
    let hits = inferred.iter().filter(|b| truth.contains(b)).count();
    let precision = if inferred.is_empty() {
        0.0
    } else {
        hits as f64 / inferred.len() as f64
    };
    let recall = if truth.is_empty() {
        1.0
    } else {
        hits as f64 / truth.len() as f64
    };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };
    (precision, recall, f1)
}

/// Run statistics-only inference over one corpus format and measure its
/// field-boundary accuracy against the ground truth.
///
/// # Errors
///
/// Returns an error if the ground truth or any sample file cannot be read.
pub fn evaluate_format(format: &str) -> std::io::Result<FormatMetrics> {
    let gt = load_ground_truth(format)?;
    let mut samples = Vec::with_capacity(gt.samples.len());
    for entry in &gt.samples {
        samples.push((read_sample(format, entry)?, entry.record_count));
    }

    let slices: Vec<&[u8]> = samples.iter().map(|(bytes, _)| bytes.as_slice()).collect();
    let limits = Limits::default();
    let candidates = infer_candidates(&slices, &limits);
    let best = candidates
        .first()
        .map(|candidate| candidate.format.clone())
        .expect("inference always yields at least one candidate");
    let refined = refine(&best, &slices, &limits);

    let mut sample_metrics = Vec::with_capacity(samples.len());
    for (bytes, record_count) in &samples {
        let truth = ground_truth_boundaries(&gt, bytes, *record_count);
        let execution = execute(&refined.format, bytes, &limits);
        let inferred = inferred_boundaries(&execution.fields, execution.consumed);
        let (precision, recall, f1) = boundary_scores(&truth, &inferred);
        sample_metrics.push(SampleMetrics {
            precision,
            recall,
            f1,
            exact: truth == inferred,
        });
    }

    let count = sample_metrics.len().max(1) as f64;
    let f1 = sample_metrics.iter().map(|m| m.f1).sum::<f64>() / count;
    let precision = sample_metrics.iter().map(|m| m.precision).sum::<f64>() / count;
    let recall = sample_metrics.iter().map(|m| m.recall).sum::<f64>() / count;
    let perfect = !sample_metrics.is_empty() && sample_metrics.iter().all(|m| m.exact);

    Ok(FormatMetrics {
        format: format.to_owned(),
        f1,
        precision,
        recall,
        perfect,
        samples: sample_metrics,
    })
}

/// Evaluate field-boundary accuracy across several formats and aggregate the
/// corpus-level metrics (macro F1 and perfection rate).
///
/// # Errors
///
/// Returns an error if any format's ground truth or samples cannot be read.
pub fn evaluate_corpus(formats: &[&str]) -> std::io::Result<CorpusMetrics> {
    let mut format_metrics = Vec::with_capacity(formats.len());
    for format in formats {
        format_metrics.push(evaluate_format(format)?);
    }
    let count = format_metrics.len().max(1) as f64;
    let macro_f1 = format_metrics.iter().map(|m| m.f1).sum::<f64>() / count;
    let perfect = format_metrics.iter().filter(|m| m.perfect).count();
    let perfection_rate = perfect as f64 / count;
    Ok(CorpusMetrics {
        formats: format_metrics,
        macro_f1,
        perfection_rate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ground_truth_boundaries_cover_the_whole_sample() {
        // Every format's ground-truth boundaries must start at zero and end at
        // the sample length, with no offset beyond the sample.
        for format in ["tlv", "scma", "stot", "sdlp", "png"] {
            let gt = load_ground_truth(format).expect("load ground truth");
            for entry in &gt.samples {
                let bytes = read_sample(format, entry).expect("read sample");
                let boundaries = ground_truth_boundaries(&gt, &bytes, entry.record_count);
                assert!(boundaries.contains(&0), "{format}: missing start boundary");
                assert!(
                    boundaries.contains(&bytes.len()),
                    "{format}: missing end boundary"
                );
                assert!(
                    boundaries.iter().all(|&b| b <= bytes.len()),
                    "{format}: a boundary lies past the sample end"
                );
            }
        }
    }
}
