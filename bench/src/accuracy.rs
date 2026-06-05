//! Accuracy metrics over the ground-truth corpus (PRD Section 15).
//!
//! For each corpus format this module runs statistics-only inference and
//! measures how well the recovered structure matches the hand-verified ground
//! truth on four axes:
//!
//! - Field-boundary precision, recall, and F1: do inferred field boundaries fall
//!   at the offsets the ground truth says they should?
//! - Perfection rate: the fraction of formats recovered exactly, a metric used in
//!   the protocol-reverse-engineering literature and included here for
//!   comparability.
//! - Semantic role and type accuracy: of the ground-truth fields, how many were
//!   assigned the correct role and storage type?
//! - Parser validity: does the chosen IR parse every sample to a clean end? This
//!   is 100 percent by construction of the verification loop and is asserted
//!   rather than assumed.
//!
//! These are the numbers the full `sextant bench` command reports, so the
//! published figures and the CI regression guard are computed here, not by hand.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use sextant_engine::{FieldInstance, Limits, Value, execute, infer_candidates, refine};
use sextant_ir::Role;

use crate::{Field, GroundTruth, SizeRule, corpus_dir, load_ground_truth_in, read_sample_in};

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
    /// Whether the chosen IR parsed this sample to a clean end (parser validity).
    pub valid: bool,
}

/// Accuracy metrics for one format, aggregated over its samples.
#[derive(Debug, Clone)]
pub struct FormatMetrics {
    /// The format's machine name.
    pub format: String,
    /// The format's human-readable name.
    pub display_name: String,
    /// How many samples were evaluated.
    pub sample_count: usize,
    /// Mean field-boundary F1 across the format's samples.
    pub f1: f64,
    /// Mean field-boundary precision across the format's samples.
    pub precision: f64,
    /// Mean field-boundary recall across the format's samples.
    pub recall: f64,
    /// Whether every sample of the format was recovered exactly.
    pub perfect: bool,
    /// Fraction of ground-truth fields assigned the correct semantic role.
    pub role_accuracy: f64,
    /// Fraction of ground-truth fields assigned the correct storage type.
    pub type_accuracy: f64,
    /// Fraction of samples the chosen IR parsed to a clean end (parser validity).
    pub parser_validity: f64,
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
    /// The macro-averaged field-boundary precision across formats.
    pub macro_precision: f64,
    /// The macro-averaged field-boundary recall across formats.
    pub macro_recall: f64,
    /// The perfection rate: the fraction of formats recovered exactly.
    pub perfection_rate: f64,
    /// The macro-averaged semantic role accuracy across formats.
    pub macro_role_accuracy: f64,
    /// The macro-averaged semantic type accuracy across formats.
    pub macro_type_accuracy: f64,
    /// The fraction of all samples parsed to a clean end (parser validity).
    pub parser_validity: f64,
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

/// A canonical token for a ground-truth storage type, ignoring byte order so the
/// comparison against the executed value (which records width but not the
/// declared endianness) is on equal footing.
fn canonical_truth_type(ty: &str) -> String {
    if let Some((width, _)) = int_type(ty) {
        return format!("int{width}");
    }
    match ty {
        "bytes" => "bytes".to_owned(),
        "string" => "string".to_owned(),
        other => other.to_owned(),
    }
}

/// A canonical token for an executed field's storage type, derived from its
/// decoded value and concrete byte width. Enumerated values are folded to their
/// underlying integer width because the corpus expresses an enum as an integer
/// or string with an `enum` role, not as a distinct storage type.
fn canonical_value_type(value: &Value, width: usize) -> String {
    match value {
        Value::Integer(_) | Value::Enum { .. } => format!("int{width}"),
        Value::Bytes | Value::Opaque => "bytes".to_owned(),
        Value::Text(_) => "string".to_owned(),
        Value::Struct(_) => "struct".to_owned(),
        Value::Array(_) => "array".to_owned(),
    }
}

/// A canonical token for a ground-truth role string.
fn canonical_truth_role(role: &str) -> String {
    role.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

/// A canonical token for an executed field's role.
fn canonical_field_role(role: Option<Role>) -> String {
    match role {
        Some(Role::Magic) => "magic",
        Some(Role::Version) => "version",
        Some(Role::Length) => "length",
        Some(Role::Count) => "count",
        Some(Role::Offset) => "offset",
        Some(Role::MessageType) => "message_type",
        Some(Role::Sequence) => "sequence",
        Some(Role::Checksum) => "checksum",
        Some(Role::Timestamp) => "timestamp",
        Some(Role::Flags) => "flags",
        Some(Role::Enum) => "enum",
        Some(Role::Reserved) => "reserved",
        Some(Role::Payload) => "payload",
        Some(Role::Unknown) | None => "unknown",
    }
    .to_owned()
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

/// A single ground-truth leaf field, resolved against one concrete sample.
#[derive(Debug, Clone)]
struct TruthField {
    /// The field's start offset in the sample.
    start: usize,
    /// The field's canonical role token.
    role: String,
    /// The field's canonical storage type token.
    ty: String,
}

/// Walk the ground-truth header and records against one concrete sample,
/// resolving each field to a start offset, the values needed by later derived
/// sizes, and the cursor where the structure ends. The returned cursor is the
/// final field-boundary offset.
fn walk_ground_truth(
    gt: &GroundTruth,
    sample: &[u8],
    record_count: u64,
) -> (Vec<TruthField>, usize) {
    let mut fields = Vec::new();
    let mut values: HashMap<String, u64> = HashMap::new();
    let len = sample.len();
    let mut cursor = 0usize;

    let place = |field: &Field,
                 cursor: &mut usize,
                 values: &mut HashMap<String, u64>,
                 fields: &mut Vec<TruthField>| {
        if let Some(offset) = field.offset {
            *cursor = offset as usize;
        }
        let start = (*cursor).min(len);
        if let Some(value) = decode_int(field, sample, *cursor) {
            values.insert(field.name.clone(), value);
        }
        fields.push(TruthField {
            start,
            role: canonical_truth_role(&field.role),
            ty: canonical_truth_type(&field.ty),
        });
        *cursor += field_size(field, values, *cursor, len);
    };

    for field in &gt.structure.header {
        place(field, &mut cursor, &mut values, &mut fields);
    }
    for _ in 0..record_count {
        for field in &gt.structure.record {
            place(field, &mut cursor, &mut values, &mut fields);
        }
    }
    (fields, cursor.min(len))
}

/// Expand the ground truth into the set of field-boundary offsets for one
/// sample: the start offset of every field plus the final end offset.
fn ground_truth_boundaries(gt: &GroundTruth, sample: &[u8], record_count: u64) -> BTreeSet<usize> {
    let (fields, end) = walk_ground_truth(gt, sample, record_count);
    let mut boundaries = BTreeSet::new();
    boundaries.insert(0);
    for field in fields {
        boundaries.insert(field.start);
    }
    boundaries.insert(end);
    boundaries
}

/// A single inferred leaf field, flattened from the executed parse tree.
#[derive(Debug, Clone)]
struct InferredField {
    /// The field's role token.
    role: String,
    /// The field's storage type token.
    ty: String,
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

/// Index the inferred leaf fields by their start offset, so a ground-truth field
/// can be matched to the inferred field that begins at the same place.
fn inferred_leaves_by_start(fields: &[FieldInstance]) -> HashMap<usize, InferredField> {
    fn walk(field: &FieldInstance, out: &mut HashMap<usize, InferredField>) {
        match &field.value {
            Value::Struct(children) | Value::Array(children) => {
                for child in children {
                    walk(child, out);
                }
            }
            value => {
                let width = field.end.saturating_sub(field.start);
                out.entry(field.start).or_insert_with(|| InferredField {
                    role: canonical_field_role(field.role),
                    ty: canonical_value_type(value, width),
                });
            }
        }
    }
    let mut out = HashMap::new();
    for field in fields {
        walk(field, &mut out);
    }
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
/// field-boundary, role, type, and parser-validity accuracy against the ground
/// truth, reading the corpus from the repository `corpus/` directory.
///
/// # Errors
///
/// Returns an error if the ground truth or any sample file cannot be read.
pub fn evaluate_format(format: &str) -> std::io::Result<FormatMetrics> {
    evaluate_format_in(&corpus_dir(), format)
}

/// Run statistics-only inference over one corpus format under an arbitrary
/// corpus directory and measure its accuracy against the ground truth.
///
/// # Errors
///
/// Returns an error if the ground truth or any sample file cannot be read.
pub fn evaluate_format_in(corpus_dir: &Path, format: &str) -> std::io::Result<FormatMetrics> {
    let gt = load_ground_truth_in(corpus_dir, format)?;
    let mut samples = Vec::with_capacity(gt.samples.len());
    for entry in &gt.samples {
        samples.push((
            read_sample_in(corpus_dir, format, entry)?,
            entry.record_count,
        ));
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
    let mut role_hits = 0usize;
    let mut type_hits = 0usize;
    let mut field_total = 0usize;
    for (bytes, record_count) in &samples {
        let (truth_fields, _) = walk_ground_truth(&gt, bytes, *record_count);
        let truth_boundaries = ground_truth_boundaries(&gt, bytes, *record_count);
        let execution = execute(&refined.format, bytes, &limits);
        let inferred = inferred_boundaries(&execution.fields, execution.consumed);
        let leaves = inferred_leaves_by_start(&execution.fields);
        let (precision, recall, f1) = boundary_scores(&truth_boundaries, &inferred);

        for truth in &truth_fields {
            field_total += 1;
            if let Some(inferred_field) = leaves.get(&truth.start) {
                if inferred_field.role == truth.role {
                    role_hits += 1;
                }
                if inferred_field.ty == truth.ty {
                    type_hits += 1;
                }
            }
        }

        sample_metrics.push(SampleMetrics {
            precision,
            recall,
            f1,
            exact: truth_boundaries == inferred,
            valid: execution.succeeded() && execution.consumed == bytes.len(),
        });
    }

    let count = sample_metrics.len().max(1) as f64;
    let f1 = sample_metrics.iter().map(|m| m.f1).sum::<f64>() / count;
    let precision = sample_metrics.iter().map(|m| m.precision).sum::<f64>() / count;
    let recall = sample_metrics.iter().map(|m| m.recall).sum::<f64>() / count;
    let perfect = !sample_metrics.is_empty() && sample_metrics.iter().all(|m| m.exact);
    let valid = sample_metrics.iter().filter(|m| m.valid).count();
    let parser_validity = valid as f64 / count;
    let role_accuracy = if field_total == 0 {
        0.0
    } else {
        role_hits as f64 / field_total as f64
    };
    let type_accuracy = if field_total == 0 {
        0.0
    } else {
        type_hits as f64 / field_total as f64
    };

    Ok(FormatMetrics {
        format: format.to_owned(),
        display_name: gt.display_name,
        sample_count: sample_metrics.len(),
        f1,
        precision,
        recall,
        perfect,
        role_accuracy,
        type_accuracy,
        parser_validity,
        samples: sample_metrics,
    })
}

/// Evaluate accuracy across several formats and aggregate the corpus-level
/// metrics, reading the repository `corpus/` directory.
///
/// # Errors
///
/// Returns an error if any format's ground truth or samples cannot be read.
pub fn evaluate_corpus(formats: &[&str]) -> std::io::Result<CorpusMetrics> {
    evaluate_corpus_in(&corpus_dir(), formats)
}

/// Evaluate accuracy across several formats under an arbitrary corpus directory
/// and aggregate the corpus-level metrics.
///
/// # Errors
///
/// Returns an error if any format's ground truth or samples cannot be read.
pub fn evaluate_corpus_in(corpus_dir: &Path, formats: &[&str]) -> std::io::Result<CorpusMetrics> {
    let mut format_metrics = Vec::with_capacity(formats.len());
    for format in formats {
        format_metrics.push(evaluate_format_in(corpus_dir, format)?);
    }
    let count = format_metrics.len().max(1) as f64;
    let macro_f1 = format_metrics.iter().map(|m| m.f1).sum::<f64>() / count;
    let macro_precision = format_metrics.iter().map(|m| m.precision).sum::<f64>() / count;
    let macro_recall = format_metrics.iter().map(|m| m.recall).sum::<f64>() / count;
    let perfect = format_metrics.iter().filter(|m| m.perfect).count();
    let perfection_rate = perfect as f64 / count;
    let macro_role_accuracy = format_metrics.iter().map(|m| m.role_accuracy).sum::<f64>() / count;
    let macro_type_accuracy = format_metrics.iter().map(|m| m.type_accuracy).sum::<f64>() / count;

    let total_samples: usize = format_metrics.iter().map(|m| m.sample_count).sum();
    let valid_samples: usize = format_metrics
        .iter()
        .flat_map(|m| m.samples.iter())
        .filter(|s| s.valid)
        .count();
    let parser_validity = if total_samples == 0 {
        1.0
    } else {
        valid_samples as f64 / total_samples as f64
    };

    Ok(CorpusMetrics {
        formats: format_metrics,
        macro_f1,
        macro_precision,
        macro_recall,
        perfection_rate,
        macro_role_accuracy,
        macro_type_accuracy,
        parser_validity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ground_truth_boundaries_cover_the_whole_sample() {
        // Every format's ground-truth boundaries must start at zero and end at
        // the sample length, with no offset beyond the sample.
        for format in crate::FILE_FORMAT_CORPUS {
            let gt = crate::load_ground_truth(format).expect("load ground truth");
            for entry in &gt.samples {
                let bytes = crate::read_sample(format, entry).expect("read sample");
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

    #[test]
    fn ground_truth_fields_carry_roles_and_types() {
        // The resolved leaf fields must cover the structure and carry canonical
        // role and type tokens drawn from the corpus vocabulary.
        let gt = crate::load_ground_truth("tlv").expect("load tlv ground truth");
        let entry = &gt.samples[0];
        let bytes = crate::read_sample("tlv", entry).expect("read sample");
        let (fields, _) = walk_ground_truth(&gt, &bytes, entry.record_count);
        assert!(fields.iter().any(|f| f.role == "magic"));
        assert!(fields.iter().any(|f| f.role == "length"));
        assert!(fields.iter().any(|f| f.ty == "bytes"));
    }
}
