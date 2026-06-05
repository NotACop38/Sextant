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
use sextant_ir::{Endianness, Role};

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

/// A canonical storage type, used to compare a ground-truth field's declared
/// type against an executed field's decoded type. Integer byte order is part of
/// the type: an inferred field decoded big-endian does not match a little-endian
/// ground-truth field, so a parser that reads a numeric field with the wrong
/// endianness is not counted as a type hit.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TypeToken {
    /// A fixed-width integer. `endian` is `None` for a single byte (no byte
    /// order) and for an executed value whose byte order cannot be determined
    /// (the bytes read the same either way), which is then treated as matching.
    Int {
        /// Width in bytes.
        width: usize,
        /// Byte order, when it is meaningful and determinable.
        endian: Option<Endianness>,
    },
    /// A raw byte run.
    Bytes,
    /// A decoded string.
    Str,
    /// Any other type, compared by name.
    Other(String),
}

impl TypeToken {
    /// Whether an inferred type (`self`) matches a ground-truth type. Integers
    /// must agree on width and, for multi-byte fields, on byte order. An
    /// undeterminable inferred byte order (palindromic bytes) is not penalized.
    fn matches(&self, truth: &TypeToken) -> bool {
        match (self, truth) {
            (
                TypeToken::Int {
                    width: a,
                    endian: ea,
                },
                TypeToken::Int {
                    width: b,
                    endian: eb,
                },
            ) => {
                if a != b {
                    return false;
                }
                if *a <= 1 {
                    return true;
                }
                match (ea, eb) {
                    (Some(x), Some(y)) => x == y,
                    // Byte order not determinable on one side: do not penalize.
                    _ => true,
                }
            }
            (TypeToken::Bytes, TypeToken::Bytes) | (TypeToken::Str, TypeToken::Str) => true,
            (TypeToken::Other(x), TypeToken::Other(y)) => x == y,
            _ => false,
        }
    }
}

/// The ground-truth storage type as a [`TypeToken`], carrying declared byte
/// order for multi-byte integers.
fn truth_type_token(ty: &str) -> TypeToken {
    if let Some((width, big)) = int_type(ty) {
        let endian = if width <= 1 {
            None
        } else if big {
            Some(Endianness::Big)
        } else {
            Some(Endianness::Little)
        };
        return TypeToken::Int { width, endian };
    }
    match ty {
        "bytes" => TypeToken::Bytes,
        "string" => TypeToken::Str,
        other => TypeToken::Other(other.to_owned()),
    }
}

/// The executed field's storage type as a [`TypeToken`]. For an integer the byte
/// order the executor used is recovered from the raw bytes: whichever of the
/// little- and big-endian readings equals the decoded value is the order that
/// was applied. Enumerated values fold to their underlying integer, matching how
/// the corpus expresses an enum (an integer or string with an `enum` role).
fn inferred_type_token(value: &Value, bytes: &[u8], start: usize, end: usize) -> TypeToken {
    let width = end.saturating_sub(start);
    match value {
        Value::Integer(decoded) => integer_token(*decoded, bytes, start, end, width),
        Value::Enum { value, .. } => integer_token(*value, bytes, start, end, width),
        Value::Bytes | Value::Opaque => TypeToken::Bytes,
        Value::Text(_) => TypeToken::Str,
        Value::Struct(_) => TypeToken::Other("struct".to_owned()),
        Value::Array(_) => TypeToken::Other("array".to_owned()),
    }
}

/// Build an integer [`TypeToken`], recovering the byte order the executor applied
/// by comparing the decoded value against the little- and big-endian readings of
/// the field's bytes.
fn integer_token(decoded: i128, bytes: &[u8], start: usize, end: usize, width: usize) -> TypeToken {
    if width <= 1 || !(2..=8).contains(&width) || end > bytes.len() || start > end {
        return TypeToken::Int {
            width,
            endian: None,
        };
    }
    let slice = &bytes[start..end];
    let mut little: i128 = 0;
    for (index, &byte) in slice.iter().enumerate() {
        little |= i128::from(byte) << (8 * index);
    }
    let mut big: i128 = 0;
    for &byte in slice {
        big = (big << 8) | i128::from(byte);
    }
    let endian = if little == big {
        // The bytes read the same either way: byte order is undeterminable.
        None
    } else if decoded == big {
        Some(Endianness::Big)
    } else if decoded == little {
        Some(Endianness::Little)
    } else {
        // A signed or otherwise unexpected reading: do not assert an order.
        None
    };
    TypeToken::Int { width, endian }
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
    /// The field's end offset (exclusive) in the sample.
    end: usize,
    /// The field's canonical role token.
    role: String,
    /// The field's storage type.
    ty: TypeToken,
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
        let size = field_size(field, values, *cursor, len);
        let end = (*cursor + size).min(len);
        fields.push(TruthField {
            start,
            end,
            role: canonical_truth_role(&field.role),
            ty: truth_type_token(&field.ty),
        });
        *cursor += size;
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
    /// The field's end offset (exclusive), so a match can require the whole span
    /// to agree, not just the start.
    end: usize,
    /// The field's role token.
    role: String,
    /// The field's storage type.
    ty: TypeToken,
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
/// can be matched to the inferred field that begins at the same place. The
/// sample bytes are needed to recover an integer field's byte order.
fn inferred_leaves_by_start(
    fields: &[FieldInstance],
    bytes: &[u8],
) -> HashMap<usize, InferredField> {
    fn walk(field: &FieldInstance, bytes: &[u8], out: &mut HashMap<usize, InferredField>) {
        match &field.value {
            Value::Struct(children) | Value::Array(children) => {
                for child in children {
                    walk(child, bytes, out);
                }
            }
            value => {
                out.entry(field.start).or_insert_with(|| InferredField {
                    end: field.end,
                    role: canonical_field_role(field.role),
                    ty: inferred_type_token(value, bytes, field.start, field.end),
                });
            }
        }
    }
    let mut out = HashMap::new();
    for field in fields {
        walk(field, bytes, &mut out);
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
        let leaves = inferred_leaves_by_start(&execution.fields, bytes);
        let (precision, recall, f1) = boundary_scores(&truth_boundaries, &inferred);

        for truth in &truth_fields {
            field_total += 1;
            // Award semantic credit only when the inferred field occupies the
            // same span as the ground-truth field. A field at the right start but
            // the wrong length was not recovered, so it earns no role or type
            // hit even if its label happens to agree.
            if let Some(inferred_field) = leaves.get(&truth.start) {
                if inferred_field.end != truth.end {
                    continue;
                }
                if inferred_field.role == truth.role {
                    role_hits += 1;
                }
                if inferred_field.ty.matches(&truth.ty) {
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
        assert!(fields.iter().any(|f| f.ty == TypeToken::Bytes));
        // The TLV length field is a little-endian u16; its declared byte order is
        // part of its type token.
        assert!(fields.iter().any(|f| f.ty
            == TypeToken::Int {
                width: 2,
                endian: Some(Endianness::Little),
            }));
    }

    #[test]
    fn type_token_matching_respects_width_and_byte_order() {
        let be = TypeToken::Int {
            width: 2,
            endian: Some(Endianness::Big),
        };
        let le = TypeToken::Int {
            width: 2,
            endian: Some(Endianness::Little),
        };
        assert!(be.matches(&be));
        assert!(
            !be.matches(&le),
            "byte order must agree for multi-byte ints"
        );
        assert!(
            !be.matches(&TypeToken::Int {
                width: 4,
                endian: Some(Endianness::Big)
            }),
            "width must agree"
        );
        // A single byte has no byte order, so it always matches on width.
        let u8a = TypeToken::Int {
            width: 1,
            endian: None,
        };
        assert!(u8a.matches(&u8a));
        // Undeterminable inferred byte order is not penalized.
        let unknown = TypeToken::Int {
            width: 2,
            endian: None,
        };
        assert!(unknown.matches(&be));
    }
}
