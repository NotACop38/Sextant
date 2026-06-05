//! Candidate IR assembly and ranking (FR-12).
//!
//! [`infer_candidates`] runs the statistical pass end to end: it aligns the
//! samples (FR-7), detects a magic signature (FR-8), length, count, and offset
//! relationships (FR-9), a trailing checksum (FR-10), and sub-byte packed fields
//! (FR-11), then assembles the findings into one or more Format Hypothesis IRs.
//! Every candidate is validated against the Step 2 rules and scored by the Step
//! 3 executor and scorer, so the returned list is ranked by a real, verified
//! preliminary score rather than a guess (FR-12, FR-26).
//!
//! The pass always offers a structureless fallback (an opaque run to the end of
//! the sample) so it returns a usable, fully covering candidate even when it
//! finds no structure. Richer candidates that recover actual relationships are
//! ranked ahead of the fallback when their verified scores tie, because a tie at
//! full coverage means the structured hypothesis explains the same bytes while
//! also naming the relationships within them.

use sextant_ir::{
    Bytes, ChecksumSpec, Confidence, Constraint, CountRule, CoveredRange, Endianness, Evidence,
    Field, FieldRef, Format, Kind, RangeAnchor, Role, SampleSupport, Signedness, SizeRule,
    Structure,
};

use crate::align::{Alignment, align};
use crate::detect::{
    Bitfield, ChecksumField, ChecksumStart, IntField, IntRelation, Magic, detect_bitfields,
    detect_int_fields, detect_magic, detect_trailing_checksum,
};
use crate::limits::Limits;
use crate::scorer::{Score, ScoreWeights, score_with};
use crate::stats::shannon_entropy;

/// Bits-per-byte above which a payload region is treated as opaque rather than
/// structured. Compressed or encrypted data sits near eight; plain records sit
/// well below.
const OPAQUE_ENTROPY: f64 = 6.5;

/// One candidate Format Hypothesis IR with its verified preliminary score
/// (FR-12).
#[derive(Debug, Clone)]
pub struct Candidate {
    /// The hypothesized format.
    pub format: Format,
    /// The score of the format over the sample set, from the native scorer.
    pub score: Score,
    /// How many cross-field relationships (length, count, checksum) the
    /// candidate recovered. Used to break ties between candidates that score
    /// equally, so a richer hypothesis is preferred.
    pub relations: usize,
}

/// Run the statistical inference pass and return candidate IRs ranked by a
/// verified preliminary score, best first (FR-6 to FR-12).
///
/// The result always contains at least one valid, executable candidate. The
/// pass never panics on any input: empty sets, a single sample, identical
/// samples, and hostile bytes all produce a (possibly trivial) ranked list.
#[must_use]
pub fn infer_candidates<S: AsRef<[u8]>>(samples: &[S], limits: &Limits) -> Vec<Candidate> {
    let slices: Vec<&[u8]> = samples.iter().map(AsRef::as_ref).collect();
    let alignment = align(&slices);
    let magic = detect_magic(&slices, &alignment);
    let int_fields = detect_int_fields(&slices);

    let mut formats: Vec<(Format, usize)> = Vec::new();
    if let Some(structured) = build_structured(&slices, &alignment, magic.as_ref(), &int_fields) {
        formats.push(structured);
    }
    if let Some(baseline) = build_magic_baseline(magic.as_ref()) {
        formats.push(baseline);
    }
    formats.push(build_opaque());

    rank(formats, &slices, limits)
}

/// Validate, score, deduplicate, and order the assembled formats (FR-12).
fn rank(formats: Vec<(Format, usize)>, slices: &[&[u8]], limits: &Limits) -> Vec<Candidate> {
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for (format, relations) in formats {
        if format.validate().is_err() {
            continue;
        }
        let Ok(key) = format.to_json_compact() else {
            continue;
        };
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        let score = score_with(&format, slices, limits, ScoreWeights::default());
        candidates.push(Candidate {
            format,
            score,
            relations,
        });
    }

    candidates.sort_by(|a, b| {
        b.score
            .overall
            .partial_cmp(&a.score.overall)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.relations.cmp(&a.relations))
            .then(b.format.root.fields.len().cmp(&a.format.root.fields.len()))
            .then(a.format.name.cmp(&b.format.name))
    });
    candidates
}

/// Build the richest candidate the findings support: a magic, any header
/// fillers and packed flags, the key length or count field, and a tail modeled
/// from the relationship (FR-12). Returns `None` when no length or count
/// relationship was found, leaving the fallbacks to cover that case.
fn build_structured(
    slices: &[&[u8]],
    alignment: &Alignment,
    magic: Option<&Magic>,
    int_fields: &[IntField],
) -> Option<(Format, usize)> {
    let key = select_key(int_fields)?;
    let key_offset = key.offset;
    let magic_len = magic.map_or(0, Magic::len).min(key_offset);
    let total = slices.len();

    let mut fields: Vec<Field> = Vec::new();
    if magic_len >= 2 {
        if let Some(magic) = magic {
            fields.push(magic_field(&magic.bytes[..magic_len], total));
        }
    }

    // Fillers between the magic and the key field: packed flags or reserved
    // constants, one byte at a time.
    let bitfields = detect_bitfields(slices, magic_len, key_offset);
    for offset in magic_len..key_offset {
        fields.push(filler_field(slices, offset, &bitfields, total));
    }

    let mut relations = 1;
    fields.push(key_field(key, total));
    match key.relation {
        IntRelation::Count { record_size } => {
            fields.push(records_field(record_size, total));
        }
        IntRelation::DerivedLength { trailing } => {
            let payload_entropy = derived_payload_entropy(slices, key);
            fields.push(payload_field(
                SizeRule::Derived {
                    length_field: FieldRef::new("length"),
                },
                payload_entropy,
                total,
            ));
            if trailing > 0 {
                let checksum = detect_trailing_checksum(slices, magic_len)
                    .into_iter()
                    .find(|found| usize::from(found.width) == trailing);
                if let Some(checksum) = checksum {
                    fields.push(checksum_field(&checksum, magic_len > 0, total));
                    relations += 1;
                } else {
                    fields.push(trailer_field(trailing, total));
                }
            }
        }
        IntRelation::TotalLength => {
            fields.push(payload_field(
                SizeRule::ToEnd,
                tail_entropy(slices, key.end()),
                total,
            ));
        }
    }

    let format = Format {
        name: "candidate-structured".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(fields),
        enums: Default::default(),
        metadata: format_metadata(alignment),
    };
    Some((format, relations))
}

/// Choose the key relationship to drive the tail. A genuine length or count
/// field sits at the earliest offset after the magic, so the earliest candidate
/// is chosen first; this keeps a coincidental relationship found deeper in the
/// payload from displacing the real header field. Among candidates at the same
/// offset, a count is preferred (it decomposes the tail into records and
/// verifies the strongest), then a derived length, then a total-length field,
/// and finally the narrowest field.
fn select_key(int_fields: &[IntField]) -> Option<&IntField> {
    fn rank(relation: IntRelation) -> u8 {
        match relation {
            IntRelation::Count { .. } => 0,
            IntRelation::DerivedLength { .. } => 1,
            IntRelation::TotalLength => 2,
        }
    }
    int_fields.iter().min_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then(rank(a.relation).cmp(&rank(b.relation)))
            .then(a.width.cmp(&b.width))
    })
}

/// A magic-and-opaque-tail candidate: recovers the signature only (FR-8).
fn build_magic_baseline(magic: Option<&Magic>) -> Option<(Format, usize)> {
    let magic = magic?;
    if magic.len() < 2 {
        return None;
    }
    let fields = vec![
        magic_field(&magic.bytes, 0),
        payload_field(SizeRule::ToEnd, 0.0, 0),
    ];
    let format = Format {
        name: "candidate-magic".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(fields),
        enums: Default::default(),
        metadata: Default::default(),
    };
    Some((format, 0))
}

/// The structureless fallback: a single opaque run to the end. Always valid and
/// fully covering, so the pass never returns nothing.
fn build_opaque() -> (Format, usize) {
    let field = Field {
        name: Some("data".to_owned()),
        kind: Kind::Opaque,
        size: Some(SizeRule::ToEnd),
        offset: None,
        role: Some(Role::Payload),
        constraints: Vec::new(),
        confidence: Confidence::clamped(0.2),
        evidence: evidence(0, &["no structure recovered; whole sample left opaque"]),
    };
    let format = Format {
        name: "candidate-opaque".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(vec![field]),
        enums: Default::default(),
        metadata: Default::default(),
    };
    (format, 0)
}

fn magic_field(bytes: &[u8], total: usize) -> Field {
    Field {
        name: Some("magic".to_owned()),
        kind: Kind::Bytes,
        size: Some(SizeRule::Fixed {
            bytes: bytes.len() as u64,
        }),
        offset: None,
        role: Some(Role::Magic),
        constraints: vec![Constraint::Constant {
            value: Bytes::new(bytes.to_vec()),
        }],
        confidence: Confidence::clamped(1.0),
        evidence: evidence(
            total,
            &["invariant leading bytes shared by every sample (magic signature)"],
        ),
    }
}

fn key_field(key: &IntField, total: usize) -> Field {
    let (name, role, note): (&str, Role, &str) = match key.relation {
        IntRelation::Count { .. } => (
            "count",
            Role::Count,
            "value equals the number of fixed-size records that follow",
        ),
        IntRelation::DerivedLength { .. } => (
            "length",
            Role::Length,
            "value equals the byte length of the payload that follows",
        ),
        IntRelation::TotalLength => (
            "total_len",
            Role::Length,
            "value equals the total length of the sample",
        ),
    };
    let mut field = integer_field(name, key.width, key.big_endian, role, 0.9, total, &[note]);
    field.evidence.notes.push(values_note(&key.values));
    field
}

fn records_field(record_size: u64, total: usize) -> Field {
    let element = Field {
        name: Some("record".to_owned()),
        kind: Kind::Bytes,
        size: Some(SizeRule::Fixed { bytes: record_size }),
        offset: None,
        role: Some(Role::Payload),
        confidence: Confidence::clamped(0.6),
        constraints: Vec::new(),
        evidence: evidence(total, &["one fixed-size record"]),
    };
    Field {
        name: Some("records".to_owned()),
        kind: Kind::Array {
            element: Box::new(element),
            count: CountRule::FromField {
                count_field: FieldRef::new("count"),
            },
        },
        size: None,
        offset: None,
        role: None,
        constraints: Vec::new(),
        confidence: Confidence::clamped(0.85),
        evidence: evidence(
            total,
            &["records repeated count times, one per the count field"],
        ),
    }
}

fn payload_field(size: SizeRule, entropy: f64, total: usize) -> Field {
    let opaque = entropy >= OPAQUE_ENTROPY;
    let kind = if opaque { Kind::Opaque } else { Kind::Bytes };
    let note = if opaque {
        "high-entropy payload, left opaque"
    } else {
        "payload bytes"
    };
    Field {
        name: Some("payload".to_owned()),
        kind,
        size: Some(size),
        offset: None,
        role: Some(Role::Payload),
        constraints: Vec::new(),
        confidence: Confidence::clamped(0.6),
        evidence: evidence(total, &[note]),
    }
}

fn trailer_field(trailing: usize, total: usize) -> Field {
    Field {
        name: Some("trailer".to_owned()),
        kind: Kind::Bytes,
        size: Some(SizeRule::Fixed {
            bytes: trailing as u64,
        }),
        offset: None,
        role: Some(Role::Reserved),
        constraints: Vec::new(),
        confidence: Confidence::clamped(0.4),
        evidence: evidence(total, &["trailing bytes after the payload"]),
    }
}

fn checksum_field(checksum: &ChecksumField, has_magic: bool, total: usize) -> Field {
    let from = match checksum.start {
        ChecksumStart::SampleStart => RangeAnchor::FieldStart {
            field: FieldRef::new(if has_magic { "magic" } else { "length" }),
        },
        ChecksumStart::AfterMagic { .. } => RangeAnchor::FieldEnd {
            field: FieldRef::new("magic"),
        },
    };
    let spec = ChecksumSpec {
        algorithm: checksum.algorithm,
        covered: CoveredRange {
            from,
            to: RangeAnchor::FieldEnd {
                field: FieldRef::new("payload"),
            },
        },
    };
    let mut field = integer_field(
        "checksum",
        checksum.width,
        checksum.big_endian,
        Role::Checksum,
        0.95,
        total,
        &["value verifies as a checksum over the covered range"],
    );
    field.constraints.push(Constraint::Checksum { spec });
    field
}

/// A one-byte filler: a packed flags field when the byte's bits are partly
/// constant and partly varying, a constant when the byte is invariant, or an
/// undetermined integer otherwise.
fn filler_field(slices: &[&[u8]], offset: usize, bitfields: &[Bitfield], total: usize) -> Field {
    if let Some(bits) = bitfields.iter().find(|b| b.offset == offset) {
        let mut field = integer_field(
            "flags",
            1,
            false,
            Role::Flags,
            0.7,
            total,
            &["packed bit field"],
        );
        field.evidence.notes.push(format!(
            "constant bits {:#010b}, varying bits {:#010b}",
            bits.constant_mask, bits.varying_mask
        ));
        return field;
    }

    let bytes: Vec<u8> = slices.iter().map(|s| s[offset]).collect();
    let invariant = bytes.iter().all(|&b| Some(b) == bytes.first().copied());
    if invariant {
        let mut field = integer_field(
            "reserved",
            1,
            false,
            Role::Reserved,
            0.8,
            total,
            &["constant header byte"],
        );
        field.constraints.push(Constraint::Constant {
            value: Bytes::new(vec![bytes[0]]),
        });
        field
    } else {
        integer_field(
            "field",
            1,
            false,
            Role::Unknown,
            0.4,
            total,
            &["varying header byte of undetermined role"],
        )
    }
}

fn integer_field(
    name: &str,
    width: u8,
    big_endian: bool,
    role: Role,
    confidence: f64,
    total: usize,
    notes: &[&str],
) -> Field {
    let endianness = if width == 1 {
        None
    } else if big_endian {
        Some(Endianness::Big)
    } else {
        Some(Endianness::Little)
    };
    Field {
        name: Some(name.to_owned()),
        kind: Kind::Integer {
            width,
            signed: Signedness::Unsigned,
            endianness,
        },
        size: None,
        offset: None,
        role: Some(role),
        constraints: Vec::new(),
        confidence: Confidence::clamped(confidence),
        evidence: evidence(total, notes),
    }
}

fn evidence(total: usize, notes: &[&str]) -> Evidence {
    Evidence {
        detector: Some("statistics".to_owned()),
        support: (total > 0).then_some(SampleSupport {
            agreeing: total as u64,
            total: total as u64,
        }),
        model_rationale: None,
        notes: notes.iter().map(|note| (*note).to_owned()).collect(),
    }
}

fn values_note(values: &[u64]) -> String {
    let shown: Vec<String> = values.iter().take(8).map(u64::to_string).collect();
    format!("decoded values: {}", shown.join(", "))
}

fn format_metadata(alignment: &Alignment) -> sextant_ir::Metadata {
    let mut metadata = sextant_ir::Metadata {
        source: Some("statistical inference pass".to_owned()),
        ..Default::default()
    };
    metadata.extra.insert(
        "aligned_prefix_bytes".to_owned(),
        alignment.invariant_prefix_len().to_string(),
    );
    metadata
}

/// The entropy of the payload region of a derived-length format, taken over the
/// bytes between the length field and the trailing bytes in every sample.
fn derived_payload_entropy(slices: &[&[u8]], key: &IntField) -> f64 {
    let start = key.end();
    let mut buffer = Vec::new();
    for (slice, &len) in slices.iter().zip(&key.values) {
        let end = start + len as usize;
        if end <= slice.len() {
            buffer.extend_from_slice(&slice[start..end]);
        }
    }
    shannon_entropy(&buffer)
}

/// The entropy of the tail region from `start` to the end of every sample.
fn tail_entropy(slices: &[&[u8]], start: usize) -> f64 {
    let mut buffer = Vec::new();
    for slice in slices {
        if start <= slice.len() {
            buffer.extend_from_slice(&slice[start..]);
        }
    }
    shannon_entropy(&buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits::default()
    }

    #[test]
    fn empty_set_yields_a_valid_fallback() {
        let samples: [&[u8]; 0] = [];
        let candidates = infer_candidates(&samples, &limits());
        assert!(!candidates.is_empty());
        assert!(candidates[0].format.validate().is_ok());
    }

    #[test]
    fn single_sample_does_not_panic_and_validates() {
        let samples: [&[u8]; 1] = [b"\x00\x01\x02\x03garbage"];
        let candidates = infer_candidates(&samples, &limits());
        assert!(!candidates.is_empty());
        for candidate in &candidates {
            assert!(candidate.format.validate().is_ok());
        }
    }

    #[test]
    fn total_length_format_is_recovered() {
        let make = |payload: &[u8]| {
            let mut data = b"STOT".to_vec();
            data.extend_from_slice(&((8 + payload.len()) as u32).to_le_bytes());
            data.extend_from_slice(payload);
            data
        };
        let samples = [make(&[1, 2, 3]), make(&[4; 10]), make(&[7]), make(&[9; 6])];
        let candidates = infer_candidates(&samples, &limits());
        let best = &candidates[0];
        assert!(best.score.overall >= 0.99, "score {}", best.score.overall);
        let roles: Vec<_> = best
            .format
            .root
            .fields
            .iter()
            .filter_map(|f| f.role)
            .collect();
        assert!(roles.contains(&Role::Magic));
        assert!(roles.contains(&Role::Length));
    }
}
