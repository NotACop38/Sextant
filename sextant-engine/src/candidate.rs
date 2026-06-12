//! Candidate IR assembly and ranking (FR-12).
//!
//! [`infer_candidates`] runs the statistical pass end to end: it aligns the
//! samples (FR-7), detects a magic signature (FR-8), length, count, and offset
//! relationships (FR-9), a trailing checksum (FR-10), and packed-flag byte
//! evidence (FR-11), then assembles the findings into one or more Format
//! Hypothesis IRs.
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
    Field, FieldOffset, FieldRef, Format, Kind, RangeAnchor, Role, SampleSupport, Signedness,
    SizeRule, Structure,
};

use crate::align::{Alignment, align};
use crate::chunk::{ChunkChecksum, ChunkChecksumStart, ChunkLayout, detect_chunks};
use crate::detect::{
    Bitfield, ChecksumField, ChecksumStart, IntField, IntRelation, Magic, OffsetField,
    detect_bitfields, detect_int_fields, detect_magic, detect_offsets, detect_trailing_checksum,
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
    let offset_fields = detect_offsets(&slices);

    let mut formats: Vec<(Format, usize)> = Vec::new();
    if let Some(chunked) = build_chunked(&slices, &alignment, magic.as_ref()) {
        formats.push(chunked);
    }
    if let Some(offset_candidate) =
        build_offset_candidate(&slices, &alignment, magic.as_ref(), &offset_fields)
    {
        formats.push(offset_candidate);
    }
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

/// Build a candidate around a detected offset field. The field value is treated
/// as an absolute pointer from the current structure base to the payload marker.
/// Bytes between the pointer and the target may be padding or an unknown table,
/// so the candidate models the verified jump instead of pretending the layout is
/// purely sequential.
fn build_offset_candidate(
    slices: &[&[u8]],
    alignment: &Alignment,
    magic: Option<&Magic>,
    offset_fields: &[OffsetField],
) -> Option<(Format, usize)> {
    let offset = offset_fields.iter().min_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then(a.width.cmp(&b.width))
            .then(a.big_endian.cmp(&b.big_endian))
    })?;
    let total = slices.len();
    let magic_len = magic.map_or(0, Magic::len).min(offset.offset);

    let mut fields: Vec<Field> = Vec::new();
    if magic_len >= 2 {
        if let Some(magic) = magic {
            fields.push(magic_field(&magic.bytes[..magic_len], total));
        }
    }

    let bitfields = detect_bitfields(slices, magic_len, offset.offset);
    for byte_offset in magic_len..offset.offset {
        fields.push(filler_field(slices, byte_offset, &bitfields, total));
    }

    let mut offset_field = integer_field(
        "data_offset",
        offset.width,
        offset.big_endian,
        Role::Offset,
        0.85,
        total,
        &["value points at an invariant downstream marker"],
    );
    offset_field
        .evidence
        .notes
        .push(values_note(&offset.values));
    offset_field
        .evidence
        .notes
        .push(format!("pointed marker byte: 0x{:02x}", offset.marker));
    fields.push(offset_field);

    let mut payload = payload_field(
        SizeRule::ToEnd,
        offset_payload_entropy(slices, offset),
        total,
    );
    payload.offset = Some(FieldOffset::Derived {
        offset_field: FieldRef::new("data_offset"),
    });
    payload
        .evidence
        .notes
        .push("starts at the decoded data_offset value".to_owned());
    fields.push(payload);

    let format = Format {
        name: "candidate-offset".to_owned(),
        endianness: if offset.big_endian {
            Endianness::Big
        } else {
            Endianness::Little
        },
        root: Structure::new(fields),
        enums: Default::default(),
        metadata: format_metadata(alignment),
    };
    Some((format, 1))
}

/// Choose the key relationship to drive the tail. A genuine length or count
/// field sits at the earliest offset after the magic, so the earliest candidate
/// is chosen first; this keeps a coincidental relationship found deeper in the
/// payload from displacing the real header field. Among candidates at the same
/// offset, a count is preferred (it decomposes the tail into records and
/// verifies the strongest), then a derived length, then a total-length field.
///
/// At the same offset and relation the widest field is preferred. A wider field
/// satisfies a length relationship only when its high bytes genuinely encode the
/// length (for a small file those high bytes are the zeros of a little-endian
/// integer), so preferring the widest recovers a `u32` length where a narrower
/// read would also fit but leave the high bytes misattributed to the payload.
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
            .then(b.width.cmp(&a.width))
    })
}

/// Build a candidate from a detected repeating length-prefixed record layout
/// (FR-9, FR-10). The header is modeled as a magic and any count or filler
/// fields, followed by a to-end array of the record element. Returns `None` when
/// no chunk layout was found.
fn build_chunked(
    slices: &[&[u8]],
    alignment: &Alignment,
    magic: Option<&Magic>,
) -> Option<(Format, usize)> {
    let layout = detect_chunks(slices)?;
    let total = slices.len();
    let magic_len = magic.map_or(0, Magic::len).min(layout.header_len);

    let mut fields: Vec<Field> = Vec::new();
    if magic_len >= 2 {
        if let Some(magic) = magic {
            fields.push(magic_field(&magic.bytes[..magic_len], total));
        }
    }

    // Header fields between the magic and the record array: a count field when a
    // byte equals the record count in every sample, otherwise a filler.
    let bitfields = detect_bitfields(slices, magic_len, layout.header_len);
    for offset in magic_len..layout.header_len {
        if is_count_byte(slices, offset, &layout.record_counts) {
            let mut field = integer_field(
                "count",
                1,
                false,
                Role::Count,
                0.85,
                total,
                &["value equals the number of records that follow"],
            );
            field.evidence.notes.push(values_note(
                &layout
                    .record_counts
                    .iter()
                    .map(|&c| c as u64)
                    .collect::<Vec<_>>(),
            ));
            fields.push(field);
        } else {
            fields.push(filler_field(slices, offset, &bitfields, total));
        }
    }

    let mut relations = 1; // the per-record length relationship
    let element = chunk_element(&layout, total, &mut relations);
    fields.push(Field {
        name: Some("records".to_owned()),
        kind: Kind::Array {
            element: Box::new(element),
            count: CountRule::ToEnd,
        },
        size: None,
        offset: None,
        role: None,
        constraints: Vec::new(),
        confidence: Confidence::clamped(0.85),
        evidence: evidence(
            total,
            &["repeating length-prefixed records to the end of the sample"],
        ),
    });

    let format = Format {
        name: "candidate-chunked".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(fields),
        enums: Default::default(),
        metadata: format_metadata(alignment),
    };
    Some((format, relations))
}

/// Build the repeating record element for a chunk layout: an optional prefix, the
/// length field, an optional mid section, the length-derived data, and an
/// optional trailer that is modeled as a verified checksum when one was found.
fn chunk_element(layout: &ChunkLayout, total: usize, relations: &mut usize) -> Field {
    let mut inner: Vec<Field> = Vec::new();
    let first_name = if layout.pre > 0 { "prefix" } else { "length" };

    if layout.pre > 0 {
        inner.push(fixed_bytes_field(
            if layout.pre == 1 { "tag" } else { "prefix" },
            layout.pre as u64,
            if layout.pre == 1 {
                Role::Enum
            } else {
                Role::Unknown
            },
            0.5,
            total,
            "bytes before the record length field",
        ));
    }

    inner.push(integer_field(
        "length",
        layout.width,
        layout.big_endian,
        Role::Length,
        0.9,
        total,
        &["value equals the byte length of the record data that follows"],
    ));

    if layout.mid > 0 {
        inner.push(fixed_bytes_field(
            "type",
            layout.mid as u64,
            Role::Enum,
            0.5,
            total,
            "fixed bytes between the length and the data (for example a type tag)",
        ));
    }

    inner.push(Field {
        name: Some("data".to_owned()),
        kind: Kind::Bytes,
        size: Some(SizeRule::Derived {
            length_field: FieldRef::new("length"),
        }),
        offset: None,
        role: Some(Role::Payload),
        constraints: Vec::new(),
        confidence: Confidence::clamped(0.7),
        evidence: evidence(total, &["record data sized by the length field"]),
    });

    if layout.tail > 0 {
        if let Some(checksum) = layout.checksum {
            inner.push(chunk_checksum_field(
                layout.tail,
                first_name,
                checksum,
                total,
            ));
            *relations += 1;
        } else {
            inner.push(fixed_bytes_field(
                "trailer",
                layout.tail as u64,
                Role::Reserved,
                0.4,
                total,
                "trailing bytes after each record's data",
            ));
        }
    }

    Field {
        name: Some("record".to_owned()),
        kind: Kind::Struct {
            structure: Structure::new(inner),
        },
        size: None,
        offset: None,
        role: None,
        constraints: Vec::new(),
        confidence: Confidence::clamped(0.75),
        evidence: evidence(total, &["one length-prefixed record"]),
    }
}

/// Build the checksum field of a chunk record from a verified per-record
/// checksum, covering the record's data (and any mid section) up to the trailer.
fn chunk_checksum_field(
    width: usize,
    first_name: &str,
    checksum: ChunkChecksum,
    total: usize,
) -> Field {
    let from = match checksum.start {
        ChunkChecksumStart::RecordStart => RangeAnchor::FieldStart {
            field: FieldRef::new(first_name),
        },
        ChunkChecksumStart::AfterLength => RangeAnchor::FieldEnd {
            field: FieldRef::new("length"),
        },
    };
    let spec = ChecksumSpec {
        algorithm: checksum.algorithm,
        covered: CoveredRange {
            from,
            to: RangeAnchor::FieldEnd {
                field: FieldRef::new("data"),
            },
        },
    };
    let mut field = integer_field(
        "checksum",
        width as u8,
        checksum.big_endian,
        Role::Checksum,
        0.95,
        total,
        &["value verifies as a per-record checksum over the covered range"],
    );
    field.constraints.push(Constraint::Checksum { spec });
    field
}

/// A fixed-size bytes field with a name, role, confidence, and one note.
fn fixed_bytes_field(
    name: &str,
    bytes: u64,
    role: Role,
    confidence: f64,
    total: usize,
    note: &str,
) -> Field {
    Field {
        name: Some(name.to_owned()),
        kind: Kind::Bytes,
        size: Some(SizeRule::Fixed { bytes }),
        offset: None,
        role: Some(role),
        constraints: Vec::new(),
        confidence: Confidence::clamped(confidence),
        evidence: evidence(total, &[note]),
    }
}

/// Whether the single byte at `offset` equals the number of records in every
/// sample, identifying a record-count field.
fn is_count_byte(slices: &[&[u8]], offset: usize, record_counts: &[usize]) -> bool {
    if slices.len() != record_counts.len() {
        return false;
    }
    slices
        .iter()
        .zip(record_counts)
        .all(|(slice, &count)| count < 256 && slice.get(offset) == Some(&(count as u8)))
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
        let name = format!("flags_{offset}");
        let mut field = integer_field(
            &name,
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
        let name = format!("reserved_{offset}");
        let mut field = integer_field(
            &name,
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
        let name = format!("field_{offset}");
        integer_field(
            &name,
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

/// The entropy of every byte from each offset target through the end of the
/// sample.
fn offset_payload_entropy(slices: &[&[u8]], offset: &OffsetField) -> f64 {
    let mut buffer = Vec::new();
    for (slice, &target) in slices.iter().zip(&offset.values) {
        let Ok(target) = usize::try_from(target) else {
            continue;
        };
        if target <= slice.len() {
            buffer.extend_from_slice(&slice[target..]);
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

    #[test]
    fn structured_candidate_keeps_multiple_reserved_header_bytes() {
        // A varying byte after the magic stops the invariant prefix, so the two
        // invariant bytes that follow it become reserved fillers rather than
        // part of the magic. Before filler names carried their offset, both
        // were named "reserved", the duplicate name failed IR validation, and
        // the whole structured candidate was silently dropped.
        let make = |session: u8, fill: u8, payload_len: u8| {
            let mut data = b"MAGC".to_vec();
            data.push(session);
            // Nonzero reserved bytes: zeros here would let the detector fold
            // byte 6 into a wider big-endian integer ending at the length byte.
            data.extend_from_slice(&[0xEE, 0xEE]);
            data.push(payload_len);
            data.extend(std::iter::repeat_n(fill, usize::from(payload_len)));
            data
        };
        let samples = [make(0x11, 1, 3), make(0x57, 2, 5), make(0xd2, 3, 8)];
        let candidates = infer_candidates(&samples, &limits());
        let structured = candidates
            .iter()
            .find(|candidate| candidate.format.name == "candidate-structured")
            .expect("structured candidate should survive validation");

        let names: Vec<_> = structured
            .format
            .root
            .fields
            .iter()
            .filter_map(|field| field.name.as_deref())
            .collect();
        assert!(
            names.contains(&"reserved_5") && names.contains(&"reserved_6"),
            "reserved filler bytes must get unique names, got {names:?}"
        );
    }

    #[test]
    fn offset_relationships_are_assembled_into_candidates() {
        let samples = [
            b"OF\x05aaDxy".to_vec(),
            b"OF\x07bbbbDzz".to_vec(),
            b"OF\x06cccDq".to_vec(),
        ];
        let candidates = infer_candidates(&samples, &limits());
        let offset = candidates
            .iter()
            .find(|candidate| candidate.format.name == "candidate-offset")
            .expect("offset detector evidence should produce an offset candidate");

        assert!(
            offset
                .format
                .root
                .fields
                .iter()
                .any(|field| field.role == Some(Role::Offset)),
            "candidate must include the pointer field"
        );
        assert!(
            offset.format.root.fields.iter().any(|field| matches!(
                &field.offset,
                Some(sextant_ir::FieldOffset::Derived { offset_field })
                    if offset_field.as_str() == "data_offset"
            )),
            "candidate must include a payload field located through the pointer"
        );
    }
}
