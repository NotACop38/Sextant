//! Shared helpers for the Sextant fuzz targets (NFR-2, FR-24).
//!
//! The exporter fuzz targets must prove that no Format Hypothesis IR, however
//! hostile, makes an exporter panic. To get that breadth this module turns
//! libFuzzer's raw bytes into an arbitrary, bounded [`Format`] using the
//! `arbitrary` crate, without adding an `Arbitrary` derive to the IR crate
//! itself. The generator deliberately produces awkward field names (empty,
//! leading-digit, whitespace, quotes, newlines, non-ASCII), unusual integer
//! widths, dangling references, and oversized fixed sizes so the exporters'
//! identifier sanitizing, escaping, and graceful-degradation paths are all
//! exercised.
//!
//! Generation is depth- and breadth-bounded so a single input cannot build an
//! unbounded tree; when the fuzzer's byte budget runs out `arbitrary` simply
//! stops, which keeps each iteration fast and deterministic.

use arbitrary::{Result, Unstructured};
use sextant_ir::{
    Bytes, ChecksumAlgorithm, ChecksumSpec, Confidence, Constraint, CountRule, CoveredRange,
    Endianness, EnumDef, EnumVariant, Field, FieldOffset, FieldRef, Format, Kind, Metadata,
    RangeAnchor, Role, Signedness, SizeRule, StringEncoding, Structure,
};
use std::collections::BTreeMap;

/// The deepest nesting of structures and arrays the generator will build.
const MAX_DEPTH: usize = 4;
/// The most fields a single structure may hold.
const MAX_FIELDS: usize = 6;
/// The most named enums a format may define.
const MAX_ENUMS: usize = 3;

/// Build an arbitrary [`Format`] from the fuzzer's bytes.
///
/// The result is intentionally not guaranteed to be semantically valid: the
/// exporters must handle every IR, including ones a validator would reject, by
/// degrading gracefully rather than panicking.
pub fn arbitrary_format(u: &mut Unstructured) -> Result<Format> {
    let endianness = arbitrary_endianness(u)?;
    let root = arbitrary_structure(u, 0)?;
    let enums = arbitrary_enums(u)?;
    let metadata = arbitrary_metadata(u)?;
    Ok(Format {
        name: arbitrary_string(u)?,
        endianness,
        root,
        enums,
        metadata,
    })
}

fn arbitrary_endianness(u: &mut Unstructured) -> Result<Endianness> {
    Ok(if u.arbitrary::<bool>()? {
        Endianness::Big
    } else {
        Endianness::Little
    })
}

fn arbitrary_structure(u: &mut Unstructured, depth: usize) -> Result<Structure> {
    let count = u.int_in_range(0..=MAX_FIELDS)?;
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        if u.is_empty() {
            break;
        }
        fields.push(arbitrary_field(u, depth)?);
    }
    Ok(Structure::new(fields))
}

fn arbitrary_field(u: &mut Unstructured, depth: usize) -> Result<Field> {
    let kind = arbitrary_kind(u, depth)?;
    let mut field = Field::new(kind, arbitrary_confidence(u)?);
    if let Some(name) = arbitrary_optional_name(u)? {
        field = field.with_name(name);
    }
    if u.arbitrary::<bool>()? {
        if let Some(size) = arbitrary_size(u)? {
            field = field.with_size(size);
        }
    }
    if u.arbitrary::<bool>()? {
        field.offset = arbitrary_offset(u)?;
    }
    if u.arbitrary::<bool>()? {
        field = field.with_role(arbitrary_role(u)?);
    }
    let constraints = u.int_in_range(0..=2)?;
    for _ in 0..constraints {
        field.constraints.push(arbitrary_constraint(u)?);
    }
    Ok(field)
}

fn arbitrary_kind(u: &mut Unstructured, depth: usize) -> Result<Kind> {
    // Leaf kinds only once the depth budget is spent, so the tree stays bounded.
    let leaf_only = depth >= MAX_DEPTH;
    let choice = u.int_in_range(0..=if leaf_only { 4 } else { 6 })?;
    Ok(match choice {
        0 => Kind::Integer {
            width: arbitrary_width(u)?,
            signed: arbitrary_signedness(u)?,
            endianness: arbitrary_optional_endianness(u)?,
        },
        1 => Kind::Bytes,
        2 => Kind::String {
            encoding: arbitrary_encoding(u)?,
        },
        3 => Kind::Enum {
            enum_ref: arbitrary_string(u)?,
            width: arbitrary_width(u)?,
            endianness: arbitrary_optional_endianness(u)?,
        },
        4 => Kind::Opaque,
        5 => Kind::Struct {
            structure: arbitrary_structure(u, depth + 1)?,
        },
        _ => Kind::Array {
            element: Box::new(arbitrary_field(u, depth + 1)?),
            count: arbitrary_count(u)?,
        },
    })
}

fn arbitrary_width(u: &mut Unstructured) -> Result<u8> {
    // Mostly the valid widths, but sometimes an invalid one so the exporters'
    // fallbacks are exercised.
    let widths = [1u8, 2, 4, 8, 0, 3, 16];
    Ok(*u.choose(&widths)?)
}

fn arbitrary_signedness(u: &mut Unstructured) -> Result<Signedness> {
    Ok(if u.arbitrary::<bool>()? {
        Signedness::Signed
    } else {
        Signedness::Unsigned
    })
}

fn arbitrary_optional_endianness(u: &mut Unstructured) -> Result<Option<Endianness>> {
    Ok(if u.arbitrary::<bool>()? {
        Some(arbitrary_endianness(u)?)
    } else {
        None
    })
}

fn arbitrary_encoding(u: &mut Unstructured) -> Result<StringEncoding> {
    let all = [
        StringEncoding::Ascii,
        StringEncoding::Utf8,
        StringEncoding::Utf16Le,
        StringEncoding::Utf16Be,
        StringEncoding::Latin1,
    ];
    Ok(*u.choose(&all)?)
}

fn arbitrary_role(u: &mut Unstructured) -> Result<Role> {
    let all = [
        Role::Magic,
        Role::Version,
        Role::Length,
        Role::Count,
        Role::Offset,
        Role::MessageType,
        Role::Sequence,
        Role::Checksum,
        Role::Timestamp,
        Role::Flags,
        Role::Enum,
        Role::Reserved,
        Role::Payload,
        Role::Unknown,
    ];
    Ok(*u.choose(&all)?)
}

fn arbitrary_size(u: &mut Unstructured) -> Result<Option<SizeRule>> {
    Ok(Some(match u.int_in_range(0..=3)? {
        0 => SizeRule::Fixed {
            // Include oversized values so the exporters' size rendering is
            // stressed without the executor ever being involved here.
            bytes: u.arbitrary::<u64>()?,
        },
        1 => SizeRule::Derived {
            length_field: arbitrary_ref(u)?,
        },
        2 => SizeRule::Delimited {
            terminator: arbitrary_bytes(u)?,
            include_terminator: u.arbitrary()?,
        },
        _ => SizeRule::ToEnd,
    }))
}

fn arbitrary_count(u: &mut Unstructured) -> Result<CountRule> {
    Ok(match u.int_in_range(0..=3)? {
        0 => CountRule::Fixed {
            count: u.arbitrary::<u64>()?,
        },
        1 => CountRule::FromField {
            count_field: arbitrary_ref(u)?,
        },
        2 => CountRule::BoundedBy {
            length_field: arbitrary_ref(u)?,
        },
        _ => CountRule::ToEnd,
    })
}

fn arbitrary_offset(u: &mut Unstructured) -> Result<Option<FieldOffset>> {
    Ok(Some(match u.int_in_range(0..=1)? {
        0 => FieldOffset::Absolute {
            bytes: u.arbitrary::<u64>()?,
        },
        _ => FieldOffset::Derived {
            offset_field: arbitrary_ref(u)?,
        },
    }))
}

fn arbitrary_constraint(u: &mut Unstructured) -> Result<Constraint> {
    Ok(match u.int_in_range(0..=2)? {
        0 => Constraint::Constant {
            value: arbitrary_bytes(u)?,
        },
        1 => Constraint::IntRange {
            min: i128::from(u.arbitrary::<i64>()?),
            max: i128::from(u.arbitrary::<i64>()?),
        },
        _ => Constraint::Checksum {
            spec: ChecksumSpec {
                algorithm: arbitrary_algorithm(u)?,
                covered: CoveredRange {
                    from: arbitrary_anchor(u)?,
                    to: arbitrary_anchor(u)?,
                },
            },
        },
    })
}

fn arbitrary_algorithm(u: &mut Unstructured) -> Result<ChecksumAlgorithm> {
    let all = [
        ChecksumAlgorithm::Crc32,
        ChecksumAlgorithm::Crc16,
        ChecksumAlgorithm::Additive,
        ChecksumAlgorithm::Xor,
    ];
    Ok(*u.choose(&all)?)
}

fn arbitrary_anchor(u: &mut Unstructured) -> Result<RangeAnchor> {
    let field = arbitrary_ref(u)?;
    Ok(if u.arbitrary::<bool>()? {
        RangeAnchor::FieldStart { field }
    } else {
        RangeAnchor::FieldEnd { field }
    })
}

fn arbitrary_enums(u: &mut Unstructured) -> Result<BTreeMap<String, EnumDef>> {
    let count = u.int_in_range(0..=MAX_ENUMS)?;
    let mut enums = BTreeMap::new();
    for _ in 0..count {
        if u.is_empty() {
            break;
        }
        let variants = u.int_in_range(0..=4)?;
        let mut list = Vec::with_capacity(variants);
        for _ in 0..variants {
            list.push(EnumVariant {
                value: i128::from(u.arbitrary::<i64>()?),
                name: arbitrary_string(u)?,
                description: if u.arbitrary::<bool>()? {
                    Some(arbitrary_string(u)?)
                } else {
                    None
                },
            });
        }
        let width = if u.arbitrary::<bool>()? {
            Some(arbitrary_width(u)?)
        } else {
            None
        };
        enums.insert(
            arbitrary_string(u)?,
            EnumDef {
                width,
                variants: list,
            },
        );
    }
    Ok(enums)
}

fn arbitrary_metadata(u: &mut Unstructured) -> Result<Metadata> {
    let mut metadata = Metadata::default();
    if u.arbitrary::<bool>()? {
        metadata.description = Some(arbitrary_string(u)?);
    }
    if u.arbitrary::<bool>()? {
        metadata.version = Some(arbitrary_string(u)?);
    }
    if u.arbitrary::<bool>()? {
        metadata.source = Some(arbitrary_string(u)?);
    }
    Ok(metadata)
}

fn arbitrary_confidence(u: &mut Unstructured) -> Result<Confidence> {
    Ok(Confidence::clamped(f64::from(u.arbitrary::<u8>()?) / 255.0))
}

fn arbitrary_ref(u: &mut Unstructured) -> Result<FieldRef> {
    Ok(FieldRef::new(arbitrary_string(u)?))
}

fn arbitrary_bytes(u: &mut Unstructured) -> Result<Bytes> {
    let len = u.int_in_range(0..=8)?;
    Ok(Bytes::new(u.bytes(len)?.to_vec()))
}

fn arbitrary_optional_name(u: &mut Unstructured) -> Result<Option<String>> {
    if u.arbitrary::<bool>()? {
        Ok(Some(arbitrary_string(u)?))
    } else {
        Ok(None)
    }
}

/// A string drawn from a small pool of exporter-hostile shapes, plus the
/// occasional arbitrary UTF-8 run. The pool keeps the awkward cases (empty,
/// leading digit, whitespace, quotes, newlines, non-ASCII, all-separator) dense
/// so the identifier sanitizers and string escapers are hit early.
fn arbitrary_string(u: &mut Unstructured) -> Result<String> {
    Ok(match u.int_in_range(0..=9u8)? {
        0 => String::new(),
        1 => "type".to_owned(),
        2 => "123abc".to_owned(),
        3 => "a b\tc".to_owned(),
        4 => "quote\"'`backtick".to_owned(),
        5 => "line\nbreak".to_owned(),
        6 => "n\u{00fc}\u{00f1}i\u{00e7}\u{00f8}d\u{00e9}".to_owned(),
        7 => "--__--".to_owned(),
        8 => "end".to_owned(),
        _ => {
            let len = u.int_in_range(0..=12)?;
            String::from_utf8_lossy(u.bytes(len)?).into_owned()
        }
    })
}
