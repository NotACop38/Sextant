//! Sized structs and structure extents in the native executor.
//!
//! A struct with a size rule is a bounded region: its fields parse inside the
//! region and cannot run past it, the next field starts after the region, and
//! bytes the fields leave unread are gaps rather than a parse failure. An
//! unsized struct ends at the furthest byte any of its fields reaches, which
//! also defines how far the root reached and so which bytes are trailing.

use std::collections::BTreeMap;

use sextant_engine::{FailureReason, Limits, Value, execute, score};
use sextant_ir::{
    Bytes, ChecksumAlgorithm, ChecksumSpec, Confidence, Constraint, CountRule, CoveredRange,
    Endianness, Field, FieldOffset, FieldRef, Format, Kind, RangeAnchor, Signedness, SizeRule,
    Structure,
};

fn format_of(fields: Vec<Field>) -> Format {
    Format {
        name: "sized".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(fields),
        enums: BTreeMap::new(),
        metadata: Default::default(),
    }
}

fn u8_field(name: &str) -> Field {
    Field::new(
        Kind::Integer {
            width: 1,
            signed: Signedness::Unsigned,
            endianness: None,
        },
        Confidence::CERTAIN,
    )
    .with_name(name)
}

fn u16_field(name: &str) -> Field {
    Field::new(
        Kind::Integer {
            width: 2,
            signed: Signedness::Unsigned,
            endianness: None,
        },
        Confidence::CERTAIN,
    )
    .with_name(name)
}

fn bytes_field(name: &str, size: SizeRule) -> Field {
    Field::new(Kind::Bytes, Confidence::CERTAIN)
        .with_name(name)
        .with_size(size)
}

fn struct_field(name: &str, fields: Vec<Field>) -> Field {
    Field::new(
        Kind::Struct {
            structure: Structure::new(fields),
        },
        Confidence::CERTAIN,
    )
    .with_name(name)
}

fn derived(name: &str) -> SizeRule {
    SizeRule::Derived {
        length_field: FieldRef::new(name),
    }
}

/// A chunk: a length, then a body of exactly that many bytes holding a tag and
/// the rest as data, then a trailing marker byte.
fn chunk_format() -> Format {
    let body = struct_field(
        "body",
        vec![u8_field("tag"), bytes_field("data", SizeRule::ToEnd)],
    )
    .with_size(derived("length"));
    format_of(vec![u8_field("length"), body, u8_field("marker")])
}

#[test]
fn a_sized_struct_bounds_its_fields_and_the_next_field_follows_the_region() {
    let format = chunk_format();
    format.validate().expect("valid IR");
    // length 3: body = tag 0x07 + data [0xaa, 0xbb], then marker 0xee.
    let sample = [3u8, 0x07, 0xaa, 0xbb, 0xee];
    let execution = execute(&format, &sample, &Limits::default());
    assert!(execution.succeeded(), "{:?}", execution.failure);
    assert_eq!(execution.consumed, sample.len());

    let body = &execution.fields[1];
    assert_eq!((body.start, body.end), (1, 4));
    let Value::Struct(children) = &body.value else {
        panic!("the body is a struct");
    };
    // The to_end data field stops at the region end, not the sample end.
    assert_eq!((children[1].start, children[1].end), (2, 4));
    assert_eq!((execution.fields[2].start, execution.fields[2].end), (4, 5));
    assert!(score(&format, &[&sample[..]]).fully_verified());
}

#[test]
fn bytes_a_sized_struct_leaves_unread_are_gaps_not_a_failure() {
    // The body holds only a tag, so the rest of the region is unexplained.
    let body = struct_field("body", vec![u8_field("tag")]).with_size(derived("length"));
    let format = format_of(vec![u8_field("length"), body, u8_field("marker")]);
    format.validate().expect("valid IR");
    let sample = [3u8, 0x07, 0xaa, 0xbb, 0xee];
    let execution = execute(&format, &sample, &Limits::default());
    assert!(execution.succeeded(), "{:?}", execution.failure);
    assert_eq!((execution.fields[1].start, execution.fields[1].end), (1, 4));
    assert_eq!((execution.fields[2].start, execution.fields[2].end), (4, 5));

    let scored = score(&format, &[&sample[..]]);
    let sample_score = &scored.samples[0];
    assert!(sample_score.parsed);
    assert_eq!(sample_score.gap_bytes, 2);
    assert_eq!(sample_score.trailing_bytes, 0);
    assert_eq!(sample_score.explained_bytes, 3);
    assert!(!scored.fully_verified());
}

#[test]
fn an_unread_tail_at_the_sample_end_is_a_gap_too() {
    // Explained, gap, and trailing bytes partition the sample, even when the
    // unread tail of a sized struct runs to the end of the sample.
    let body = struct_field("body", vec![u8_field("tag")]).with_size(SizeRule::ToEnd);
    let format = format_of(vec![body]);
    let sample = [1u8, 2, 3, 4];
    let scored = score(&format, &[&sample[..]]);
    let sample_score = &scored.samples[0];
    assert!(sample_score.parsed);
    assert_eq!(sample_score.explained_bytes, 1);
    assert_eq!(sample_score.gap_bytes, 3);
    assert_eq!(sample_score.trailing_bytes, 0);
}

#[test]
fn fields_cannot_run_past_the_region_even_with_bytes_to_spare() {
    // The body is sized to one byte but holds a u16, and the sample has more
    // bytes after the region. The field must not borrow them.
    let body = struct_field("body", vec![u16_field("wide")]).with_size(derived("length"));
    let format = format_of(vec![u8_field("length"), body, u8_field("marker")]);
    format.validate().expect("valid IR");
    let sample = [1u8, 0x07, 0xaa, 0xee];
    let execution = execute(&format, &sample, &Limits::default());
    let failure = execution
        .failure
        .expect("the body field overruns its region");
    assert_eq!(failure.offset, 1);
    assert!(matches!(
        failure.reason,
        FailureReason::UnexpectedEndOfInput {
            needed: 2,
            available: 1
        }
    ));
}

#[test]
fn a_region_that_runs_past_the_sample_is_a_truncation() {
    let format = chunk_format();
    let sample = [9u8, 0x07, 0xaa];
    let execution = execute(&format, &sample, &Limits::default());
    let failure = execution.failure.expect("the region needs nine bytes");
    assert!(matches!(
        failure.reason,
        FailureReason::UnexpectedEndOfInput {
            needed: 9,
            available: 2
        }
    ));
}

#[test]
fn a_fixed_size_struct_advances_by_its_size() {
    let body = struct_field("body", vec![u8_field("tag")]).with_size(SizeRule::Fixed { bytes: 3 });
    let format = format_of(vec![body, u8_field("after")]);
    format.validate().expect("valid IR");
    let execution = execute(&format, &[1u8, 2, 3, 4], &Limits::default());
    assert!(execution.succeeded());
    assert_eq!((execution.fields[1].start, execution.fields[1].end), (3, 4));
}

#[test]
fn a_checksum_anchored_to_a_sized_struct_covers_the_whole_region() {
    // An additive checksum over the body region, unread tail included.
    let body = struct_field("body", vec![u8_field("tag")]).with_size(derived("length"));
    let mut sum = u8_field("sum");
    sum.constraints.push(Constraint::Checksum {
        spec: ChecksumSpec {
            algorithm: ChecksumAlgorithm::Additive,
            covered: CoveredRange {
                from: RangeAnchor::FieldStart {
                    field: FieldRef::new("body"),
                },
                to: RangeAnchor::FieldEnd {
                    field: FieldRef::new("body"),
                },
            },
        },
    });
    let format = format_of(vec![u8_field("length"), body, sum]);
    format.validate().expect("valid IR");
    let sample = [3u8, 1, 2, 3, 6];
    let execution = execute(&format, &sample, &Limits::default());
    assert!(execution.succeeded());
    let check = execution
        .checks
        .iter()
        .find(|check| check.field.as_deref() == Some("sum"))
        .expect("the checksum was evaluated");
    assert!(check.passed, "{}", check.detail);
}

#[test]
fn offsets_inside_a_sized_struct_are_relative_to_it_and_stay_inside_it() {
    let mut late = u8_field("late");
    late.offset = Some(FieldOffset::Absolute { bytes: 2 });
    let body = struct_field("body", vec![late]).with_size(derived("length"));
    let format = format_of(vec![u8_field("length"), body]);
    format.validate().expect("valid IR");

    let inside = execute(&format, &[3u8, 0, 0, 0x55], &Limits::default());
    assert!(inside.succeeded(), "{:?}", inside.failure);
    let Value::Struct(children) = &inside.fields[1].value else {
        panic!("the body is a struct");
    };
    assert_eq!(
        (children[0].start, children[0].value.clone()),
        (3, Value::Integer(0x55))
    );

    // A two-byte region cannot hold a field at relative offset two, although
    // the sample has the byte.
    let outside = execute(&format, &[2u8, 0, 0, 0x55], &Limits::default());
    assert!(outside.failure.is_some());
}

#[test]
fn a_struct_ends_at_its_furthest_field_even_when_the_cursor_moves_back() {
    // `late` is read at relative offset 2, then `early` jumps back to offset 0:
    // the struct still spans [0, 3), so the next field starts at 3.
    let mut late = u8_field("late");
    late.offset = Some(FieldOffset::Absolute { bytes: 2 });
    let mut early = u8_field("early");
    early.offset = Some(FieldOffset::Absolute { bytes: 0 });
    let format = format_of(vec![
        struct_field("header", vec![late, early]),
        u8_field("after"),
    ]);
    format.validate().expect("valid IR");
    let sample = [1u8, 2, 3, 4];
    let execution = execute(&format, &sample, &Limits::default());
    assert!(execution.succeeded(), "{:?}", execution.failure);
    assert_eq!((execution.fields[0].start, execution.fields[0].end), (0, 3));
    assert_eq!((execution.fields[1].start, execution.fields[1].end), (3, 4));
}

#[test]
fn a_backward_positioned_last_field_leaves_no_trailing_bytes() {
    // The root reads [0, 2) and [2, 4), then re-reads byte 0 last. Every byte
    // is explained, so nothing trails even though the cursor ends at 1.
    let mut first = u8_field("first");
    first.offset = Some(FieldOffset::Absolute { bytes: 0 });
    let format = format_of(vec![
        u16_field("a"),
        u16_field("b"),
        Field {
            name: Some("again".to_owned()),
            ..first
        },
    ]);
    let sample = [1u8, 2, 3, 4];
    let scored = score(&format, &[&sample[..]]);
    let sample_score = &scored.samples[0];
    assert!(sample_score.parsed);
    assert_eq!(sample_score.trailing_bytes, 0);
    assert_eq!(sample_score.gap_bytes, 0);
    assert_eq!(sample_score.overlap_bytes, 1);
}

#[test]
fn a_delimited_struct_in_unvalidated_ir_is_bounded_and_never_panics() {
    // Validation rejects a delimited struct, but the executor must still run
    // unvalidated IR safely: the terminator bounds the region.
    let body = struct_field("body", vec![u8_field("tag")]).with_size(SizeRule::Delimited {
        terminator: Bytes::new(vec![0]),
        include_terminator: false,
    });
    let format = format_of(vec![body, u8_field("after")]);
    assert!(format.validate().is_err());
    let execution = execute(&format, &[7u8, 8, 0, 9], &Limits::default());
    assert!(execution.succeeded(), "{:?}", execution.failure);
    assert_eq!((execution.fields[0].start, execution.fields[0].end), (0, 3));
    assert_eq!((execution.fields[1].start, execution.fields[1].end), (3, 4));

    let missing = execute(&format, &[7u8, 8, 9], &Limits::default());
    assert!(matches!(
        missing.failure.map(|failure| failure.reason),
        Some(FailureReason::TerminatorNotFound)
    ));
}

#[test]
fn a_sized_array_of_sized_structs_parses_each_record_in_its_region() {
    // Records of [len][len bytes of body: tag + data], bounded by a total.
    let record = struct_field(
        "record",
        vec![
            u8_field("len"),
            struct_field(
                "body",
                vec![u8_field("tag"), bytes_field("data", SizeRule::ToEnd)],
            )
            .with_size(derived("len")),
        ],
    );
    let format = format_of(vec![
        u8_field("total"),
        Field::new(
            Kind::Array {
                element: Box::new(record),
                count: CountRule::BoundedBy {
                    length_field: FieldRef::new("total"),
                },
            },
            Confidence::CERTAIN,
        )
        .with_name("records"),
    ]);
    format.validate().expect("valid IR");
    let sample = [7u8, 2, 0xa1, 0x01, 3, 0xa2, 0x02, 0x03];
    let scored = score(&format, &[&sample[..]]);
    assert!(scored.fully_verified(), "{:?}", scored.samples[0]);
}
