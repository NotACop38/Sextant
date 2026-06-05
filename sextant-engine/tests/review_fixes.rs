//! Regression tests for robustness fixes surfaced in code review: no panic on a
//! wide bytes checksum, truncated bounded arrays fail, incomplete nested structs
//! are dropped from the tree, array-element checksums are evaluated, and the
//! decoded-string preview is bounded (FR-24 and verification correctness).

use sextant_engine::{CheckKind, FailureReason, Limits, Value, execute};
use sextant_ir::{
    ChecksumAlgorithm, ChecksumSpec, Confidence, Constraint, CountRule, CoveredRange, Endianness,
    Field, FieldRef, Format, Kind, RangeAnchor, Signedness, SizeRule, Structure,
};

fn u(width: u8) -> Kind {
    Kind::Integer {
        width,
        signed: Signedness::Unsigned,
        endianness: None,
    }
}

fn named(name: &str, kind: Kind) -> Field {
    Field::new(kind, Confidence::CERTAIN).with_name(name)
}

fn format(name: &str, endianness: Endianness, fields: Vec<Field>) -> Format {
    Format {
        name: name.to_owned(),
        endianness,
        root: Structure::new(fields),
        enums: Default::default(),
        metadata: Default::default(),
    }
}

fn crc_over(field: &str) -> Constraint {
    Constraint::Checksum {
        spec: ChecksumSpec {
            algorithm: ChecksumAlgorithm::Crc32,
            covered: CoveredRange {
                from: RangeAnchor::FieldStart {
                    field: FieldRef::new(field),
                },
                to: RangeAnchor::FieldEnd {
                    field: FieldRef::new(field),
                },
            },
        },
    }
}

#[test]
fn wide_bytes_checksum_field_does_not_panic() {
    // A checksum stored in a bytes field wider than eight bytes used to overflow
    // the little-endian integer decoder and panic. It must now decode safely.
    let mut csum = named("csum", Kind::Bytes).with_size(SizeRule::Fixed { bytes: 12 });
    csum.constraints.push(crc_over("body"));
    let format = format(
        "wide_csum",
        Endianness::Little,
        vec![
            named("body", Kind::Bytes).with_size(SizeRule::Fixed { bytes: 4 }),
            csum,
        ],
    );
    let sample = vec![0u8; 16];
    let execution = execute(&format, &sample, &Limits::default());
    // The point is that it returned at all (no panic) and recorded the checksum.
    assert!(
        execution
            .checks
            .iter()
            .any(|check| matches!(check.kind, CheckKind::Checksum(_)))
    );
}

#[test]
fn truncated_bounded_array_fails_instead_of_succeeding() {
    let format = format(
        "bounded",
        Endianness::Big,
        vec![
            named("blen", u(1)).with_role(sextant_ir::Role::Length),
            Field::new(
                Kind::Array {
                    element: Box::new(named("b", u(1))),
                    count: CountRule::BoundedBy {
                        length_field: FieldRef::new("blen"),
                    },
                },
                Confidence::CERTAIN,
            )
            .with_name("tail"),
        ],
    );

    // blen says 10 bytes but only 5 follow: this is truncated and must fail.
    let truncated = vec![10u8, 1, 2, 3, 4, 5];
    let execution = execute(&format, &truncated, &Limits::default());
    assert!(!execution.succeeded());
    assert!(matches!(
        execution.failure.as_ref().map(|failure| &failure.reason),
        Some(FailureReason::UnexpectedEndOfInput { .. })
    ));

    // A matching length parses cleanly.
    let exact = vec![3u8, 1, 2, 3];
    let execution = execute(&format, &exact, &Limits::default());
    assert!(execution.succeeded());
    let Value::Array(elements) = &execution.fields[1].value else {
        panic!("tail must be an array");
    };
    assert_eq!(elements.len(), 3);
}

#[test]
fn incomplete_nested_struct_is_not_in_the_tree() {
    // outer = { a: u8, b: u32 }; a sample with only two bytes truncates b, so
    // the partial outer struct must not appear in the returned tree.
    let format = format(
        "nested",
        Endianness::Big,
        vec![
            Field::new(
                Kind::Struct {
                    structure: Structure::new(vec![named("a", u(1)), named("b", u(4))]),
                },
                Confidence::CERTAIN,
            )
            .with_name("outer"),
        ],
    );
    let execution = execute(&format, &[0x01, 0x02], &Limits::default());
    assert!(!execution.succeeded());
    assert!(
        execution.fields.is_empty(),
        "the incomplete struct must be dropped, got {:?}",
        execution.fields
    );
}

#[test]
fn array_element_checksums_are_evaluated() {
    // An array whose element is a bytes field carrying a checksum constraint.
    // The element checksum covers the preceding `body` field.
    let mut element = named("stored", Kind::Bytes).with_size(SizeRule::Fixed { bytes: 4 });
    element.constraints.push(crc_over("body"));
    let format = format(
        "elem_csum",
        Endianness::Big,
        vec![
            named("body", Kind::Bytes).with_size(SizeRule::Fixed { bytes: 4 }),
            Field::new(
                Kind::Array {
                    element: Box::new(element),
                    count: CountRule::Fixed { count: 1 },
                },
                Confidence::CERTAIN,
            )
            .with_name("checksums"),
        ],
    );

    let body = [0x01u8, 0x02, 0x03, 0x04];
    let good_crc = sextant_engine::checksum::crc32(&body).to_be_bytes();

    // Correct checksum: the element check passes.
    let mut good = body.to_vec();
    good.extend_from_slice(&good_crc);
    let execution = execute(&format, &good, &Limits::default());
    let checksum_checks: Vec<_> = execution
        .checks
        .iter()
        .filter(|check| matches!(check.kind, CheckKind::Checksum(_)))
        .collect();
    assert_eq!(
        checksum_checks.len(),
        1,
        "the element checksum must be recorded"
    );
    assert!(
        checksum_checks[0].passed,
        "a correct element checksum verifies"
    );

    // Wrong checksum: the element check now fails, so consistency would drop.
    let mut bad = body.to_vec();
    bad.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    let execution = execute(&format, &bad, &Limits::default());
    assert!(
        execution
            .checks
            .iter()
            .any(|check| matches!(check.kind, CheckKind::Checksum(_)) && !check.passed),
        "a wrong element checksum must fail rather than go unchecked"
    );
}

#[test]
fn decoded_string_preview_is_bounded() {
    // A to-end string over a large buffer must not materialize the whole value;
    // the preview is capped while the field range stays full.
    let format = format(
        "bigstr",
        Endianness::Big,
        vec![
            named(
                "text",
                Kind::String {
                    encoding: sextant_ir::StringEncoding::Ascii,
                },
            )
            .with_size(SizeRule::ToEnd),
        ],
    );
    let sample = vec![b'a'; 10_000];
    let execution = execute(&format, &sample, &Limits::default());
    let field = &execution.fields[0];
    // The field still spans the whole buffer.
    assert_eq!(field.end - field.start, 10_000);
    let Value::Text(text) = &field.value else {
        panic!("text field");
    };
    assert!(
        text.len() <= 4096,
        "the preview must be bounded, got {}",
        text.len()
    );
}

#[test]
fn a_checksum_over_a_huge_range_respects_the_work_limit() {
    // A checksum over a to-end payload must charge work for hashing, so a tight
    // step budget stops it rather than spending CPU proportional to the input.
    let mut csum = named("csum", u(4));
    csum.constraints.push(crc_over("body"));
    let format = format(
        "big_csum",
        Endianness::Big,
        vec![
            named("len", u(4)).with_role(sextant_ir::Role::Length),
            named("body", Kind::Bytes).with_size(SizeRule::Derived {
                length_field: FieldRef::new("len"),
            }),
            csum,
        ],
    );
    // A 64 KiB body with a stored CRC, but a work budget far below the body size.
    let body_len: u32 = 65536;
    let mut sample = body_len.to_be_bytes().to_vec();
    sample.extend(std::iter::repeat_n(0u8, body_len as usize));
    sample.extend_from_slice(&[0, 0, 0, 0]);
    let limits = Limits {
        max_steps: 1024,
        timeout: None,
        ..Limits::default()
    };
    let execution = execute(&format, &sample, &limits);
    assert!(matches!(
        execution.failure.as_ref().map(|failure| &failure.reason),
        Some(FailureReason::StepLimit { .. })
    ));
}
