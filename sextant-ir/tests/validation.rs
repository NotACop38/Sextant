//! Validation tests: malformed IRs must be rejected with clear, located errors
//! (Step 2 acceptance criteria).
//!
//! Each test builds a structurally valid IR (so it still round-trips, FR-19)
//! that violates one semantic rule, then asserts the matching error is
//! reported.

use std::collections::BTreeMap;

use sextant_ir::bytes::Bytes;
use sextant_ir::{
    ChecksumAlgorithm, ChecksumSpec, Confidence, Constraint, CountRule, CoveredRange, Endianness,
    EnumDef, EnumVariant, Field, FieldOffset, FieldRef, Format, Kind, RangeAnchor, Role,
    Signedness, SizeRule, Structure, ValidationErrorKind,
};

/// Wrap a list of root fields into a little-endian format with no enums.
fn format_of(fields: Vec<Field>) -> Format {
    Format {
        name: "test".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(fields),
        enums: BTreeMap::new(),
        metadata: Default::default(),
    }
}

fn integer(name: &str, width: u8) -> Field {
    Field::new(
        Kind::Integer {
            width,
            signed: Signedness::Unsigned,
            endianness: None,
        },
        Confidence::CERTAIN,
    )
    .with_name(name)
}

/// Collect the error kinds from a failed validation, asserting it failed.
fn error_kinds(format: &Format) -> Vec<ValidationErrorKind> {
    let report = format.validate().expect_err("validation should fail");
    // The report must render a clear, non-empty message.
    let rendered = report.to_string();
    assert!(
        rendered.contains("validation failed"),
        "rendered: {rendered}"
    );
    assert!(!report.errors.is_empty());
    report.errors.into_iter().map(|error| error.kind).collect()
}

fn has_kind(kinds: &[ValidationErrorKind], wanted: &ValidationErrorKind) -> bool {
    kinds.iter().any(|kind| kind == wanted)
}

#[test]
fn png_fixture_is_valid() {
    let format = sextant_ir::fixtures::png_ground_truth();
    assert!(
        format.validate().is_ok(),
        "PNG fixture failed validation: {:?}",
        format.validate()
    );
}

#[test]
fn dangling_size_reference_is_rejected() {
    let format = format_of(vec![
        Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("value")
            .with_size(SizeRule::Derived {
                length_field: FieldRef::new("nonexistent"),
            }),
    ]);
    let kinds = error_kinds(&format);
    assert!(has_kind(
        &kinds,
        &ValidationErrorKind::DanglingFieldRef {
            name: "nonexistent".to_owned(),
        }
    ));
}

#[test]
fn dangling_count_reference_is_rejected() {
    let array = Field {
        name: Some("items".to_owned()),
        kind: Kind::Array {
            element: Box::new(integer("item", 2)),
            count: CountRule::FromField {
                count_field: FieldRef::new("missing_count"),
            },
        },
        size: None,
        offset: None,
        role: None,
        constraints: Vec::new(),
        confidence: Confidence::CERTAIN,
        evidence: Default::default(),
    };
    let kinds = error_kinds(&format_of(vec![array]));
    assert!(has_kind(
        &kinds,
        &ValidationErrorKind::DanglingFieldRef {
            name: "missing_count".to_owned(),
        }
    ));
}

#[test]
fn forward_reference_is_rejected() {
    // `value` derives its size from `length`, but `length` comes after it.
    let format = format_of(vec![
        Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("value")
            .with_size(SizeRule::Derived {
                length_field: FieldRef::new("length"),
            }),
        integer("length", 2).with_role(Role::Length),
    ]);
    let kinds = error_kinds(&format);
    assert!(has_kind(
        &kinds,
        &ValidationErrorKind::ForwardReference {
            name: "length".to_owned(),
        }
    ));
}

#[test]
fn reference_to_non_integer_is_rejected() {
    let format = format_of(vec![
        Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("label")
            .with_size(SizeRule::Fixed { bytes: 4 }),
        Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("value")
            .with_size(SizeRule::Derived {
                length_field: FieldRef::new("label"),
            }),
    ]);
    let kinds = error_kinds(&format);
    assert!(has_kind(
        &kinds,
        &ValidationErrorKind::ReferenceNotInteger {
            name: "label".to_owned(),
        }
    ));
}

#[test]
fn dangling_enum_reference_is_rejected() {
    let format = format_of(vec![Field {
        name: Some("kind".to_owned()),
        kind: Kind::Enum {
            enum_ref: "no_such_enum".to_owned(),
            width: 1,
            endianness: None,
        },
        size: None,
        offset: None,
        role: Some(Role::Enum),
        constraints: Vec::new(),
        confidence: Confidence::CERTAIN,
        evidence: Default::default(),
    }]);
    let kinds = error_kinds(&format);
    assert!(has_kind(
        &kinds,
        &ValidationErrorKind::DanglingEnumRef {
            name: "no_such_enum".to_owned(),
        }
    ));
}

#[test]
fn defined_enum_reference_is_accepted() {
    let mut enums = BTreeMap::new();
    enums.insert(
        "kinds".to_owned(),
        EnumDef {
            width: Some(1),
            variants: vec![EnumVariant {
                value: 1,
                name: "one".to_owned(),
                description: None,
            }],
        },
    );
    let format = Format {
        name: "test".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(vec![Field {
            name: Some("kind".to_owned()),
            kind: Kind::Enum {
                enum_ref: "kinds".to_owned(),
                width: 1,
                endianness: None,
            },
            size: None,
            offset: None,
            role: Some(Role::Enum),
            constraints: Vec::new(),
            confidence: Confidence::CERTAIN,
            evidence: Default::default(),
        }]),
        enums,
        metadata: Default::default(),
    };
    assert!(format.validate().is_ok());
}

#[test]
fn overlapping_fixed_fields_are_rejected() {
    let a = Field::new(Kind::Bytes, Confidence::CERTAIN)
        .with_name("a")
        .with_size(SizeRule::Fixed { bytes: 4 });
    let a = Field {
        offset: Some(FieldOffset::Absolute { bytes: 0 }),
        ..a
    };
    let b = Field::new(Kind::Bytes, Confidence::CERTAIN)
        .with_name("b")
        .with_size(SizeRule::Fixed { bytes: 4 });
    let b = Field {
        offset: Some(FieldOffset::Absolute { bytes: 2 }),
        ..b
    };
    let kinds = error_kinds(&format_of(vec![a, b]));
    assert!(
        kinds.iter().any(
            |kind| matches!(kind, ValidationErrorKind::OverlappingFields { at, .. } if *at == 2)
        ),
        "expected an overlap at offset 2, got {kinds:?}"
    );
}

#[test]
fn adjacent_positioned_fields_do_not_overlap() {
    let a = Field {
        offset: Some(FieldOffset::Absolute { bytes: 0 }),
        ..Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("a")
            .with_size(SizeRule::Fixed { bytes: 4 })
    };
    let b = Field {
        offset: Some(FieldOffset::Absolute { bytes: 4 }),
        ..Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("b")
            .with_size(SizeRule::Fixed { bytes: 4 })
    };
    assert!(format_of(vec![a, b]).validate().is_ok());
}

#[test]
fn duplicate_field_name_is_rejected() {
    let format = format_of(vec![integer("dup", 1), integer("dup", 2)]);
    let kinds = error_kinds(&format);
    assert!(has_kind(
        &kinds,
        &ValidationErrorKind::DuplicateFieldName {
            name: "dup".to_owned(),
        }
    ));
}

#[test]
fn zero_sized_fixed_field_is_rejected() {
    let format = format_of(vec![
        Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("empty")
            .with_size(SizeRule::Fixed { bytes: 0 }),
    ]);
    assert!(has_kind(
        &error_kinds(&format),
        &ValidationErrorKind::ZeroSizedField
    ));
}

#[test]
fn insane_fixed_size_is_rejected() {
    let huge = sextant_ir::validate::MAX_FIXED_FIELD_BYTES + 1;
    let format = format_of(vec![
        Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("huge")
            .with_size(SizeRule::Fixed { bytes: huge }),
    ]);
    assert!(has_kind(
        &error_kinds(&format),
        &ValidationErrorKind::InsaneFixedSize { bytes: huge }
    ));
}

#[test]
fn invalid_integer_width_is_rejected() {
    let format = format_of(vec![integer("odd", 3)]);
    assert!(has_kind(
        &error_kinds(&format),
        &ValidationErrorKind::InvalidIntegerWidth { width: 3 }
    ));
}

#[test]
fn empty_terminator_is_rejected() {
    let format = format_of(vec![
        Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("str")
            .with_size(SizeRule::Delimited {
                terminator: Bytes::default(),
                include_terminator: false,
            }),
    ]);
    assert!(has_kind(
        &error_kinds(&format),
        &ValidationErrorKind::EmptyTerminator
    ));
}

#[test]
fn out_of_range_confidence_is_rejected() {
    // Build via JSON so the out-of-range value survives into the IR: the
    // checked constructor would refuse it, but deserialization is permissive.
    let json = r#"{
        "name": "test",
        "endianness": "little",
        "root": { "fields": [
            { "name": "x", "kind": { "type": "integer", "width": 1, "signed": "unsigned" }, "confidence": 1.5 }
        ] }
    }"#;
    let format = Format::from_json(json).expect("deserialize");
    let kinds = error_kinds(&format);
    assert!(
        kinds
            .iter()
            .any(|kind| matches!(kind, ValidationErrorKind::ConfidenceOutOfRange { value } if *value == 1.5)),
        "got {kinds:?}"
    );
}

#[test]
fn size_rule_on_struct_is_rejected() {
    let format = format_of(vec![Field {
        name: Some("nested".to_owned()),
        kind: Kind::Struct {
            structure: Structure::new(vec![integer("inner", 1)]),
        },
        size: Some(SizeRule::Fixed { bytes: 1 }),
        offset: None,
        role: None,
        constraints: Vec::new(),
        confidence: Confidence::CERTAIN,
        evidence: Default::default(),
    }]);
    assert!(
        error_kinds(&format)
            .iter()
            .any(|kind| matches!(kind, ValidationErrorKind::SizeKindMismatch { .. }))
    );
}

#[test]
fn bytes_without_size_is_rejected() {
    let format = format_of(vec![
        Field::new(Kind::Bytes, Confidence::CERTAIN).with_name("b"),
    ]);
    assert!(
        error_kinds(&format)
            .iter()
            .any(|kind| matches!(kind, ValidationErrorKind::SizeKindMismatch { .. }))
    );
}

#[test]
fn constant_size_mismatch_is_rejected() {
    let field = Field {
        name: Some("magic".to_owned()),
        kind: Kind::Bytes,
        size: Some(SizeRule::Fixed { bytes: 4 }),
        offset: None,
        role: Some(Role::Magic),
        constraints: vec![Constraint::Constant {
            value: Bytes::new(vec![0x01, 0x02]),
        }],
        confidence: Confidence::CERTAIN,
        evidence: Default::default(),
    };
    assert!(has_kind(
        &error_kinds(&format_of(vec![field])),
        &ValidationErrorKind::ConstantSizeMismatch {
            expected: 4,
            actual: 2,
        }
    ));
}

#[test]
fn inverted_int_range_is_rejected() {
    let field = Field {
        constraints: vec![Constraint::IntRange { min: 10, max: 1 }],
        ..integer("ranged", 2)
    };
    assert!(has_kind(
        &error_kinds(&format_of(vec![field])),
        &ValidationErrorKind::IntRangeInverted { min: 10, max: 1 }
    ));
}

#[test]
fn insane_array_count_is_rejected() {
    let count = sextant_ir::validate::MAX_ARRAY_COUNT + 1;
    let array = Field {
        name: Some("items".to_owned()),
        kind: Kind::Array {
            element: Box::new(integer("item", 1)),
            count: CountRule::Fixed { count },
        },
        size: None,
        offset: None,
        role: None,
        constraints: Vec::new(),
        confidence: Confidence::CERTAIN,
        evidence: Default::default(),
    };
    assert!(has_kind(
        &error_kinds(&format_of(vec![array])),
        &ValidationErrorKind::InsaneArrayCount { count }
    ));
}

#[test]
fn nesting_deeper_than_the_cap_is_rejected() {
    // Build a chain of nested structs one deeper than MAX_NESTING_DEPTH.
    let mut field = integer("leaf", 1);
    for depth in (0..=sextant_ir::MAX_NESTING_DEPTH).rev() {
        field = Field::new(
            Kind::Struct {
                structure: Structure::new(vec![field]),
            },
            Confidence::CERTAIN,
        )
        .with_name(format!("s{depth}"));
    }
    let kinds = error_kinds(&format_of(vec![field]));
    assert!(
        kinds
            .iter()
            .any(|kind| matches!(kind, ValidationErrorKind::NestingTooDeep { .. })),
        "got {kinds:?}"
    );
}

#[test]
fn inconsistent_sample_support_is_rejected() {
    let field = Field {
        evidence: sextant_ir::Evidence {
            support: Some(sextant_ir::SampleSupport {
                agreeing: 10,
                total: 3,
            }),
            ..Default::default()
        },
        ..integer("x", 1)
    };
    assert!(has_kind(
        &error_kinds(&format_of(vec![field])),
        &ValidationErrorKind::SampleSupportInconsistent {
            agreeing: 10,
            total: 3,
        }
    ));
}

#[test]
fn dangling_checksum_anchor_is_rejected() {
    let field = Field {
        name: Some("crc".to_owned()),
        kind: Kind::Integer {
            width: 4,
            signed: Signedness::Unsigned,
            endianness: None,
        },
        size: None,
        offset: None,
        role: Some(Role::Checksum),
        constraints: vec![Constraint::Checksum {
            spec: ChecksumSpec {
                algorithm: ChecksumAlgorithm::Crc32,
                covered: CoveredRange {
                    from: RangeAnchor::FieldStart {
                        field: FieldRef::new("ghost"),
                    },
                    to: RangeAnchor::FieldEnd {
                        field: FieldRef::new("crc"),
                    },
                },
            },
        }],
        confidence: Confidence::CERTAIN,
        evidence: Default::default(),
    };
    assert!(has_kind(
        &error_kinds(&format_of(vec![field])),
        &ValidationErrorKind::DanglingFieldRef {
            name: "ghost".to_owned(),
        }
    ));
}

#[test]
fn duplicate_enum_value_is_rejected() {
    let mut enums = BTreeMap::new();
    enums.insert(
        "dup".to_owned(),
        EnumDef {
            width: Some(1),
            variants: vec![
                EnumVariant {
                    value: 1,
                    name: "a".to_owned(),
                    description: None,
                },
                EnumVariant {
                    value: 1,
                    name: "b".to_owned(),
                    description: None,
                },
            ],
        },
    );
    let format = Format {
        name: "test".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(vec![integer("x", 1)]),
        enums,
        metadata: Default::default(),
    };
    assert!(has_kind(
        &error_kinds(&format),
        &ValidationErrorKind::DuplicateEnumValue {
            enum_name: "dup".to_owned(),
            value: 1,
        }
    ));
}

#[test]
fn multiple_errors_are_all_reported() {
    // Two independent problems: an invalid width and a dangling reference.
    let format = format_of(vec![
        integer("bad_width", 7),
        Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("v")
            .with_size(SizeRule::Derived {
                length_field: FieldRef::new("absent"),
            }),
    ]);
    let kinds = error_kinds(&format);
    assert!(
        kinds.len() >= 2,
        "expected at least two errors, got {kinds:?}"
    );
    assert!(has_kind(
        &kinds,
        &ValidationErrorKind::InvalidIntegerWidth { width: 7 }
    ));
    assert!(has_kind(
        &kinds,
        &ValidationErrorKind::DanglingFieldRef {
            name: "absent".to_owned(),
        }
    ));
}

#[test]
fn overlap_through_positioned_nested_struct_is_detected() {
    // The nested struct's only child is absolute-positioned, yet its byte
    // extent is still statically known, so an overlap with a sibling must be
    // caught.
    let inner = Field {
        name: Some("inner".to_owned()),
        kind: Kind::Struct {
            structure: Structure::new(vec![Field {
                offset: Some(FieldOffset::Absolute { bytes: 0 }),
                ..Field::new(Kind::Bytes, Confidence::CERTAIN)
                    .with_name("a")
                    .with_size(SizeRule::Fixed { bytes: 8 })
            }]),
        },
        size: None,
        offset: Some(FieldOffset::Absolute { bytes: 0 }),
        role: None,
        constraints: Vec::new(),
        confidence: Confidence::CERTAIN,
        evidence: Default::default(),
    };
    let sibling = Field {
        offset: Some(FieldOffset::Absolute { bytes: 4 }),
        ..Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("b")
            .with_size(SizeRule::Fixed { bytes: 4 })
    };
    let kinds = error_kinds(&format_of(vec![inner, sibling]));
    assert!(
        kinds
            .iter()
            .any(|kind| matches!(kind, ValidationErrorKind::OverlappingFields { .. })),
        "expected an overlap through the nested struct, got {kinds:?}"
    );
}

#[test]
fn enum_width_conflict_is_rejected() {
    let mut enums = BTreeMap::new();
    enums.insert(
        "kinds".to_owned(),
        EnumDef {
            width: Some(1),
            variants: vec![EnumVariant {
                value: 1,
                name: "one".to_owned(),
                description: None,
            }],
        },
    );
    let format = Format {
        name: "test".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(vec![Field {
            name: Some("k".to_owned()),
            kind: Kind::Enum {
                enum_ref: "kinds".to_owned(),
                width: 4,
                endianness: None,
            },
            size: None,
            offset: None,
            role: Some(Role::Enum),
            constraints: Vec::new(),
            confidence: Confidence::CERTAIN,
            evidence: Default::default(),
        }]),
        enums,
        metadata: Default::default(),
    };
    assert!(has_kind(
        &error_kinds(&format),
        &ValidationErrorKind::EnumWidthMismatch {
            enum_name: "kinds".to_owned(),
            field_width: 4,
            enum_width: 1,
        }
    ));
}

#[test]
fn inverted_checksum_range_is_rejected() {
    // The covered range starts at the end of a later field and ends at the
    // start of an earlier one, which is not a real byte span.
    let crc = Field {
        name: Some("crc".to_owned()),
        kind: Kind::Integer {
            width: 4,
            signed: Signedness::Unsigned,
            endianness: None,
        },
        size: None,
        offset: None,
        role: Some(Role::Checksum),
        constraints: vec![Constraint::Checksum {
            spec: ChecksumSpec {
                algorithm: ChecksumAlgorithm::Crc32,
                covered: CoveredRange {
                    from: RangeAnchor::FieldEnd {
                        field: FieldRef::new("body"),
                    },
                    to: RangeAnchor::FieldStart {
                        field: FieldRef::new("header"),
                    },
                },
            },
        }],
        confidence: Confidence::CERTAIN,
        evidence: Default::default(),
    };
    let format = format_of(vec![
        Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("header")
            .with_size(SizeRule::Fixed { bytes: 4 }),
        Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("body")
            .with_size(SizeRule::Fixed { bytes: 4 }),
        crc,
    ]);
    assert!(has_kind(
        &error_kinds(&format),
        &ValidationErrorKind::InvertedChecksumRange {
            from: "body".to_owned(),
            to: "header".to_owned(),
        }
    ));
}
