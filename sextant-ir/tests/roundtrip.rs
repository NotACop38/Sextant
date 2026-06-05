//! Lossless JSON round-trip tests (FR-19).
//!
//! Any IR must serialize to JSON and deserialize back to an equal value. These
//! tests cover the showcase fixture, a hand-built valid IR, and a single IR
//! that touches every kind, size rule, count rule, offset, constraint, and
//! anchor variant so that no serde representation is left unexercised.

use std::collections::BTreeMap;

use sextant_ir::bytes::Bytes;
use sextant_ir::model::SampleSupport;
use sextant_ir::{
    ChecksumAlgorithm, ChecksumSpec, Confidence, Constraint, CountRule, CoveredRange, Endianness,
    EnumDef, EnumVariant, Field, FieldOffset, FieldRef, Format, Kind, Metadata, RangeAnchor, Role,
    Signedness, SizeRule, StringEncoding, Structure,
};

fn assert_round_trips(format: &Format) {
    let pretty = format.to_json().expect("serialize pretty");
    let from_pretty = Format::from_json(&pretty).expect("deserialize pretty");
    assert_eq!(*format, from_pretty, "pretty JSON did not round-trip");

    let compact = format.to_json_compact().expect("serialize compact");
    let from_compact = Format::from_json(&compact).expect("deserialize compact");
    assert_eq!(*format, from_compact, "compact JSON did not round-trip");

    // Serializing the re-parsed value must reproduce the same text, proving the
    // representation is stable and carries no hidden state.
    let again = from_pretty.to_json().expect("re-serialize");
    assert_eq!(pretty, again, "re-serialized JSON drifted");
}

#[test]
fn png_fixture_round_trips() {
    let format = sextant_ir::fixtures::png_ground_truth();
    assert_round_trips(&format);
}

#[test]
fn valid_tlv_like_ir_round_trips() {
    let format = valid_tlv_like();
    assert!(
        format.validate().is_ok(),
        "the hand-built TLV IR should validate: {:?}",
        format.validate()
    );
    assert_round_trips(&format);
}

#[test]
fn comprehensive_ir_round_trips() {
    // Not necessarily semantically valid: the point is to exercise every serde
    // variant and confirm the round-trip is lossless regardless.
    let format = comprehensive();
    assert_round_trips(&format);
}

/// A small, semantically valid TLV-style IR: a magic, a count, and an array of
/// length-prefixed records whose value size is derived from a length field.
fn valid_tlv_like() -> Format {
    let record = Field {
        name: Some("record".to_owned()),
        kind: Kind::Struct {
            structure: Structure::new(vec![
                Field::new(
                    Kind::Integer {
                        width: 1,
                        signed: Signedness::Unsigned,
                        endianness: None,
                    },
                    Confidence::CERTAIN,
                )
                .with_name("tag")
                .with_role(Role::Enum),
                Field::new(
                    Kind::Integer {
                        width: 2,
                        signed: Signedness::Unsigned,
                        endianness: None,
                    },
                    Confidence::CERTAIN,
                )
                .with_name("length")
                .with_role(Role::Length),
                Field::new(Kind::Bytes, Confidence::clamped(0.9))
                    .with_name("value")
                    .with_size(SizeRule::Derived {
                        length_field: FieldRef::new("length"),
                    })
                    .with_role(Role::Payload),
            ]),
        },
        size: None,
        offset: None,
        role: None,
        constraints: Vec::new(),
        confidence: Confidence::CERTAIN,
        evidence: Default::default(),
    };

    Format {
        name: "tlv".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(vec![
            Field::new(Kind::Bytes, Confidence::CERTAIN)
                .with_name("magic")
                .with_size(SizeRule::Fixed { bytes: 4 })
                .with_role(Role::Magic),
            Field::new(
                Kind::Integer {
                    width: 1,
                    signed: Signedness::Unsigned,
                    endianness: None,
                },
                Confidence::CERTAIN,
            )
            .with_name("record_count")
            .with_role(Role::Count),
            Field {
                name: Some("records".to_owned()),
                kind: Kind::Array {
                    element: Box::new(record),
                    count: CountRule::FromField {
                        count_field: FieldRef::new("record_count"),
                    },
                },
                size: None,
                offset: None,
                role: None,
                constraints: Vec::new(),
                confidence: Confidence::CERTAIN,
                evidence: Default::default(),
            },
        ]),
        enums: BTreeMap::new(),
        metadata: Metadata {
            description: Some("A controlled tag-length-value container.".to_owned()),
            ..Default::default()
        },
    }
}

/// An IR that touches every variant of every IR enum at least once.
fn comprehensive() -> Format {
    let mut enums = BTreeMap::new();
    enums.insert(
        "color_type".to_owned(),
        EnumDef {
            width: Some(1),
            variants: vec![
                EnumVariant {
                    value: 0,
                    name: "grayscale".to_owned(),
                    description: Some("one channel".to_owned()),
                },
                EnumVariant {
                    value: 2,
                    name: "rgb".to_owned(),
                    description: None,
                },
            ],
        },
    );

    let mut extra = BTreeMap::new();
    extra.insert("origin".to_owned(), "test".to_owned());

    let fields = vec![
        // Integer with an endianness override.
        Field {
            name: Some("be_int".to_owned()),
            kind: Kind::Integer {
                width: 8,
                signed: Signedness::Signed,
                endianness: Some(Endianness::Big),
            },
            size: Some(SizeRule::Fixed { bytes: 8 }),
            offset: Some(FieldOffset::Absolute { bytes: 0 }),
            role: Some(Role::Timestamp),
            constraints: vec![Constraint::IntRange {
                min: -10,
                max: 1_000_000,
            }],
            confidence: Confidence::CERTAIN,
            evidence: sextant_ir::model::Evidence {
                detector: Some("test".to_owned()),
                support: Some(SampleSupport {
                    agreeing: 3,
                    total: 4,
                }),
                model_rationale: Some("looks like a unix time".to_owned()),
                notes: vec!["note one".to_owned(), "note two".to_owned()],
            },
        },
        // Bytes with a constant constraint.
        Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("magic")
            .with_size(SizeRule::Fixed { bytes: 2 })
            .with_role(Role::Magic),
        // String, delimited, terminator included.
        Field {
            name: Some("name".to_owned()),
            kind: Kind::String {
                encoding: StringEncoding::Utf8,
            },
            size: Some(SizeRule::Delimited {
                terminator: Bytes::new(vec![0x00]),
                include_terminator: true,
            }),
            offset: None,
            role: Some(Role::Unknown),
            constraints: Vec::new(),
            confidence: Confidence::clamped(0.5),
            evidence: Default::default(),
        },
        // Enum referencing the named enum.
        Field {
            name: Some("color".to_owned()),
            kind: Kind::Enum {
                enum_ref: "color_type".to_owned(),
                width: 1,
                endianness: Some(Endianness::Little),
            },
            size: None,
            offset: Some(FieldOffset::Derived {
                offset_field: FieldRef::new("be_int"),
            }),
            role: Some(Role::Enum),
            constraints: Vec::new(),
            confidence: Confidence::NONE,
            evidence: Default::default(),
        },
        // Opaque blob to end.
        Field::new(Kind::Opaque, Confidence::clamped(0.25))
            .with_name("trailer")
            .with_size(SizeRule::ToEnd)
            .with_role(Role::Reserved),
        // Nested struct holding a checksum and a string with the other encodings.
        Field {
            name: Some("footer".to_owned()),
            kind: Kind::Struct {
                structure: Structure::new(vec![
                    Field {
                        name: Some("ascii".to_owned()),
                        kind: Kind::String {
                            encoding: StringEncoding::Ascii,
                        },
                        size: Some(SizeRule::Fixed { bytes: 3 }),
                        offset: None,
                        role: None,
                        constraints: Vec::new(),
                        confidence: Confidence::CERTAIN,
                        evidence: Default::default(),
                    },
                    Field {
                        name: Some("utf16le".to_owned()),
                        kind: Kind::String {
                            encoding: StringEncoding::Utf16Le,
                        },
                        size: Some(SizeRule::Fixed { bytes: 4 }),
                        offset: None,
                        role: None,
                        constraints: Vec::new(),
                        confidence: Confidence::CERTAIN,
                        evidence: Default::default(),
                    },
                    Field {
                        name: Some("utf16be".to_owned()),
                        kind: Kind::String {
                            encoding: StringEncoding::Utf16Be,
                        },
                        size: Some(SizeRule::Fixed { bytes: 4 }),
                        offset: None,
                        role: None,
                        constraints: Vec::new(),
                        confidence: Confidence::CERTAIN,
                        evidence: Default::default(),
                    },
                    Field {
                        name: Some("latin1".to_owned()),
                        kind: Kind::String {
                            encoding: StringEncoding::Latin1,
                        },
                        size: Some(SizeRule::Fixed { bytes: 2 }),
                        offset: None,
                        role: None,
                        constraints: Vec::new(),
                        confidence: Confidence::CERTAIN,
                        evidence: Default::default(),
                    },
                    Field {
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
                                        field: FieldRef::new("ascii"),
                                    },
                                    to: RangeAnchor::FieldEnd {
                                        field: FieldRef::new("latin1"),
                                    },
                                },
                            },
                        }],
                        confidence: Confidence::CERTAIN,
                        evidence: Default::default(),
                    },
                ]),
            },
            size: None,
            offset: None,
            role: None,
            constraints: Vec::new(),
            confidence: Confidence::CERTAIN,
            evidence: Default::default(),
        },
        // Arrays exercising every count rule, plus a flags integer and the
        // remaining checksum algorithms and roles.
        array_field("fixed_array", CountRule::Fixed { count: 4 }),
        array_field(
            "from_field_array",
            CountRule::FromField {
                count_field: FieldRef::new("be_int"),
            },
        ),
        array_field(
            "bounded_array",
            CountRule::BoundedBy {
                length_field: FieldRef::new("be_int"),
            },
        ),
        array_field("to_end_array", CountRule::ToEnd),
        Field {
            name: Some("flags".to_owned()),
            kind: Kind::Integer {
                width: 2,
                signed: Signedness::Unsigned,
                endianness: None,
            },
            size: None,
            offset: None,
            role: Some(Role::Flags),
            constraints: vec![
                Constraint::Constant {
                    value: Bytes::new(vec![0xff, 0x00]),
                },
                Constraint::Checksum {
                    spec: ChecksumSpec {
                        algorithm: ChecksumAlgorithm::Crc16,
                        covered: CoveredRange {
                            from: RangeAnchor::FieldStart {
                                field: FieldRef::new("magic"),
                            },
                            to: RangeAnchor::FieldEnd {
                                field: FieldRef::new("magic"),
                            },
                        },
                    },
                },
            ],
            confidence: Confidence::CERTAIN,
            evidence: Default::default(),
        },
        Field {
            name: Some("additive_sum".to_owned()),
            kind: Kind::Integer {
                width: 1,
                signed: Signedness::Unsigned,
                endianness: None,
            },
            size: None,
            offset: None,
            role: Some(Role::Version),
            constraints: vec![Constraint::Checksum {
                spec: ChecksumSpec {
                    algorithm: ChecksumAlgorithm::Additive,
                    covered: CoveredRange {
                        from: RangeAnchor::FieldStart {
                            field: FieldRef::new("magic"),
                        },
                        to: RangeAnchor::FieldEnd {
                            field: FieldRef::new("magic"),
                        },
                    },
                },
            }],
            confidence: Confidence::CERTAIN,
            evidence: Default::default(),
        },
        Field {
            name: Some("xor_sum".to_owned()),
            kind: Kind::Integer {
                width: 1,
                signed: Signedness::Unsigned,
                endianness: None,
            },
            size: None,
            offset: None,
            role: Some(Role::Offset),
            constraints: vec![Constraint::Checksum {
                spec: ChecksumSpec {
                    algorithm: ChecksumAlgorithm::Xor,
                    covered: CoveredRange {
                        from: RangeAnchor::FieldStart {
                            field: FieldRef::new("magic"),
                        },
                        to: RangeAnchor::FieldEnd {
                            field: FieldRef::new("magic"),
                        },
                    },
                },
            }],
            confidence: Confidence::CERTAIN,
            evidence: Default::default(),
        },
    ];

    Format {
        name: "everything".to_owned(),
        endianness: Endianness::Big,
        root: Structure::new(fields),
        enums,
        metadata: Metadata {
            description: Some("Touches every IR variant.".to_owned()),
            version: Some("1".to_owned()),
            source: Some("test".to_owned()),
            extra,
        },
    }
}

fn array_field(name: &str, count: CountRule) -> Field {
    Field {
        name: Some(name.to_owned()),
        kind: Kind::Array {
            element: Box::new(Field::new(
                Kind::Integer {
                    width: 2,
                    signed: Signedness::Unsigned,
                    endianness: None,
                },
                Confidence::CERTAIN,
            )),
            count,
        },
        size: None,
        offset: None,
        role: Some(Role::Unknown),
        constraints: Vec::new(),
        confidence: Confidence::CERTAIN,
        evidence: Default::default(),
    }
}
