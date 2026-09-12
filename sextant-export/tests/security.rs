//! Security regressions at the public exporter boundary.

use sextant_export::{ExportFormat, export};
use sextant_ir::{
    Bytes, ChecksumAlgorithm, ChecksumSpec, Confidence, Constraint, CountRule, CoveredRange,
    Endianness, EnumDef, EnumVariant, Field, FieldOffset, FieldRef, Format, Kind, Metadata,
    RangeAnchor, Signedness, SizeRule, Structure,
};

fn format_of(fields: Vec<Field>) -> Format {
    Format {
        name: "regression".into(),
        endianness: Endianness::Little,
        root: Structure::new(fields),
        enums: Default::default(),
        metadata: Metadata::default(),
    }
}

#[test]
fn checksum_anchors_cannot_escape_template_comments() {
    let name = "payload\nwhile(1) {}\r\n//\u{2028}end";
    let payload = Field::new(Kind::Bytes, Confidence::CERTAIN)
        .with_name(name)
        .with_size(SizeRule::Fixed { bytes: 1 });
    let mut checksum = Field::new(
        Kind::Integer {
            width: 1,
            signed: Signedness::Unsigned,
            endianness: None,
        },
        Confidence::CERTAIN,
    )
    .with_name("checksum");
    checksum.constraints.push(Constraint::Checksum {
        spec: ChecksumSpec {
            algorithm: ChecksumAlgorithm::Additive,
            covered: CoveredRange {
                from: RangeAnchor::FieldStart {
                    field: FieldRef::new(name),
                },
                to: RangeAnchor::FieldEnd {
                    field: FieldRef::new(name),
                },
            },
        },
    });
    let format = format_of(vec![payload, checksum]);
    format
        .validate()
        .expect("the hostile name is valid IR data");
    for target in [ExportFormat::ImHex, ExportFormat::Bt] {
        let source = export(&format, target).unwrap();
        assert!(
            source.contains("while(1) {}"),
            "retain the label for review"
        );
        for line in source.lines().filter(|line| line.contains("while(1) {}")) {
            assert!(line.trim_start().starts_with("//"), "active source: {line}");
        }
    }
}

#[test]
fn malformed_ir_is_rejected_before_rendering() {
    let format = format_of(vec![Field::new(
        Kind::Integer {
            width: 0,
            signed: Signedness::Unsigned,
            endianness: None,
        },
        Confidence::CERTAIN,
    )]);
    for target in ExportFormat::ALL {
        assert!(
            export(&format, target).is_err(),
            "accepted malformed IR for {target}"
        );
    }
}

#[test]
fn references_shadowed_by_future_local_fields_are_rejected() {
    let length = || {
        Field::new(
            Kind::Integer {
                width: 1,
                signed: Signedness::Unsigned,
                endianness: None,
            },
            Confidence::CERTAIN,
        )
        .with_name("length")
    };
    let payload = Field::new(Kind::Bytes, Confidence::CERTAIN)
        .with_name("payload")
        .with_size(SizeRule::Derived {
            length_field: FieldRef::new("length"),
        });
    let record = Field::new(
        Kind::Struct {
            structure: Structure::new(vec![payload, length()]),
        },
        Confidence::CERTAIN,
    )
    .with_name("record");
    let format = format_of(vec![length(), record]);
    format.validate().unwrap();
    let execution = sextant_engine::execute(
        &format,
        &[2, 0xaa, 0xbb, 1],
        &sextant_engine::Limits::default(),
    );
    assert!(execution.succeeded(), "{execution:?}");
    for target in ExportFormat::ALL {
        let error = export(&format, target).expect_err("forward shadowing is unsupported");
        assert!(
            error.to_string().contains("not-yet-parsed"),
            "{target}: {error}"
        );
    }
}

#[test]
fn array_element_names_cannot_shadow_their_own_size_reference() {
    let length = Field::new(
        Kind::Integer {
            width: 1,
            signed: Signedness::Unsigned,
            endianness: None,
        },
        Confidence::CERTAIN,
    )
    .with_name("length");
    let element = Field::new(Kind::Bytes, Confidence::CERTAIN)
        .with_name("length")
        .with_size(SizeRule::Derived {
            length_field: FieldRef::new("length"),
        });
    let items = Field::new(
        Kind::Array {
            element: Box::new(element),
            count: CountRule::Fixed { count: 1 },
        },
        Confidence::CERTAIN,
    )
    .with_name("items");
    let format = format_of(vec![length, items]);
    format.validate().unwrap();
    assert!(
        sextant_engine::execute(
            &format,
            &[2, 0xaa, 0xbb],
            &sextant_engine::Limits::default()
        )
        .succeeded()
    );
    for target in ExportFormat::ALL {
        assert!(export(&format, target).is_err(), "{target}");
    }
}

fn enum_def(names: &[&str]) -> EnumDef {
    EnumDef {
        width: Some(1),
        variants: names
            .iter()
            .enumerate()
            .map(|(value, name)| EnumVariant {
                value: value as i128 + 1,
                name: (*name).into(),
                description: None,
            })
            .collect(),
    }
}

fn assert_enum_identifiers_rejected(format: &Format) {
    format.validate().unwrap();
    for target in [ExportFormat::Kaitai, ExportFormat::ImHex, ExportFormat::Bt] {
        let error = export(format, target).expect_err("colliding names must not be emitted");
        assert!(
            error.to_string().contains("identifiers collide"),
            "{target}: {error}"
        );
    }
    assert!(export(format, ExportFormat::Wireshark).is_ok());
}

#[test]
fn enum_names_and_variants_must_remain_unique_after_sanitizing() {
    let mut format = format_of(vec![]);
    format.enums.insert("a-b".into(), enum_def(&["one"]));
    format.enums.insert("a b".into(), enum_def(&["two"]));
    assert_enum_identifiers_rejected(&format);
    format.enums.clear();
    format
        .enums
        .insert("values".into(), enum_def(&["a-b", "a b"]));
    assert_enum_identifiers_rejected(&format);
}

#[test]
fn enums_cannot_collide_with_nested_or_wrapper_types() {
    let value =
        || Field::new(Kind::Bytes, Confidence::CERTAIN).with_size(SizeRule::Fixed { bytes: 1 });
    let record = Field::new(
        Kind::Struct {
            structure: Structure::new(vec![value()]),
        },
        Confidence::CERTAIN,
    )
    .with_name("record");
    let mut format = format_of(vec![record.clone()]);
    format.enums.insert("record".into(), enum_def(&["one"]));
    assert_enum_identifiers_rejected(&format);
    let inner = Field::new(
        Kind::Array {
            element: Box::new(value()),
            count: CountRule::Fixed { count: 1 },
        },
        Confidence::CERTAIN,
    )
    .with_name("record");
    format.root = Structure::new(vec![
        Field::new(
            Kind::Array {
                element: Box::new(inner),
                count: CountRule::Fixed { count: 1 },
            },
            Confidence::CERTAIN,
        )
        .with_name("items"),
    ]);
    assert_enum_identifiers_rejected(&format);
    // The second type with the same raw name receives an allocator suffix.
    format.root = Structure::new(vec![
        record.clone(),
        Field::new(
            Kind::Struct {
                structure: Structure::new(vec![record]),
            },
            Confidence::CERTAIN,
        )
        .with_name("container"),
    ]);
    format.enums.clear();
    format.enums.insert("record_2".into(), enum_def(&["one"]));
    format.validate().unwrap();
    assert!(export(&format, ExportFormat::Kaitai).is_err());
}

#[test]
fn numeric_dependencies_need_a_stable_identifier_and_supported_type() {
    let length = Field::new(
        Kind::Integer {
            width: 1,
            signed: Signedness::Unsigned,
            endianness: None,
        },
        Confidence::CERTAIN,
    )
    .with_name("_");
    let payload = |name: &str| {
        Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("payload")
            .with_size(SizeRule::Derived {
                length_field: FieldRef::new(name),
            })
    };
    let mut format = format_of(vec![length, payload("_")]);
    format.validate().unwrap();
    assert!(
        sextant_engine::execute(&format, &[1, 0xaa], &sextant_engine::Limits::default())
            .succeeded()
    );
    for target in [
        ExportFormat::ImHex,
        ExportFormat::Bt,
        ExportFormat::Wireshark,
    ] {
        let error = export(&format, target).unwrap_err();
        assert!(error.to_string().contains("stable identifier"));
    }
    assert!(export(&format, ExportFormat::Kaitai).is_ok());
    format.enums.insert("sizes".into(), enum_def(&["one"]));
    format.root = Structure::new(vec![
        Field::new(
            Kind::Enum {
                enum_ref: "sizes".into(),
                width: 1,
                endianness: None,
            },
            Confidence::CERTAIN,
        )
        .with_name("length"),
        payload("length"),
    ]);
    format.validate().unwrap();
    assert!(
        sextant_engine::execute(&format, &[1, 0xaa], &sextant_engine::Limits::default())
            .succeeded()
    );
    let error = export(&format, ExportFormat::Kaitai).unwrap_err();
    assert!(error.to_string().contains("numeric dependencies on enum"));
    for target in [
        ExportFormat::ImHex,
        ExportFormat::Bt,
        ExportFormat::Wireshark,
    ] {
        assert!(export(&format, target).is_ok());
    }
}

#[test]
fn templates_reject_layouts_they_cannot_preserve() {
    let mut field = Field::new(Kind::Bytes, Confidence::CERTAIN)
        .with_name("payload")
        .with_size(SizeRule::Fixed { bytes: 1 });
    field.offset = Some(FieldOffset::Absolute { bytes: 10 });
    let positioned = format_of(vec![field]);
    let delimited = format_of(vec![
        Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("payload")
            .with_size(SizeRule::Delimited {
                terminator: Bytes::new(vec![0]),
                include_terminator: false,
            }),
    ]);
    for target in [ExportFormat::ImHex, ExportFormat::Bt] {
        assert!(export(&positioned, target).is_err());
        assert!(export(&delimited, target).is_err());
    }
}

#[test]
fn deeply_repeated_long_names_cannot_amplify_generated_source() {
    let leaf =
        || Field::new(Kind::Bytes, Confidence::CERTAIN).with_size(SizeRule::Fixed { bytes: 1 });
    let mut fields = Vec::new();
    for index in 0..64 {
        fields.push(leaf().with_name(format!("value_{index}")));
    }
    let parent = Field::new(
        Kind::Struct {
            structure: Structure::new(fields),
        },
        Confidence::CERTAIN,
    )
    .with_name("a".repeat(16384));
    let format = format_of(vec![parent]);
    format.validate().unwrap();
    assert!(export(&format, ExportFormat::Wireshark).is_err());
}
