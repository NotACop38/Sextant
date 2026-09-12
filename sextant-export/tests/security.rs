//! Security regressions at the public exporter boundary.

use sextant_export::{ExportFormat, export};
use sextant_ir::{
    Bytes, ChecksumAlgorithm, ChecksumSpec, Confidence, Constraint, CoveredRange, Endianness,
    Field, FieldOffset, FieldRef, Format, Kind, Metadata, RangeAnchor, Signedness, SizeRule,
    Structure,
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
