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

/// Names that each try to close a comment or doc form some target generates.
const HOSTILE_NAMES: &[&str] = &[
    "p */ throw new Error('INJECTED'); /* q",
    "p ]## quit(3) ##[ q",
    "p \\u002a/ q",
    "r\nthrow new Error('INJECTED')\n// q",
    "p \"\"\" ''' ` --[[ ]] --> <!-- ?> \u{202e} \u{2028} \u{85} q",
];

/// Sequences that must never reach generated source from IR text.
const TERMINATORS: &[&str] = &[
    "*/", "/*", "]##", "##[", "\"\"\"", "'''", "`", "--[[", "]]", "-->", "<!--", "?>", "\\u002a",
    "\u{202e}", "\u{2028}", "\u{85}",
];

fn checksum_over(index: usize, name: &str) -> Field {
    let mut checksum = Field::new(
        Kind::Integer {
            width: 1,
            signed: Signedness::Unsigned,
            endianness: None,
        },
        Confidence::CERTAIN,
    )
    .with_name(format!("sum_{index}"));
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
    checksum
}

#[test]
fn hostile_names_cannot_escape_comments_or_docs_in_any_exporter() {
    let mut fields = Vec::new();
    for (index, name) in HOSTILE_NAMES.iter().enumerate() {
        fields.push(
            Field::new(Kind::Bytes, Confidence::CERTAIN)
                .with_name(*name)
                .with_size(SizeRule::Fixed { bytes: 1 }),
        );
        fields.push(checksum_over(index, name));
    }
    let mut format = format_of(fields);
    format.metadata.description = Some(HOSTILE_NAMES.join(" "));
    format.validate().expect("hostile names are valid IR data");
    for target in ExportFormat::ALL {
        let source = export(&format, target).unwrap();
        // Lua has no C-style comments and carries IR names only inside escaped
        // string literals, which the Lua tests cover; every other target places
        // IR text in comments or docs, which must hold no terminator at all.
        if target != ExportFormat::Wireshark {
            for terminator in TERMINATORS {
                assert!(
                    !source.contains(terminator),
                    "{target}: {terminator:?} reached generated source:\n{source}"
                );
            }
        }
        let mut seen = 0;
        for line in source.lines().filter(|line| line.contains("INJECTED")) {
            seen += 1;
            let line = line.trim_start();
            match target {
                // The compiler copies these notes into doc comments.
                ExportFormat::Kaitai => assert!(
                    line.starts_with("doc: 'checksum: Additive over [")
                        || line.starts_with("title: '"),
                    "{target}: active source: {line}"
                ),
                ExportFormat::ImHex | ExportFormat::Bt => {
                    assert!(line.starts_with("//"), "{target}: active source: {line}")
                }
                // Labels are string literals in field registrations, never
                // comment text.
                ExportFormat::Wireshark => assert!(
                    line.starts_with("f[\"") && line.contains("ProtoField."),
                    "{target}: unexpected line: {line}"
                ),
            }
        }
        // Comment-bearing targets keep the sanitized text for review. Lua
        // labels these fields with their sanitized identifiers instead.
        if target != ExportFormat::Wireshark {
            assert!(seen > 0, "{target}: the hostile text was dropped entirely");
        }
    }
}

fn struct_named(name: &str) -> Field {
    Field::new(
        Kind::Struct {
            structure: Structure::new(vec![
                Field::new(
                    Kind::Integer {
                        width: 1,
                        signed: Signedness::Unsigned,
                        endianness: None,
                    },
                    Confidence::CERTAIN,
                )
                .with_name("inner"),
            ]),
        },
        Confidence::CERTAIN,
    )
    .with_name(name)
}

#[test]
fn kaitai_builtin_type_names_become_user_types() {
    let names = [
        "f4", "u4", "u1", "s2be", "f8le", "str", "strz", "b1", "b12", "b64le",
    ];
    let format = format_of(names.iter().map(|name| struct_named(name)).collect());
    format.validate().unwrap();
    let ksy = export(&format, ExportFormat::Kaitai).unwrap();
    for name in names {
        assert!(
            ksy.contains(&format!("- id: {name}\n    type: {name}_x\n")),
            "{name}:\n{ksy}"
        );
        assert!(
            ksy.contains(&format!("\n  {name}_x:\n    seq:\n")),
            "{name}:\n{ksy}"
        );
        assert!(
            !ksy.contains(&format!("- id: {name}\n    type: {name}\n")),
            "{name} still names a built-in type:\n{ksy}"
        );
    }
    // The capability check follows the same renaming: an enum spelled like
    // the renamed type shares its generated class name and is rejected.
    for enum_name in ["f4", "f4_x"] {
        let mut clash = format_of(vec![struct_named("f4")]);
        clash.enums.insert(enum_name.into(), enum_def(&["one"]));
        clash.validate().unwrap();
        let error = export(&clash, ExportFormat::Kaitai).unwrap_err();
        assert!(error.to_string().contains("identifiers collide"), "{error}");
    }
    // Two types that both want f4_x get distinct allocated names instead.
    let both = format_of(vec![struct_named("f4"), struct_named("f4_x")]);
    both.validate().unwrap();
    let ksy = export(&both, ExportFormat::Kaitai).unwrap();
    assert!(
        ksy.contains("type: f4_x\n") && ksy.contains("type: f4_x_2\n"),
        "{ksy}"
    );
}

#[test]
fn kaitai_keywords_are_renamed_at_declaration_and_every_reference() {
    let byte = |name: &str| {
        Field::new(
            Kind::Integer {
                width: 1,
                signed: Signedness::Unsigned,
                endianness: None,
            },
            Confidence::CERTAIN,
        )
        .with_name(name)
    };
    let mut fields = Vec::new();
    // Expression keywords, YAML 1.1 words, and target-language keywords.
    let words = [
        "true", "not", "and", "yes", "off", "null", "class", "def", "wait", "read",
    ];
    for word in words {
        fields.push(byte(word));
        fields.push(
            Field::new(Kind::Bytes, Confidence::CERTAIN)
                .with_name(format!("{word} body"))
                .with_size(SizeRule::Derived {
                    length_field: FieldRef::new(word),
                }),
        );
    }
    let mut format = format_of(fields);
    format.name = "none".into();
    format.validate().unwrap();
    let ksy = export(&format, ExportFormat::Kaitai).unwrap();
    assert!(ksy.contains("  id: none_x\n"), "{ksy}");
    for word in words {
        assert!(ksy.contains(&format!("- id: {word}_x\n")), "{word}:\n{ksy}");
        assert!(ksy.contains(&format!("size: {word}_x\n")), "{word}:\n{ksy}");
        assert!(!ksy.contains(&format!("- id: {word}\n")), "{word}:\n{ksy}");
    }
    // Ordinary names are not renamed.
    assert!(ksy.contains("- id: true_body\n"), "{ksy}");
}

#[test]
fn template_reserved_names_are_renamed_at_declaration_and_every_reference() {
    let byte = |name: &str| {
        Field::new(
            Kind::Integer {
                width: 1,
                signed: Signedness::Unsigned,
                endianness: None,
            },
            Confidence::CERTAIN,
        )
        .with_name(name)
    };
    let sized = |name: &str| {
        Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name(format!("{name} body"))
            .with_size(SizeRule::Derived {
                length_field: FieldRef::new(name),
            })
    };
    let counted = |name: &str| {
        Field::new(
            Kind::Array {
                element: Box::new(byte("item")),
                count: CountRule::FromField {
                    count_field: FieldRef::new(name),
                },
            },
            Confidence::CERTAIN,
        )
        .with_name(format!("{name} items"))
    };
    for (target, words, type_name) in [
        (ExportFormat::ImHex, ["u8", "struct", "std"], "FileSize"),
        (ExportFormat::Bt, ["int", "local", "string"], "FileSize_"),
    ] {
        let mut fields = Vec::new();
        for word in words {
            fields.push(byte(word));
            fields.push(sized(word));
            fields.push(counted(word));
        }
        fields.push(struct_named("file size"));
        let mut format = format_of(fields);
        format.name = "struct".into();
        format.validate().unwrap();
        let source = export(&format, target).unwrap();
        for word in words {
            for expected in [
                format!(" {word}_;"),
                format!("{word}_body[{word}_];"),
                format!("{word}_items[{word}_];"),
            ] {
                assert!(source.contains(&expected), "{target}: {expected}\n{source}");
            }
            assert!(
                !source.contains(&format!(" {word};")),
                "{target}:\n{source}"
            );
        }
        assert!(
            source.contains(&format!("{type_name} file_size;")),
            "{target}:\n{source}"
        );
        let root = match target {
            ExportFormat::ImHex => "Struct struct_ @ 0x00;",
            _ => "} struct_;",
        };
        assert!(source.contains(root), "{target}:\n{source}");
        // A field whose sanitized name already carries the suffix would
        // collide with the renamed keyword, so the pair is rejected.
        let clash = format_of(vec![byte(words[1]), byte(&format!("{}_", words[1]))]);
        clash.validate().unwrap();
        let error = export(&clash, target).unwrap_err();
        assert!(error.to_string().contains("collide"), "{target}: {error}");
    }
    // 010 keeps typedefs and enum constants clear of the functions the
    // template calls and of upper-case built-in types.
    let mut format = format_of(vec![struct_named("d w o r d")]);
    format.enums.insert("f eof".into(), enum_def(&["f tell"]));
    format.validate().unwrap();
    let bt = export(&format, ExportFormat::Bt).unwrap();
    for expected in ["} DWORD_;", "} FEof_;", "FTell_ = 1"] {
        assert!(bt.contains(expected), "{expected}:\n{bt}");
    }
}

#[test]
fn kaitai_rejects_enum_values_its_compiler_cannot_represent() {
    let enum_field = Field::new(
        Kind::Enum {
            enum_ref: "wide".into(),
            width: 8,
            endianness: None,
        },
        Confidence::CERTAIN,
    )
    .with_name("value");
    for (value, accepted) in [
        (i128::from(i64::MAX), true),
        (i128::from(i64::MIN), true),
        (i128::from(i64::MAX) + 1, false),
        (i128::from(u64::MAX), false),
        (i128::from(i64::MIN) - 1, false),
    ] {
        let mut format = format_of(vec![enum_field.clone()]);
        format.enums.insert(
            "wide".into(),
            EnumDef {
                width: Some(8),
                variants: vec![EnumVariant {
                    value,
                    name: "top".into(),
                    description: None,
                }],
            },
        );
        format.validate().unwrap();
        match export(&format, ExportFormat::Kaitai) {
            Ok(ksy) => {
                assert!(accepted, "{value} accepted:\n{ksy}");
                assert!(ksy.contains(&format!("{value}: top")), "{ksy}");
            }
            Err(error) => {
                assert!(!accepted, "{value} rejected: {error}");
                assert!(
                    error.to_string().contains("signed 64-bit"),
                    "{value}: {error}"
                );
            }
        }
        // The other targets are unaffected by the Kaitai key limit.
        for target in [
            ExportFormat::ImHex,
            ExportFormat::Bt,
            ExportFormat::Wireshark,
        ] {
            assert!(export(&format, target).is_ok(), "{target} {value}");
        }
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
