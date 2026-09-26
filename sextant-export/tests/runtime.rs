//! Execute generated parsers, including malformed-input regressions.

use sextant_export::crossval::{CrossValidation, cross_validate};
use sextant_export::{ExportFormat, export};
use sextant_ir::{
    Bytes, ChecksumAlgorithm, ChecksumSpec, Confidence, Constraint, CountRule, CoveredRange,
    Endianness, EnumDef, EnumVariant, Field, FieldRef, Format, Kind, Metadata, RangeAnchor,
    Signedness, SizeRule, StringEncoding, Structure,
};
use std::fmt::Write as _;
use std::process::Command;

fn format_of(fields: Vec<Field>) -> Format {
    Format {
        name: "runtime_test".into(),
        endianness: Endianness::Little,
        root: Structure::new(fields),
        enums: Default::default(),
        metadata: Metadata::default(),
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
fn array(element: Field, count: CountRule) -> Field {
    Field::new(
        Kind::Array {
            element: Box::new(element),
            count,
        },
        Confidence::CERTAIN,
    )
    .with_name("items")
}
fn lua(format: &Format, sample: &[u8]) -> Option<String> {
    if Command::new("lua").arg("-v").output().is_err() {
        assert!(
            std::env::var_os("SEXTANT_REQUIRE_LUA").is_none(),
            "Lua runtime required"
        );
        eprintln!("Lua runtime unavailable: skipped");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let parser = dir.path().join("parser.lua");
    std::fs::write(&parser, export(format, ExportFormat::Wireshark).unwrap()).unwrap();
    let mut hex = String::new();
    for byte in sample {
        write!(hex, "{byte:02x}").unwrap();
    }
    let result = Command::new("lua")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lua_runtime.lua"
        ))
        .arg(parser)
        .arg(hex)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "Lua failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Some(String::from_utf8(result.stdout).unwrap())
}

#[test]
fn lua_rejects_zero_progress_and_truncated_arrays() {
    let format = format_of(vec![
        integer("length", 1),
        array(
            Field::new(Kind::Bytes, Confidence::CERTAIN).with_size(SizeRule::Derived {
                length_field: FieldRef::new("length"),
            }),
            CountRule::ToEnd,
        ),
    ]);
    if let Some(output) = lua(&format, &[1, 171]) {
        assert_eq!(output.trim(), "OK 0:1,1:1");
    }
    if let Some(output) = lua(&format, &[0, 171]) {
        assert!(
            output.contains("Sextant: array element made no progress"),
            "{output}"
        );
    }
    let counted = format_of(vec![
        integer("count", 4),
        array(
            integer("item", 1),
            CountRule::FromField {
                count_field: FieldRef::new("count"),
            },
        ),
    ]);
    if let Some(output) = lua(&counted, &[2, 0, 0, 0, 171]) {
        assert!(
            output.contains("Sextant: field exceeds enclosing boundary"),
            "{output}"
        );
    }
    if let Some(output) = lua(&counted, &[255, 255, 255, 255, 171]) {
        assert!(output.contains("Sextant: array count limit"), "{output}");
    }
}

#[test]
fn lua_delimiters_and_bounded_arrays_respect_boundaries() {
    let delimited = format_of(vec![
        Field::new(Kind::Bytes, Confidence::CERTAIN).with_size(SizeRule::Delimited {
            terminator: Bytes::new(vec![0, 0]),
            include_terminator: false,
        }),
    ]);
    if let Some(output) = lua(&delimited, &[1]) {
        assert!(output.contains("Sextant: missing delimiter"), "{output}");
    }
    if let Some(output) = lua(&delimited, &[1, 0, 0]) {
        assert_eq!(output.trim(), "OK 0:1");
    }
    let bounded = format_of(vec![
        integer("length", 1),
        array(
            integer("word", 2),
            CountRule::BoundedBy {
                length_field: FieldRef::new("length"),
            },
        ),
        integer("tail", 1),
    ]);
    if let Some(output) = lua(&bounded, &[2, 1, 2, 3]) {
        assert_eq!(output.trim(), "OK 0:1,1:2,3:1");
    }
    if let Some(output) = lua(&bounded, &[1, 1, 2, 3]) {
        assert!(
            output.contains("Sextant: field exceeds enclosing boundary"),
            "{output}"
        );
    }
}

#[test]
fn generated_lua_matches_native_ranges_on_the_showcase_corpus() {
    fn leaf_ranges(fields: &[sextant_engine::FieldInstance], ranges: &mut Vec<String>) {
        for field in fields {
            match &field.value {
                sextant_engine::Value::Struct(children)
                | sextant_engine::Value::Array(children) => leaf_ranges(children, ranges),
                _ => ranges.push(format!("{}:{}", field.start, field.end - field.start)),
            }
        }
    }
    for format in [
        sextant_ir::fixtures::tlv_ground_truth(),
        sextant_ir::fixtures::png_ground_truth(),
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("corpus")
            .join(&format.name)
            .join("samples");
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|extension| extension.to_str())
                != Some(format.name.as_str())
            {
                continue;
            }
            let sample = std::fs::read(path).unwrap();
            let parsed =
                sextant_engine::execute(&format, &sample, &sextant_engine::Limits::default());
            assert!(parsed.succeeded());
            let mut ranges = Vec::new();
            leaf_ranges(&parsed.fields, &mut ranges);
            if let Some(output) = lua(&format, &sample) {
                assert_eq!(output.trim(), format!("OK {}", ranges.join(",")));
            }
        }
    }
}

fn checked_crossval(format: &Format, sample: Vec<u8>, success: bool) {
    match cross_validate(format, &[sample]) {
        CrossValidation::Skipped { reason } => assert!(
            std::env::var_os("SEXTANT_REQUIRE_KAITAI").is_none(),
            "{reason}"
        ),
        result => assert_eq!(result.passed(), success, "{result:?}"),
    }
}

#[test]
fn kaitai_bounded_array_preserves_the_outer_tail_and_ancestor_reference() {
    // The record's payload references the root's width across the synthetic
    // bounded-array wrapper and the record type, requiring two parent hops.
    let record = Field::new(
        Kind::Struct {
            structure: Structure::new(vec![
                integer("tag", 1),
                Field::new(Kind::Bytes, Confidence::CERTAIN)
                    .with_name("payload")
                    .with_size(SizeRule::Derived {
                        length_field: FieldRef::new("width"),
                    }),
            ]),
        },
        Confidence::CERTAIN,
    )
    .with_name("record");
    let format = format_of(vec![
        integer("width", 1),
        integer("length", 1),
        array(
            record,
            CountRule::BoundedBy {
                length_field: FieldRef::new("length"),
            },
        ),
        integer("tail", 1),
    ]);
    checked_crossval(&format, vec![1, 4, 7, 8, 9, 10, 255], true);
    checked_crossval(&format, vec![1, 3, 7, 8, 9, 255], false);
}

#[test]
fn kaitai_cross_validation_rejects_unconsumed_input() {
    let format = format_of(vec![integer("one", 1)]);
    checked_crossval(&format, vec![1], true);
    checked_crossval(&format, vec![1, 2], false);
}

#[test]
fn generated_module_name_cannot_shadow_the_python_runtime() {
    let mut format = format_of(vec![integer("one", 1)]);
    format.name = "kaitaistruct".into();
    checked_crossval(&format, vec![1], true);
}

fn signed(name: &str, width: u8) -> Field {
    Field::new(
        Kind::Integer {
            width,
            signed: Signedness::Signed,
            endianness: None,
        },
        Confidence::CERTAIN,
    )
    .with_name(name)
}

fn record(name: &str, fields: Vec<Field>) -> Field {
    Field::new(
        Kind::Struct {
            structure: Structure::new(fields),
        },
        Confidence::CERTAIN,
    )
    .with_name(name)
}

fn native_ok(format: &Format, sample: &[u8]) -> bool {
    let parsed = sextant_engine::execute(format, sample, &sextant_engine::Limits::default());
    parsed.succeeded() && parsed.consumed == sample.len()
}

#[test]
fn kaitai_structs_named_like_builtin_types_parse_as_user_types() {
    // Each struct holds one byte. Read as the built-in type instead (a float,
    // a u4, or an encoding-less string), the spec would fail to compile or
    // need more bytes than the sample has.
    let names = ["f4", "u4", "s8le", "str", "strz", "b12"];
    let format = format_of(
        names
            .iter()
            .map(|name| record(name, vec![integer("inner", 1)]))
            .collect(),
    );
    let sample: Vec<u8> = (1..=6).collect();
    assert!(native_ok(&format, &sample));
    checked_crossval(&format, sample, true);
}

#[test]
fn kaitai_reserved_identifiers_compile_and_parse() {
    // Kaitai expression keywords, YAML 1.1 words, and Python keywords as field,
    // type, enum, variant, and root names, with keywords used as references.
    let mut fields = Vec::new();
    for word in [
        "true", "not", "and", "or", "yes", "off", "null", "class", "import",
    ] {
        fields.push(integer(word, 1));
        fields.push(
            Field::new(Kind::Bytes, Confidence::CERTAIN)
                .with_name(format!("{word} body"))
                .with_size(SizeRule::Derived {
                    length_field: FieldRef::new(word),
                }),
        );
    }
    fields.push(record("none", vec![integer("x", 1)]));
    fields.push(record("false", vec![integer("x", 1)]));
    fields.push(
        Field::new(
            Kind::Enum {
                enum_ref: "kind".into(),
                width: 1,
                endianness: None,
            },
            Confidence::CERTAIN,
        )
        .with_name("lambda"),
    );
    let mut format = format_of(fields);
    format.name = "none".into();
    format.enums.insert(
        "kind".into(),
        EnumDef {
            width: Some(1),
            variants: ["class", "def", "mro", "true", "none"]
                .iter()
                .enumerate()
                .map(|(index, name)| EnumVariant {
                    value: index as i128 + 1,
                    name: (*name).into(),
                    description: None,
                })
                .collect(),
        },
    );
    let mut sample = Vec::new();
    for length in [1u8, 0, 2, 0, 1, 0, 1, 0, 1] {
        sample.push(length);
        sample.extend(std::iter::repeat_n(0xaa, usize::from(length)));
    }
    sample.extend([7, 8, 3]);
    assert!(native_ok(&format, &sample));
    checked_crossval(&format, sample, true);
}

#[test]
fn kaitai_hostile_doc_text_still_compiles_and_parses() {
    let name = "p */ throw new Error('INJECTED'); /* q\n]## quit(3) ##[ \"\"\"";
    let mut sum = integer("sum", 1);
    sum.constraints.push(Constraint::Checksum {
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
    let mut format = format_of(vec![
        Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name(name)
            .with_size(SizeRule::Fixed { bytes: 1 }),
        sum,
    ]);
    format.metadata.description = Some(name.into());
    checked_crossval(&format, vec![5, 5], true);
}

#[test]
fn kaitai_signed_counts_fail_exactly_where_the_executor_does() {
    let items = |count: &str| {
        array(
            integer("item", 1),
            CountRule::FromField {
                count_field: FieldRef::new(count),
            },
        )
    };
    let format = format_of(vec![signed("count", 1), items("count")]);
    assert!(native_ok(&format, &[2, 7, 8]));
    checked_crossval(&format, vec![2, 7, 8], true);
    // A negative count is a native structural failure. Kaitai alone would read
    // zero elements; the generated guard makes it fail too.
    assert!(!native_ok(&format, &[0xff]));
    checked_crossval(&format, vec![0xff], false);
    // The guard runs only where the array is parsed: with no record present,
    // the executor never evaluates the negative ancestor count, and neither
    // does Kaitai.
    let nested = format_of(vec![
        signed("count", 1),
        array(
            record("record", vec![integer("tag", 1), items("count")]),
            CountRule::ToEnd,
        ),
    ]);
    assert!(native_ok(&nested, &[0xff]));
    checked_crossval(&nested, vec![0xff], true);
    assert!(!native_ok(&nested, &[0xff, 1]));
    checked_crossval(&nested, vec![0xff, 1], false);
}

#[test]
fn kaitai_strict_text_decoding_is_reported_as_a_divergence() {
    let format = format_of(vec![
        Field::new(
            Kind::String {
                encoding: StringEncoding::Ascii,
            },
            Confidence::CERTAIN,
        )
        .with_name("label")
        .with_size(SizeRule::Fixed { bytes: 2 }),
    ]);
    let ksy = export(&format, ExportFormat::Kaitai).unwrap();
    assert!(
        ksy.contains("\ndoc: 'Sextant verified this layout natively with lenient text decoding")
    );
    checked_crossval(&format, b"ok".to_vec(), true);
    // The executor accepts invalid ASCII leniently; the strict Python runtime
    // does not, and the result must say why rather than claim agreement.
    assert!(native_ok(&format, &[0xff, 0xfe]));
    match cross_validate(&format, &[vec![0xff, 0xfe]]) {
        CrossValidation::Skipped { reason } => assert!(
            std::env::var_os("SEXTANT_REQUIRE_KAITAI").is_none(),
            "{reason}"
        ),
        CrossValidation::Failed { detail } => {
            assert!(detail.contains("decoding divergence"), "{detail}")
        }
        other => panic!("strict decoding must not pass silently: {other:?}"),
    }
}

#[test]
fn lua_keywords_as_names_still_produce_a_loadable_dissector() {
    // Every IR-derived Lua identifier is prefixed (proto_, v_) or quoted, so
    // Lua keywords never reach a bare identifier position.
    let mut fields = Vec::new();
    for word in ["local", "function", "nil", "and", "end", "then", "repeat"] {
        fields.push(integer(word, 1));
    }
    fields.push(
        Field::new(Kind::Bytes, Confidence::CERTAIN)
            .with_name("until")
            .with_size(SizeRule::Derived {
                length_field: FieldRef::new("local"),
            }),
    );
    let mut format = format_of(fields);
    format.name = "end".into();
    let sample = [2, 1, 1, 1, 1, 1, 1, 0xaa, 0xbb];
    assert!(native_ok(&format, &sample));
    if let Some(output) = lua(&format, &sample) {
        assert_eq!(output.trim(), "OK 0:1,1:1,2:1,3:1,4:1,5:1,6:1,7:2");
    }
}

#[test]
fn explicit_compiler_pin_never_falls_back() {
    const CHILD: &str = "SEXTANT_PIN_REGRESSION_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let result = cross_validate(&format_of(vec![integer("one", 1)]), &[vec![1]]);
        assert!(
            matches!(result, CrossValidation::Failed { .. }),
            "invalid pin fell back: {result:?}"
        );
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let result = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "explicit_compiler_pin_never_falls_back",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env(
            "SEXTANT_KAITAI_COMPILER",
            dir.path().join("missing-compiler"),
        )
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
