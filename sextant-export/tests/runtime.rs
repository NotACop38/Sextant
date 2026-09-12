//! Execute generated parsers, including malformed-input regressions.

use sextant_export::crossval::{CrossValidation, cross_validate};
use sextant_export::{ExportFormat, export};
use sextant_ir::{
    Bytes, Confidence, CountRule, Endianness, Field, FieldRef, Format, Kind, Metadata, Signedness,
    SizeRule, Structure,
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
