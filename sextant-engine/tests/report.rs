//! Step 7 acceptance tests: the report JSON validates against the committed
//! schema (FR-34), and the report and the `inspect` rendering are pinned by
//! snapshot tests (FR-35).
//!
//! The schema is validated by a small, self-contained checker (below) rather
//! than a third-party crate, so the test stays offline and adds no dependencies.
//! It supports exactly the JSON Schema keywords the committed schema uses, and
//! the negative cases prove it actually enforces them rather than passing
//! everything.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use sextant_engine::{
    InferenceOptions, IngestOptions, InspectOptions, Report, RunMetadata, infer, ingest, render,
    score,
};

/// The workspace root, resolved from the engine crate's manifest directory.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the engine crate has a parent directory")
        .to_path_buf()
}

/// Read the committed report JSON Schema.
fn report_schema() -> Value {
    let path = workspace_root().join("schemas").join("report.schema.json");
    let text = fs::read_to_string(&path).expect("read the committed report schema");
    serde_json::from_str(&text).expect("the committed report schema is valid JSON")
}

/// Read the three TLV corpus samples in sorted order.
fn tlv_samples() -> Vec<Vec<u8>> {
    let dir = workspace_root().join("corpus").join("tlv").join("samples");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("read the tlv samples directory")
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "tlv"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| fs::read(&path).expect("read a sample"))
        .collect()
}

/// Build a deterministic report from the hand-authored TLV ground-truth IR
/// scored against the TLV corpus. Using the fixture (rather than the inference
/// heuristics) keeps the snapshots stable as the inference pipeline evolves.
fn fixture_report() -> Report {
    let format = sextant_ir::fixtures::tlv_ground_truth();
    let samples = tlv_samples();
    let slices: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
    let score = score(&format, &slices);
    let metadata = RunMetadata {
        tool_version: "0.0.0".to_owned(),
        sample_count: slices.len(),
        total_bytes: slices.iter().map(|sample| sample.len()).sum(),
        no_llm: true,
    };
    Report::build(format, score, Vec::new(), metadata)
}

/// Compare `actual` against the committed snapshot named `name`. Set
/// `UPDATE_SNAPSHOTS=1` in the environment to (re)write the snapshot file.
fn assert_snapshot(name: &str, actual: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("snapshots")
        .join(name);
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        fs::create_dir_all(path.parent().expect("snapshot has a parent"))
            .expect("create the snapshots directory");
        fs::write(&path, actual).expect("write the snapshot");
        return;
    }
    let expected = fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("missing snapshot {name}; rerun with UPDATE_SNAPSHOTS=1 to create it")
    });
    assert_eq!(
        actual, expected,
        "snapshot {name} does not match; rerun with UPDATE_SNAPSHOTS=1 to update it"
    );
}

#[test]
fn inferred_report_validates_against_the_schema() {
    let dir = workspace_root().join("corpus").join("tlv").join("samples");
    let set = ingest(
        &[dir.to_string_lossy().into_owned()],
        &IngestOptions::default(),
    )
    .expect("ingest the tlv corpus");
    let report = infer(&set, &InferenceOptions::default());
    let value: Value = serde_json::to_value(&report).expect("serialize the report to a value");
    let errors = validate_against_schema(&value);
    assert!(
        errors.is_empty(),
        "the inferred report did not validate against the schema: {errors:#?}"
    );
}

#[test]
fn fixture_report_validates_against_the_schema() {
    let report = fixture_report();
    let value: Value = serde_json::to_value(&report).expect("serialize the report to a value");
    let errors = validate_against_schema(&value);
    assert!(
        errors.is_empty(),
        "the fixture report did not validate against the schema: {errors:#?}"
    );
}

#[test]
fn schema_rejects_malformed_reports() {
    // A bad schema_version (const violation).
    let mut value = serde_json::to_value(fixture_report()).expect("serialize");
    value["schema_version"] = Value::String("9.9".to_owned());
    assert!(
        !validate_against_schema(&value).is_empty(),
        "a wrong schema_version must be rejected"
    );

    // A missing required top-level member.
    let mut value = serde_json::to_value(fixture_report()).expect("serialize");
    value.as_object_mut().expect("object").remove("score");
    assert!(
        !validate_against_schema(&value).is_empty(),
        "a missing score must be rejected"
    );

    // An out-of-range confidence in the field map.
    let mut value = serde_json::to_value(fixture_report()).expect("serialize");
    value["field_map"][0]["confidence"] = serde_json::json!(2.0);
    assert!(
        !validate_against_schema(&value).is_empty(),
        "a confidence above one must be rejected"
    );

    // An unexpected extra property.
    let mut value = serde_json::to_value(fixture_report()).expect("serialize");
    value["surprise"] = Value::Bool(true);
    assert!(
        !validate_against_schema(&value).is_empty(),
        "an unexpected property must be rejected"
    );
}

#[test]
fn report_round_trips_through_json() {
    let report = fixture_report();
    let json = report.to_json().expect("serialize the report");
    let parsed = Report::from_json(&json).expect("parse the report back");
    let reparsed = parsed.to_json().expect("reserialize the report");
    assert_eq!(json, reparsed, "the report JSON did not round-trip");
}

#[test]
fn report_json_matches_snapshot() {
    let report = fixture_report();
    let json = report.to_json().expect("serialize the report");
    assert_snapshot("tlv_report.json", &json);
}

#[test]
fn inspect_rendering_matches_snapshot() {
    let report = fixture_report();
    let samples = tlv_samples();
    let view = render(&report, &samples[0], &InspectOptions::default());
    assert_snapshot("tlv_inspect.txt", &view);
}

// ---------------------------------------------------------------------------
// A minimal JSON Schema validator, supporting only the keywords the committed
// report schema uses: type, properties, required, additionalProperties (false),
// items, enum, const, minimum, maximum, oneOf, and $ref into #/$defs.
// ---------------------------------------------------------------------------

/// Validate a report value against the committed schema, returning every error.
fn validate_against_schema(instance: &Value) -> Vec<String> {
    let schema = report_schema();
    let mut errors = Vec::new();
    validate(&schema, &schema, instance, "$", &mut errors);
    errors
}

fn validate(root: &Value, schema: &Value, instance: &Value, path: &str, errors: &mut Vec<String>) {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        match resolve_ref(root, reference) {
            Some(resolved) => validate(root, resolved, instance, path, errors),
            None => errors.push(format!("{path}: unresolved $ref {reference}")),
        }
        return;
    }

    if let Some(expected) = schema.get("type") {
        if !type_matches(expected, instance) {
            errors.push(format!(
                "{path}: expected type {expected}, got {}",
                type_name(instance)
            ));
            return;
        }
    }

    if let Some(constant) = schema.get("const") {
        if instance != constant {
            errors.push(format!("{path}: expected const {constant}, got {instance}"));
        }
    }

    if let Some(Value::Array(allowed)) = schema.get("enum") {
        if !allowed.iter().any(|value| value == instance) {
            errors.push(format!(
                "{path}: {instance} is not one of the allowed values"
            ));
        }
    }

    if let (Some(minimum), Some(number)) = (
        schema.get("minimum").and_then(Value::as_f64),
        instance.as_f64(),
    ) {
        if number < minimum {
            errors.push(format!("{path}: {number} is below the minimum {minimum}"));
        }
    }
    if let (Some(maximum), Some(number)) = (
        schema.get("maximum").and_then(Value::as_f64),
        instance.as_f64(),
    ) {
        if number > maximum {
            errors.push(format!("{path}: {number} is above the maximum {maximum}"));
        }
    }

    if let Some(Value::Array(branches)) = schema.get("oneOf") {
        let matched = branches
            .iter()
            .filter(|branch| {
                let mut branch_errors = Vec::new();
                validate(root, branch, instance, path, &mut branch_errors);
                branch_errors.is_empty()
            })
            .count();
        if matched != 1 {
            errors.push(format!(
                "{path}: matched {matched} of the oneOf branches, expected exactly one"
            ));
        }
    }

    if let Value::Object(object) = instance {
        if let Some(Value::Array(required)) = schema.get("required") {
            for entry in required {
                if let Some(name) = entry.as_str() {
                    if !object.contains_key(name) {
                        errors.push(format!("{path}: missing required property {name}"));
                    }
                }
            }
        }
        let properties = schema.get("properties").and_then(Value::as_object);
        if let Some(properties) = properties {
            for (key, child) in object {
                if let Some(child_schema) = properties.get(key) {
                    validate(root, child_schema, child, &format!("{path}/{key}"), errors);
                }
            }
        }
        if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
            for key in object.keys() {
                let known = properties.is_some_and(|props| props.contains_key(key));
                if !known {
                    errors.push(format!("{path}: unexpected property {key}"));
                }
            }
        }
    }

    if let Value::Array(items) = instance {
        if let Some(item_schema) = schema.get("items") {
            for (index, item) in items.iter().enumerate() {
                validate(root, item_schema, item, &format!("{path}/{index}"), errors);
            }
        }
    }
}

/// Resolve a `#/...` JSON pointer reference against the root schema.
fn resolve_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let rest = reference.strip_prefix("#/")?;
    let mut current = root;
    for part in rest.split('/') {
        current = current.get(part)?;
    }
    Some(current)
}

/// Whether `instance` matches a schema `type` value (a string or array of them).
fn type_matches(expected: &Value, instance: &Value) -> bool {
    match expected {
        Value::String(name) => single_type_matches(name, instance),
        Value::Array(names) => names
            .iter()
            .filter_map(Value::as_str)
            .any(|name| single_type_matches(name, instance)),
        _ => true,
    }
}

fn single_type_matches(name: &str, instance: &Value) -> bool {
    match name {
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "boolean" => instance.is_boolean(),
        "null" => instance.is_null(),
        "number" => instance.is_number(),
        "integer" => instance.is_i64() || instance.is_u64(),
        _ => false,
    }
}

fn type_name(instance: &Value) -> &'static str {
    match instance {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
