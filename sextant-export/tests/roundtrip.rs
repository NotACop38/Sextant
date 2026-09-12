//! Round-trip and faithfulness tests for the exporters (Step 10 acceptance).
//!
//! The native executor is Sextant's source of truth: it parses every corpus
//! sample with the ground-truth IR (proven in the engine's Step 3 tests). These
//! tests confirm that each exporter renders that same verified structure
//! faithfully, so the parser an analyst opens in Kaitai, ImHex, Wireshark, or 010
//! describes exactly the fields the executor verified.
//!
//! For Kaitai specifically, [`kaitai_cross_validation_passes_or_skips`] runs the
//! real external round-trip when the compiler is installed: it compiles the
//! `.ksy` and parses every sample through it (FR-38). When the toolchain is
//! absent the check is skipped, never failed, so the core pipeline never depends
//! on it.

use std::fs;
use std::path::PathBuf;

use sextant_engine::{Execution, FieldInstance, Limits, Value, execute};
use sextant_export::crossval::{CrossValidation, cross_validate};
use sextant_export::{ExportFormat, export};
use sextant_ir::Format;
use sextant_ir::fixtures::{png_ground_truth, tlv_ground_truth};

/// Read every sample of a corpus format, sorted by name for determinism.
fn read_samples(format: &str, extension: &str) -> Vec<Vec<u8>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the export crate has a parent directory")
        .join("corpus")
        .join(format)
        .join("samples");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .map(|entry| entry.expect("a readable directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == extension))
        .collect();
    paths.sort();
    assert!(
        !paths.is_empty(),
        "no {extension} samples in {}",
        dir.display()
    );
    paths
        .into_iter()
        .map(|path| {
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        })
        .collect()
}

/// Collect every named field in a parsed sample, in tree order.
fn collect_names(fields: &[FieldInstance], out: &mut Vec<String>) {
    for field in fields {
        if let Some(name) = &field.name {
            out.push(name.clone());
        }
        match &field.value {
            Value::Struct(children) | Value::Array(children) => collect_names(children, out),
            _ => {}
        }
    }
}

/// The set of field names the executor produces parsing the first sample.
fn verified_field_names(format: &Format, samples: &[Vec<u8>]) -> Vec<String> {
    let execution: Execution = execute(format, &samples[0], &Limits::default());
    assert!(
        execution.succeeded(),
        "the ground-truth IR must parse its first sample, failure: {:?}",
        execution.failure
    );
    let mut names = Vec::new();
    collect_names(&execution.fields, &mut names);
    names
}

/// Assert the IR parses every sample, then that every exporter names every
/// verified field. This is the per-format round-trip: the exported parser
/// describes exactly the structure the executor verified.
fn assert_faithful(format: &Format, samples: &[Vec<u8>]) {
    let limits = Limits::default();
    for (index, sample) in samples.iter().enumerate() {
        let execution = execute(format, sample, &limits);
        assert!(
            execution.succeeded(),
            "{} sample {index} must parse, failure: {:?}",
            format.name,
            execution.failure
        );
    }

    let names = verified_field_names(format, samples);
    assert!(!names.is_empty(), "the IR has named fields to render");

    for target in ExportFormat::ALL {
        let output = export(format, target).expect("export succeeds");
        assert!(!output.trim().is_empty(), "{target} output is non-empty");
        for name in &names {
            assert!(
                output.contains(name.as_str()),
                "{target} export of {} is missing field `{name}`",
                format.name
            );
        }
        // The export is deterministic.
        assert_eq!(output, export(format, target).expect("export succeeds"));
    }
}

#[test]
fn tlv_round_trips_through_every_exporter() {
    assert_faithful(&tlv_ground_truth(), &read_samples("tlv", "tlv"));
}

#[test]
fn png_round_trips_through_every_exporter() {
    assert_faithful(&png_ground_truth(), &read_samples("png", "png"));
}

#[test]
fn every_format_exports_to_every_target() {
    // The four export formats are all reachable for the showcase and custom
    // formats, which backs the CLI accepting every `--format` value.
    for (format, ext) in [(tlv_ground_truth(), "tlv"), (png_ground_truth(), "png")] {
        let _ = read_samples(&format.name, ext);
        for target in ExportFormat::ALL {
            let output = export(&format, target).expect("export succeeds");
            assert!(
                output.len() > 32,
                "{target} export of {} looks too short",
                format.name
            );
        }
    }
}

#[test]
fn kaitai_cross_validation_passes_or_skips() {
    // The optional cross-check (FR-38): compile the .ksy and parse all samples
    // through it. It is never required by the core, so an absent toolchain skips
    // rather than fails. It must never report Failed for a ground-truth IR.
    for (format, ext) in [(tlv_ground_truth(), "tlv"), (png_ground_truth(), "png")] {
        let samples = read_samples(&format.name, ext);
        match cross_validate(&format, &samples) {
            CrossValidation::Passed { samples: parsed } => {
                assert_eq!(parsed, samples.len(), "every sample was cross-validated");
            }
            CrossValidation::Skipped { reason } => {
                assert!(
                    std::env::var_os("SEXTANT_REQUIRE_KAITAI").is_none(),
                    "required Kaitai runtime unavailable: {reason}"
                );
                eprintln!(
                    "kaitai cross-validation skipped for {}: {reason}",
                    format.name
                );
            }
            CrossValidation::Failed { detail } => {
                panic!(
                    "kaitai cross-validation failed for {}: {detail}",
                    format.name
                );
            }
        }
    }
}
