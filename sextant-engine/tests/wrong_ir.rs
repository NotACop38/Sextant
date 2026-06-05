//! Step 3 acceptance: a deliberately wrong IR scores low, and the breakdown
//! points at the dimension that failed.

use std::fs;
use std::path::PathBuf;

use sextant_engine::{CheckKind, Limits, execute, score};
use sextant_ir::{Constraint, Endianness, Kind};

fn read_samples(format: &str, extension: &str) -> Vec<Vec<u8>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the engine crate has a parent directory")
        .join("corpus")
        .join(format)
        .join("samples");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("read corpus dir")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == extension))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| fs::read(path).expect("read sample"))
        .collect()
}

#[test]
fn wrong_endianness_craters_coverage_and_generality() {
    // PNG is big-endian. Reading it little-endian misreads every chunk length,
    // so the first chunk's data overruns the buffer and the parse fails.
    let mut format = sextant_ir::fixtures::png_ground_truth();
    format.endianness = Endianness::Little;
    let samples = read_samples("png", "png");

    // Every sample fails to parse at a localized offset.
    for sample in &samples {
        let execution = execute(&format, sample, &Limits::default());
        assert!(
            !execution.succeeded(),
            "the broken IR must fail to parse a PNG"
        );
        assert!(execution.failure.is_some());
    }

    let report = score(&format, &samples);
    assert!(
        report.overall < 0.4,
        "overall should be low, got {report:#?}"
    );
    assert!(report.generality < 0.01, "generality should be ~0");
    assert!(report.coverage < 0.5, "coverage should be low");
    // The correct IR, by contrast, scores near 1.0 on the same samples.
    let correct = score(&sextant_ir::fixtures::png_ground_truth(), &samples);
    assert!(correct.overall >= 0.99);
    assert!(report.overall < correct.overall);
}

#[test]
fn wrong_checksum_algorithm_isolates_the_consistency_dimension() {
    // Keep the PNG structure correct but claim the CRC field is an additive
    // checksum. The bytes still parse perfectly (coverage and generality stay
    // high), but every checksum check fails, so consistency drops.
    let mut format = sextant_ir::fixtures::png_ground_truth();
    set_crc_algorithm(&mut format, sextant_ir::ChecksumAlgorithm::Additive);
    let samples = read_samples("png", "png");

    for sample in &samples {
        let execution = execute(&format, sample, &Limits::default());
        assert!(execution.succeeded(), "structure still parses");
        let failing: Vec<_> = execution
            .checks
            .iter()
            .filter(|check| !check.passed)
            .collect();
        assert!(!failing.is_empty(), "the bad checksum must fail");
        assert!(
            failing
                .iter()
                .all(|check| matches!(check.kind, CheckKind::Checksum(_))),
            "only the checksum checks should fail"
        );
    }

    let report = score(&format, &samples);
    // The breakdown points squarely at consistency: coverage and generality are
    // intact, consistency is not.
    assert!(
        report.coverage >= 0.99,
        "coverage intact: {}",
        report.coverage
    );
    assert!((report.generality - 1.0).abs() < 1e-9);
    assert!(
        report.consistency < 0.5,
        "consistency should drop, got {}",
        report.consistency
    );
    assert!(report.consistency < report.coverage);
}

#[test]
fn wrong_magic_constant_lowers_consistency_only() {
    // A single wrong byte in the magic constant: the field still consumes its
    // bytes (coverage intact) but the constant check fails (consistency dips).
    let mut format = sextant_ir::fixtures::tlv_ground_truth();
    if let Some(Constraint::Constant { value }) = format.root.fields[0].constraints.first_mut() {
        value.0[0] ^= 0xFF;
    } else {
        panic!("expected a constant constraint on the magic field");
    }
    let samples = read_samples("tlv", "tlv");

    let report = score(&format, &samples);
    assert!(report.coverage >= 0.99, "coverage stays high");
    assert!(
        (report.generality - 1.0).abs() < 1e-9,
        "generality stays 1.0"
    );
    assert!(
        report.consistency < 1.0,
        "the failing magic must lower consistency"
    );
}

/// Set the algorithm of the PNG chunk CRC checksum constraint.
fn set_crc_algorithm(format: &mut sextant_ir::Format, algorithm: sextant_ir::ChecksumAlgorithm) {
    let chunks = &mut format.root.fields[1];
    let Kind::Array { element, .. } = &mut chunks.kind else {
        panic!("chunks must be an array");
    };
    let Kind::Struct { structure } = &mut element.kind else {
        panic!("a chunk must be a struct");
    };
    let crc = structure
        .fields
        .iter_mut()
        .find(|field| field.name.as_deref() == Some("crc"))
        .expect("crc field");
    for constraint in &mut crc.constraints {
        if let Constraint::Checksum { spec } = constraint {
            spec.algorithm = algorithm;
        }
    }
}
