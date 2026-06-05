//! Step 3 acceptance: the hand-authored IRs parse their corpus samples and
//! score at or near 1.0, and checksum verification passes on PNG CRC-32.

use std::fs;
use std::path::PathBuf;

use sextant_engine::{CheckKind, Limits, Value, execute, score};
use sextant_ir::fixtures::{png_ground_truth, tlv_ground_truth};

/// Read every sample of a corpus format, sorted by file name for determinism.
fn read_samples(format: &str, extension: &str) -> Vec<Vec<u8>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the engine crate has a parent directory")
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

#[test]
fn png_ir_parses_its_corpus_and_scores_near_one() {
    let format = png_ground_truth();
    format.validate().expect("PNG fixture validates");
    let samples = read_samples("png", "png");
    let limits = Limits::default();

    for (index, sample) in samples.iter().enumerate() {
        let execution = execute(&format, sample, &limits);
        assert!(
            execution.succeeded(),
            "PNG sample {index} should parse cleanly, failure: {:?}",
            execution.failure
        );
        assert_eq!(
            execution.consumed,
            sample.len(),
            "PNG sample {index} should be fully consumed"
        );
        // Every constraint check (the signature and each chunk CRC) must hold.
        assert!(
            execution.checks.iter().all(|check| check.passed),
            "PNG sample {index} has a failing constraint: {:?}",
            execution.checks.iter().find(|check| !check.passed)
        );
        // At least one CRC-32 checksum was verified.
        assert!(
            execution.checks.iter().any(|check| matches!(
                check.kind,
                CheckKind::Checksum(sextant_ir::ChecksumAlgorithm::Crc32)
            ) && check.passed),
            "PNG sample {index} should verify a CRC-32"
        );
    }

    let report = score(&format, &samples);
    assert!(
        report.overall >= 0.99,
        "PNG overall score should be near 1.0, got {report:#?}"
    );
    assert!(report.coverage >= 0.99, "coverage {}", report.coverage);
    assert!(
        report.consistency >= 0.99,
        "consistency {}",
        report.consistency
    );
    assert!(
        (report.generality - 1.0).abs() < 1e-9,
        "generality {}",
        report.generality
    );
}

#[test]
fn png_first_chunk_is_a_correctly_decoded_ihdr() {
    let format = png_ground_truth();
    let samples = read_samples("png", "png");
    let execution = execute(&format, &samples[0], &Limits::default());

    // root.fields = [signature, chunks]; chunks is an array of chunk structs.
    let chunks = &execution.fields[1];
    let Value::Array(elements) = &chunks.value else {
        panic!("chunks must decode to an array");
    };
    let first = &elements[0];
    let Value::Struct(chunk_fields) = &first.value else {
        panic!("a chunk must decode to a struct");
    };
    // length = 13 (IHDR data length), chunk_type = "IHDR".
    let Value::Integer(length) = chunk_fields[0].value else {
        panic!("length must be an integer");
    };
    assert_eq!(length, 13);
    let Value::Text(chunk_type) = &chunk_fields[1].value else {
        panic!("chunk_type must be text");
    };
    assert_eq!(chunk_type, "IHDR");
    // The final chunk is IEND.
    let Value::Struct(last_fields) = &elements[elements.len() - 1].value else {
        panic!("last chunk must be a struct");
    };
    let Value::Text(last_type) = &last_fields[1].value else {
        panic!("chunk_type must be text");
    };
    assert_eq!(last_type, "IEND");
}

#[test]
fn tlv_ir_parses_its_corpus_and_scores_near_one() {
    let format = tlv_ground_truth();
    format.validate().expect("TLV fixture validates");
    let samples = read_samples("tlv", "tlv");
    let limits = Limits::default();

    for (index, sample) in samples.iter().enumerate() {
        let execution = execute(&format, sample, &limits);
        assert!(
            execution.succeeded(),
            "TLV sample {index} should parse cleanly, failure: {:?}",
            execution.failure
        );
        assert_eq!(execution.consumed, sample.len());
        assert!(execution.checks.iter().all(|check| check.passed));

        // record_count (byte 5) governs the number of records actually parsed.
        let expected_records = u64::from(sample[5]);
        let records = &execution.fields[3];
        let Value::Array(elements) = &records.value else {
            panic!("records must decode to an array");
        };
        assert_eq!(elements.len() as u64, expected_records);
    }

    let report = score(&format, &samples);
    assert!(
        report.overall >= 0.99,
        "TLV overall score should be near 1.0, got {report:#?}"
    );
}

#[test]
fn tlv_value_length_always_matches_its_length_field() {
    // The verification invariant for a length relationship: in a valid parse,
    // each value field is exactly as long as its preceding length field says.
    let format = tlv_ground_truth();
    let samples = read_samples("tlv", "tlv");
    for sample in &samples {
        let execution = execute(&format, sample, &Limits::default());
        let Value::Array(records) = &execution.fields[3].value else {
            panic!("records array");
        };
        for record in records {
            let Value::Struct(fields) = &record.value else {
                panic!("record struct");
            };
            let Value::Integer(length) = fields[1].value else {
                panic!("length integer");
            };
            let value = &fields[2];
            assert_eq!(
                (value.end - value.start) as i128,
                length,
                "value byte length must equal the length field"
            );
        }
    }
}
