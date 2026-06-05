//! Tests for the hand-authored PNG ground-truth IR.
//!
//! These pin the structure later steps depend on (Step 3 executes this IR
//! against PNG samples and expects a near-perfect score) and prove the fixture
//! is committed, parses, validates, and round-trips.

use sextant_ir::fixtures::{PNG_GROUND_TRUTH_JSON, png_ground_truth};
use sextant_ir::{
    ChecksumAlgorithm, Constraint, CountRule, Endianness, Format, Kind, RangeAnchor, Role, SizeRule,
};

/// The canonical eight-byte PNG signature.
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

#[test]
fn fixture_parses_validates_and_round_trips() {
    let format = png_ground_truth();
    assert_eq!(format.name, "png");
    assert_eq!(format.endianness, Endianness::Big);
    format.validate().expect("PNG fixture must validate");

    let json = format.to_json().expect("serialize");
    let reparsed = Format::from_json(&json).expect("deserialize");
    assert_eq!(format, reparsed);

    // The committed JSON constant parses to the same value.
    let from_const = Format::from_json(PNG_GROUND_TRUTH_JSON).expect("parse embedded JSON");
    assert_eq!(format, from_const);
}

#[test]
fn signature_field_carries_the_real_png_magic() {
    let format = png_ground_truth();
    let signature = &format.root.fields[0];
    assert_eq!(signature.name.as_deref(), Some("signature"));
    assert_eq!(signature.role, Some(Role::Magic));
    assert!(matches!(signature.kind, Kind::Bytes));
    assert!(matches!(signature.size, Some(SizeRule::Fixed { bytes: 8 })));

    let Constraint::Constant { value } = &signature.constraints[0] else {
        panic!("signature must have a constant constraint");
    };
    assert_eq!(value.as_slice(), PNG_SIGNATURE);
}

#[test]
fn chunks_are_a_to_end_array_of_length_type_data_crc() {
    let format = png_ground_truth();
    let chunks = &format.root.fields[1];
    assert_eq!(chunks.name.as_deref(), Some("chunks"));

    let Kind::Array { element, count } = &chunks.kind else {
        panic!("chunks must be an array");
    };
    assert!(matches!(count, CountRule::ToEnd));

    let Kind::Struct { structure } = &element.kind else {
        panic!("a chunk must be a struct");
    };
    let names: Vec<_> = structure
        .fields
        .iter()
        .map(|field| field.name.as_deref().unwrap_or_default())
        .collect();
    assert_eq!(names, ["length", "chunk_type", "data", "crc"]);

    // The data field's size is derived from the length field.
    let data = &structure.fields[2];
    let Some(SizeRule::Derived { length_field }) = &data.size else {
        panic!("data size must be derived from a length field");
    };
    assert_eq!(length_field.as_str(), "length");

    // The CRC covers the chunk type and data with CRC-32.
    let crc = &structure.fields[3];
    assert_eq!(crc.role, Some(Role::Checksum));
    let Constraint::Checksum { spec } = &crc.constraints[0] else {
        panic!("crc must have a checksum constraint");
    };
    assert_eq!(spec.algorithm, ChecksumAlgorithm::Crc32);
    let RangeAnchor::FieldStart { field: from } = &spec.covered.from else {
        panic!("checksum must start at a field start");
    };
    let RangeAnchor::FieldEnd { field: to } = &spec.covered.to else {
        panic!("checksum must end at a field end");
    };
    assert_eq!(from.as_str(), "chunk_type");
    assert_eq!(to.as_str(), "data");
}
