//! Tests for the hand-authored TLV ground-truth IR.
//!
//! These prove the fixture is committed, parses, validates, and round-trips, and
//! pin the structure the executor and scorer tests depend on in Step 3.

use sextant_ir::fixtures::{TLV_GROUND_TRUTH_JSON, tlv_ground_truth};
use sextant_ir::{CountRule, Endianness, Format, Kind, Role, SizeRule};

#[test]
fn fixture_parses_validates_and_round_trips() {
    let format = tlv_ground_truth();
    assert_eq!(format.name, "tlv");
    assert_eq!(format.endianness, Endianness::Little);
    format.validate().expect("TLV fixture must validate");

    let json = format.to_json().expect("serialize");
    let reparsed = Format::from_json(&json).expect("deserialize");
    assert_eq!(format, reparsed);

    let from_const = Format::from_json(TLV_GROUND_TRUTH_JSON).expect("parse embedded JSON");
    assert_eq!(format, from_const);
}

#[test]
fn header_then_a_from_field_array_of_records() {
    let format = tlv_ground_truth();
    let names: Vec<_> = format
        .root
        .fields
        .iter()
        .map(|field| field.name.as_deref().unwrap_or_default())
        .collect();
    assert_eq!(names, ["magic", "version", "record_count", "records"]);

    let magic = &format.root.fields[0];
    assert_eq!(magic.role, Some(Role::Magic));
    assert!(matches!(magic.size, Some(SizeRule::Fixed { bytes: 4 })));

    let records = &format.root.fields[3];
    let Kind::Array { element, count } = &records.kind else {
        panic!("records must be an array");
    };
    let CountRule::FromField { count_field } = count else {
        panic!("records count must come from a field");
    };
    assert_eq!(count_field.as_str(), "record_count");

    let Kind::Struct { structure } = &element.kind else {
        panic!("a record must be a struct");
    };
    let value = structure
        .fields
        .iter()
        .find(|field| field.name.as_deref() == Some("value"))
        .expect("record has a value field");
    let Some(SizeRule::Derived { length_field }) = &value.size else {
        panic!("value size must be derived from length");
    };
    assert_eq!(length_field.as_str(), "length");
}
