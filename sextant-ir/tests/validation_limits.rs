//! Resource regressions for IR validation before recursive semantic checks.

use std::collections::BTreeMap;

use sextant_ir::{
    Confidence, CountRule, Endianness, EnumDef, EnumVariant, Field, FieldOffset, FieldRef, Format,
    Kind, MAX_DIAGNOSTIC_TEXT_BYTES, MAX_NESTING_DEPTH, MAX_VALIDATION_ERRORS, Signedness,
    SizeRule, Structure, ValidationErrorKind,
};

fn format_of(fields: Vec<Field>) -> Format {
    Format {
        name: "validation_limits".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(fields),
        enums: BTreeMap::new(),
        metadata: Default::default(),
    }
}

fn integer(name: impl Into<String>) -> Field {
    Field::new(
        Kind::Integer {
            width: 1,
            signed: Signedness::Unsigned,
            endianness: None,
        },
        Confidence::CERTAIN,
    )
    .with_name(name)
}

fn bytes(name: impl Into<String>, size: SizeRule) -> Field {
    Field::new(Kind::Bytes, Confidence::CERTAIN)
        .with_name(name)
        .with_size(size)
}

/// Test setup can exceed the supported depth, so dispose of its owned tree
/// iteratively rather than exercising Rust's recursive enum destructor.
fn drop_tree(format: Format) {
    let mut pending = format.root.fields;
    while let Some(field) = pending.pop() {
        match field.kind {
            Kind::Struct { mut structure } => pending.append(&mut structure.fields),
            Kind::Array { element, .. } => pending.push(*element),
            _ => {}
        }
    }
}

#[test]
fn nested_arrays_cannot_bypass_the_depth_limit() {
    let mut field = integer("leaf");
    for _ in 0..=sextant_ir::MAX_NESTING_DEPTH {
        field = Field::new(
            Kind::Array {
                element: Box::new(field),
                count: CountRule::Fixed { count: 1 },
            },
            Confidence::CERTAIN,
        );
    }
    let report = format_of(vec![field])
        .validate()
        .expect_err("array nesting must be bounded");
    assert!(
        report
            .errors
            .iter()
            .any(|error| matches!(error.kind, ValidationErrorKind::NestingTooDeep { .. }))
    );
}

#[test]
fn shape_rejection_precedes_recursive_layout_on_a_very_deep_tree() {
    let mut field = integer("leaf");
    for _ in 0..10_000 {
        field = Field::new(
            Kind::Struct {
                structure: Structure::new(vec![field]),
            },
            Confidence::CERTAIN,
        );
    }
    let format = format_of(vec![field]);
    let report = format
        .validate()
        .expect_err("reject before fixed_len recurses");
    assert_eq!(report.errors.len(), 1);
    assert!(
        matches!(report.errors[0].kind, ValidationErrorKind::NestingTooDeep { depth } if depth == MAX_NESTING_DEPTH + 1)
    );
    assert!(report.truncated);
    drop_tree(format);
}

#[test]
fn arrays_at_the_depth_limit_remain_valid() {
    let mut field = integer("leaf");
    for _ in 0..MAX_NESTING_DEPTH {
        field = Field::new(
            Kind::Array {
                element: Box::new(field),
                count: CountRule::Fixed { count: 1 },
            },
            Confidence::CERTAIN,
        );
    }
    assert!(format_of(vec![field]).validate().is_ok());
}

#[test]
fn thousands_of_overlaps_produce_a_bounded_honest_report() {
    let format = format_of(
        (0..4096)
            .map(|index| Field {
                offset: Some(FieldOffset::Absolute { bytes: 0 }),
                ..integer(format!("f_{index}"))
            })
            .collect(),
    );
    let report = format.validate().expect_err("overlapping layout");
    assert_eq!(report.errors.len(), MAX_VALIDATION_ERRORS);
    assert!(report.truncated);
    assert!(report.errors.iter().all(|error| matches!(
        error.kind,
        ValidationErrorKind::OverlappingFields { at: 0, .. }
    )));
    assert!(report.to_string().contains("additional problems may exist"));
}

#[test]
fn independent_malformed_fields_also_respect_the_diagnostic_limit() {
    let format = format_of(
        (0..4096)
            .map(|index| bytes(format!("f_{index}"), SizeRule::Fixed { bytes: 0 }))
            .collect(),
    );
    let report = format.validate().expect_err("zero-sized bytes");
    assert_eq!(report.errors.len(), MAX_VALIDATION_ERRORS);
    assert!(report.truncated);
    assert!(
        report
            .errors
            .iter()
            .all(|error| matches!(error.kind, ValidationErrorKind::ZeroSizedField))
    );
}

#[test]
fn positioned_gaps_and_reverse_declaration_order_are_preserved() {
    let fields = (0..8192)
        .rev()
        .map(|index| Field {
            offset: Some(FieldOffset::Absolute { bytes: index * 2 }),
            ..integer(format!("f_{index}"))
        })
        .collect();
    assert!(format_of(fields).validate().is_ok());
}

#[test]
fn sweep_detects_contained_ranges_and_keeps_declaration_labels() {
    let later_in_bytes = Field {
        offset: Some(FieldOffset::Absolute { bytes: 7 }),
        ..integer("first_declared")
    };
    let covering = Field {
        offset: Some(FieldOffset::Absolute { bytes: 0 }),
        ..bytes("second_declared", SizeRule::Fixed { bytes: 10 })
    };
    let report = format_of(vec![later_in_bytes, covering])
        .validate()
        .expect_err("overlap");
    assert!(!report.truncated);
    assert!(report.errors.iter().any(|error| matches!(&error.kind,
        ValidationErrorKind::OverlappingFields { first, second, at: 7 }
        if first.contains("first_declared") && second.contains("second_declared")
    )));
}

#[test]
fn empty_structures_and_zero_count_arrays_have_no_overlap_range() {
    let covering = bytes("covering", SizeRule::Fixed { bytes: 10 });
    let empty = Field {
        offset: Some(FieldOffset::Absolute { bytes: 4 }),
        ..Field::new(
            Kind::Struct {
                structure: Structure::new(vec![]),
            },
            Confidence::CERTAIN,
        )
    };
    let zero_count = Field {
        offset: Some(FieldOffset::Absolute { bytes: 7 }),
        ..Field::new(
            Kind::Array {
                element: Box::new(integer("item")),
                count: CountRule::Fixed { count: 0 },
            },
            Confidence::CERTAIN,
        )
    };
    assert!(
        format_of(vec![covering, empty, zero_count])
            .validate()
            .is_ok()
    );
}

#[test]
fn wide_scopes_resolve_prior_and_ancestor_names() {
    let mut fields: Vec<Field> = (0..8192)
        .map(|index| integer(format!("length_{index}")))
        .collect();
    let members = (0..8192)
        .map(|index| {
            bytes(
                format!("body_{index}"),
                SizeRule::Derived {
                    length_field: FieldRef::new(format!("length_{index}")),
                },
            )
        })
        .collect();
    fields.push(Field::new(
        Kind::Struct {
            structure: Structure::new(members),
        },
        Confidence::CERTAIN,
    ));
    assert!(format_of(fields).validate().is_ok());
}

#[test]
fn a_later_local_name_does_not_hide_an_available_ancestor() {
    let body = bytes(
        "body",
        SizeRule::Derived {
            length_field: FieldRef::new("length"),
        },
    );
    let child = Field::new(
        Kind::Struct {
            structure: Structure::new(vec![body, integer("length")]),
        },
        Confidence::CERTAIN,
    );
    assert!(format_of(vec![integer("length"), child]).validate().is_ok());
}

#[test]
fn nested_array_elements_resolve_counts_and_lengths_from_outer_scopes() {
    let payload = bytes(
        "payload",
        SizeRule::Derived {
            length_field: FieldRef::new("length"),
        },
    );
    let element = Field::new(
        Kind::Array {
            element: Box::new(payload),
            count: CountRule::FromField {
                count_field: FieldRef::new("count"),
            },
        },
        Confidence::CERTAIN,
    );
    let array = Field::new(
        Kind::Array {
            element: Box::new(element),
            count: CountRule::FromField {
                count_field: FieldRef::new("count"),
            },
        },
        Confidence::CERTAIN,
    );
    assert!(
        format_of(vec![integer("length"), integer("count"), array])
            .validate()
            .is_ok()
    );
}

#[test]
fn large_enums_are_checked_without_pairwise_search() {
    let mut format = format_of(vec![integer("field")]);
    let variants: Vec<EnumVariant> = (0..16_384)
        .map(|value| EnumVariant {
            value,
            name: format!("value_{value}"),
            description: None,
        })
        .collect();
    format.enums.insert(
        "values".to_owned(),
        EnumDef {
            width: Some(8),
            variants,
        },
    );
    assert!(format.validate().is_ok());
    format
        .enums
        .get_mut("values")
        .expect("enum")
        .variants
        .push(EnumVariant {
            value: 8192,
            name: "duplicate".to_owned(),
            description: None,
        });
    let report = format.validate().expect_err("duplicate value");
    assert_eq!(report.errors.len(), 1);
    assert!(matches!(
        report.errors[0].kind,
        ValidationErrorKind::DuplicateEnumValue { value: 8192, .. }
    ));
}

#[test]
fn long_unicode_names_are_valid_but_diagnostics_are_bounded() {
    let name = "é".repeat(8192);
    assert!(format_of(vec![integer(&name)]).validate().is_ok());
    let format = format_of(vec![integer(&name), integer(&name)]);
    let report = format.validate().expect_err("duplicate name");
    assert_eq!(format.root.fields[0].name.as_deref(), Some(name.as_str()));
    assert!(
        !report.truncated,
        "only the label is shortened, not the validation"
    );
    assert!(
        report
            .errors
            .iter()
            .all(|error| error.path.len() <= MAX_DIAGNOSTIC_TEXT_BYTES)
    );
    assert!(
        matches!(&report.errors[0].kind, ValidationErrorKind::DuplicateFieldName { name }
        if name.len() <= MAX_DIAGNOSTIC_TEXT_BYTES && name.ends_with("... [truncated]"))
    );
}

#[test]
fn enum_names_cannot_expand_diagnostic_paths_without_bound() {
    let mut format = format_of(vec![]);
    format.enums.insert(
        "界".repeat(8192),
        EnumDef {
            width: Some(3),
            variants: vec![],
        },
    );
    let report = format.validate().expect_err("invalid enum width");
    assert_eq!(report.errors.len(), 1);
    assert!(report.errors[0].path.len() <= MAX_DIAGNOSTIC_TEXT_BYTES);
    assert!(report.errors[0].path.ends_with("... [truncated]"));
}
