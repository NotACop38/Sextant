//! Regression coverage for unvalidated IR allocation and work amplification.

use std::time::Duration;

use sextant_engine::{FailureReason, Limits, execute};
use sextant_ir::{
    Bytes, ChecksumAlgorithm, ChecksumSpec, Confidence, Constraint, CountRule, CoveredRange,
    Endianness, EnumDef, EnumVariant, Field, FieldOffset, FieldRef, Format, Kind, RangeAnchor,
    Signedness, SizeRule, StringEncoding, Structure,
};

fn byte() -> Field {
    Field::new(
        Kind::Integer {
            width: 1,
            signed: Signedness::Unsigned,
            endianness: None,
        },
        Confidence::CERTAIN,
    )
}

fn format(fields: Vec<Field>) -> Format {
    Format {
        name: "bounded".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(fields),
        enums: Default::default(),
        metadata: Default::default(),
    }
}

fn repeated(element: Field, count: u64) -> Format {
    format(vec![Field::new(
        Kind::Array {
            element: Box::new(element),
            count: CountRule::Fixed { count },
        },
        Confidence::CERTAIN,
    )])
}

fn budget(bytes: usize) -> Limits {
    Limits {
        max_output_bytes: bytes,
        timeout: None,
        ..Limits::default()
    }
}

fn assert_output_limit(format: &Format, sample: &[u8], bytes: usize) {
    let execution = execute(format, sample, &budget(bytes));
    assert!(
        matches!(execution.failure.as_ref().map(|f| &f.reason),
        Some(FailureReason::OutputLimit { limit }) if *limit == bytes),
        "{:?}",
        execution.failure
    );
    assert!(
        execution.checks.len() <= bytes / std::mem::size_of::<sextant_engine::ConstraintCheck>()
    );
}

#[test]
fn repeated_large_names_stop_before_retaining_all_instances() {
    let format = repeated(byte().with_name("n".repeat(1024)), 32);
    let execution = execute(&format, &[0; 32], &budget(8192));
    assert!(matches!(
        execution.failure.map(|f| f.reason),
        Some(FailureReason::OutputLimit { .. })
    ));
    assert!(execution.leaf_ranges.len() < 8);
    assert!(
        execution.fields.is_empty(),
        "incomplete array is not retained"
    );
}

#[test]
fn repeated_enum_names_are_charged_before_cloning() {
    let mut format = repeated(
        Field::new(
            Kind::Enum {
                width: 1,
                endianness: None,
                enum_ref: "values".to_owned(),
            },
            Confidence::CERTAIN,
        ),
        32,
    );
    format.enums.insert(
        "values".to_owned(),
        EnumDef {
            width: Some(1),
            variants: vec![EnumVariant {
                value: 0,
                name: "v".repeat(1024),
                description: None,
            }],
        },
    );
    assert_output_limit(&format, &[0; 32], 8192);
}

#[test]
fn decoded_text_and_reference_failure_names_obey_the_budget() {
    let text = Field::new(
        Kind::String {
            encoding: StringEncoding::Utf8,
        },
        Confidence::CERTAIN,
    )
    .with_size(SizeRule::Fixed { bytes: 1024 });
    assert_output_limit(&format(vec![text]), &[0xff; 1024], 2048);
    let mut unresolved = byte();
    unresolved.offset = Some(FieldOffset::Derived {
        offset_field: FieldRef::new("r".repeat(4096)),
    });
    assert_output_limit(&format(vec![unresolved]), &[0], 2048);
}

#[test]
fn every_constraint_result_and_pending_checksum_is_budgeted() {
    let mut field = byte().with_name("b");
    field.constraints = vec![Constraint::IntRange { min: 0, max: 255 }; 100];
    assert_output_limit(&format(vec![field]), &[0], 4096);

    let checksum = Constraint::Checksum {
        spec: ChecksumSpec {
            algorithm: ChecksumAlgorithm::Crc32,
            covered: CoveredRange {
                from: RangeAnchor::FieldStart {
                    field: FieldRef::new("b"),
                },
                to: RangeAnchor::FieldEnd {
                    field: FieldRef::new("b"),
                },
            },
        },
    };
    let mut field = byte().with_name("b");
    field.constraints = vec![checksum; 100];
    assert_output_limit(&format(vec![field]), &[0], 4096);
}

#[test]
fn huge_failed_constants_have_bounded_diagnostics() {
    let mut field = byte();
    field.constraints.push(Constraint::Constant {
        value: Bytes::new(vec![1; 65536]),
    });
    let execution = execute(&format(vec![field]), &[0], &budget(4096));
    assert!(execution.succeeded(), "{:?}", execution.failure);
    assert_eq!(execution.checks.len(), 1);
    assert!(!execution.checks[0].passed);
    assert!(execution.checks[0].detail.len() < 192);
}

#[test]
fn enum_search_and_binding_comparisons_consume_work() {
    let mut enum_format = format(vec![Field::new(
        Kind::Enum {
            width: 1,
            endianness: None,
            enum_ref: "e".to_owned(),
        },
        Confidence::CERTAIN,
    )]);
    enum_format.enums.insert(
        "e".to_owned(),
        EnumDef {
            width: Some(1),
            variants: (1..1000)
                .map(|value| EnumVariant {
                    value,
                    name: "v".to_owned(),
                    description: None,
                })
                .collect(),
        },
    );
    let limits = Limits {
        max_steps: 100,
        timeout: None,
        ..Limits::default()
    };
    assert!(matches!(
        execute(&enum_format, &[0], &limits)
            .failure
            .map(|f| f.reason),
        Some(FailureReason::StepLimit { .. })
    ));

    let name = "x".repeat(1024);
    let mut target = byte();
    target.offset = Some(FieldOffset::Derived {
        offset_field: FieldRef::new(name.clone()),
    });
    let fields = vec![byte().with_name(name), target];
    assert!(matches!(
        execute(&format(fields), &[0], &limits)
            .failure
            .map(|f| f.reason),
        Some(FailureReason::StepLimit { .. })
    ));
}

#[test]
fn delimiter_comparison_work_includes_terminator_length() {
    let field = Field::new(Kind::Bytes, Confidence::CERTAIN).with_size(SizeRule::Delimited {
        terminator: Bytes::new(vec![0; 128]),
        include_terminator: false,
    });
    let limits = Limits {
        max_steps: 100,
        timeout: None,
        ..Limits::default()
    };
    assert!(matches!(
        execute(&format(vec![field]), &[0; 256], &limits)
            .failure
            .map(|f| f.reason),
        Some(FailureReason::StepLimit { .. })
    ));
}

#[test]
fn zero_timeout_stops_tiny_and_empty_parses_and_huge_timeout_does_not_panic() {
    for fields in [vec![], vec![byte()]] {
        let format = format(fields);
        let execution = execute(
            &format,
            &[0],
            &Limits::default().with_timeout(Duration::ZERO),
        );
        assert!(matches!(
            execution.failure.map(|f| f.reason),
            Some(FailureReason::Timeout)
        ));
        assert!(execution.fields.is_empty());
        let execution = execute(
            &format,
            &[0],
            &Limits::default().with_timeout(Duration::MAX),
        );
        assert!(execution.succeeded());
    }
}
