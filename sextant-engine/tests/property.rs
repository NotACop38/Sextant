//! Property-based tests for the parse invariants and resource limits (FR-24,
//! NFR-2, Step 13).
//!
//! These tests use `proptest` to assert the executor's hard invariants over a
//! large, shrinking space of inputs, complementing the coverage-guided
//! `cargo-fuzz` targets in `fuzz/` and the deterministic property tests in
//! `robustness.rs`. They focus on the two invariants Step 13 calls out by name:
//!
//! 1. a parse never overruns the sample, and
//! 2. a length field always matches what it governs in a valid parse,
//!
//! plus the resource bounds that make the executor safe on hostile input:
//! recursion depth, array length, total field count, and total work all stop a
//! runaway parse with a localized failure rather than a crash, hang, or
//! unbounded allocation.

use proptest::prelude::*;
use sextant_engine::{Execution, FailureReason, Limits, Value, execute, score};
use sextant_ir::{
    ChecksumAlgorithm, ChecksumSpec, Confidence, Constraint, CountRule, CoveredRange, Endianness,
    Field, FieldRef, Format, Kind, RangeAnchor, Role, Signedness, SizeRule, Structure,
};

fn int(width: u8) -> Kind {
    Kind::Integer {
        width,
        signed: Signedness::Unsigned,
        endianness: None,
    }
}

fn field(name: &str, kind: Kind) -> Field {
    Field::new(kind, Confidence::CERTAIN).with_name(name)
}

/// The length-prefixed body with a trailing CRC-32 used by the length and CRC
/// invariant tests.
fn len_crc_format() -> Format {
    Format {
        name: "len_crc".to_owned(),
        endianness: Endianness::Big,
        root: Structure::new(vec![
            field("len", int(2)).with_role(Role::Length),
            field("body", Kind::Bytes).with_size(SizeRule::Derived {
                length_field: FieldRef::new("len"),
            }),
            {
                let mut crc = field("crc", int(4)).with_role(Role::Checksum);
                crc.constraints.push(Constraint::Checksum {
                    spec: ChecksumSpec {
                        algorithm: ChecksumAlgorithm::Crc32,
                        covered: CoveredRange {
                            from: RangeAnchor::FieldStart {
                                field: FieldRef::new("body"),
                            },
                            to: RangeAnchor::FieldEnd {
                                field: FieldRef::new("body"),
                            },
                        },
                    },
                });
                crc
            },
        ]),
        enums: Default::default(),
        metadata: Default::default(),
    }
}

/// A counted array of one-byte elements, used to test the count invariant.
fn counted_array_format() -> Format {
    Format {
        name: "counted".to_owned(),
        endianness: Endianness::Big,
        root: Structure::new(vec![
            field("n", int(1)).with_role(Role::Count),
            Field::new(
                Kind::Array {
                    element: Box::new(field("b", int(1))),
                    count: CountRule::FromField {
                        count_field: FieldRef::new("n"),
                    },
                },
                Confidence::CERTAIN,
            )
            .with_name("items"),
        ]),
        enums: Default::default(),
        metadata: Default::default(),
    }
}

/// The battery of IRs the overrun property runs every random sample through.
fn battery() -> Vec<Format> {
    vec![
        sextant_ir::fixtures::png_ground_truth(),
        sextant_ir::fixtures::tlv_ground_truth(),
        len_crc_format(),
        counted_array_format(),
    ]
}

/// Count every field instance, including the ones nested in structs and arrays.
fn count_instances(execution: &Execution) -> usize {
    fn walk(value: &Value) -> usize {
        match value {
            Value::Struct(fields) | Value::Array(fields) => {
                1 + fields.iter().map(|f| walk(&f.value)).sum::<usize>()
            }
            _ => 1,
        }
    }
    execution.fields.iter().map(|f| walk(&f.value)).sum()
}

/// Assert the executor's hard invariants for one result.
fn assert_invariants(
    execution: &Execution,
    sample_len: usize,
    limits: &Limits,
) -> Result<(), TestCaseError> {
    prop_assert_eq!(execution.sample_len, sample_len);
    for &(start, end) in &execution.leaf_ranges {
        prop_assert!(start <= end, "a leaf range runs backward");
        prop_assert!(end <= sample_len, "a leaf range overran the sample");
    }
    prop_assert!(
        execution.consumed <= sample_len,
        "consumed beyond the sample"
    );
    prop_assert!(
        count_instances(execution) <= limits.max_total_fields,
        "field count exceeded the memory bound"
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Invariant 1: a parse never overruns the sample, whatever the bytes or the
    /// IR, and the score is always a finite value in 0 to 1.
    #[test]
    fn a_parse_never_overruns(sample in proptest::collection::vec(any::<u8>(), 0..512), pick in 0usize..4) {
        let formats = battery();
        let limits = Limits::for_fuzzing();
        let format = &formats[pick % formats.len()];
        let execution = execute(format, &sample, &limits);
        assert_invariants(&execution, sample.len(), &limits)?;

        let report = score(format, std::slice::from_ref(&sample.as_slice()));
        prop_assert!(report.overall.is_finite());
        prop_assert!((0.0..=1.0).contains(&report.overall));
    }

    /// Invariant 2: in a valid parse, a length field always matches what it
    /// governs. For any body, the well-formed len/body/crc buffer parses, the
    /// body field is exactly as long as the length field says, and the CRC
    /// verifies.
    #[test]
    fn a_length_always_matches_what_it_governs(body in proptest::collection::vec(any::<u8>(), 0..400)) {
        let format = len_crc_format();
        let crc = sextant_engine::checksum::crc32(&body);
        let mut sample = Vec::new();
        sample.extend_from_slice(&(body.len() as u16).to_be_bytes());
        sample.extend_from_slice(&body);
        sample.extend_from_slice(&crc.to_be_bytes());

        let execution = execute(&format, &sample, &Limits::default());
        prop_assert!(execution.succeeded(), "a well-formed buffer must parse");
        prop_assert!(
            execution.checks.iter().all(|check| check.passed),
            "every constraint, including the CRC, must verify"
        );
        // The length field governs the body: the body's byte span equals the
        // declared length.
        let len_field = &execution.fields[0];
        let body_field = &execution.fields[1];
        prop_assert_eq!(body_field.end - body_field.start, body.len());
        if let Value::Integer(declared) = len_field.value {
            prop_assert_eq!(declared, body.len() as i128);
        } else {
            prop_assert!(false, "the length field did not decode as an integer");
        }
    }

    /// In a valid parse, a count field always matches the number of array
    /// elements it governs.
    #[test]
    fn a_count_always_matches_its_array(elements in proptest::collection::vec(any::<u8>(), 0..200)) {
        let format = counted_array_format();
        let mut sample = vec![elements.len() as u8];
        sample.extend_from_slice(&elements);

        let execution = execute(&format, &sample, &Limits::default());
        prop_assert!(execution.succeeded(), "a well-formed buffer must parse");
        let items = &execution.fields[1];
        if let Value::Array(parsed) = &items.value {
            prop_assert_eq!(parsed.len(), elements.len());
        } else {
            prop_assert!(false, "the array field did not decode as an array");
        }
    }

    /// Resource limit: a fixed array claiming an enormous element count over a
    /// small buffer is bounded by the buffer, never by the count. It fails
    /// cleanly and never explains more bytes than the buffer holds, so it cannot
    /// allocate without bound.
    #[test]
    fn a_huge_fixed_array_is_bounded_by_the_buffer(count in 1_000_000u64..u64::MAX, len in 0usize..64) {
        let format = Format {
            name: "huge".to_owned(),
            endianness: Endianness::Big,
            root: Structure::new(vec![
                Field::new(
                    Kind::Array {
                        element: Box::new(field("b", int(1))),
                        count: CountRule::Fixed { count },
                    },
                    Confidence::CERTAIN,
                )
                .with_name("items"),
            ]),
            enums: Default::default(),
            metadata: Default::default(),
        };
        let sample = vec![0u8; len];
        let execution = execute(&format, &sample, &Limits::default());
        // It stopped when the buffer ran out, not after allocating billions.
        prop_assert!(!execution.succeeded());
        prop_assert!(execution.leaf_ranges.len() <= len);
    }

    /// Resource limit: a structure nested deeper than the configured depth limit
    /// always stops with a depth failure and never overflows the stack.
    #[test]
    fn deep_nesting_always_hits_the_depth_limit(extra in 0usize..256, max_depth in 1usize..32) {
        let mut inner = Structure::new(vec![field("leaf", int(1))]);
        for _ in 0..(max_depth + extra + 1) {
            inner = Structure::new(vec![
                Field::new(Kind::Struct { structure: inner }, Confidence::CERTAIN).with_name("nest"),
            ]);
        }
        let format = Format {
            name: "deep".to_owned(),
            endianness: Endianness::Big,
            root: inner,
            enums: Default::default(),
            metadata: Default::default(),
        };
        let limits = Limits::default().with_max_depth(max_depth);
        let execution = execute(&format, &[0u8; 64], &limits);
        let hit_depth_limit = matches!(
            execution.failure.as_ref().map(|f| &f.reason),
            Some(FailureReason::DepthLimit { .. })
        );
        prop_assert!(hit_depth_limit, "expected a depth-limit failure");
    }

    /// Resource limit: the per-array element cap stops a to-end array of
    /// one-byte elements over a large buffer before it produces more than the
    /// cap, bounding both time and memory.
    #[test]
    fn the_array_cap_bounds_a_to_end_array(cap in 1usize..256) {
        let format = Format {
            name: "to_end".to_owned(),
            endianness: Endianness::Big,
            root: Structure::new(vec![
                Field::new(
                    Kind::Array {
                        element: Box::new(field("b", int(1))),
                        count: CountRule::ToEnd,
                    },
                    Confidence::CERTAIN,
                )
                .with_name("items"),
            ]),
            enums: Default::default(),
            metadata: Default::default(),
        };
        // A buffer larger than the cap forces the limit to bite.
        let sample = vec![0u8; cap + 64];
        let limits = Limits {
            max_array_elements: cap,
            ..Limits::default()
        };
        let execution = execute(&format, &sample, &limits);
        let hit_array_limit = matches!(
            execution.failure.as_ref().map(|f| &f.reason),
            Some(FailureReason::ArrayLimit { limit }) if *limit == cap
        );
        prop_assert!(hit_array_limit, "expected an array-limit failure");
    }
}
