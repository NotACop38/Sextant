//! Resource-limit enforcement tests (FR-24, NFR-2, Step 13).
//!
//! Every dimension of [`Limits`] must stop a runaway parse with a localized
//! failure rather than a panic, hang, or unbounded allocation. The depth,
//! array-element, and work (step) caps are exercised in `robustness.rs`,
//! `property.rs`, and `review_fixes.rs`; this file fills the remaining gaps,
//! asserting the total-field cap and the wall-clock timeout each bite, and that
//! the default and fuzzing limits bound every dimension.

use std::time::Duration;

use sextant_engine::{FailureReason, Limits, execute};
use sextant_ir::{
    Confidence, CountRule, Endianness, Field, FieldRef, Format, Kind, Role, Signedness, Structure,
};

fn u(width: u8) -> Kind {
    Kind::Integer {
        width,
        signed: Signedness::Unsigned,
        endianness: None,
    }
}

fn named(name: &str, kind: Kind) -> Field {
    Field::new(kind, Confidence::CERTAIN).with_name(name)
}

/// A count-prefixed array of one-byte elements, the simplest way to make the
/// executor produce an arbitrary number of field instances.
fn counted_bytes() -> Format {
    Format {
        name: "counted".to_owned(),
        endianness: Endianness::Big,
        root: Structure::new(vec![
            named("n", u(2)).with_role(Role::Count),
            Field::new(
                Kind::Array {
                    element: Box::new(named("b", u(1))),
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

#[test]
fn the_total_field_cap_stops_a_wide_array() {
    // A count of 5000 one-byte elements with the bytes present would produce
    // thousands of instances; a tight total-field cap must stop it first so
    // memory stays bounded (FR-24).
    let format = counted_bytes();
    let count: u16 = 5000;
    let mut sample = count.to_be_bytes().to_vec();
    sample.extend(std::iter::repeat_n(0u8, count as usize));

    let limits = Limits {
        max_total_fields: 100,
        timeout: None,
        ..Limits::default()
    };
    let execution = execute(&format, &sample, &limits);
    assert!(
        matches!(
            execution.failure.as_ref().map(|failure| &failure.reason),
            Some(FailureReason::FieldLimit { limit }) if *limit == 100
        ),
        "expected a field-limit failure, got {:?}",
        execution.failure
    );
    // The cap bounds the instances actually retained.
    assert!(execution.leaf_ranges.len() <= 100);
}

#[test]
fn the_wall_clock_timeout_stops_a_long_parse() {
    // With a zero-length deadline, any parse that does enough work to reach the
    // clock-check interval must stop with a timeout rather than running on
    // (FR-24). A to-end array over a large buffer accumulates the needed work.
    let format = Format {
        name: "to_end".to_owned(),
        endianness: Endianness::Big,
        root: Structure::new(vec![
            Field::new(
                Kind::Array {
                    element: Box::new(named("b", u(1))),
                    count: CountRule::ToEnd,
                },
                Confidence::CERTAIN,
            )
            .with_name("items"),
        ]),
        enums: Default::default(),
        metadata: Default::default(),
    };
    let sample = vec![0u8; 100_000];
    let limits = Limits {
        timeout: Some(Duration::ZERO),
        ..Limits::default()
    };
    let execution = execute(&format, &sample, &limits);
    assert!(
        matches!(
            execution.failure.as_ref().map(|failure| &failure.reason),
            Some(FailureReason::Timeout)
        ),
        "expected a timeout failure, got {:?}",
        execution.failure
    );
}

#[test]
fn the_default_and_fuzzing_limits_bound_every_dimension() {
    // A regression guard: no dimension may be left unbounded. Each cap must be a
    // positive, finite value, and the fuzzing profile must drop the wall clock
    // so runs stay deterministic while still bounding work.
    for limits in [Limits::default(), Limits::for_fuzzing()] {
        assert!(limits.max_depth > 0);
        assert!(limits.max_array_elements > 0);
        assert!(limits.max_total_fields > 0);
        assert!(limits.max_steps > 0);
    }
    assert!(Limits::default().timeout.is_some());
    assert!(
        Limits::for_fuzzing().timeout.is_none(),
        "fuzzing must rely on the work cap, not the clock, to stay deterministic"
    );
    // The fuzzing caps are no looser than the defaults on every bounded
    // dimension, so a fuzz iteration can never do more work than a normal run.
    let (def, fuzz) = (Limits::default(), Limits::for_fuzzing());
    assert!(fuzz.max_depth <= def.max_depth);
    assert!(fuzz.max_array_elements <= def.max_array_elements);
    assert!(fuzz.max_total_fields <= def.max_total_fields);
    assert!(fuzz.max_steps <= def.max_steps);
}

#[test]
fn with_timeout_sets_a_deadline_without_clearing_by_accident() {
    // Omitting an optional CLI timeout must leave the default five-second cap.
    // The builder takes a Duration (not Option) so `timeout.map(...)` cannot
    // silently clear it when the flag is absent.
    let defaults = Limits::default();
    assert_eq!(defaults.timeout, Some(Duration::from_secs(5)));
    let raised = defaults.clone().with_timeout(Duration::from_secs(30));
    assert_eq!(raised.timeout, Some(Duration::from_secs(30)));
    let cleared = Limits::default().clear_timeout();
    assert!(cleared.timeout.is_none());
}
