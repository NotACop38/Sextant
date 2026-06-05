#![no_main]
//! Fuzz target: feed arbitrary bytes to the native IR executor (FR-24, NFR-2).
//!
//! Sextant parses untrusted, potentially hostile input, so the executor must
//! never panic, hang, or allocate without bound on any input. This target picks
//! one of a battery of IRs with the first input byte and runs the rest of the
//! input through both the executor and the scorer under tight, deterministic
//! limits. libFuzzer's coverage-guided search drives the byte stream; any panic,
//! abort, or out-of-memory is a finding. The in-tree property tests in
//! `sextant-engine/tests/robustness.rs` assert the same invariants on stable.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use sextant_engine::{execute, score, Limits};
use sextant_ir::{
    ChecksumAlgorithm, ChecksumSpec, Confidence, Constraint, CountRule, CoveredRange, Endianness,
    Field, FieldRef, Format, Kind, RangeAnchor, Signedness, SizeRule, Structure,
};

fn battery() -> &'static [Format] {
    static FORMATS: OnceLock<Vec<Format>> = OnceLock::new();
    FORMATS.get_or_init(build_battery)
}

fn int(width: u8) -> Kind {
    Kind::Integer {
        width,
        signed: Signedness::Unsigned,
        endianness: None,
    }
}

fn named(name: &str, kind: Kind) -> Field {
    Field::new(kind, Confidence::CERTAIN).with_name(name)
}

fn build_battery() -> Vec<Format> {
    let mut formats = vec![
        sextant_ir::fixtures::png_ground_truth(),
        sextant_ir::fixtures::tlv_ground_truth(),
    ];

    // A length-prefixed body with a CRC-32 over it.
    formats.push(Format {
        name: "len_crc".to_owned(),
        endianness: Endianness::Big,
        root: Structure::new(vec![
            named("len", int(2)),
            named("body", Kind::Bytes).with_size(SizeRule::Derived {
                length_field: FieldRef::new("len"),
            }),
            {
                let mut crc = named("crc", int(4));
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
    });

    // A checksum stored in a bytes field wider than eight bytes, plus a
    // little-endian order: the path that used to overflow the integer decoder.
    formats.push(Format {
        name: "wide_csum".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(vec![
            named("body", Kind::Bytes).with_size(SizeRule::Fixed { bytes: 4 }),
            {
                let mut csum = named("csum", Kind::Bytes).with_size(SizeRule::Fixed { bytes: 12 });
                csum.constraints.push(Constraint::Checksum {
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
                csum
            },
        ]),
        enums: Default::default(),
        metadata: Default::default(),
    });

    // Counted then bounded arrays of small structs.
    formats.push(Format {
        name: "arrays".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(vec![
            named("n", int(1)),
            Field::new(
                Kind::Array {
                    element: Box::new(named(
                        "pair",
                        Kind::Struct {
                            structure: Structure::new(vec![named("a", int(1)), named("b", int(2))]),
                        },
                    )),
                    count: CountRule::FromField {
                        count_field: FieldRef::new("n"),
                    },
                },
                Confidence::CERTAIN,
            )
            .with_name("items"),
            named("blen", int(1)),
            Field::new(
                Kind::Array {
                    element: Box::new(named("b", int(1))),
                    count: CountRule::BoundedBy {
                        length_field: FieldRef::new("blen"),
                    },
                },
                Confidence::CERTAIN,
            )
            .with_name("tail"),
        ]),
        enums: Default::default(),
        metadata: Default::default(),
    });

    formats
}

fuzz_target!(|data: &[u8]| {
    let formats = battery();
    let limits = Limits::for_fuzzing();
    // Use the first byte to pick an IR; the rest is the sample under test.
    let (selector, sample) = data.split_first().unwrap_or((&0, &[]));
    let format = &formats[usize::from(*selector) % formats.len()];

    let execution = execute(format, sample, &limits);
    // Invariant: no leaf field ever overruns the sample.
    for &(start, end) in &execution.leaf_ranges {
        assert!(start <= end && end <= sample.len());
    }

    // Scoring must always yield a finite value in 0..=1.
    let report = score(format, std::slice::from_ref(&sample));
    assert!(report.overall.is_finite() && (0.0..=1.0).contains(&report.overall));
});
