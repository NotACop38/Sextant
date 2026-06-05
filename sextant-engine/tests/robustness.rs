//! Step 3 acceptance and FR-24/NFR-2: the executor never panics, hangs, or
//! allocates without bound on any input, and it honors its resource limits.
//!
//! These are property-style tests: they feed many randomized byte buffers
//! through a battery of IRs and assert structural invariants and resource bounds
//! hold every time. A tiny deterministic PRNG keeps them dependency-free and
//! reproducible. The `cargo-fuzz` target in `fuzz/` covers the same executor
//! with libFuzzer's coverage-guided search.

use sextant_engine::{Execution, FailureReason, Limits, execute, score};
use sextant_ir::{
    Bytes, ChecksumAlgorithm, ChecksumSpec, Confidence, Constraint, CountRule, CoveredRange,
    Endianness, Field, FieldRef, Format, Kind, RangeAnchor, Signedness, SizeRule, Structure,
};

/// A minimal xorshift64* pseudo-random generator: deterministic, fast, and with
/// no external dependency.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next_u64() & 0xFF) as u8).collect()
    }
}

fn int(width: u8, signed: Signedness) -> Kind {
    Kind::Integer {
        width,
        signed,
        endianness: None,
    }
}

fn field(name: &str, kind: Kind) -> Field {
    Field::new(kind, Confidence::CERTAIN).with_name(name)
}

/// A battery of IRs that exercise every executor code path: integers, derived
/// sizes, delimiters, to-end, fixed and from-field and bounded arrays, nested
/// structs, absolute offsets, opaque blobs, enums, and checksums.
fn ir_battery() -> Vec<Format> {
    let mut formats = Vec::new();
    formats.push(sextant_ir::fixtures::png_ground_truth());
    formats.push(sextant_ir::fixtures::tlv_ground_truth());

    // A length-prefixed blob followed by a CRC-32 over the blob.
    formats.push(Format {
        name: "len_crc".to_owned(),
        endianness: Endianness::Big,
        root: Structure::new(vec![
            field("len", int(2, Signedness::Unsigned)).with_role(sextant_ir::Role::Length),
            field("body", Kind::Bytes).with_size(SizeRule::Derived {
                length_field: FieldRef::new("len"),
            }),
            {
                let mut crc = field("crc", int(4, Signedness::Unsigned));
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

    // A NUL-delimited string then an opaque tail.
    formats.push(Format {
        name: "delimited".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(vec![
            field(
                "name",
                Kind::String {
                    encoding: sextant_ir::StringEncoding::Ascii,
                },
            )
            .with_size(SizeRule::Delimited {
                terminator: Bytes::new(vec![0x00]),
                include_terminator: true,
            }),
            field("rest", Kind::Opaque).with_size(SizeRule::ToEnd),
        ]),
        enums: Default::default(),
        metadata: Default::default(),
    });

    // A counted array of fixed structs, then a bounded array.
    formats.push(Format {
        name: "arrays".to_owned(),
        endianness: Endianness::Big,
        root: Structure::new(vec![
            field("n", int(1, Signedness::Unsigned)).with_role(sextant_ir::Role::Count),
            Field::new(
                Kind::Array {
                    element: Box::new(field("pair", {
                        Kind::Struct {
                            structure: Structure::new(vec![
                                field("a", int(1, Signedness::Unsigned)),
                                field("b", int(1, Signedness::Unsigned)),
                            ]),
                        }
                    })),
                    count: CountRule::FromField {
                        count_field: FieldRef::new("n"),
                    },
                },
                Confidence::CERTAIN,
            )
            .with_name("items"),
            field("blen", int(1, Signedness::Unsigned)).with_role(sextant_ir::Role::Length),
            Field::new(
                Kind::Array {
                    element: Box::new(field("byte", int(1, Signedness::Unsigned))),
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

    // Absolute and derived offsets.
    formats.push(Format {
        name: "offsets".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(vec![
            field("ptr", int(2, Signedness::Unsigned)).with_role(sextant_ir::Role::Offset),
            {
                let mut at = field("at_ptr", int(1, Signedness::Unsigned));
                at.offset = Some(sextant_ir::FieldOffset::Derived {
                    offset_field: FieldRef::new("ptr"),
                });
                at
            },
            {
                let mut abs = field("at_abs", int(1, Signedness::Unsigned));
                abs.offset = Some(sextant_ir::FieldOffset::Absolute { bytes: 1 });
                abs
            },
        ]),
        enums: Default::default(),
        metadata: Default::default(),
    });

    formats
}

/// Assert the executor's hard invariants for a single result on a sample.
fn assert_invariants(execution: &Execution, sample_len: usize, limits: &Limits) {
    assert_eq!(execution.sample_len, sample_len);
    // The parse never reads beyond the sample (no overruns).
    for &(start, end) in &execution.leaf_ranges {
        assert!(start <= end, "a leaf range runs backward");
        assert!(
            end <= sample_len,
            "a leaf range overran the sample: {end} > {sample_len}"
        );
    }
    assert!(
        execution.consumed <= sample_len,
        "consumed beyond the sample"
    );
    // Memory is bounded: the field count never exceeds the configured cap.
    assert!(count_instances(execution) <= limits.max_total_fields);
}

fn count_instances(execution: &Execution) -> usize {
    fn walk(value: &sextant_engine::Value) -> usize {
        use sextant_engine::Value;
        match value {
            Value::Struct(fields) | Value::Array(fields) => {
                1 + fields.iter().map(|f| walk(&f.value)).sum::<usize>()
            }
            _ => 1,
        }
    }
    execution.fields.iter().map(|f| walk(&f.value)).sum()
}

#[test]
fn random_bytes_never_panic_and_respect_invariants() {
    let formats = ir_battery();
    let limits = Limits::for_fuzzing();
    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_F00D);

    for _ in 0..20_000 {
        let len = rng.below(512);
        let sample = rng.bytes(len);
        let format = &formats[rng.below(formats.len())];
        let execution = execute(format, &sample, &limits);
        assert_invariants(&execution, sample.len(), &limits);
        // Scoring a random sample always yields a finite value in 0..=1.
        let report = score(format, std::slice::from_ref(&sample));
        assert!(report.overall.is_finite() && (0.0..=1.0).contains(&report.overall));
    }
}

#[test]
fn truncations_of_real_samples_never_panic() {
    // Truncating valid samples at every length is a classic source of parser
    // crashes. Every prefix must parse or fail cleanly.
    let formats = ir_battery();
    let limits = Limits::default();
    let png = sextant_ir::fixtures::png_ground_truth();
    let tlv = sextant_ir::fixtures::tlv_ground_truth();
    let png_bytes = include_bytes!("../../corpus/png/samples/sample_03.png");
    let tlv_bytes = include_bytes!("../../corpus/tlv/samples/sample_02.tlv");

    for prefix in 0..=png_bytes.len() {
        let execution = execute(&png, &png_bytes[..prefix], &limits);
        assert_invariants(&execution, prefix, &limits);
    }
    for prefix in 0..=tlv_bytes.len() {
        let execution = execute(&tlv, &tlv_bytes[..prefix], &limits);
        assert_invariants(&execution, prefix, &limits);
    }
    // And the whole battery against a few odd buffers.
    for format in &formats {
        for sample in [vec![], vec![0u8], vec![0xFFu8; 3], vec![0u8; 64]] {
            let execution = execute(format, &sample, &limits);
            assert_invariants(&execution, sample.len(), &limits);
        }
    }
}

#[test]
fn the_length_invariant_holds_on_every_valid_parse() {
    // For randomly generated valid len/body/crc buffers, the body is always
    // exactly as long as the length field says, and the CRC verifies.
    let format = &ir_battery()[2]; // the len_crc format
    let mut rng = Rng::new(12345);
    for _ in 0..2000 {
        let body_len = rng.below(200);
        let body = rng.bytes(body_len);
        let crc = sextant_engine::checksum::crc32(&body);
        let mut sample = Vec::new();
        sample.extend_from_slice(&(body_len as u16).to_be_bytes());
        sample.extend_from_slice(&body);
        sample.extend_from_slice(&crc.to_be_bytes());

        let execution = execute(format, &sample, &Limits::default());
        assert!(execution.succeeded(), "a well-formed buffer must parse");
        assert!(
            execution.checks.iter().all(|check| check.passed),
            "the CRC must verify"
        );
        // The body field length equals the length field value.
        let body_field = &execution.fields[1];
        assert_eq!(body_field.end - body_field.start, body_len);
    }
}

#[test]
fn deep_nesting_hits_the_depth_limit_without_overflowing_the_stack() {
    // Build a structure nested far deeper than the depth limit allows.
    let mut inner = Structure::new(vec![field("leaf", int(1, Signedness::Unsigned))]);
    for _ in 0..200 {
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
    let limits = Limits::default().with_max_depth(16);
    let execution = execute(&format, &[0u8; 8], &limits);
    assert!(matches!(
        execution.failure.as_ref().map(|f| &f.reason),
        Some(FailureReason::DepthLimit { .. })
    ));
}

#[test]
fn a_zero_width_repeat_stops_instead_of_looping_forever() {
    // A to-end array whose element consumes no bytes must stop, not spin.
    let format = Format {
        name: "zero_width".to_owned(),
        endianness: Endianness::Big,
        root: Structure::new(vec![
            Field::new(
                Kind::Array {
                    element: Box::new(Field::new(
                        Kind::Struct {
                            structure: Structure::new(vec![]),
                        },
                        Confidence::CERTAIN,
                    )),
                    count: CountRule::ToEnd,
                },
                Confidence::CERTAIN,
            )
            .with_name("loop"),
        ]),
        enums: Default::default(),
        metadata: Default::default(),
    };
    let execution = execute(&format, &[0u8; 32], &Limits::default());
    assert!(matches!(
        execution.failure.as_ref().map(|f| &f.reason),
        Some(FailureReason::ZeroWidthRepeat)
    ));
}

#[test]
fn a_huge_fixed_array_is_bounded_by_the_buffer_not_the_count() {
    // A fixed array claiming four billion one-byte elements over a tiny buffer
    // must fail on the missing bytes quickly, never trying to allocate them.
    let format = Format {
        name: "huge".to_owned(),
        endianness: Endianness::Big,
        root: Structure::new(vec![
            Field::new(
                Kind::Array {
                    element: Box::new(field("b", int(1, Signedness::Unsigned))),
                    count: CountRule::Fixed {
                        count: 4_000_000_000,
                    },
                },
                Confidence::CERTAIN,
            )
            .with_name("items"),
        ]),
        enums: Default::default(),
        metadata: Default::default(),
    };
    let execution = execute(&format, &[0u8; 16], &Limits::default());
    assert!(matches!(
        execution.failure.as_ref().map(|f| &f.reason),
        Some(FailureReason::UnexpectedEndOfInput { .. })
    ));
    // It explained at most the bytes that were actually present.
    assert!(execution.leaf_ranges.len() <= 16);
}
