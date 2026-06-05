//! Inference engine for Sextant.
//!
//! This crate holds the native IR executor and scorer (the verification
//! substrate), and will grow to include sample ingestion, the statistical
//! inference pass, and the refinement loop in later checklist steps. The
//! executor and scorer are native Rust, free of any JVM, the Kaitai compiler,
//! and network access, so they run under `--no-llm` and offline (FR-21).
//!
//! # The verification substrate (Step 3)
//!
//! [`execute`] runs a [`Format`](sextant_ir::Format) against one sample and
//! returns an [`Execution`]: a tree of [`FieldInstance`]s with concrete byte
//! ranges and decoded values, the constraint checks performed, and either a
//! clean end or a localized [`ParseFailure`]. [`score`] runs the IR against a
//! whole sample set and returns a [`Score`] in the range 0 to 1 with a
//! structured breakdown over coverage, consistency, and generality (PRD
//! Section 11).
//!
//! Both are bounded by [`Limits`] (FR-24) and never panic on any input:
//!
//! ```
//! use sextant_engine::{execute, score, Limits};
//!
//! let format = sextant_ir::fixtures::png_ground_truth();
//! // An empty sample simply fails to parse; it never panics.
//! let execution = execute(&format, &[], &Limits::default());
//! assert!(!execution.succeeded());
//!
//! let samples: &[&[u8]] = &[&[]];
//! let report = score(&format, samples);
//! assert!(report.overall <= 1.0);
//! ```

pub mod checksum;
pub mod executor;
pub mod limits;
pub mod scorer;

pub use executor::{
    CheckKind, ConstraintCheck, Execution, FailureReason, FieldInstance, ParseFailure, Value,
    execute,
};
pub use limits::Limits;
pub use scorer::{SampleScore, Score, ScoreWeights, score, score_with};
