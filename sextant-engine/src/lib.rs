//! Inference engine for Sextant.
//!
//! This crate holds sample ingestion, the native IR executor and scorer (the
//! verification substrate), the statistical inference pass, the refinement loop,
//! and the language-model semantic pass. The executor and scorer are native
//! Rust, free of any JVM, the Kaitai compiler, and network access, so they run
//! under `--no-llm` and offline (FR-21).
//!
//! # The semantic pass (Step 9)
//!
//! [`semantic_pass`] sends a candidate's field summary and a byte-capped view of
//! the samples to a model, receives a structured [`ModelProposal`] (never
//! free-form text, FR-30), and applies each proposed annotation or refinement
//! only when the scorer confirms the verified fit does not regress (FR-26,
//! FR-31). [`infer_with_llm`] layers this on top of the statistics-only pipeline
//! and guarantees the final score never drops below the statistics-only
//! baseline. The model accelerates the search; it never overrules the executor.
//!
//! # Statistical inference (Step 5)
//!
//! [`infer_candidates`] turns a sample set into one or more candidate
//! [`Format`](sextant_ir::Format) hypotheses using classical techniques:
//! byte statistics (FR-6), positional [`align`]ment (FR-7), magic, length,
//! count, offset, checksum, and sub-byte field detection (FR-8 to FR-11). Each
//! candidate is validated and scored by the executor and scorer, so the list is
//! ranked by a verified preliminary score (FR-12).
//!
//! # Ingestion (Step 4)
//!
//! [`ingest`] turns user inputs (files, directories, and glob patterns) into a
//! [`SampleSet`]: an ordered list of [`Sample`]s, each with [`Provenance`].
//! Per-sample and total byte caps bound memory and are surfaced through
//! [`Notice`]s (FR-1, FR-3, FR-4, FR-5).
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

pub mod align;
pub mod candidate;
pub mod checksum;
pub mod chunk;
pub mod detect;
pub mod executor;
pub mod ingest;
pub mod inspect;
pub mod limits;
pub mod orchestrate;
pub mod refine;
pub mod report;
pub mod scorer;
pub mod semantic;
pub mod stats;

pub use align::{Alignment, Column, Region, align};
pub use candidate::{Candidate, infer_candidates};
pub use chunk::{ChunkChecksum, ChunkChecksumStart, ChunkLayout, detect_chunks};
pub use detect::{
    Bitfield, ChecksumField, ChecksumStart, IntField, IntRelation, Magic, OffsetField,
    detect_bitfields, detect_int_fields, detect_magic, detect_offsets, detect_trailing_checksum,
};
pub use executor::{
    CheckKind, ConstraintCheck, Execution, FailureReason, FieldInstance, ParseFailure, Value,
    execute,
};
pub use ingest::{
    DEFAULT_MAX_BYTES_PER_SAMPLE, DEFAULT_MAX_TOTAL_BYTES, IngestError, IngestOptions, Notice,
    Provenance, Sample, SampleSet, ingest,
};
pub use inspect::{InspectOptions, render};
pub use limits::Limits;
pub use orchestrate::{InferenceOptions, infer, infer_with_llm};
pub use refine::{RefineOutcome, RefineStep, Refinement, refine};
pub use report::{FieldMapEntry, REPORT_SCHEMA_VERSION, Report, RunMetadata};
pub use scorer::{SampleScore, Score, ScoreWeights, score, score_with};
pub use semantic::{
    DEFAULT_MAX_PROMPT_BYTES_PER_SAMPLE, DEFAULT_MAX_SAMPLES_IN_PROMPT, FieldProposal,
    ModelProposal, SemanticOptions, SemanticOutcome, semantic_pass,
};
pub use stats::{ByteHistogram, ngram_counts, shannon_entropy, windowed_entropy};
