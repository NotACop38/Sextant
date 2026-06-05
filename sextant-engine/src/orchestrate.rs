//! End-to-end inference orchestration (PRD Section 9, milestone M1).
//!
//! [`infer`] wires the statistics-only pipeline together: it takes an ingested
//! [`SampleSet`], generates candidate IRs ([`infer_candidates`]), selects the
//! best by verified score, runs the heuristic refinement loop ([`refine`]) under
//! the non-regression invariant (FR-26), and assembles the outcome into a
//! [`DraftReport`].
//!
//! This is the `--no-llm` path in full. It depends only on `sextant-engine` and
//! `sextant-ir`, neither of which links any network, async, or HTTP crate, so a
//! run performs zero network egress (NFR-4). The language-model pass is layered
//! on in later steps and always flows through the same executor and scorer.

use sextant_ir::Format;

use crate::candidate::infer_candidates;
use crate::ingest::{Sample, SampleSet};
use crate::limits::Limits;
use crate::refine::refine;
use crate::report::{DraftReport, RunMetadata};
use crate::scorer::{ScoreWeights, score_with};

/// Options controlling an inference run.
#[derive(Debug, Clone)]
pub struct InferenceOptions {
    /// Executor and scorer resource limits (FR-24).
    pub limits: Limits,
    /// Whether to run statistics-only with the language model disabled. The
    /// model is not yet wired in, so this is effectively always true today; the
    /// flag records intent and guarantees the offline, zero-egress path (NFR-4).
    pub no_llm: bool,
}

impl Default for InferenceOptions {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            no_llm: true,
        }
    }
}

/// Run statistics-only inference over a sample set and return a draft report
/// (milestone M1). The result always contains a usable, scored field map: even
/// when no structure is recovered the pipeline returns a valid covering
/// hypothesis rather than nothing.
#[must_use]
pub fn infer(samples: &SampleSet, options: &InferenceOptions) -> DraftReport {
    let slices: Vec<&[u8]> = samples.samples.iter().map(Sample::bytes).collect();

    let candidates = infer_candidates(&slices, &options.limits);
    // `infer_candidates` always returns at least the opaque fallback, so `best`
    // is present; guard anyway so this function never panics.
    let best = candidates
        .into_iter()
        .next()
        .map_or_else(empty_format, |candidate| candidate.format);

    let refinement = refine(&best, &slices, &options.limits);
    let score = score_with(
        &refinement.format,
        &slices,
        &options.limits,
        ScoreWeights::default(),
    );

    let metadata = RunMetadata {
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        sample_count: samples.len(),
        total_bytes: samples.total_bytes,
        no_llm: options.no_llm,
    };

    DraftReport::build(refinement.format, score, refinement.history, metadata)
}

/// A trivial empty format, used only as an unreachable fallback so [`infer`]
/// never panics even if candidate generation ever returns nothing.
fn empty_format() -> Format {
    use sextant_ir::{Confidence, Field, Kind, SizeRule, Structure};
    Format {
        name: "empty".to_owned(),
        endianness: sextant_ir::Endianness::Little,
        root: Structure::new(vec![Field {
            name: Some("data".to_owned()),
            kind: Kind::Opaque,
            size: Some(SizeRule::ToEnd),
            offset: None,
            role: Some(sextant_ir::Role::Payload),
            constraints: Vec::new(),
            confidence: Confidence::clamped(0.1),
            evidence: Default::default(),
        }]),
        enums: Default::default(),
        metadata: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::{IngestOptions, ingest};
    use std::path::PathBuf;

    fn corpus_dir(format: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("engine crate has a parent")
            .join("corpus")
            .join(format)
            .join("samples")
    }

    #[test]
    fn infer_produces_a_scored_field_map_for_a_corpus_format() {
        let dir = corpus_dir("sdlp");
        let set = ingest(
            &[dir.to_string_lossy().into_owned()],
            &IngestOptions::default(),
        )
        .expect("ingest sdlp");
        let report = infer(&set, &InferenceOptions::default());
        assert!(report.score.overall >= 0.99);
        assert!(!report.field_map.is_empty());
        assert!(report.metadata.no_llm);
        assert_eq!(report.metadata.sample_count, set.len());
    }

    #[test]
    fn infer_on_an_empty_set_does_not_panic() {
        let set = SampleSet::default();
        let report = infer(&set, &InferenceOptions::default());
        // With no samples the score is zero, but a valid report is still built.
        assert_eq!(report.metadata.sample_count, 0);
        assert!(!report.field_map.is_empty());
    }
}
