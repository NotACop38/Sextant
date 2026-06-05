//! End-to-end inference orchestration (PRD Section 9, milestone M1).
//!
//! [`infer`] wires the statistics-only pipeline together: it takes an ingested
//! [`SampleSet`], generates candidate IRs ([`infer_candidates`]), selects the
//! best by verified score, runs the heuristic refinement loop ([`refine`]) under
//! the non-regression invariant (FR-26), and assembles the outcome into a
//! [`Report`].
//!
//! This is the `--no-llm` path in full. It depends only on `sextant-engine` and
//! `sextant-ir`, neither of which links any network, async, or HTTP crate, so a
//! run performs zero network egress (NFR-4). The language-model pass is layered
//! on in later steps and always flows through the same executor and scorer.

use sextant_ir::Format;
use sextant_llm::{LlmClient, LlmProvider};

use crate::candidate::infer_candidates;
use crate::ingest::{Sample, SampleSet};
use crate::limits::Limits;
use crate::refine::{Refinement, refine};
use crate::report::{Report, RunMetadata};
use crate::semantic::{SemanticOptions, semantic_pass};

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
pub fn infer(samples: &SampleSet, options: &InferenceOptions) -> Report {
    let slices: Vec<&[u8]> = samples.samples.iter().map(Sample::bytes).collect();
    let refinement = statistics_refinement(&slices, &options.limits);
    let metadata = run_metadata(samples, options.no_llm);
    Report::build(
        refinement.format,
        refinement.score,
        refinement.history,
        metadata,
    )
}

/// Run statistics-only inference and then the language-model semantic pass over
/// the best candidate, returning a report (milestone M2).
///
/// The semantic pass flows through the same scorer the heuristic loop uses, so a
/// model proposal is applied only when the verified fit does not regress (FR-26,
/// FR-31). The function is defensive about the central invariant: even if the
/// pass somehow returned a worse IR, or the model call fails (a tripped call cap
/// or budget, a transport error, or an unparseable response), the run degrades
/// gracefully to the verified statistics-only result and never reports a score
/// below the statistics-only baseline (PRD Section 12, NFR-9).
#[must_use]
pub fn infer_with_llm<P: LlmProvider>(
    samples: &SampleSet,
    options: &InferenceOptions,
    client: &LlmClient<P>,
    semantic: &SemanticOptions,
) -> Report {
    let slices: Vec<&[u8]> = samples.samples.iter().map(Sample::bytes).collect();
    let baseline = statistics_refinement(&slices, &options.limits);

    // The semantic pass records the model's format-family guess directly in the
    // returned format's metadata, so the outcome's format carries it already.
    let (format, score, mut semantic_history) =
        match semantic_pass(&baseline.format, &slices, client, &options.limits, semantic) {
            // The pass guarantees non-regression, but guard the invariant here
            // too: never accept a result below the statistics-only baseline.
            Ok(outcome) if outcome.score.overall + 1e-9 >= baseline.score.overall => {
                (outcome.format, outcome.score, outcome.history)
            }
            _ => (baseline.format.clone(), baseline.score.clone(), Vec::new()),
        };

    // The report's refinement history is the statistics-only steps followed by
    // the semantic pass's accepted and rejected proposals (FR-28).
    let mut history = baseline.history;
    history.append(&mut semantic_history);

    let metadata = run_metadata(samples, false);
    Report::build(format, score, history, metadata)
}

/// Run candidate generation and the heuristic refinement loop, returning the
/// best verified IR with its score and accepted-step history. This is the shared
/// statistics-only core of both [`infer`] and [`infer_with_llm`].
fn statistics_refinement(slices: &[&[u8]], limits: &Limits) -> Refinement {
    let candidates = infer_candidates(slices, limits);
    // `infer_candidates` always returns at least the opaque fallback, so `best`
    // is present; guard anyway so this never panics.
    let best = candidates
        .into_iter()
        .next()
        .map_or_else(empty_format, |candidate| candidate.format);
    refine(&best, slices, limits)
}

/// Assemble run metadata from a sample set.
fn run_metadata(samples: &SampleSet, no_llm: bool) -> RunMetadata {
    RunMetadata {
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        sample_count: samples.len(),
        total_bytes: samples.total_bytes,
        no_llm,
    }
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
