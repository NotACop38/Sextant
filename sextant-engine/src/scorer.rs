//! The native fit scorer (FR-22, FR-23, PRD Section 11).
//!
//! [`score`] executes a [`Format`] against every sample and combines three
//! dimensions into a single fit value in the range 0 to 1, with a structured
//! breakdown the report and the refinement loop can act on:
//!
//! - **Coverage**: the fraction of each sample's bytes that fields explain, with
//!   no overruns and no double-counted overlaps. Unexplained gaps and trailing
//!   bytes lower it.
//! - **Consistency**: of the constraints an IR claims for a sample (constants,
//!   integer ranges, and checksums), how many hold. A sample the IR cannot parse
//!   has verified nothing, so its consistency is zero.
//! - **Generality**: the fraction of samples that parse to a clean end. An IR
//!   that fits some samples but fails others is the overfitting case the PRD
//!   penalizes.
//!
//! Coverage and consistency are aggregated across samples with a penalized mean
//! (half the mean plus half the worst sample) so that an IR which fits one
//! sample but fails another cannot hide behind the average. This realizes the
//! "penalize overfitting" requirement directly in the aggregate.

use sextant_ir::Format;

use crate::executor::{Execution, ParseFailure, execute};
use crate::limits::Limits;

/// The relative weight of each dimension in the overall fit score.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoreWeights {
    /// Weight of the coverage dimension.
    pub coverage: f64,
    /// Weight of the consistency dimension.
    pub consistency: f64,
    /// Weight of the generality dimension.
    pub generality: f64,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            coverage: 0.45,
            consistency: 0.35,
            generality: 0.20,
        }
    }
}

impl ScoreWeights {
    fn total(&self) -> f64 {
        self.coverage + self.consistency + self.generality
    }
}

/// The fit of an IR over a sample set: an overall score in 0 to 1 plus the
/// per-dimension and per-sample breakdown (FR-23).
#[derive(Debug, Clone, PartialEq)]
pub struct Score {
    /// The overall weighted fit, in the range 0 to 1.
    pub overall: f64,
    /// The aggregated coverage dimension, in 0 to 1.
    pub coverage: f64,
    /// The aggregated consistency dimension, in 0 to 1.
    pub consistency: f64,
    /// The generality dimension, in 0 to 1.
    pub generality: f64,
    /// The weights used to combine the dimensions.
    pub weights: ScoreWeights,
    /// The per-sample breakdown, in sample order.
    pub samples: Vec<SampleScore>,
}

/// The fit of an IR against one sample.
#[derive(Debug, Clone, PartialEq)]
pub struct SampleScore {
    /// The sample's index in the set.
    pub index: usize,
    /// The sample's length in bytes.
    pub sample_len: usize,
    /// How many distinct bytes fields explained.
    pub explained_bytes: usize,
    /// How many bytes were explained more than once (overlap penalty).
    pub overlap_bytes: usize,
    /// How many bytes inside the parsed region went unexplained (gaps).
    pub gap_bytes: usize,
    /// How many trailing bytes after the parse went unexplained.
    pub trailing_bytes: usize,
    /// The sample's coverage sub-score, in 0 to 1.
    pub coverage: f64,
    /// The sample's consistency sub-score, in 0 to 1.
    pub consistency: f64,
    /// Whether the parse reached a clean end.
    pub parsed: bool,
    /// How many constraint checks the parse performed on this sample.
    pub constraints_total: usize,
    /// How many of those checks passed.
    pub constraints_passed: usize,
    /// The localized failure, when the parse did not reach a clean end.
    pub failure: Option<ParseFailure>,
}

/// Score `format` against `samples` with the default weights and limits.
#[must_use]
pub fn score<S: AsRef<[u8]>>(format: &Format, samples: &[S]) -> Score {
    score_with(format, samples, &Limits::default(), ScoreWeights::default())
}

/// Score `format` against `samples` with explicit limits and weights.
#[must_use]
pub fn score_with<S: AsRef<[u8]>>(
    format: &Format,
    samples: &[S],
    limits: &Limits,
    weights: ScoreWeights,
) -> Score {
    let mut sample_scores = Vec::with_capacity(samples.len());
    for (index, sample) in samples.iter().enumerate() {
        let execution = execute(format, sample.as_ref(), limits);
        sample_scores.push(score_sample(index, &execution));
    }

    if sample_scores.is_empty() {
        return Score {
            overall: 0.0,
            coverage: 0.0,
            consistency: 0.0,
            generality: 0.0,
            weights,
            samples: sample_scores,
        };
    }

    let coverage = penalized_mean(sample_scores.iter().map(|sample| sample.coverage));
    let consistency = penalized_mean(sample_scores.iter().map(|sample| sample.consistency));
    let generality = mean(
        sample_scores
            .iter()
            .map(|sample| if sample.parsed { 1.0 } else { 0.0 }),
    );

    let weight_total = weights.total();
    let overall = if weight_total > 0.0 {
        (weights.coverage * coverage
            + weights.consistency * consistency
            + weights.generality * generality)
            / weight_total
    } else {
        0.0
    };

    Score {
        overall: clamp01(overall),
        coverage: clamp01(coverage),
        consistency: clamp01(consistency),
        generality: clamp01(generality),
        weights,
        samples: sample_scores,
    }
}

/// Build the per-sample score from one execution.
fn score_sample(index: usize, execution: &Execution) -> SampleScore {
    let sample_len = execution.sample_len;
    let (explained, overlap, gap) = coverage_stats(&execution.leaf_ranges, sample_len);
    let trailing = sample_len.saturating_sub(execution.consumed);

    let coverage = if sample_len == 0 {
        if execution.succeeded() { 1.0 } else { 0.0 }
    } else {
        clamp01((explained as f64 - overlap as f64) / sample_len as f64)
    };

    let constraints_total = execution.checks.len();
    let constraints_passed = execution.constraints_passed();
    let parsed = execution.succeeded();
    let consistency = if !parsed {
        // An IR that cannot parse a sample has verified none of that sample's
        // relationships, so its consistency for that sample is zero.
        0.0
    } else if constraints_total == 0 {
        1.0
    } else {
        constraints_passed as f64 / constraints_total as f64
    };

    SampleScore {
        index,
        sample_len,
        explained_bytes: explained,
        overlap_bytes: overlap,
        gap_bytes: gap,
        trailing_bytes: trailing,
        coverage,
        consistency,
        parsed,
        constraints_total,
        constraints_passed,
        failure: execution.failure.clone(),
    }
}

/// Compute explained, overlapped, and gap byte counts from the leaf ranges,
/// clipped to the sample length.
fn coverage_stats(ranges: &[(usize, usize)], sample_len: usize) -> (usize, usize, usize) {
    if sample_len == 0 {
        return (0, 0, 0);
    }
    let mut covered = vec![false; sample_len];
    let mut total_leaf = 0usize;
    let mut max_end = 0usize;
    for &(start, end) in ranges {
        let start = start.min(sample_len);
        let end = end.min(sample_len);
        if start >= end {
            continue;
        }
        total_leaf += end - start;
        max_end = max_end.max(end);
        covered[start..end].fill(true);
    }
    let explained = covered.iter().filter(|&&bit| bit).count();
    let overlap = total_leaf - explained;
    // Gaps are unexplained bytes that fall before the furthest explained byte.
    let gap = covered[..max_end].iter().filter(|&&bit| !bit).count();
    (explained, overlap, gap)
}

/// The arithmetic mean of an iterator of values, or 0 for an empty iterator.
fn mean<I: Iterator<Item = f64>>(values: I) -> f64 {
    let mut sum = 0.0;
    let mut count = 0usize;
    for value in values {
        sum += value;
        count += 1;
    }
    if count == 0 { 0.0 } else { sum / count as f64 }
}

/// Half the mean plus half the minimum. The minimum term drags the aggregate
/// down when any single sample scores poorly, which is how the scorer penalizes
/// an IR that fits some samples but not others (PRD Section 11).
fn penalized_mean<I: Iterator<Item = f64>>(values: I) -> f64 {
    let mut sum = 0.0;
    let mut count = 0usize;
    let mut min = f64::INFINITY;
    for value in values {
        sum += value;
        count += 1;
        if value < min {
            min = value;
        }
    }
    if count == 0 {
        return 0.0;
    }
    let mean = sum / count as f64;
    0.5 * mean + 0.5 * min
}

fn clamp01(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_stats_counts_overlap_and_gaps() {
        // [0,4) and [2,6) overlap on [2,4): explained 6, overlap 2, no gaps.
        let (explained, overlap, gap) = coverage_stats(&[(0, 4), (2, 6)], 8);
        assert_eq!(explained, 6);
        assert_eq!(overlap, 2);
        assert_eq!(gap, 0);

        // [0,2) and [4,6): a two-byte gap at [2,4) inside the parsed region.
        let (explained, overlap, gap) = coverage_stats(&[(0, 2), (4, 6)], 8);
        assert_eq!(explained, 4);
        assert_eq!(overlap, 0);
        assert_eq!(gap, 2);
    }

    #[test]
    fn penalized_mean_punishes_the_worst_sample() {
        // A uniform set keeps its value; a split set is dragged toward the min.
        assert!((penalized_mean([1.0, 1.0].into_iter()) - 1.0).abs() < 1e-9);
        assert!((penalized_mean([1.0, 0.0].into_iter()) - 0.25).abs() < 1e-9);
    }

    #[test]
    fn empty_sample_set_scores_zero() {
        let format = sextant_ir::fixtures::png_ground_truth();
        let empty: &[&[u8]] = &[];
        let score = score(&format, empty);
        assert_eq!(score.overall, 0.0);
    }
}
