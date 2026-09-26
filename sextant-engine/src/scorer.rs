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
//!
//! # Fit versus structure
//!
//! Fit answers "does this hypothesis parse every sample without contradiction?"
//! A single opaque field that runs to the end of each sample fits perfectly, so
//! fit alone cannot tell a hypothesis that recovered a format from one that
//! recovered nothing. [`Score::structure`] answers the second question with a
//! two-part description-length estimate: how many bits the hypothesis still
//! needs to reproduce the samples, relative to storing them raw.
//!
//! - Bytes pinned by a passing constant, and checksums that verify, cost
//!   nothing per sample; the model pays once for the constant bytes.
//! - A typed integer costs the base-two logarithm of the range of values it
//!   takes across every sample, plus a small parameter cost for that range.
//! - Printable ASCII text costs `log2(95)` bits per character.
//! - Raw bytes, opaque payloads, failed constants, and bytes no field explains
//!   cost eight bits each.
//! - Every field definition the parse visits costs a fixed model charge, so
//!   splitting bytes into many fields cannot buy credit.
//!
//! The structure measure is `1 - described_bits / raw_bits`, clamped to 0 to 1.
//! It is zero for an opaque hypothesis and grows as constants, checksums, and
//! typed fields explain more of the samples. Payload bytes are unpredictable by
//! nature, so a payload-heavy format has a low ceiling. It is comparable between
//! hypotheses over the same samples, which is how candidate ranking and
//! refinement use it, but it is not a probability and not a semantic judgment.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sextant_ir::{Constraint, Field, Format, Kind};

use crate::executor::{CheckKind, Execution, FieldInstance, ParseFailure, Value, execute};
use crate::limits::Limits;

/// The relative weight of each dimension in the overall fit score.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Score {
    /// The overall weighted fit, in the range 0 to 1.
    pub overall: f64,
    /// The aggregated coverage dimension, in 0 to 1.
    pub coverage: f64,
    /// The aggregated consistency dimension, in 0 to 1.
    pub consistency: f64,
    /// The generality dimension, in 0 to 1.
    pub generality: f64,
    /// How much of the sample content the hypothesis explains, in 0 to 1: one
    /// minus the ratio of described bits to raw bits (see the module
    /// documentation). Zero for an opaque hypothesis. It is reported beside the
    /// fit dimensions and is not part of [`Score::overall`].
    #[serde(default)]
    pub structure: f64,
    /// The weights used to combine the dimensions.
    pub weights: ScoreWeights,
    /// The per-sample breakdown, in sample order.
    pub samples: Vec<SampleScore>,
}

impl Score {
    /// The checksum checks that passed, summed over every sample.
    #[must_use]
    pub fn checksums_passed(&self) -> usize {
        self.samples
            .iter()
            .map(|sample| sample.checksums_passed)
            .sum()
    }

    /// Whether every supplied sample was fully covered without a parse failure,
    /// gap, overlap, or failed constraint. This checks sample fit, not whether
    /// inferred field boundaries or semantic labels are correct on unseen data.
    #[must_use]
    pub fn fully_verified(&self) -> bool {
        !self.samples.is_empty() && self.samples.iter().all(SampleScore::fully_verified)
    }

    /// The common refinement gate: retain the full sample set, never lower the
    /// aggregate fit, and never sacrifice a previously successful sample to
    /// improve the average. Full verification already established for a sample
    /// must also survive the proposal (FR-26, FR-31).
    #[must_use]
    pub fn preserves_verified_fit(&self, baseline: &Self) -> bool {
        self.overall.is_finite()
            && baseline.overall.is_finite()
            && self.overall >= baseline.overall
            && self.samples.len() == baseline.samples.len()
            && self
                .samples
                .iter()
                .zip(&baseline.samples)
                .all(|(after, before)| {
                    after.index == before.index
                        && after.sample_len == before.sample_len
                        && (!before.parsed || after.parsed)
                        && (!before.fully_verified() || after.fully_verified())
                })
    }
}

/// The fit of an IR against one sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// How many checksum checks passed: the strongest structural evidence a
    /// parse can produce, since a checksum verifies by chance only rarely.
    #[serde(default)]
    pub checksums_passed: usize,
    /// The localized failure, when the parse did not reach a clean end.
    pub failure: Option<ParseFailure>,
}

impl SampleScore {
    /// Whether this sample was completely consumed and every declared
    /// constraint passed. Opaque bytes can satisfy this without revealing any
    /// structure, so this is not a semantic confidence measure.
    #[must_use]
    pub fn fully_verified(&self) -> bool {
        self.parsed
            && self.failure.is_none()
            && self.explained_bytes == self.sample_len
            && self.overlap_bytes == 0
            && self.gap_bytes == 0
            && self.trailing_bytes == 0
            && self.constraints_passed == self.constraints_total
    }
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
    let mut tally = StructureTally::default();
    for (index, sample) in samples.iter().enumerate() {
        let bytes = sample.as_ref();
        let execution = execute(format, bytes, limits);
        let sample_score = score_sample(index, &execution);
        tally.add_sample(
            &format.root.fields,
            &execution,
            bytes,
            sample_score.explained_bytes,
        );
        sample_scores.push(sample_score);
    }

    if sample_scores.is_empty() {
        return Score {
            overall: 0.0,
            coverage: 0.0,
            consistency: 0.0,
            generality: 0.0,
            structure: 0.0,
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
        structure: tally.finish(),
        weights,
        samples: sample_scores,
    }
}

/// The model charge, in bits, for each field definition a parse visits whose
/// content is not fully predicted. It is the price of a boundary: a split must
/// save more than this across the sample set to raise the structure measure.
/// Fields pinned entirely by a constant pay only for their constant bytes, so
/// dividing a constant run is neutral rather than rewarded or punished.
const FIELD_MODEL_BITS: f64 = 16.0;
/// Bits per byte for content the hypothesis does not predict.
const RAW_BITS_PER_BYTE: f64 = 8.0;
/// Bits per character of printable ASCII text: `log2(95)`.
const PRINTABLE_BITS_PER_BYTE: f64 = 6.569_855_608_330_948;

/// Integer values one field definition took across the sample set.
#[derive(Debug, Clone, Copy)]
struct IntTally {
    min: i128,
    max: i128,
    count: u64,
}

/// What one field definition contributed to the description length.
#[derive(Debug, Default)]
struct FieldTally {
    /// Constant bytes the model stores once for this definition.
    constant_bytes: usize,
    /// Whether every visited instance was predicted by a passing constant.
    only_constant: bool,
    /// Values of the integer instances that no constraint predicted.
    ints: Option<IntTally>,
}

/// Accumulates the description-length estimate behind [`Score::structure`].
///
/// Field definitions are identified by address. The format is borrowed
/// immutably for the whole scoring pass, so each definition keeps one stable,
/// unique address, and every element of an array maps to its element
/// definition. The address is only compared, never dereferenced. Tallies are
/// kept in first-visit order, which follows the deterministic parse order, so
/// the floating-point sum in [`StructureTally::finish`] is reproducible run to
/// run (a hash map's iteration order over addresses is not).
#[derive(Debug, Default)]
struct StructureTally {
    raw_bits: f64,
    data_bits: f64,
    fields: Vec<FieldTally>,
    index: HashMap<*const Field, usize>,
}

/// Whether a field's constraints of each kind were checked and all passed.
#[derive(Debug, Clone, Copy, Default)]
struct Verified {
    constant: Option<bool>,
    checksum: Option<bool>,
}

impl StructureTally {
    /// Fold one sample's execution into the estimate.
    fn add_sample(
        &mut self,
        root: &[Field],
        execution: &Execution,
        sample: &[u8],
        explained_bytes: usize,
    ) {
        let len = sample.len();
        self.raw_bits += RAW_BITS_PER_BYTE * len as f64;
        // Bytes no field explains (gaps, trailing bytes, and everything after a
        // parse failure) are stored raw.
        self.data_bits += RAW_BITS_PER_BYTE * len.saturating_sub(explained_bytes) as f64;

        let mut verified: HashMap<(usize, &str), Verified> = HashMap::new();
        for check in &execution.checks {
            let entry = verified
                .entry((check.at, check.field.as_deref().unwrap_or("")))
                .or_default();
            let slot = match check.kind {
                CheckKind::Constant => &mut entry.constant,
                CheckKind::Checksum(_) => &mut entry.checksum,
                CheckKind::IntRange => continue,
            };
            *slot = Some(slot.unwrap_or(true) && check.passed);
        }
        self.walk_structure(root, &execution.fields, sample, &verified);
    }

    fn walk_structure(
        &mut self,
        fields: &[Field],
        instances: &[FieldInstance],
        sample: &[u8],
        verified: &HashMap<(usize, &str), Verified>,
    ) {
        // Instances are a prefix of the structure's fields, in order: the
        // executor parses fields sequentially and stops at the first failure.
        for (field, instance) in fields.iter().zip(instances) {
            self.walk_field(field, instance, sample, verified);
        }
    }

    fn walk_field(
        &mut self,
        field: &Field,
        instance: &FieldInstance,
        sample: &[u8],
        verified: &HashMap<(usize, &str), Verified>,
    ) {
        let key = std::ptr::from_ref(field);
        let (slot, first_visit) = match self.index.get(&key) {
            Some(&slot) => (slot, false),
            None => {
                self.fields.push(FieldTally::default());
                self.index.insert(key, self.fields.len() - 1);
                (self.fields.len() - 1, true)
            }
        };
        let tally = &mut self.fields[slot];
        if first_visit {
            tally.constant_bytes = field
                .constraints
                .iter()
                .map(|constraint| match constraint {
                    Constraint::Constant { value } => value.len(),
                    _ => 0,
                })
                .sum();
            tally.only_constant = tally.constant_bytes > 0;
        }
        match (&field.kind, &instance.value) {
            (Kind::Struct { structure }, Value::Struct(children)) => {
                tally.only_constant = false;
                self.walk_structure(&structure.fields, children, sample, verified);
                return;
            }
            (Kind::Array { element, .. }, Value::Array(elements)) => {
                tally.only_constant = false;
                for child in elements {
                    self.walk_field(element, child, sample, verified);
                }
                return;
            }
            _ => {}
        }

        let state = verified
            .get(&(instance.start, instance.name.as_deref().unwrap_or("")))
            .copied()
            .unwrap_or_default();
        let declares = |wanted: fn(&Constraint) -> bool| field.constraints.iter().any(wanted);
        let constant =
            declares(|c| matches!(c, Constraint::Constant { .. })) && state.constant == Some(true);
        let checksum =
            declares(|c| matches!(c, Constraint::Checksum { .. })) && state.checksum == Some(true);
        if !constant {
            tally.only_constant = false;
        }
        if constant || checksum {
            return;
        }

        let bytes = sample
            .get(instance.start..instance.end.min(sample.len()))
            .unwrap_or(&[]);
        match instance.value {
            Value::Integer(value) | Value::Enum { value, .. } => {
                let ints = tally.ints.get_or_insert(IntTally {
                    min: value,
                    max: value,
                    count: 0,
                });
                ints.min = ints.min.min(value);
                ints.max = ints.max.max(value);
                ints.count += 1;
            }
            Value::Text(_) if bytes.iter().all(|byte| (0x20..0x7f).contains(byte)) => {
                self.data_bits += PRINTABLE_BITS_PER_BYTE * bytes.len() as f64;
            }
            _ => self.data_bits += RAW_BITS_PER_BYTE * bytes.len() as f64,
        }
    }

    /// The structure measure: one minus described bits over raw bits.
    fn finish(&self) -> f64 {
        if self.raw_bits <= 0.0 {
            return 0.0;
        }
        let mut described = self.data_bits;
        for tally in &self.fields {
            described += RAW_BITS_PER_BYTE * tally.constant_bytes as f64;
            if !tally.only_constant {
                described += FIELD_MODEL_BITS;
            }
            if let Some(ints) = tally.ints {
                // Two-part code: the range's endpoints once, then each value
                // uniformly within the observed range.
                described += magnitude_bits(ints.min) + magnitude_bits(ints.max);
                let span = (ints.max - ints.min).unsigned_abs() as f64 + 1.0;
                described += ints.count as f64 * span.log2();
            }
        }
        clamp01(1.0 - described / self.raw_bits)
    }
}

/// Bits to write an integer's magnitude plus a sign or terminator bit.
fn magnitude_bits(value: i128) -> f64 {
    (value.unsigned_abs() as f64 + 1.0).log2() + 1.0
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
    let checksums_passed = execution
        .checks
        .iter()
        .filter(|check| check.passed && matches!(check.kind, CheckKind::Checksum(_)))
        .count();
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
        checksums_passed,
        failure: execution.failure.clone(),
    }
}

/// Compute explained, overlapped, and gap byte counts from the leaf ranges,
/// clipped to the sample length.
///
/// This merges sorted intervals rather than materializing one boolean per
/// sample byte, so its memory is proportional to the number of leaf fields
/// (already bounded by the executor's field limit) and not to the sample size
/// (FR-24).
fn coverage_stats(ranges: &[(usize, usize)], sample_len: usize) -> (usize, usize, usize) {
    if sample_len == 0 {
        return (0, 0, 0);
    }
    // Clip every range to the sample and drop empties.
    let mut clipped: Vec<(usize, usize)> = ranges
        .iter()
        .map(|&(start, end)| (start.min(sample_len), end.min(sample_len)))
        .filter(|&(start, end)| start < end)
        .collect();
    if clipped.is_empty() {
        return (0, 0, 0);
    }
    let total_leaf: usize = clipped.iter().map(|&(start, end)| end - start).sum();
    clipped.sort_unstable();

    // Merge overlapping intervals; the merged length is the explained bytes.
    let mut explained = 0usize;
    let mut run_start = clipped[0].0;
    let mut run_end = clipped[0].1;
    for &(start, end) in &clipped[1..] {
        if start > run_end {
            explained += run_end - run_start;
            run_start = start;
            run_end = end;
        } else {
            run_end = run_end.max(end);
        }
    }
    explained += run_end - run_start;

    // The intervals are sorted and disjoint after merging, so the final run end
    // is the furthest explained byte.
    let max_end = run_end;
    let overlap = total_leaf - explained;
    // Gaps are unexplained bytes that fall before the furthest explained byte.
    let gap = max_end - explained;
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

    #[test]
    fn full_verification_requires_complete_coverage_and_passing_constraints() {
        use sextant_ir::{Bytes, Confidence, Constraint, Field, Kind, SizeRule, Structure};
        let mut format = sextant_ir::fixtures::tlv_ground_truth();
        format.root = Structure::new(vec![
            Field::new(Kind::Bytes, Confidence::CERTAIN).with_size(SizeRule::Fixed { bytes: 1 }),
        ]);
        let full = score(&format, &[&[1u8][..]]);
        assert!(full.fully_verified());
        let prefix = score(&format, &[&[1u8, 2][..]]);
        assert!(prefix.samples[0].parsed);
        assert!(!prefix.fully_verified());
        format.root.fields[0]
            .constraints
            .push(Constraint::Constant {
                value: Bytes::new(vec![2]),
            });
        assert!(!score(&format, &[&[1u8][..]]).fully_verified());
        assert!(!score(&format, &[] as &[&[u8]]).fully_verified());
    }
}
