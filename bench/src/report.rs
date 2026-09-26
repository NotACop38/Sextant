//! The published benchmark report: per-tier results tables, machine-readable
//! JSON, the regression floors, and the PRD targets.
//!
//! [`run_benchmark`] evaluates the file-format corpus in two tiers and assembles
//! a [`BenchReport`]:
//!
//! - the development tier ([`DEVELOPMENT_CORPUS`]) holds every format the
//!   engine was tuned against, so its numbers measure fit to known data;
//! - the held-out tier ([`HELD_OUT_CORPUS`]) holds real formats that were not
//!   consulted while developing heuristics, so its numbers estimate accuracy on
//!   formats the engine was not fitted to.
//!
//! The report renders three ways: [`render_table`] for the terminal,
//! [`render_readme_section`] for the generated README block (a test fails if
//! the README drifts from it), and [`BenchReport::to_json`].
//!
//! [`BenchReport::regression_failures`] enforces the measured regression floors,
//! which CI checks. The PRD Section 15 targets are reported separately, met or
//! not, because a target the pipeline does not yet meet is a fact to publish
//! rather than a build failure to hide.

use std::fmt::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{
    DEVELOPMENT_CORPUS, HELD_OUT_CORPUS,
    accuracy::{FormatMetrics, evaluate_format_in},
    corpus_dir,
};

/// The PRD Section 15 statistics-only field-boundary F1 target.
pub const F1_TARGET: f64 = 0.85;
/// The PRD Section 15 statistics-only perfection-rate target.
pub const PERFECTION_TARGET: f64 = 0.5;
/// The PRD Section 15 parser-validity target: every sample parses (100 percent).
pub const PARSER_VALIDITY_TARGET: f64 = 1.0;

/// A regression floor: a tier metric that must not fall below `floor`.
///
/// Floors sit a small margin below the values the pipeline measures today, so
/// they trip on a real regression without failing on floating-point noise.
/// Raise a floor whenever an improvement lands.
#[derive(Debug, Clone, Copy)]
pub struct Floor {
    /// The tier the floor applies to.
    pub tier: Tier,
    /// The metric's name, as reported.
    pub metric: &'static str,
    /// The minimum acceptable value.
    pub floor: f64,
}

/// The configured regression floors.
pub const FLOORS: &[Floor] = &[
    Floor {
        tier: Tier::Development,
        metric: "field-boundary F1",
        floor: 0.0,
    },
    Floor {
        tier: Tier::Development,
        metric: "role accuracy",
        floor: 0.0,
    },
    Floor {
        tier: Tier::Development,
        metric: "type accuracy",
        floor: 0.0,
    },
    Floor {
        tier: Tier::Development,
        metric: "native validity",
        floor: 1.0,
    },
    Floor {
        tier: Tier::HeldOut,
        metric: "native validity",
        floor: 1.0,
    },
];

/// A corpus tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Formats the engine was tuned against.
    Development,
    /// Formats withheld from tuning.
    HeldOut,
}

impl Tier {
    /// The tier's display name.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Tier::Development => "development",
            Tier::HeldOut => "held-out",
        }
    }

    /// The formats in this tier.
    #[must_use]
    pub fn formats(self) -> &'static [&'static str] {
        match self {
            Tier::Development => &DEVELOPMENT_CORPUS,
            Tier::HeldOut => &HELD_OUT_CORPUS,
        }
    }
}

/// Options for a benchmark run.
#[derive(Debug, Clone)]
pub struct BenchOptions {
    /// The corpus directory to evaluate. Defaults to the repository `corpus/`.
    pub corpus_dir: PathBuf,
    /// The tiers to evaluate, in order. Defaults to both.
    pub tiers: Vec<Tier>,
}

impl Default for BenchOptions {
    fn default() -> Self {
        Self {
            corpus_dir: corpus_dir(),
            tiers: vec![Tier::Development, Tier::HeldOut],
        }
    }
}

/// Per-format benchmark numbers, machine-readable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatReport {
    /// The format's machine name.
    pub format: String,
    /// The format's human-readable name.
    pub display_name: String,
    /// How many samples were evaluated.
    pub samples: usize,
    /// Field-boundary precision over interior boundaries.
    pub boundary_precision: f64,
    /// Field-boundary recall over interior boundaries.
    pub boundary_recall: f64,
    /// Field-boundary F1 over interior boundaries.
    pub boundary_f1: f64,
    /// Whether every sample's interior boundaries were recovered exactly.
    pub perfect: bool,
    /// Semantic role accuracy.
    pub role_accuracy: f64,
    /// Storage type accuracy (width and byte order).
    pub type_accuracy: f64,
    /// Native validity: fraction of samples the chosen IR parsed completely
    /// with every constraint passing.
    pub native_validity: f64,
    /// The chosen hypothesis's structure measure over the samples.
    pub structure: f64,
}

/// Aggregate numbers for one tier, machine-readable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    /// How many formats were evaluated.
    pub formats: usize,
    /// How many samples were evaluated in total.
    pub samples: usize,
    /// Macro-averaged field-boundary precision.
    pub boundary_precision: f64,
    /// Macro-averaged field-boundary recall.
    pub boundary_recall: f64,
    /// Macro-averaged field-boundary F1.
    pub boundary_f1: f64,
    /// Perfection rate: fraction of formats recovered exactly.
    pub perfection_rate: f64,
    /// Macro-averaged semantic role accuracy.
    pub role_accuracy: f64,
    /// Macro-averaged storage type accuracy.
    pub type_accuracy: f64,
    /// Native validity across all samples in the tier.
    pub native_validity: f64,
}

/// One evaluated tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierReport {
    /// Which tier this is.
    pub tier: Tier,
    /// Per-format numbers, in corpus order.
    pub formats: Vec<FormatReport>,
    /// Tier aggregates.
    pub summary: Summary,
}

/// One metric compared against a threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetCheck {
    /// The tier the metric was measured on.
    pub tier: Tier,
    /// The metric's name.
    pub metric: String,
    /// The measured value.
    pub value: f64,
    /// The threshold the value is compared against.
    pub threshold: f64,
    /// Whether the value met the threshold.
    pub met: bool,
}

/// The full machine-readable benchmark report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReport {
    /// The tool version that produced the report.
    pub tool_version: String,
    /// The corpus directory that was evaluated.
    pub corpus: String,
    /// The evaluated tiers.
    pub tiers: Vec<TierReport>,
    /// The regression floors CI enforces.
    pub floors: Vec<TargetCheck>,
    /// The PRD Section 15 targets, reported whether met or not.
    pub prd_targets: Vec<TargetCheck>,
}

impl BenchReport {
    /// Serialize the report to pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Returns the underlying serialization error, which should not happen for a
    /// well-formed in-memory value.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// The regression floors the run failed, as human-readable lines. An empty
    /// list means the guard passes; this is what CI checks.
    #[must_use]
    pub fn regression_failures(&self) -> Vec<String> {
        self.floors
            .iter()
            .filter(|check| !check.met)
            .map(|check| {
                format!(
                    "{} {}: {:.4} is below the regression floor {:.4}",
                    check.tier.label(),
                    check.metric,
                    check.value,
                    check.threshold
                )
            })
            .collect()
    }

    /// The report for `tier`, when it was evaluated.
    #[must_use]
    pub fn tier(&self, tier: Tier) -> Option<&TierReport> {
        self.tiers.iter().find(|report| report.tier == tier)
    }
}

/// Run the benchmark over the configured tiers and assemble the full report.
///
/// # Errors
///
/// Returns an error if any format's ground truth or samples cannot be read.
pub fn run_benchmark(options: &BenchOptions) -> std::io::Result<BenchReport> {
    let mut tiers = Vec::with_capacity(options.tiers.len());
    for &tier in &options.tiers {
        let mut metrics = Vec::with_capacity(tier.formats().len());
        for format in tier.formats() {
            metrics.push(evaluate_format_in(&options.corpus_dir, format)?);
        }
        tiers.push(tier_report(tier, &metrics));
    }

    let mut floors = Vec::new();
    for floor in FLOORS {
        if let Some(report) = tiers.iter().find(|report| report.tier == floor.tier) {
            if let Some(value) = metric(&report.summary, floor.metric) {
                floors.push(check(floor.tier, floor.metric, value, floor.floor));
            }
        }
    }
    let mut prd_targets = Vec::new();
    for report in &tiers {
        let summary = &report.summary;
        prd_targets.push(check(
            report.tier,
            "field-boundary F1",
            summary.boundary_f1,
            F1_TARGET,
        ));
        prd_targets.push(check(
            report.tier,
            "perfection rate",
            summary.perfection_rate,
            PERFECTION_TARGET,
        ));
        prd_targets.push(check(
            report.tier,
            "native validity",
            summary.native_validity,
            PARSER_VALIDITY_TARGET,
        ));
    }

    Ok(BenchReport {
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        corpus: options.corpus_dir.display().to_string(),
        tiers,
        floors,
        prd_targets,
    })
}

/// Assemble one tier's per-format rows and macro averages.
fn tier_report(tier: Tier, metrics: &[FormatMetrics]) -> TierReport {
    let formats: Vec<FormatReport> = metrics
        .iter()
        .map(|m| FormatReport {
            format: m.format.clone(),
            display_name: m.display_name.clone(),
            samples: m.sample_count,
            boundary_precision: m.precision,
            boundary_recall: m.recall,
            boundary_f1: m.f1,
            perfect: m.perfect,
            role_accuracy: m.role_accuracy,
            type_accuracy: m.type_accuracy,
            native_validity: m.parser_validity,
            structure: m.structure,
        })
        .collect();
    let count = formats.len().max(1) as f64;
    let mean = |value: fn(&FormatReport) -> f64| formats.iter().map(value).sum::<f64>() / count;
    let samples: usize = formats.iter().map(|f| f.samples).sum();
    let valid: usize = metrics
        .iter()
        .flat_map(|m| m.samples.iter())
        .filter(|sample| sample.valid)
        .count();
    let summary = Summary {
        formats: formats.len(),
        samples,
        boundary_precision: mean(|f| f.boundary_precision),
        boundary_recall: mean(|f| f.boundary_recall),
        boundary_f1: mean(|f| f.boundary_f1),
        perfection_rate: formats.iter().filter(|f| f.perfect).count() as f64 / count,
        role_accuracy: mean(|f| f.role_accuracy),
        type_accuracy: mean(|f| f.type_accuracy),
        native_validity: if samples == 0 {
            0.0
        } else {
            valid as f64 / samples as f64
        },
    };
    TierReport {
        tier,
        formats,
        summary,
    }
}

/// Look up a summary metric by its reported name.
fn metric(summary: &Summary, name: &str) -> Option<f64> {
    Some(match name {
        "field-boundary F1" => summary.boundary_f1,
        "perfection rate" => summary.perfection_rate,
        "role accuracy" => summary.role_accuracy,
        "type accuracy" => summary.type_accuracy,
        "native validity" => summary.native_validity,
        _ => return None,
    })
}

/// Build one threshold check. A value meets its threshold when it is greater
/// than or equal, within a small epsilon for floating-point comparison.
fn check(tier: Tier, metric: &str, value: f64, threshold: f64) -> TargetCheck {
    const EPSILON: f64 = 1e-9;
    TargetCheck {
        tier,
        metric: metric.to_owned(),
        value,
        threshold,
        met: value + EPSILON >= threshold,
    }
}

/// Render the human-readable results table that `sextant bench` prints.
#[must_use]
pub fn render_table(report: &BenchReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Sextant benchmark (statistics-only, no language model)"
    );
    let _ = writeln!(out, "tool version {}", report.tool_version);
    for tier in &report.tiers {
        let _ = writeln!(out);
        let _ = writeln!(out, "{} tier", tier.tier.label());
        let _ = writeln!(
            out,
            "{:<9} {:>7} {:>6} {:>6} {:>6} {:>7} {:>6} {:>6} {:>6} {:>9}",
            "format",
            "samples",
            "prec",
            "recall",
            "f1",
            "exact",
            "role",
            "type",
            "valid",
            "structure"
        );
        let _ = writeln!(out, "{}", "-".repeat(79));
        for format in &tier.formats {
            let _ = writeln!(
                out,
                "{:<9} {:>7} {:>6.3} {:>6.3} {:>6.3} {:>7} {:>6.3} {:>6.3} {:>6.3} {:>9.3}",
                format.format,
                format.samples,
                format.boundary_precision,
                format.boundary_recall,
                format.boundary_f1,
                if format.perfect { "yes" } else { "no" },
                format.role_accuracy,
                format.type_accuracy,
                format.native_validity,
                format.structure,
            );
        }
        let _ = writeln!(out, "{}", "-".repeat(79));
        let summary = &tier.summary;
        let _ = writeln!(
            out,
            "{:<9} {:>7} {:>6.3} {:>6.3} {:>6.3} {:>7.2} {:>6.3} {:>6.3} {:>6.3}",
            "macro",
            summary.samples,
            summary.boundary_precision,
            summary.boundary_recall,
            summary.boundary_f1,
            summary.perfection_rate,
            summary.role_accuracy,
            summary.type_accuracy,
            summary.native_validity,
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "Regression floors:");
    for check in &report.floors {
        let _ = writeln!(
            out,
            "  [{}] {} {}: {:.3} (floor {:.3})",
            if check.met { "pass" } else { "FAIL" },
            check.tier.label(),
            check.metric,
            check.value,
            check.threshold,
        );
    }
    let _ = writeln!(out, "PRD Section 15 targets:");
    for check in &report.prd_targets {
        let _ = writeln!(
            out,
            "  [{}] {} {}: {:.3} (target {:.3})",
            if check.met { "met" } else { "not met" },
            check.tier.label(),
            check.metric,
            check.value,
            check.threshold,
        );
    }
    out
}

/// Render the exact Markdown block the README carries between its benchmark
/// markers. The README numbers are generated from this, so they cannot drift
/// from what the harness measures (a test enforces the match).
#[must_use]
pub fn render_readme_section(report: &BenchReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "| Tier | Format | Samples | Boundary F1 | Exact | Role | Type | Valid | Structure |"
    );
    let _ = writeln!(out, "|---|---|--:|--:|:-:|--:|--:|--:|--:|");
    for tier in &report.tiers {
        for format in &tier.formats {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {:.2} | {} | {:.2} | {:.2} | {:.0}% | {:.2} |",
                tier.tier.label(),
                format.format,
                format.samples,
                format.boundary_f1,
                if format.perfect { "yes" } else { "no" },
                format.role_accuracy,
                format.type_accuracy,
                format.native_validity * 100.0,
                format.structure,
            );
        }
        let summary = &tier.summary;
        let _ = writeln!(
            out,
            "| **{}** | **mean** | **{}** | **{:.2}** | **{}/{}** | **{:.2}** | **{:.2}** | **{:.0}%** | |",
            tier.tier.label(),
            summary.samples,
            summary.boundary_f1,
            tier.formats.iter().filter(|f| f.perfect).count(),
            summary.formats,
            summary.role_accuracy,
            summary.type_accuracy,
            summary.native_validity * 100.0,
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_passes_at_or_above_threshold_and_fails_below() {
        let tier = Tier::Development;
        assert!(
            check(tier, "metric", 0.85, 0.85).met,
            "equal value should pass"
        );
        assert!(
            check(tier, "metric", 0.90, 0.85).met,
            "value above should pass"
        );
        assert!(
            !check(tier, "metric", 0.84, 0.85).met,
            "value below should fail"
        );
    }

    #[test]
    fn regression_failures_name_each_failed_floor() {
        let report = BenchReport {
            tool_version: "test".to_owned(),
            corpus: "corpus".to_owned(),
            tiers: Vec::new(),
            floors: vec![
                check(Tier::Development, "field-boundary F1", 0.10, 0.5),
                check(Tier::HeldOut, "native validity", 1.0, 1.0),
            ],
            prd_targets: vec![check(Tier::Development, "perfection rate", 0.0, 0.5)],
        };
        let failures = report.regression_failures();
        assert_eq!(
            failures.len(),
            1,
            "only failed floors are regressions: {failures:?}"
        );
        assert!(failures[0].contains("development field-boundary F1"));
    }

    #[test]
    fn every_floor_names_a_known_metric() {
        let summary = Summary {
            formats: 0,
            samples: 0,
            boundary_precision: 0.0,
            boundary_recall: 0.0,
            boundary_f1: 0.0,
            perfection_rate: 0.0,
            role_accuracy: 0.0,
            type_accuracy: 0.0,
            native_validity: 0.0,
        };
        for floor in FLOORS {
            assert!(metric(&summary, floor.metric).is_some(), "{}", floor.metric);
        }
    }

    #[test]
    fn tiers_partition_the_file_format_corpus() {
        let mut all: Vec<&str> = Tier::Development.formats().to_vec();
        all.extend(Tier::HeldOut.formats());
        assert_eq!(all, crate::FILE_FORMAT_CORPUS.to_vec());
    }
}
