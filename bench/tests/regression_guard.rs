//! Step 12 acceptance and the CI regression guard (PRD Section 15).
//!
//! These tests run the full benchmark harness and enforce that:
//!
//! - every configured target is met (the regression guard CI also runs as
//!   `bench --check`), so a metric drop below threshold fails the build;
//! - the statistics-only pipeline clears the PRD Section 15 file-format targets
//!   (field-boundary F1 at least 0.85, perfection at least 0.5, parser validity
//!   100 percent);
//! - the README benchmark block is generated from the harness and has not
//!   drifted from what the harness currently measures.

use bench::{BenchOptions, render_readme_section, run_benchmark};

/// The PRD Section 15 statistics-only field-boundary F1 target.
const F1_TARGET: f64 = 0.85;
/// The PRD Section 15 statistics-only perfection-rate target.
const PERFECTION_TARGET: f64 = 0.5;

#[test]
fn regression_guard_all_targets_met() {
    let report = run_benchmark(&BenchOptions::default()).expect("run the benchmark");
    let failures = report.regression_failures();
    assert!(
        failures.is_empty(),
        "regression guard failed: {failures:?}\nsummary: {:?}",
        report.summary
    );
    assert!(report.targets.all_met);
}

#[test]
fn statistics_only_pipeline_meets_prd_targets() {
    let report = run_benchmark(&BenchOptions::default()).expect("run the benchmark");
    let summary = &report.summary;

    assert!(
        summary.boundary_f1 >= F1_TARGET,
        "field-boundary F1 {:.4} is below the PRD target {F1_TARGET}",
        summary.boundary_f1
    );
    assert!(
        summary.perfection_rate >= PERFECTION_TARGET,
        "perfection rate {:.4} is below the PRD target {PERFECTION_TARGET}",
        summary.perfection_rate
    );
    // Parser validity is 100 percent by construction of the verification loop:
    // the chosen IR parses every sample to a clean end (PRD Section 15).
    assert!(
        (summary.parser_validity - 1.0).abs() < 1e-9,
        "parser validity {:.4} is not 100 percent",
        summary.parser_validity
    );
}

#[test]
fn readme_benchmark_block_matches_harness() {
    let report = run_benchmark(&BenchOptions::default()).expect("run the benchmark");
    let expected = render_readme_section(&report);

    let readme = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../README.md"))
        .expect("read README.md");
    let start_marker = "<!-- BENCH:START -->";
    let end_marker = "<!-- BENCH:END -->";
    let start = readme
        .find(start_marker)
        .expect("README has the BENCH:START marker")
        + start_marker.len();
    let end = readme
        .find(end_marker)
        .expect("README has the BENCH:END marker");
    let block = readme[start..end].trim();

    assert_eq!(
        block,
        expected.trim(),
        "README benchmark block is stale. Regenerate it with `cargo run -p sextant-bench -- --write-readme`."
    );
}
