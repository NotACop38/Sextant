//! The CI regression guard (PRD Section 15).
//!
//! These tests run the full benchmark harness once, over both corpus tiers, and
//! enforce that:
//!
//! - every configured regression floor holds (CI also runs this check as
//!   `sextant-bench --check`), so a metric drop below its floor fails the build;
//! - the README benchmark block is generated from the harness and has not
//!   drifted from what the harness currently measures.
//!
//! The PRD Section 15 targets are reported by the harness, met or not, and are
//! deliberately not asserted here: publishing an unmet target is honest, while
//! hiding it behind a failing build is not.

use std::sync::OnceLock;

use bench::{BenchOptions, BenchReport, render_readme_section, run_benchmark};

/// One benchmark run shared by every test in this file, since a full run
/// re-infers every corpus format.
fn report() -> &'static BenchReport {
    static REPORT: OnceLock<BenchReport> = OnceLock::new();
    REPORT.get_or_init(|| run_benchmark(&BenchOptions::default()).expect("run the benchmark"))
}

#[test]
fn regression_floors_hold() {
    let report = report();
    let failures = report.regression_failures();
    assert!(
        failures.is_empty(),
        "regression guard failed:\n{}",
        failures.join("\n")
    );
    assert!(
        !report.floors.is_empty(),
        "the regression guard must check at least one floor"
    );
}

#[test]
fn readme_benchmark_block_matches_harness() {
    let expected = render_readme_section(report());

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
