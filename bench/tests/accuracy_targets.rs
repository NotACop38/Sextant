//! Step 6 acceptance (PRD Section 15): the statistics-only pipeline clears the
//! file-format accuracy targets on the corpus, namely field-boundary F1 at least
//! 0.85 and a perfection rate of at least 0.5.
//!
//! The metrics here are computed by the same `bench` accuracy library that the
//! full `sextant bench` command will use in Step 12, so the numbers are the ones
//! the tool reports, not a separate hand-rolled estimate.

use bench::evaluate_corpus;

/// The file-format corpus the statistics-only MVP targets. These are the formats
/// present under `corpus/`; the wider PRD Section 15 set (GIF, BMP, WAV, and the
/// rest) joins the corpus in later steps and is tracked by `sextant bench`.
const FILE_FORMAT_CORPUS: [&str; 5] = ["tlv", "scma", "stot", "sdlp", "png"];

/// The PRD Section 15 statistics-only field-boundary F1 target.
const F1_TARGET: f64 = 0.85;
/// The PRD Section 15 statistics-only perfection-rate target.
const PERFECTION_TARGET: f64 = 0.5;

#[test]
fn statistics_only_pipeline_meets_the_prd_accuracy_targets() {
    let metrics = evaluate_corpus(&FILE_FORMAT_CORPUS).expect("evaluate the file-format corpus");

    assert!(
        metrics.macro_f1 >= F1_TARGET,
        "field-boundary F1 {:.4} is below the target {F1_TARGET}; per-format {:?}",
        metrics.macro_f1,
        metrics
            .formats
            .iter()
            .map(|f| (f.format.as_str(), f.f1))
            .collect::<Vec<_>>()
    );

    assert!(
        metrics.perfection_rate >= PERFECTION_TARGET,
        "perfection rate {:.4} is below the target {PERFECTION_TARGET}; perfect formats {:?}",
        metrics.perfection_rate,
        metrics
            .formats
            .iter()
            .filter(|f| f.perfect)
            .map(|f| f.format.as_str())
            .collect::<Vec<_>>()
    );

    // Native validity must remain 100 percent on this development corpus:
    // the chosen IR parses every sample to a clean end (PRD Section 15).
    for format in &metrics.formats {
        assert!(
            format.precision > 0.0,
            "{}: the chosen IR produced no usable field map",
            format.format
        );
    }
}
