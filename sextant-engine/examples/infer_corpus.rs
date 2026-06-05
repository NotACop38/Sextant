//! Runnable example: infer a corpus format end to end, offline.
//!
//! This drives the same statistics-only pipeline the `sextant infer --no-llm`
//! command uses, but through the library API, so it doubles as a worked example
//! of how to embed Sextant. It ingests the bundled TLV corpus, infers a
//! structure, and prints the fit score and the field map. No network access and
//! no language model are involved.
//!
//! Run it from the repository root with:
//!
//! ```text
//! cargo run -p sextant-engine --example infer_corpus
//! ```
//!
//! Pass a different corpus format name as the first argument to try another one,
//! for example `cargo run -p sextant-engine --example infer_corpus -- png`.

use std::path::PathBuf;
use std::process::ExitCode;

use sextant_engine::{InferenceOptions, IngestOptions, infer, ingest};

fn main() -> ExitCode {
    // Default to the TLV format; allow an override on the command line.
    let format = std::env::args().nth(1).unwrap_or_else(|| "tlv".to_owned());

    // Locate the corpus relative to this crate, so the example works no matter
    // the current working directory (the same approach the bench harness uses).
    let samples_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the sextant-engine crate always has a parent directory")
        .join("corpus")
        .join(&format)
        .join("samples");

    let samples_arg = samples_dir.to_string_lossy().into_owned();
    println!("Inferring the '{format}' format from {samples_arg}");

    // Ingest the samples with default caps.
    let sample_set = match ingest(&[samples_arg.as_str()], &IngestOptions::default()) {
        Ok(set) => set,
        Err(error) => {
            eprintln!("ingestion failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "Ingested {} samples ({} bytes total).",
        sample_set.len(),
        sample_set.samples.iter().map(|s| s.len()).sum::<usize>(),
    );

    // Run statistics-only inference. This is fully offline (NFR-4).
    let options = InferenceOptions {
        no_llm: true,
        ..InferenceOptions::default()
    };
    let report = infer(&sample_set, &options);

    println!(
        "\nBest hypothesis: {} (fit score {:.3})",
        report.format.name, report.score.overall,
    );
    println!(
        "  coverage {:.3}  consistency {:.3}  generality {:.3}",
        report.score.coverage, report.score.consistency, report.score.generality,
    );

    println!("\nField map:");
    for entry in &report.field_map {
        let indent = "  ".repeat(entry.depth + 1);
        println!(
            "{indent}{}: {}, {}, {} (confidence {:.2})",
            entry.name, entry.role, entry.kind, entry.size, entry.confidence,
        );
    }

    // The chosen IR parsed every sample by construction of the verification
    // loop, so a healthy run scores at or near 1.0.
    if report.score.overall >= 0.5 {
        println!("\nThe inferred structure is verified against all samples.");
        ExitCode::SUCCESS
    } else {
        eprintln!("\nNo usable hypothesis was found for '{format}'.");
        ExitCode::FAILURE
    }
}
