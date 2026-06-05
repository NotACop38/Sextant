//! The `sextant` command-line interface.
//!
//! The `infer` subcommand runs the statistics-only inference pipeline end to end
//! (Step 6): it ingests files, directories, and glob patterns into a normalized
//! sample set (Step 4), generates and scores candidate hypotheses, selects the
//! best, refines it under the non-regression invariant, and prints a scored field
//! map. With `--no-llm` (and today in every mode, since the language-model pass
//! is layered on in a later step) the run is fully offline and performs zero
//! network egress (NFR-4). Reporting to JSON and the exporters are wired in by
//! later checklist steps, so `inspect`, `export`, and `bench` still print a
//! not-yet-implemented message.

use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use sextant_engine::{
    DEFAULT_MAX_BYTES_PER_SAMPLE, DEFAULT_MAX_TOTAL_BYTES, DraftReport, InferenceOptions,
    IngestOptions, Limits, SampleSet, infer, ingest,
};

/// The PRD exit code for an input error (Section 14): a path that does not
/// exist, a malformed glob, an unreadable file, or no usable samples.
const EXIT_INPUT_ERROR: u8 = 2;
/// The PRD exit code for inference producing no usable hypothesis (Section 14).
const EXIT_NO_HYPOTHESIS: u8 = 3;

/// Infer the structure of unknown binary formats and protocols from samples,
/// then emit parsers verified against those samples.
#[derive(Debug, Parser)]
#[command(name = "sextant", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Infer structure from one or more sample files, directories, or globs.
    Infer {
        /// Sample inputs to analyze: files, directories, or glob patterns.
        #[arg(value_name = "INPUTS", required = true)]
        inputs: Vec<String>,
        /// Descend into subdirectories when an input is a directory.
        #[arg(short = 'r', long)]
        recursive: bool,
        /// Cap the bytes read from any single sample.
        #[arg(long, value_name = "N", default_value_t = DEFAULT_MAX_BYTES_PER_SAMPLE)]
        max_bytes_per_sample: usize,
        /// Cap the total bytes read across all samples.
        #[arg(long, value_name = "N", default_value_t = DEFAULT_MAX_TOTAL_BYTES)]
        max_total_bytes: usize,
        /// Run statistics-only with no language model and no network egress.
        /// The model pass is not yet implemented, so this is the default
        /// behavior today; the flag documents intent and guarantees the offline
        /// path.
        #[arg(long)]
        no_llm: bool,
        /// Wall-clock cap, in seconds, for executing the IR against each sample.
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
    },
    /// Read a sample through an inferred field map (annotated hex view).
    Inspect {
        /// Report produced by `sextant infer`.
        #[arg(value_name = "REPORT")]
        report: String,
    },
    /// Export a verified parser from a report.
    Export {
        /// Report produced by `sextant infer`.
        #[arg(value_name = "REPORT")]
        report: String,
    },
    /// Run the accuracy benchmark over the ground-truth corpus.
    Bench,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Infer {
            inputs,
            recursive,
            max_bytes_per_sample,
            max_total_bytes,
            no_llm,
            timeout,
        } => run_infer(
            &inputs,
            recursive,
            max_bytes_per_sample,
            max_total_bytes,
            no_llm,
            timeout,
        ),
        Command::Inspect { .. } => not_implemented("inspect"),
        Command::Export { .. } => not_implemented("export"),
        Command::Bench => not_implemented("bench"),
    }
}

/// Ingest the inputs, run statistics-only inference, and print a scored field
/// map (Step 6). The `--no-llm` path is fully offline (NFR-4).
fn run_infer(
    inputs: &[String],
    recursive: bool,
    max_bytes_per_sample: usize,
    max_total_bytes: usize,
    no_llm: bool,
    timeout: Option<u64>,
) -> ExitCode {
    let options = IngestOptions {
        max_bytes_per_sample,
        max_total_bytes,
        recursive,
    };
    let set = match ingest(inputs, &options) {
        Ok(set) if set.is_empty() => {
            eprintln!("sextant infer: no samples found in the given inputs");
            return ExitCode::from(EXIT_INPUT_ERROR);
        }
        Ok(set) => set,
        Err(error) => {
            eprintln!("sextant infer: {error}");
            return ExitCode::from(EXIT_INPUT_ERROR);
        }
    };

    print_sample_set(&set);

    if !no_llm {
        eprintln!(
            "sextant infer: the language-model pass is not yet available; running statistics-only."
        );
    }
    let inference = InferenceOptions {
        limits: Limits::default().with_timeout(timeout.map(Duration::from_secs)),
        // The model pass is not yet wired in, so every run is statistics-only
        // and offline regardless of the flag (NFR-4).
        no_llm: true,
    };
    let report = infer(&set, &inference);
    print_report(&report);

    if report.field_map.is_empty() {
        eprintln!("sextant infer: no usable hypothesis was produced");
        ExitCode::from(EXIT_NO_HYPOTHESIS)
    } else {
        ExitCode::SUCCESS
    }
}

/// Print the scored field map and the fit-score breakdown of a draft report.
fn print_report(report: &DraftReport) {
    let score = &report.score;
    println!();
    println!(
        "Best hypothesis: {} (fit score {:.3})",
        report.format.name, score.overall
    );
    println!(
        "  coverage {:.3}  consistency {:.3}  generality {:.3}",
        score.coverage, score.consistency, score.generality
    );
    if report.metadata.no_llm {
        println!("  mode: statistics-only (no language model, no network egress)");
    }

    println!("Field map:");
    for entry in &report.field_map {
        let indent = "  ".repeat(entry.depth + 1);
        println!(
            "{indent}{name}: {role}, {kind}, {size} (confidence {conf:.2})",
            name = entry.name,
            role = entry.role,
            kind = entry.kind,
            size = entry.size,
            conf = entry.confidence,
        );
    }

    if report.refinement.is_empty() {
        println!("Refinement: no improving change was found (already converged).");
    } else {
        println!(
            "Refinement: {} accepted change(s):",
            report.refinement.len()
        );
        for step in &report.refinement {
            println!(
                "  {} (score {:.3} to {:.3})",
                step.description, step.score_before, step.score_after
            );
        }
    }
}

/// Print the ingested sample count, each sample's path and retained size, the
/// total, and any cap notices to standard output.
fn print_sample_set(set: &SampleSet) {
    println!(
        "Ingested {} {} ({} bytes total).",
        set.len(),
        plural(set.len(), "sample", "samples"),
        set.total_bytes
    );
    for sample in &set.samples {
        let path = sample.provenance.path.display();
        if sample.provenance.is_truncated() {
            println!(
                "  {path}: {} bytes (clipped from {} bytes)",
                sample.provenance.length, sample.provenance.original_length
            );
        } else {
            println!("  {path}: {} bytes", sample.provenance.length);
        }
    }
    for notice in &set.notices {
        println!("note: {notice}");
    }
}

/// Choose the singular or plural word for a count.
fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

/// Report a subcommand that is not yet wired up and exit non-zero.
fn not_implemented(command: &str) -> ExitCode {
    eprintln!(
        "sextant {command}: not yet implemented. See docs/ENGINEERING_CHECKLIST.md for the build plan."
    );
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn help_lists_every_subcommand() {
        let help = Cli::command().render_long_help().to_string();
        for subcommand in ["infer", "inspect", "export", "bench"] {
            assert!(
                help.contains(subcommand),
                "help output is missing the `{subcommand}` subcommand"
            );
        }
    }

    #[test]
    fn version_is_present() {
        let command = Cli::command();
        let version = command.get_version();
        assert!(version.is_some_and(|value| !value.is_empty()));
    }
}
