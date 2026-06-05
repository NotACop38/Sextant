//! The `sextant` command-line interface.
//!
//! The `infer` subcommand now performs sample ingestion (Step 4): it resolves
//! files, directories, and glob patterns into a normalized sample set with
//! provenance, enforces the byte caps, and reports the sample count and sizes.
//! Statistical inference, reporting, and the exporters are wired in by later
//! checklist steps, so `inspect`, `export`, and `bench` still print a
//! not-yet-implemented message. The full exit-code contract from the PRD is
//! implemented alongside those subcommands.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sextant_engine::{
    DEFAULT_MAX_BYTES_PER_SAMPLE, DEFAULT_MAX_TOTAL_BYTES, IngestOptions, SampleSet, ingest,
};

/// The PRD exit code for an input error (Section 14): a path that does not
/// exist, a malformed glob, an unreadable file, or no usable samples.
const EXIT_INPUT_ERROR: u8 = 2;

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
        } => run_infer(&inputs, recursive, max_bytes_per_sample, max_total_bytes),
        Command::Inspect { .. } => not_implemented("inspect"),
        Command::Export { .. } => not_implemented("export"),
        Command::Bench => not_implemented("bench"),
    }
}

/// Ingest the inputs and report the sample set. Inference itself arrives in a
/// later checklist step; this realizes the Step 4 ingestion behavior.
fn run_infer(
    inputs: &[String],
    recursive: bool,
    max_bytes_per_sample: usize,
    max_total_bytes: usize,
) -> ExitCode {
    let options = IngestOptions {
        max_bytes_per_sample,
        max_total_bytes,
        recursive,
    };
    match ingest(inputs, &options) {
        Ok(set) if set.is_empty() => {
            eprintln!("sextant infer: no samples found in the given inputs");
            ExitCode::from(EXIT_INPUT_ERROR)
        }
        Ok(set) => {
            print_sample_set(&set);
            eprintln!(
                "sextant infer: ingestion complete. Statistical inference arrives in a later checklist step."
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("sextant infer: {error}");
            ExitCode::from(EXIT_INPUT_ERROR)
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
