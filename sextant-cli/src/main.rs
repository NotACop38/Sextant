//! The `sextant` command-line interface.
//!
//! This is the command skeleton. Each subcommand currently prints a
//! not-yet-implemented message and exits non-zero. Ingestion, inference, the
//! executor, reporting, and the exporters are wired in by later checklist
//! steps. The full exit-code contract from the PRD is implemented alongside
//! those subcommands.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

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
        /// Sample inputs to analyze.
        #[arg(value_name = "INPUTS")]
        inputs: Vec<String>,
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
    let command = match cli.command {
        Command::Infer { .. } => "infer",
        Command::Inspect { .. } => "inspect",
        Command::Export { .. } => "export",
        Command::Bench => "bench",
    };
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
