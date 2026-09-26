//! The `sextant` command-line interface.
//!
//! The `infer` subcommand runs the statistics-only inference pipeline end to end
//! (Step 6): it ingests files, directories, and glob patterns into a normalized
//! sample set (Step 4), generates and scores candidate hypotheses, selects the
//! best, refines it under the non-regression invariant, and prints a scored field
//! map. With `--out` it also writes the machine-readable JSON report (FR-34).
//! A run is statistics-only and fully offline, with zero network egress, unless
//! `--provider` opts in to the model pass (NFR-4); `--no-llm` states that
//! intent explicitly and conflicts with `--provider`. The model pass needs a
//! build with the `llm` feature, and its proposals are kept only when the
//! native executor verifies they do not lower the fit (FR-26).
//!
//! The `inspect` subcommand reads a sample through a report and renders an
//! annotated hex view (FR-35). The `export` subcommand reads a report and emits
//! an editable parser (Kaitai, ImHex, Wireshark, or 010) from the chosen IR
//! (FR-36, FR-37), with an optional Kaitai cross-check (FR-38). The `bench`
//! subcommand runs the accuracy benchmark over the ground-truth corpus and
//! prints the PRD Section 15 metrics table (Step 12), exiting non-zero if any
//! metric falls below its regression floor so it doubles as a regression guard.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use sextant_engine::ingest::read_regular_file;
use sextant_engine::pcap::extract_capture;
use sextant_engine::protocol::Population;
use sextant_engine::{
    Clustering, DEFAULT_MAX_BYTES_PER_SAMPLE, DEFAULT_MAX_MESSAGES, DEFAULT_MAX_REPORT_BYTES,
    DEFAULT_MAX_TOTAL_BYTES, ExtractOptions, InferenceOptions, IngestOptions, InspectOptions,
    Limits, PcapError, ProtocolInference, Report, SampleSet, Transport, infer, infer_protocol,
    ingest, render,
};
use sextant_export::{ExportFormat, export};

mod model;

/// The PRD exit code for a usage error (Section 14): an unknown flag, a missing
/// required argument, or a malformed flag value.
const EXIT_USAGE_ERROR: u8 = 1;
/// The PRD exit code for an input error (Section 14): a path that does not
/// exist, a malformed glob, an unreadable file, or no usable samples.
const EXIT_INPUT_ERROR: u8 = 2;
/// The PRD exit code for inference producing no usable hypothesis (Section 14).
const EXIT_NO_HYPOTHESIS: u8 = 3;
/// The PRD exit code for an export error (Section 14).
const EXIT_EXPORT_ERROR: u8 = 4;
/// The PRD exit code for an internal error (Section 14).
const EXIT_INTERNAL_ERROR: u8 = 5;

/// Write a line to standard output (see [`write_stdout`]).
macro_rules! outln {
    () => {
        write_stdout(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        write_stdout(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// Write to standard output without a line break (see [`write_stdout`]).
macro_rules! out {
    ($($arg:tt)*) => {
        write_stdout(format_args!($($arg)*))
    };
}

/// Write to standard output. When the reader has closed the pipe early (for
/// example `sextant infer samples | head`), the program ends quietly with
/// success, as a filter should, instead of panicking as `println!` does. Any
/// other write error is reported and ends the program with the internal-error
/// code.
fn write_stdout(text: std::fmt::Arguments<'_>) {
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    if let Err(error) = stdout.write_fmt(text) {
        if error.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("sextant: could not write to standard output: {error}");
        std::process::exit(i32::from(EXIT_INTERNAL_ERROR));
    }
}

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
        /// This is already the behavior without --provider; the flag states the
        /// intent and refuses to combine with --provider.
        #[arg(long)]
        no_llm: bool,
        /// Opt in to the model pass with this provider (anthropic, openai, or
        /// ollama). The model proposes names, roles, and refinements; each is
        /// kept only if the native executor verifies it does not lower the fit.
        /// The credential comes from the environment or the Sextant config
        /// file, never from a flag. The request holds the candidate field
        /// layout and at most 256 bytes from each of the first four samples.
        #[arg(long, value_name = "NAME", conflicts_with = "no_llm")]
        provider: Option<String>,
        /// The model to ask (default: the provider's default model).
        #[arg(long, value_name = "ID", requires = "provider")]
        model: Option<String>,
        /// Cap the model calls this run may make.
        #[arg(long, value_name = "N", requires = "provider", default_value_t = 8)]
        max_llm_calls: u32,
        /// Wall-clock cap, in seconds, for executing the IR against each sample.
        /// When omitted, the default five-second executor timeout is kept.
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
        /// Cap how many protocol messages are extracted from captures (FR-2).
        #[arg(long, value_name = "N", default_value_t = DEFAULT_MAX_MESSAGES)]
        max_messages: usize,
        /// Treat the inputs as packet captures and extract this transport's
        /// payloads (tcp or udp). Requires --port (FR-2).
        #[arg(long, value_name = "TCP|UDP")]
        transport: Option<String>,
        /// The port that identifies the protocol in a capture. Requires
        /// --transport (FR-2).
        #[arg(long, value_name = "N")]
        port: Option<u16>,
        /// Write the machine-readable JSON report to this path (FR-34).
        #[arg(long, value_name = "FILE")]
        out: Option<String>,
        /// Allow `--out` to overwrite an existing file or write outside the
        /// current working directory.
        #[arg(long)]
        force: bool,
    },
    /// Read a sample through an inferred field map (annotated hex view, FR-35).
    Inspect {
        /// Report produced by `sextant infer --out` (a JSON report file).
        #[arg(value_name = "REPORT")]
        report: String,
        /// The sample file to render through the report.
        #[arg(long, value_name = "FILE")]
        sample: String,
        /// Color each field's bytes in the hex dump and its name in the table.
        #[arg(long)]
        color: bool,
        /// Cap the bytes read from the sample file.
        #[arg(long, value_name = "N", default_value_t = DEFAULT_MAX_BYTES_PER_SAMPLE)]
        max_bytes_per_sample: usize,
    },
    /// Export a verified parser from a report (FR-36, FR-37).
    Export {
        /// Report produced by `sextant infer`.
        #[arg(value_name = "REPORT")]
        report: String,
        /// The target parser format: kaitai, imhex, wireshark, or 010.
        #[arg(long, value_name = "FMT")]
        format: String,
        /// Write the generated parser to this path. Defaults to standard output.
        #[arg(long, value_name = "FILE")]
        out: Option<String>,
        /// For the Kaitai format, additionally compile the spec and parse the
        /// given samples through it as an independent cross-check (FR-38). This
        /// is optional and never required: it reports separately and a missing
        /// compiler is reported as skipped, not failed. The compiler is taken
        /// from `SEXTANT_KAITAI_COMPILER` when set, otherwise from PATH.
        #[arg(long, value_name = "DIR")]
        cross_validate: Option<String>,
        /// Allow `--out` to overwrite an existing file or write outside the
        /// current working directory.
        #[arg(long)]
        force: bool,
    },
    /// Run the accuracy benchmark over the ground-truth corpus (PRD Section 15).
    Bench {
        /// The corpus directory to evaluate. Defaults to the repository corpus.
        #[arg(long, value_name = "DIR")]
        corpus: Option<String>,
        /// Write the machine-readable JSON results to this path.
        #[arg(long, value_name = "FILE")]
        out: Option<String>,
        /// Allow `--out` to overwrite an existing file or write outside the
        /// current working directory.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return report_parse_outcome(&error),
    };
    match cli.command {
        Command::Infer {
            inputs,
            recursive,
            max_bytes_per_sample,
            max_total_bytes,
            no_llm: _,
            provider,
            model,
            max_llm_calls,
            timeout,
            max_messages,
            transport,
            port,
            out,
            force,
        } => {
            let request = provider.as_deref().map(|provider| model::ModelRequest {
                provider,
                model: model.as_deref(),
                max_calls: max_llm_calls,
            });
            run_infer(
                &inputs,
                recursive,
                max_bytes_per_sample,
                max_total_bytes,
                timeout,
                max_messages,
                transport.as_deref(),
                port,
                out.as_deref(),
                force,
                request.as_ref(),
            )
        }
        Command::Inspect {
            report,
            sample,
            color,
            max_bytes_per_sample,
        } => run_inspect(&report, &sample, color, max_bytes_per_sample),
        Command::Export {
            report,
            format,
            out,
            cross_validate,
            force,
        } => run_export(
            &report,
            &format,
            out.as_deref(),
            cross_validate.as_deref(),
            force,
        ),
        Command::Bench { corpus, out, force } => {
            run_bench(corpus.as_deref(), out.as_deref(), force)
        }
    }
}

/// Report a command line that did not parse into a command, with the PRD exit
/// codes (Section 14): `--help` and `--version` print to standard output and
/// exit 0, and a usage error prints to standard error and exits 1, distinct
/// from the input-error code 2.
fn report_parse_outcome(error: &clap::Error) -> ExitCode {
    if error.use_stderr() {
        // The message can quote the offending argument, so it is rendered as
        // plain text and escaped line by line before it reaches the terminal.
        let text = error.to_string();
        let lines: Vec<Cow<'_, str>> = text.split('\n').map(escape_untrusted).collect();
        eprint!("{}", lines.join("\n"));
        ExitCode::from(EXIT_USAGE_ERROR)
    } else {
        // Help and version text is Sextant's own; a closed stream is not an
        // error worth reporting.
        let _ = error.print();
        ExitCode::SUCCESS
    }
}

/// Escape the characters of an untrusted string (a path, a pattern, a
/// command-line argument, or text from a report) that could drive or disguise
/// terminal output: control characters such as escape, carriage return, and
/// newline, and bidirectional, invisible, and other formatting characters (see
/// [`sextant_engine::text::is_unsafe_to_display`]). Each becomes a visible
/// Rust-style escape such as `\u{1b}`; everything else, including ordinary
/// non-ASCII text, is kept as is.
fn escape_untrusted(text: &str) -> Cow<'_, str> {
    sextant_engine::text::escape_for_display(text)
}

/// Run the accuracy benchmark over the ground-truth corpus and print the results
/// table (PRD Section 15). With `--out` it also writes the machine-readable JSON
/// results. The benchmark is statistics-only and fully offline: it runs the
/// verified core over the corpus and reports field-boundary precision, recall,
/// and F1, the perfection rate, role and type accuracy, and native validity.
/// It exits non-zero when any metric falls below its regression floor, so the
/// same command doubles as a regression guard. The PRD Section 15 targets are
/// reported, met or not, but do not decide the exit status.
fn run_bench(corpus: Option<&str>, out: Option<&str>, force: bool) -> ExitCode {
    let mut options = bench::BenchOptions::default();
    if let Some(dir) = corpus {
        options.corpus_dir = PathBuf::from(dir);
    } else if !options.corpus_dir.is_dir() {
        // The default corpus is a sibling of the source tree, so it is present
        // in a workspace checkout but not in an installed binary. Guide the user
        // to point at one explicitly rather than failing with a path that does
        // not exist on their machine.
        eprintln!(
            "sextant bench: no built-in corpus at {}.\n\
             Pass --corpus <dir> to point at a ground-truth corpus, for example \
             the corpus/ directory of a Sextant repository checkout.",
            options.corpus_dir.display()
        );
        return ExitCode::from(EXIT_INPUT_ERROR);
    }

    let report = match bench::run_benchmark(&options) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("sextant bench: could not evaluate the corpus: {error}");
            return ExitCode::from(EXIT_INPUT_ERROR);
        }
    };

    out!("{}", bench::render_table(&report));

    if let Some(path) = out {
        match report.to_json() {
            Ok(json) => {
                if let Err(error) = write_output_file(path, format!("{json}\n").as_bytes(), force) {
                    eprintln!("sextant bench: could not write results to {path}: {error}");
                    return ExitCode::from(EXIT_INPUT_ERROR);
                }
                outln!("\nWrote machine-readable results to {path}");
            }
            Err(error) => {
                eprintln!("sextant bench: could not serialize results: {error}");
                return ExitCode::from(EXIT_INTERNAL_ERROR);
            }
        }
    }

    let failures = report.regression_failures();
    if failures.is_empty() {
        ExitCode::SUCCESS
    } else {
        eprintln!("\nsextant bench: metrics below their regression floors:");
        for failure in &failures {
            eprintln!("  {failure}");
        }
        ExitCode::from(EXIT_NO_HYPOTHESIS)
    }
}

/// Ingest the inputs, run inference, and print a scored field map (Step 6).
/// Without `--provider` the run is statistics-only and fully offline (NFR-4);
/// with it, the model pass runs after statistical inference and every
/// proposal it keeps was verified by the executor (FR-26). When a transport
/// and port are given, the inputs are read as packet captures and protocol
/// inference runs instead (Step 11, FR-2).
#[allow(clippy::too_many_arguments)]
fn run_infer(
    inputs: &[String],
    recursive: bool,
    max_bytes_per_sample: usize,
    max_total_bytes: usize,
    timeout: Option<u64>,
    max_messages: usize,
    transport: Option<&str>,
    port: Option<u16>,
    out: Option<&str>,
    force: bool,
    model_request: Option<&model::ModelRequest<'_>>,
) -> ExitCode {
    if model_request.is_some() && (transport.is_some() || port.is_some()) {
        eprintln!(
            "sextant infer: --provider applies to file-format inference; protocol inference \
             from captures is statistics-only."
        );
        return ExitCode::from(EXIT_USAGE_ERROR);
    }
    // Build the provider before reading any input, so a missing credential or
    // an unknown provider fails fast and nothing is sent.
    let model = match model_request.map(model::Model::prepare).transpose() {
        Ok(model) => model,
        Err(message) => {
            eprintln!("sextant infer: {}", escape_untrusted(&message));
            return ExitCode::from(EXIT_USAGE_ERROR);
        }
    };
    match (transport, port) {
        (Some(transport), Some(port)) => {
            return run_infer_protocol(
                inputs,
                transport,
                port,
                recursive,
                max_bytes_per_sample,
                max_total_bytes,
                timeout,
                max_messages,
                out,
                force,
            );
        }
        (Some(_), None) | (None, Some(_)) => {
            eprintln!(
                "sextant infer: --transport and --port must be given together for capture input."
            );
            return ExitCode::from(EXIT_INPUT_ERROR);
        }
        (None, None) => {}
    }

    let options = IngestOptions::default()
        .with_max_bytes_per_sample(max_bytes_per_sample)
        .with_max_total_bytes(max_total_bytes)
        .with_recursive(recursive);
    let Some(set) = ingest_or_report(inputs, &options, "samples") else {
        return ExitCode::from(EXIT_INPUT_ERROR);
    };

    print_sample_set(&set, "sample", "samples");

    let inference = InferenceOptions {
        limits: limits_with_optional_timeout(timeout),
        // Without --provider no model exists, so the run is statistics-only
        // and offline (NFR-4).
        no_llm: model.is_none(),
    };
    let report = match &model {
        Some(model) => model.infer(&set, &inference),
        None => infer(&set, &inference),
    };
    print_report(&report);
    if let Some(error) = report
        .metadata
        .model
        .as_ref()
        .and_then(|usage| usage.error.as_deref())
    {
        eprintln!(
            "sextant infer: the model contributed nothing ({}); the verified statistics-only \
             result stands",
            escape_untrusted(error)
        );
    }

    if let Some(path) = out {
        let shown = escape_untrusted(path);
        match write_report(&report, path, force) {
            Ok(()) => outln!("\nWrote report to {shown}"),
            Err(error) => {
                eprintln!(
                    "sextant infer: could not write report to {shown}: {}",
                    escape_untrusted(&error.to_string())
                );
                return ExitCode::from(EXIT_INPUT_ERROR);
            }
        }
    }

    if !report.score.fully_verified() {
        eprintln!(
            "sextant infer: the hypothesis did not fully verify every retained sample; inspect the report for failures or resource limits"
        );
        ExitCode::from(EXIT_NO_HYPOTHESIS)
    } else {
        ExitCode::SUCCESS
    }
}

/// Read the inputs as packet captures, extract the transport payloads on the
/// selected port, run protocol inference, and print the clustered field map
/// (Step 11, FR-2). Writes the report with `--out` so it can be exported to a
/// Wireshark dissector, the primary output for the protocol track.
///
/// Capture inputs are resolved exactly like file inputs, through [`ingest`]:
/// files, directories (recursively with `-r`), and globs, with the same
/// per-sample and total byte caps and their notices (FR-5, FR-24), the same
/// refusal of FIFOs, sockets, and devices, and the same de-duplication of a
/// capture named twice. A capture clipped by a cap is reported, as are packets
/// the reader skipped or dropped.
#[allow(clippy::too_many_arguments)]
fn run_infer_protocol(
    inputs: &[String],
    transport: &str,
    port: u16,
    recursive: bool,
    max_bytes_per_sample: usize,
    max_total_bytes: usize,
    timeout: Option<u64>,
    max_messages: usize,
    out: Option<&str>,
    force: bool,
) -> ExitCode {
    let Some(transport) = Transport::parse(transport) else {
        eprintln!(
            "sextant infer: unknown transport `{}`. Use tcp or udp.",
            escape_untrusted(transport)
        );
        return ExitCode::from(EXIT_INPUT_ERROR);
    };

    let options = IngestOptions::default()
        .with_max_bytes_per_sample(max_bytes_per_sample)
        .with_max_total_bytes(max_total_bytes)
        .with_recursive(recursive);
    let Some(set) = ingest_or_report(inputs, &options, "captures") else {
        return ExitCode::from(EXIT_INPUT_ERROR);
    };
    print_sample_set(&set, "file", "files");
    for sample in &set.samples {
        if sample.provenance.is_truncated() {
            outln!(
                "note: {} was clipped to {} of {} bytes by --max-bytes-per-sample; packets \
                 after that point were not read.",
                escape_untrusted(&sample.path().display().to_string()),
                sample.provenance.length,
                sample.provenance.original_length
            );
        }
    }

    let mut extract = ExtractOptions::new(transport, port);
    let mut messages = Vec::new();
    let mut message_cap_hit = false;
    for sample in &set.samples {
        let path = sample.path().display().to_string();
        let shown = escape_untrusted(&path);
        // Leave room under the global message cap for this capture. With none
        // left, the reader still reports whether a further message existed.
        extract.max_messages = max_messages.saturating_sub(messages.len());
        let extraction = match extract_capture(sample.bytes(), &extract) {
            Ok(extraction) => extraction,
            // A file that a directory or glob swept in and that is not a
            // capture at all (a README beside the captures) is skipped with a
            // note. A file named explicitly, or a damaged capture, is an error.
            Err(PcapError::UnknownFormat)
                if !inputs.iter().any(|input| Path::new(input) == sample.path()) =>
            {
                outln!("note: {shown}: skipped, not a pcap or pcapng capture.");
                continue;
            }
            Err(error) => {
                eprintln!("sextant infer: {shown}: {error}");
                return ExitCode::from(EXIT_INPUT_ERROR);
            }
        };
        for notice in extraction.notices() {
            outln!("note: {shown}: {notice}.");
        }
        messages.extend(extraction.messages);
        if extraction.message_cap_reached {
            message_cap_hit = true;
            break;
        }
    }
    let cap_note = format!(
        "note: stopped at the --max-messages cap of {max_messages}; further messages were ignored."
    );

    if messages.is_empty() {
        if message_cap_hit {
            eprintln!("{cap_note}");
        }
        eprintln!(
            "sextant infer: no {transport} payloads on port {port} were found in the capture(s)."
        );
        return ExitCode::from(EXIT_INPUT_ERROR);
    }

    // Re-index the messages across all captures so association and sequence
    // detection see one ordered stream.
    for (index, message) in messages.iter_mut().enumerate() {
        message.index = index;
    }

    let limits = limits_with_optional_timeout(timeout);
    let inference = infer_protocol(&messages, transport, port, &limits);

    outln!(
        "Extracted {} {transport} message(s) on port {port}.",
        inference.message_count
    );
    if message_cap_hit {
        outln!("{cap_note}");
    }
    print_clustering(&inference, port);
    outln!(
        "Request/response pairs associated: {}.",
        inference.associations.len()
    );
    print_report(&inference.report);

    if let Some(path) = out {
        let shown = escape_untrusted(path);
        match write_report(&inference.report, path, force) {
            Ok(()) => {
                outln!("\nWrote report to {shown}");
                outln!(
                    "Export a Wireshark dissector with: sextant export {shown} --format wireshark"
                );
            }
            Err(error) => {
                eprintln!(
                    "sextant infer: could not write report to {shown}: {}",
                    escape_untrusted(&error.to_string())
                );
                return ExitCode::from(EXIT_INPUT_ERROR);
            }
        }
    }

    if !inference.report.score.fully_verified() {
        eprintln!(
            "sextant infer: the hypothesis did not fully verify every retained message; inspect the report for failures or resource limits"
        );
        ExitCode::from(EXIT_NO_HYPOTHESIS)
    } else {
        ExitCode::SUCCESS
    }
}

/// Print how the messages clustered by type (FR-2), naming the messages the
/// clusters cover: the requests toward the port when both directions are
/// present, otherwise every message.
fn print_clustering(inference: &ProtocolInference, port: u16) {
    let clustering: &Clustering = &inference.clustering;
    let covered = clustering.clustered();
    let excluded = clustering.excluded_short;
    let members = match clustering.population {
        Population::Requests => format!("request(s) sent to port {port}"),
        Population::Responses => format!("response(s) sent from port {port}"),
        Population::AllMessages => "message(s) in either direction".to_owned(),
    };
    let scope = if excluded == 0 {
        format!("all {covered} {members}")
    } else {
        format!(
            "{covered} of the {} {members}, leaving out {excluded} too short to hold the type byte",
            covered + excluded
        )
    };
    match &clustering.discriminant {
        Some(discriminant) => {
            outln!(
                "Message clustering over {scope}: {} type(s) discriminated at byte offset {}.",
                clustering.clusters.len(),
                discriminant.offset
            );
            for cluster in &clustering.clusters {
                if let Some(value) = cluster.type_value {
                    outln!("  type {value:#04x}: {} message(s)", cluster.indices.len());
                }
            }
        }
        None => outln!(
            "Message clustering over {scope}: a single message type (no discriminant found)."
        ),
    }
}

/// Read at most `cap` bytes from a regular file. A very large file is never
/// read whole: the read limit bounds both the bytes read and the allocation, so
/// an attacker-sized input costs only `cap` bytes of memory (FR-24, FR-5). The
/// file is checked through its open handle, which is opened without blocking
/// where the platform allows, so a FIFO, socket, or device is refused instead
/// of hanging the read.
fn read_capped(path: &str, cap: usize) -> std::io::Result<Vec<u8>> {
    read_regular_file(Path::new(path), cap).map(|(data, _)| data)
}

/// Apply an optional CLI timeout without clearing the default five-second cap
/// when the flag is omitted.
fn limits_with_optional_timeout(timeout: Option<u64>) -> Limits {
    match timeout {
        Some(seconds) => Limits::default().with_timeout(Duration::from_secs(seconds)),
        None => Limits::default(),
    }
}

/// Serialize a report to pretty JSON and write it to `path` (FR-34).
fn write_report(report: &Report, path: &str, force: bool) -> std::io::Result<()> {
    let json = report
        .to_json()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    write_output_file(path, json.as_bytes(), force)
}

/// Write `bytes` to `path`, refusing overwrites and cwd escapes without `--force`.
fn write_output_file(path: &str, bytes: &[u8], force: bool) -> std::io::Result<()> {
    use std::io::Write;

    check_output_path(path, force)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        // Atomically refuse existing files, including dangling symlinks and
        // files created after the path check.
        options.create_new(true);
    }
    options.open(path)?.write_all(bytes)
}

/// Refuse to overwrite an existing file or write outside the current working
/// directory unless `force` is set.
fn check_output_path(path: &str, force: bool) -> std::io::Result<()> {
    let target = Path::new(path);
    if !force && std::fs::symlink_metadata(target).is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("refusing to overwrite existing file `{path}` without --force"),
        ));
    }
    if force {
        return Ok(());
    }
    let cwd = std::env::current_dir()?;
    let absolute = if target.is_absolute() {
        target.to_path_buf()
    } else {
        cwd.join(target)
    };
    // Compare the parent directory (or the path itself) against cwd after
    // canonicalizing existing components so `../` escapes are caught.
    let anchor = if absolute.exists() {
        fs_canonicalize(&absolute)?
    } else if let Some(parent) = absolute.parent() {
        if parent.as_os_str().is_empty() {
            cwd.clone()
        } else if parent.exists() {
            fs_canonicalize(parent)?.join(absolute.file_name().unwrap_or_default())
        } else {
            absolute.clone()
        }
    } else {
        absolute.clone()
    };
    let cwd_canon = fs_canonicalize(&cwd)?;
    if !anchor.starts_with(&cwd_canon) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "refusing to write `{path}` outside the current working directory without --force"
            ),
        ));
    }
    Ok(())
}

fn fs_canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(path)
}

/// Load a report JSON file with a hard size cap, then validate its IR.
fn load_report(path: &str) -> Result<Report, String> {
    let file_len = std::fs::metadata(path)
        .map(|meta| meta.len() as usize)
        .map_err(|error| format!("could not read report {path}: {error}"))?;
    if file_len > DEFAULT_MAX_REPORT_BYTES {
        return Err(format!(
            "{path} is {file_len} bytes, above the {DEFAULT_MAX_REPORT_BYTES}-byte report size cap"
        ));
    }
    let bytes = read_capped(path, DEFAULT_MAX_REPORT_BYTES)
        .map_err(|error| format!("could not read report {path}: {error}"))?;
    let text =
        String::from_utf8(bytes).map_err(|error| format!("{path} is not valid UTF-8: {error}"))?;
    let report = Report::from_json(&text)
        .map_err(|error| format!("{path} is not a valid report: {error}"))?;
    report
        .format
        .validate()
        .map_err(|error| format!("{path} contains an invalid format hypothesis:\n{error}"))?;
    Ok(report)
}

/// Read a report and a sample, then print the annotated hex view (FR-35).
fn run_inspect(
    report_path: &str,
    sample_path: &str,
    color: bool,
    max_bytes_per_sample: usize,
) -> ExitCode {
    let report = match load_report(report_path) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("sextant inspect: {error}");
            return ExitCode::from(EXIT_INPUT_ERROR);
        }
    };
    let sample = match read_capped(sample_path, max_bytes_per_sample) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("sextant inspect: could not read sample {sample_path}: {error}");
            return ExitCode::from(EXIT_INPUT_ERROR);
        }
    };
    if let Ok(meta) = std::fs::metadata(sample_path) {
        if meta.len() as usize > sample.len() {
            eprintln!(
                "sextant inspect: sample truncated to {max_bytes_per_sample} bytes \
                 (file is {} bytes); raise --max-bytes-per-sample to read more.",
                meta.len()
            );
        }
    }

    let options = InspectOptions {
        color,
        ..InspectOptions::default()
    };
    out!("{}", render(&report, &sample, &options));
    ExitCode::SUCCESS
}

/// Read a report, export the chosen IR to a parser format, and write it out
/// (FR-36, FR-37). Optionally cross-validate a Kaitai export (FR-38).
fn run_export(
    report_path: &str,
    format_name: &str,
    out: Option<&str>,
    cross_validate: Option<&str>,
    force: bool,
) -> ExitCode {
    let Some(target) = ExportFormat::parse(format_name) else {
        eprintln!(
            "sextant export: unknown format `{format_name}`. Use one of: kaitai, imhex, wireshark, 010."
        );
        return ExitCode::from(EXIT_EXPORT_ERROR);
    };

    let report = match load_report(report_path) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("sextant export: {error}");
            return ExitCode::from(EXIT_INPUT_ERROR);
        }
    };

    let parser = match export(&report.format, target) {
        Ok(parser) => parser,
        Err(error) => {
            eprintln!("sextant export: {error}");
            return ExitCode::from(EXIT_EXPORT_ERROR);
        }
    };

    match out {
        Some(path) => {
            if let Err(error) = write_output_file(path, parser.as_bytes(), force) {
                eprintln!("sextant export: could not write {path}: {error}");
                return ExitCode::from(EXIT_EXPORT_ERROR);
            }
            outln!("Wrote {target} parser to {path}");
        }
        None => out!("{parser}"),
    }

    if let Some(dir) = cross_validate {
        if let Some(code) = run_cross_validate(&report, target, dir) {
            return code;
        }
    }

    ExitCode::SUCCESS
}

/// Run the optional Kaitai cross-check on every sample in `dir` (FR-38). Returns
/// `Some(exit code)` on a hard failure and `None` otherwise. A cross-check is
/// only meaningful for the Kaitai target and never required by the pipeline.
fn run_cross_validate(report: &Report, target: ExportFormat, dir: &str) -> Option<ExitCode> {
    if target != ExportFormat::Kaitai {
        eprintln!("sextant export: --cross-validate applies only to the kaitai format; ignoring.");
        return None;
    }
    let samples = match read_sample_dir(dir) {
        Ok(samples) => samples,
        Err(error) => {
            eprintln!("sextant export: could not read samples from {dir}: {error}");
            return Some(ExitCode::from(EXIT_INPUT_ERROR));
        }
    };
    match sextant_export::crossval::cross_validate(&report.format, &samples) {
        sextant_export::crossval::CrossValidation::Passed { samples } => {
            outln!("Cross-validation: the Kaitai spec compiled and parsed all {samples} samples.");
            None
        }
        sextant_export::crossval::CrossValidation::Skipped { reason } => {
            outln!("Cross-validation: skipped ({reason}).");
            None
        }
        sextant_export::crossval::CrossValidation::Failed { detail } => {
            eprintln!("sextant export: cross-validation failed: {detail}");
            Some(ExitCode::from(EXIT_EXPORT_ERROR))
        }
    }
}

/// Read every regular file in a directory into memory, sorted by name, with the
/// same per-sample and total byte caps as ingestion (FR-5, FR-24).
fn read_sample_dir(dir: &str) -> std::io::Result<Vec<Vec<u8>>> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .collect();
    paths.sort();
    let mut samples = Vec::new();
    let mut total = 0usize;
    for path in paths {
        let remaining = DEFAULT_MAX_TOTAL_BYTES.saturating_sub(total);
        if remaining == 0 {
            break;
        }
        let cap = DEFAULT_MAX_BYTES_PER_SAMPLE.min(remaining);
        let bytes = read_capped(&path.to_string_lossy(), cap)?;
        total += bytes.len();
        samples.push(bytes);
    }
    Ok(samples)
}

/// Print the scored field map and the fit-score breakdown of a report. Names,
/// labels, and step descriptions are escaped, since a hypothesis can carry
/// names from a model.
fn print_report(report: &Report) {
    let score = &report.score;
    outln!();
    outln!(
        "Best hypothesis: {} (fit score {:.3})",
        escape_untrusted(&report.format.name),
        score.overall
    );
    outln!(
        "  coverage {:.3}  consistency {:.3}  generality {:.3}  structure {:.3}",
        score.coverage,
        score.consistency,
        score.generality,
        score.structure
    );
    let verified = score
        .samples
        .iter()
        .filter(|sample| sample.fully_verified())
        .count();
    outln!(
        "  {verified} of {} sample(s) fully verified; {} checksum check(s) passed",
        score.samples.len(),
        score.checksums_passed()
    );
    match &report.metadata.model {
        None => outln!("  mode: statistics-only (no language model, no network egress)"),
        Some(usage) => {
            outln!(
                "  mode: model-assisted; every accepted proposal was verified by the native executor"
            );
            outln!(
                "  model: {} {}, {} call(s), {} input and {} output token(s); {} proposal(s) \
                 accepted, {} rejected",
                escape_untrusted(&usage.provider),
                escape_untrusted(&usage.model),
                usage.calls,
                usage.input_tokens,
                usage.output_tokens,
                usage.accepted,
                usage.rejected
            );
        }
    }

    outln!("Field map:");
    for entry in &report.field_map {
        let indent = "  ".repeat(entry.depth + 1);
        outln!(
            "{indent}{name}: {role}, {kind}, {size} (confidence {conf:.2})",
            name = escape_untrusted(&entry.name),
            role = escape_untrusted(&entry.role),
            kind = escape_untrusted(&entry.kind),
            size = escape_untrusted(&entry.size),
            conf = entry.confidence,
        );
    }
    outln!(
        "  (confidence describes evidence from these samples, not certainty about field meaning; \
         per-field evidence is in the report JSON)"
    );

    if report.refinement.is_empty() {
        outln!("Refinement: no improving change was found (already converged).");
    } else {
        outln!(
            "Refinement: {} accepted change(s):",
            report.refinement.len()
        );
        for step in &report.refinement {
            outln!(
                "  {} (score {:.3} to {:.3})",
                escape_untrusted(&step.description),
                step.score_before,
                step.score_after
            );
        }
    }
}

/// Ingest `inputs`, or report why nothing usable came of them. On an ingestion
/// error, or when the inputs hold no `what` at all, the reason and any notices
/// that explain it (a skipped FIFO, a traversal limit) go to standard error and
/// `None` is returned for the caller to exit with the input-error code.
fn ingest_or_report(inputs: &[String], options: &IngestOptions, what: &str) -> Option<SampleSet> {
    match ingest(inputs, options) {
        Ok(set) if set.is_empty() => {
            for notice in &set.notices {
                eprintln!("note: {}", escape_untrusted(&notice.to_string()));
            }
            eprintln!("sextant infer: no {what} found in the given inputs");
            None
        }
        Ok(set) => Some(set),
        Err(error) => {
            eprintln!("sextant infer: {}", escape_untrusted(&error.to_string()));
            None
        }
    }
}

/// Print the ingested sample count, each sample's path (escaped, since file
/// names are untrusted) and retained size, the total, and any cap notices to
/// standard output. `singular` and `plural_form` name what the samples are.
fn print_sample_set(set: &SampleSet, singular: &str, plural_form: &str) {
    outln!(
        "Ingested {} {} ({} bytes total).",
        set.len(),
        plural(set.len(), singular, plural_form),
        set.total_bytes
    );
    for sample in &set.samples {
        let path = sample.provenance.path.display().to_string();
        let path = escape_untrusted(&path);
        if sample.provenance.is_truncated() {
            outln!(
                "  {path}: {} bytes (clipped from {} bytes)",
                sample.provenance.length,
                sample.provenance.original_length
            );
        } else {
            outln!("  {path}: {} bytes", sample.provenance.length);
        }
    }
    for notice in &set.notices {
        outln!("note: {}", escape_untrusted(&notice.to_string()));
    }
}

/// Choose the singular or plural word for a count.
fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use std::time::Duration;

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

    #[test]
    fn untrusted_text_is_escaped_for_the_terminal() {
        // Clean text, including non-ASCII names, is borrowed unchanged.
        assert!(matches!(
            escape_untrusted("caf\u{e9}/sample_01.bin"),
            Cow::Borrowed(_)
        ));
        assert_eq!(
            escape_untrusted("a\u{1b}[2Jb\r\nc\u{9b}d"),
            "a\\u{1b}[2Jb\\r\\nc\\u{9b}d"
        );
        for bidi in ['\u{202a}', '\u{202e}', '\u{2066}', '\u{2069}'] {
            let escaped = escape_untrusted(&format!("x{bidi}y")).into_owned();
            assert!(!escaped.contains(bidi), "{escaped:?}");
            assert!(escaped.starts_with("x\\u{"), "{escaped:?}");
        }
        // Windows path separators and quotes are left alone.
        assert_eq!(
            escape_untrusted("C:\\data\\\"a\".bin"),
            "C:\\data\\\"a\".bin"
        );
    }

    #[test]
    fn omitted_timeout_keeps_the_default_five_second_cap() {
        let limits = limits_with_optional_timeout(None);
        assert_eq!(limits.timeout, Some(Duration::from_secs(5)));
        let raised = limits_with_optional_timeout(Some(30));
        assert_eq!(raised.timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn output_path_refuses_overwrite_without_force() {
        let dir = std::env::temp_dir().join(format!("sextant-out-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("exists.txt");
        std::fs::write(&path, b"old").expect("seed");
        let err = check_output_path(&path.to_string_lossy(), false).expect_err("overwrite");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        check_output_path(&path.to_string_lossy(), true).expect("force allows overwrite");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
