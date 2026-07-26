//! The `sextant` command-line interface.
//!
//! The `infer` subcommand runs the statistics-only inference pipeline end to end
//! (Step 6): it ingests files, directories, and glob patterns into a normalized
//! sample set (Step 4), generates and scores candidate hypotheses, selects the
//! best, refines it under the non-regression invariant, and prints a scored field
//! map. With `--out` it also writes the machine-readable JSON report (FR-34).
//! With `--no-llm` (and today in every CLI mode, since provider flags are not
//! exposed yet) the run is fully offline and performs zero network egress
//! (NFR-4).
//!
//! The `inspect` subcommand reads a sample through a report and renders an
//! annotated hex view (FR-35). The `export` subcommand reads a report and emits
//! an editable parser (Kaitai, ImHex, Wireshark, or 010) from the chosen IR
//! (FR-36, FR-37), with an optional Kaitai cross-check (FR-38). The `bench`
//! subcommand runs the accuracy benchmark over the ground-truth corpus and
//! prints the PRD Section 15 metrics table (Step 12), exiting non-zero if any
//! configured target is missed so it doubles as the CI regression guard.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use sextant_engine::{
    Clustering, DEFAULT_MAX_BYTES_PER_SAMPLE, DEFAULT_MAX_MESSAGES, DEFAULT_MAX_REPORT_BYTES,
    DEFAULT_MAX_TOTAL_BYTES, ExtractOptions, InferenceOptions, IngestOptions, InspectOptions,
    Limits, ProtocolInference, Report, SampleSet, Transport, extract_messages, infer,
    infer_protocol, ingest, render,
};
use sextant_export::{ExportFormat, export};

/// The PRD exit code for an input error (Section 14): a path that does not
/// exist, a malformed glob, an unreadable file, or no usable samples.
const EXIT_INPUT_ERROR: u8 = 2;
/// The PRD exit code for inference producing no usable hypothesis (Section 14).
const EXIT_NO_HYPOTHESIS: u8 = 3;
/// The PRD exit code for an export error (Section 14).
const EXIT_EXPORT_ERROR: u8 = 4;
/// The PRD exit code for an internal error (Section 14).
const EXIT_INTERNAL_ERROR: u8 = 5;

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
        /// The CLI does not expose provider flags yet, so this is the default
        /// behavior today; the flag documents intent and guarantees the offline
        /// path.
        #[arg(long)]
        no_llm: bool,
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
    let cli = Cli::parse();
    match cli.command {
        Command::Infer {
            inputs,
            recursive,
            max_bytes_per_sample,
            max_total_bytes,
            no_llm: _,
            timeout,
            max_messages,
            transport,
            port,
            out,
            force,
        } => run_infer(
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
        ),
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

/// Run the accuracy benchmark over the ground-truth corpus and print the results
/// table (PRD Section 15). With `--out` it also writes the machine-readable JSON
/// results. The benchmark is statistics-only and fully offline: it runs the
/// verified core over the corpus and reports field-boundary precision, recall,
/// and F1, the perfection rate, role and type accuracy, and parser validity.
/// It exits non-zero if any configured target is missed, so the same command CI
/// runs as a regression guard fails the build on an accuracy drop.
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

    print!("{}", bench::render_table(&report));

    if let Some(path) = out {
        match report.to_json() {
            Ok(json) => {
                if let Err(error) = write_output_file(path, format!("{json}\n").as_bytes(), force) {
                    eprintln!("sextant bench: could not write results to {path}: {error}");
                    return ExitCode::from(EXIT_INPUT_ERROR);
                }
                println!("\nWrote machine-readable results to {path}");
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
        eprintln!("\nsextant bench: metrics below configured thresholds:");
        for failure in &failures {
            eprintln!("  {failure}");
        }
        ExitCode::from(EXIT_NO_HYPOTHESIS)
    }
}

/// Ingest the inputs, run statistics-only inference, and print a scored field
/// map (Step 6). Every run is fully offline today, with or without `--no-llm`
/// (NFR-4); the flag is accepted so scripts can pin the guarantee. When a
/// transport and port are given, the inputs are read as packet captures and
/// protocol inference runs instead (Step 11, FR-2).
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
) -> ExitCode {
    match (transport, port) {
        (Some(transport), Some(port)) => {
            return run_infer_protocol(
                inputs,
                transport,
                port,
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

    let inference = InferenceOptions {
        limits: limits_with_optional_timeout(timeout),
        // CLI provider flags are not yet wired in, so every run is
        // statistics-only and offline whether or not --no-llm was given
        // (NFR-4). The field map states the mode, so a default run is not
        // warned at as if it were degraded.
        no_llm: true,
    };
    let report = infer(&set, &inference);
    print_report(&report);

    if let Some(path) = out {
        match write_report(&report, path, force) {
            Ok(()) => println!("\nWrote report to {path}"),
            Err(error) => {
                eprintln!("sextant infer: could not write report to {path}: {error}");
                return ExitCode::from(EXIT_INPUT_ERROR);
            }
        }
    }

    if report.field_map.is_empty() {
        eprintln!("sextant infer: no usable hypothesis was produced");
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
/// The byte caps bound memory exactly as they do for file ingestion (FR-5,
/// FR-24): each capture is read with a bounded reader so a single attacker-sized
/// pcap cannot exhaust memory, and reading stops once the captures together would
/// exceed the total cap.
#[allow(clippy::too_many_arguments)]
fn run_infer_protocol(
    inputs: &[String],
    transport: &str,
    port: u16,
    max_bytes_per_sample: usize,
    max_total_bytes: usize,
    timeout: Option<u64>,
    max_messages: usize,
    out: Option<&str>,
    force: bool,
) -> ExitCode {
    let Some(transport) = Transport::parse(transport) else {
        eprintln!("sextant infer: unknown transport `{transport}`. Use tcp or udp.");
        return ExitCode::from(EXIT_INPUT_ERROR);
    };
    let mut extract = ExtractOptions::new(transport, port);
    extract.max_messages = max_messages;

    let mut messages = Vec::new();
    let mut total_read = 0usize;
    let mut message_cap_hit = false;
    for input in inputs {
        if messages.len() >= max_messages {
            message_cap_hit = true;
            break;
        }
        // A capture is read with the same caps file ingestion enforces: at most
        // the per-sample cap from any one file, and never past the total cap.
        let remaining = max_total_bytes.saturating_sub(total_read);
        if remaining == 0 {
            eprintln!(
                "sextant infer: reached the total-input cap of {max_total_bytes} bytes; \
                 skipping remaining capture(s)."
            );
            break;
        }
        let cap = max_bytes_per_sample.min(remaining);
        let bytes = match read_capped(input, cap) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("sextant infer: could not read capture {input}: {error}");
                return ExitCode::from(EXIT_INPUT_ERROR);
            }
        };
        total_read += bytes.len();
        // Leave room under the global message cap for this capture.
        extract.max_messages = max_messages.saturating_sub(messages.len());
        match extract_messages(&bytes, &extract) {
            Ok(extracted) => messages.extend(extracted),
            Err(error) => {
                eprintln!("sextant infer: {input}: {error}");
                return ExitCode::from(EXIT_INPUT_ERROR);
            }
        }
    }
    if messages.len() >= max_messages {
        message_cap_hit = true;
        messages.truncate(max_messages);
    }

    if messages.is_empty() {
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

    println!(
        "Extracted {} {transport} message(s) on port {port}.",
        inference.message_count
    );
    if message_cap_hit {
        println!(
            "note: stopped at the --max-messages cap of {max_messages}; further messages were ignored."
        );
    }
    print_clustering(&inference);
    println!(
        "Request/response pairs associated: {}.",
        inference.associations.len()
    );
    print_report(&inference.report);

    if let Some(path) = out {
        match write_report(&inference.report, path, force) {
            Ok(()) => {
                println!("\nWrote report to {path}");
                println!(
                    "Export a Wireshark dissector with: sextant export {path} --format wireshark"
                );
            }
            Err(error) => {
                eprintln!("sextant infer: could not write report to {path}: {error}");
                return ExitCode::from(EXIT_INPUT_ERROR);
            }
        }
    }

    if inference.report.field_map.is_empty() {
        eprintln!("sextant infer: no usable hypothesis was produced");
        ExitCode::from(EXIT_NO_HYPOTHESIS)
    } else {
        ExitCode::SUCCESS
    }
}

/// Print how the messages clustered by type (FR-2).
fn print_clustering(inference: &ProtocolInference) {
    let clustering: &Clustering = &inference.clustering;
    match &clustering.discriminant {
        Some(discriminant) => {
            println!(
                "Message clustering: {} type(s) discriminated at byte offset {}.",
                clustering.clusters.len(),
                discriminant.offset
            );
            for cluster in &clustering.clusters {
                if let Some(value) = cluster.type_value {
                    println!("  type {value:#04x}: {} message(s)", cluster.indices.len());
                }
            }
        }
        None => println!("Message clustering: a single message type (no discriminant found)."),
    }
}

/// Read at most `cap` bytes from a file. A very large capture is never read
/// whole: the read limit bounds both the bytes read and the allocation, so an
/// attacker-sized pcap costs only `cap` bytes of memory (FR-24, FR-5).
fn read_capped(path: &str, cap: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)?;
    let mut data = Vec::new();
    file.take(cap as u64).read_to_end(&mut data)?;
    Ok(data)
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
    check_output_path(path, force)?;
    std::fs::write(path, bytes)
}

/// Refuse to overwrite an existing file or write outside the current working
/// directory unless `force` is set.
fn check_output_path(path: &str, force: bool) -> std::io::Result<()> {
    let target = Path::new(path);
    if !force && target.exists() {
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
    print!("{}", render(&report, &sample, &options));
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
            println!("Wrote {target} parser to {path}");
        }
        None => print!("{parser}"),
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
            println!(
                "Cross-validation: the Kaitai spec compiled and parsed all {samples} samples."
            );
            None
        }
        sextant_export::crossval::CrossValidation::Skipped { reason } => {
            println!("Cross-validation: skipped ({reason}).");
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

/// Print the scored field map and the fit-score breakdown of a report.
fn print_report(report: &Report) {
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
    println!(
        "  (confidence: 0.00 weak evidence to 1.00 verified against every sample; \
         per-field evidence is in the report JSON)"
    );

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
