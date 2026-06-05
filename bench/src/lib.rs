//! Evaluation and benchmark harness for the Sextant ground-truth corpus.
//!
//! This crate loads the corpus under `corpus/`, runs statistics-only inference
//! over each format, and computes the accuracy metrics that PRD Section 15
//! defines: field-boundary precision, recall, and F1; the perfection rate;
//! semantic role and type accuracy; and parser validity. [`run_benchmark`]
//! produces a [`BenchReport`] that renders both a human-readable results table
//! and machine-readable JSON, and that the README benchmark numbers and the CI
//! regression guard are generated from (so the published numbers are never
//! hand-written and cannot silently drift).
//!
//! The ground-truth schema here is intentionally independent of the engine's
//! internal IR (`sextant-ir`). Keeping the corpus description stable as the
//! engine evolves means accuracy numbers stay comparable over time.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub mod accuracy;
pub mod report;

pub use accuracy::{CorpusMetrics, FormatMetrics, SampleMetrics, evaluate_corpus, evaluate_format};
pub use report::{
    Baseline, BenchOptions, BenchReport, FormatReport, Summary, TargetCheck, Targets,
    render_readme_section, render_table, run_benchmark,
};

/// The file-format corpus the statistics-only MVP is measured against (PRD
/// Section 15). These are the formats present under `corpus/` with the
/// header-and-record ground-truth schema this harness evaluates. The protocol
/// track (Modbus/TCP and the toy protocol) is captured-packet input with its own
/// ground-truth schema and is exercised by the Step 11 protocol tests and the
/// Wireshark dissector round-trip, not by these file-format metrics.
pub const FILE_FORMAT_CORPUS: [&str; 5] = ["tlv", "scma", "stot", "sdlp", "png"];

/// A hand-verified description of a single corpus format.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GroundTruth {
    /// Short machine name for the format. Matches the corpus subdirectory.
    pub format: String,
    /// Human-readable name for the format.
    pub display_name: String,
    /// One-paragraph description of what the format exercises.
    pub description: String,
    /// Default byte order, for example `little` or `big`.
    pub endianness: String,
    /// Where the samples came from and how they may be redistributed.
    pub provenance: Provenance,
    /// The fixed header fields and the repeating record fields.
    pub structure: Structure,
    /// The sample files that belong to this format.
    pub samples: Vec<SampleEntry>,
}

/// Provenance metadata recording the origin and license of the samples.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Provenance {
    /// How the data was obtained, for example `synthetic` or `public-spec`.
    pub source: String,
    /// Human-readable note on where the samples came from.
    pub origin: String,
    /// License under which the samples may be redistributed.
    pub license: String,
    /// Any caveats, such as whether the samples were trimmed.
    pub notes: String,
}

/// The structural template of a format: a fixed header and a repeating record.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Structure {
    /// Fields at the start of every sample, in order.
    pub header: Vec<Field>,
    /// Fields of one repeating record, in order.
    pub record: Vec<Field>,
}

/// One field in a ground-truth structure.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Field {
    /// Field name.
    pub name: String,
    /// Absolute offset from the start of the sample, when fixed and known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// How the field's size is determined.
    pub size: SizeRule,
    /// The field's data type, for example `u8`, `u16le`, or `bytes`.
    #[serde(rename = "type")]
    pub ty: String,
    /// The field's semantic role, for example `magic`, `length`, or `payload`.
    pub role: String,
    /// An expected constant value, when the field is always the same.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constant: Option<String>,
}

/// How the size of a field is determined.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SizeRule {
    /// A fixed number of bytes.
    Fixed(u64),
    /// Derived from another field, named here (for example `length`).
    Derived(String),
}

/// One sample file belonging to a format.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SampleEntry {
    /// Path to the sample, relative to the format directory.
    pub path: String,
    /// Expected size of the sample in bytes.
    pub size: u64,
    /// Number of records the sample contains.
    pub record_count: u64,
}

/// Returns the path to the repository `corpus` directory.
#[must_use]
pub fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the bench crate always has a parent directory")
        .join("corpus")
}

/// Parses a ground-truth description from JSON text.
///
/// # Errors
///
/// Returns an error if the text is not valid ground-truth JSON.
pub fn parse_ground_truth(text: &str) -> serde_json::Result<GroundTruth> {
    serde_json::from_str(text)
}

/// Loads and parses the ground-truth description for one format under the
/// repository corpus directory.
///
/// # Errors
///
/// Returns an error if the `ground_truth.json` file cannot be read or does not
/// parse as a valid ground-truth description.
pub fn load_ground_truth(format: &str) -> std::io::Result<GroundTruth> {
    load_ground_truth_in(&corpus_dir(), format)
}

/// Loads and parses the ground-truth description for one format under an
/// arbitrary corpus directory, so the benchmark can run against a corpus passed
/// on the command line (the PRD `--corpus` option, Section 14).
///
/// # Errors
///
/// Returns an error if the `ground_truth.json` file cannot be read or does not
/// parse as a valid ground-truth description.
pub fn load_ground_truth_in(corpus_dir: &Path, format: &str) -> std::io::Result<GroundTruth> {
    let path = corpus_dir.join(format).join("ground_truth.json");
    let text = std::fs::read_to_string(&path)?;
    parse_ground_truth(&text).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{}: {error}", path.display()),
        )
    })
}

/// Reads the raw bytes of a sample listed in a ground-truth description, under
/// the repository corpus directory.
///
/// # Errors
///
/// Returns an error if the sample file cannot be read.
pub fn read_sample(format: &str, sample: &SampleEntry) -> std::io::Result<Vec<u8>> {
    read_sample_in(&corpus_dir(), format, sample)
}

/// The per-sample byte cap the benchmark reads under. A corpus passed with
/// `--corpus` is untrusted: its ground truth could name an arbitrarily large
/// sample, so each read is bounded to keep `sextant bench` within the repository
/// resource-limit invariant (FR-24, NFR-2) rather than allocating a whole file
/// up front. It matches the engine's per-sample ingestion cap so the bytes the
/// benchmark evaluates are the same the pipeline would ingest. The corpus
/// samples are tiny, so this never clips a real sample.
pub const SAMPLE_READ_CAP: usize = sextant_engine::DEFAULT_MAX_BYTES_PER_SAMPLE;

/// Reads the raw bytes of a sample listed in a ground-truth description, under
/// an arbitrary corpus directory, bounded by [`SAMPLE_READ_CAP`] so a hostile
/// corpus cannot drive an unbounded allocation.
///
/// # Errors
///
/// Returns an error if the sample file cannot be read.
pub fn read_sample_in(
    corpus_dir: &Path,
    format: &str,
    sample: &SampleEntry,
) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let path = corpus_dir.join(format).join(&sample.path);
    let file = std::fs::File::open(path)?;
    let mut data = Vec::new();
    // `take` bounds both the bytes read and the allocation: an attacker-sized
    // sample costs at most the cap, not the file's full length.
    file.take(SAMPLE_READ_CAP as u64).read_to_end(&mut data)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_ground_truth_loads_and_matches_its_samples() {
        let ground_truth = load_ground_truth("png").expect("the png ground truth should load");

        assert_eq!(ground_truth.format, "png");
        assert_eq!(ground_truth.endianness, "big");
        assert!(!ground_truth.structure.header.is_empty());
        assert!(!ground_truth.structure.record.is_empty());
        assert_eq!(ground_truth.samples.len(), 3);

        const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        for sample in &ground_truth.samples {
            let bytes = read_sample(&ground_truth.format, sample).unwrap_or_else(|error| {
                panic!("sample {} should be readable: {error}", sample.path)
            });
            assert_eq!(
                bytes.len() as u64,
                sample.size,
                "recorded size for {} does not match the file",
                sample.path
            );
            assert_eq!(
                &bytes[0..8],
                &PNG_SIGNATURE,
                "sample {} is missing the PNG signature",
                sample.path
            );
        }
    }

    #[test]
    fn tlv_ground_truth_loads_and_matches_its_samples() {
        let ground_truth = load_ground_truth("tlv").expect("the tlv ground truth should load");

        assert_eq!(ground_truth.format, "tlv");
        assert_eq!(ground_truth.endianness, "little");
        assert!(!ground_truth.structure.header.is_empty());
        assert!(!ground_truth.structure.record.is_empty());
        assert_eq!(ground_truth.samples.len(), 3);

        for sample in &ground_truth.samples {
            let bytes = read_sample(&ground_truth.format, sample).unwrap_or_else(|error| {
                panic!("sample {} should be readable: {error}", sample.path)
            });
            assert_eq!(
                bytes.len() as u64,
                sample.size,
                "recorded size for {} does not match the file",
                sample.path
            );
            assert_eq!(
                &bytes[0..4],
                b"STLV",
                "sample {} is missing the magic",
                sample.path
            );
            assert_eq!(
                u64::from(bytes[5]),
                sample.record_count,
                "record count byte mismatch in {}",
                sample.path
            );
        }
    }

    #[test]
    fn ground_truth_round_trips_through_json() {
        let ground_truth = load_ground_truth("tlv").expect("the tlv ground truth should load");
        let json = serde_json::to_string(&ground_truth).expect("serialize ground truth");
        let reparsed = parse_ground_truth(&json).expect("re-parse ground truth");
        assert_eq!(reparsed.format, ground_truth.format);
        assert_eq!(reparsed.samples.len(), ground_truth.samples.len());
    }

    #[test]
    fn missing_format_is_an_error() {
        assert!(load_ground_truth("does-not-exist").is_err());
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(parse_ground_truth("{ not valid json ").is_err());
    }
}
