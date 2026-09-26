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

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

pub mod accuracy;
pub mod report;

pub use accuracy::{FormatMetrics, SampleMetrics, evaluate_format, evaluate_format_in};
pub use report::{
    BenchOptions, BenchReport, FLOORS, Floor, FormatReport, Summary, TargetCheck, Tier, TierReport,
    render_readme_section, render_table, run_benchmark,
};

/// The file-format formats the engine is developed and tuned against: four
/// controlled formats authored for this project plus real PNG, BMP, WAV, and ZIP
/// files. Results on these formats are in-sample and measure fit to known data.
pub const DEVELOPMENT_CORPUS: [&str; 8] =
    ["tlv", "scma", "stot", "sdlp", "png", "bmp", "wav", "zip"];

/// Real file formats held out from tuning (PRD Section 15). They are evaluated
/// with the same harness but are not consulted while developing heuristics, so
/// their numbers estimate accuracy on formats the engine was not fitted to.
/// A format moves to [`DEVELOPMENT_CORPUS`] once it has been used for tuning.
pub const HELD_OUT_CORPUS: [&str; 4] = ["gif", "elf", "tar", "pcapfile"];

/// Every file-format corpus entry, development formats first. The protocol
/// track (Modbus/TCP and the toy protocol) is captured-packet input with its own
/// ground-truth schema and is exercised by the protocol tests and the Wireshark
/// dissector round trip, not by these file-format metrics.
pub const FILE_FORMAT_CORPUS: [&str; 12] = [
    "tlv", "scma", "stot", "sdlp", "png", "bmp", "wav", "zip", "gif", "elf", "tar", "pcapfile",
];

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

/// The structural template of a format: a header, a repeating record, and a
/// trailer, laid out in that order.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Structure {
    /// Fields at the start of every sample, in order.
    pub header: Vec<Field>,
    /// Fields of one repeating record, in order. Each sample declares how many
    /// records it holds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub record: Vec<Field>,
    /// Fields after the last record, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trailer: Vec<Field>,
}

impl Structure {
    /// Every field in layout order: header, one record, then trailer.
    pub fn fields(&self) -> impl Iterator<Item = &Field> {
        self.header.iter().chain(&self.record).chain(&self.trailer)
    }
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
///
/// In JSON a fixed size is a number, a derived size is the name of the length
/// field, and a rule is an object such as `{"rule": "to_end"}`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SizeRule {
    /// A fixed number of bytes.
    Fixed(u64),
    /// Derived from another field, named here (for example `length`).
    Derived(String),
    /// A size given by a named rule rather than a number or a field.
    Rule {
        /// The rule.
        rule: SizeRuleKind,
    },
}

/// A size rule that is neither a fixed number nor a length field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SizeRuleKind {
    /// The field runs to the end of the sample. Only the final field of a
    /// structure may use it.
    ToEnd,
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
    let root = format_directory(corpus_dir, format)?;
    let path = confined_file(&root, "ground_truth.json")?;
    let bytes = read_bounded(&path, MANIFEST_READ_CAP)?;
    let gt: GroundTruth = serde_json::from_slice(&bytes).map_err(invalid_corpus)?;
    validate_ground_truth(&gt)?;
    Ok(gt)
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

/// Maximum bytes in one benchmark sample. Oversized samples are rejected.
pub const SAMPLE_READ_CAP: usize = sextant_engine::DEFAULT_MAX_BYTES_PER_SAMPLE;
/// Maximum ground-truth manifest size in bytes.
pub const MANIFEST_READ_CAP: usize = 1024 * 1024;
/// Maximum retained sample bytes for one format evaluation.
pub const CORPUS_READ_CAP: u64 = 256 * 1024 * 1024;
/// Maximum samples in one format manifest.
pub const MAX_SAMPLES: usize = 256;
/// Maximum expanded ground-truth fields across one format's samples.
pub const MAX_TRUTH_FIELDS: u64 = 100_000;

fn invalid_corpus(message: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.to_string())
}

fn relative_path(path: &str) -> std::io::Result<&Path> {
    let path = Path::new(path);
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(invalid_corpus(
            "corpus paths must be relative without parent components",
        ));
    }
    Ok(path)
}

fn format_directory(corpus: &Path, format: &str) -> std::io::Result<PathBuf> {
    let corpus = corpus.canonicalize()?;
    let root = corpus.join(relative_path(format)?).canonicalize()?;
    if !root.starts_with(&corpus) || !root.is_dir() {
        return Err(invalid_corpus("format directory escapes the corpus"));
    }
    Ok(root)
}

fn confined_file(root: &Path, path: &str) -> std::io::Result<PathBuf> {
    let path = root.join(relative_path(path)?).canonicalize()?;
    if !path.starts_with(root) || !path.is_file() {
        return Err(invalid_corpus(
            "corpus entry must be a regular file inside its format directory",
        ));
    }
    Ok(path)
}

fn read_bounded(path: &Path, cap: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > cap as u64 {
        return Err(invalid_corpus(
            "corpus file exceeds its byte limit or is not regular",
        ));
    }
    let mut bytes = Vec::new();
    file.take(cap as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(invalid_corpus("corpus file exceeds its byte limit"));
    }
    Ok(bytes)
}

fn validate_ground_truth(gt: &GroundTruth) -> std::io::Result<()> {
    if gt.samples.is_empty() || gt.samples.len() > MAX_SAMPLES {
        return Err(invalid_corpus("invalid corpus sample count"));
    }
    let fields: Vec<&Field> = gt.structure.fields().collect();
    for field in &fields {
        if [&field.name, &field.ty, &field.role]
            .iter()
            .any(|value| value.len() > 256)
            || matches!(&field.size, SizeRule::Derived(name) if name.len() > 256)
        {
            return Err(invalid_corpus("ground-truth field labels exceed 256 bytes"));
        }
    }
    // A to-end field consumes the rest of the sample, so it must be the last
    // field laid out, and it cannot sit inside a repeating record.
    let last = fields.len().saturating_sub(1);
    for (index, field) in fields.iter().enumerate() {
        if matches!(
            field.size,
            SizeRule::Rule {
                rule: SizeRuleKind::ToEnd
            }
        ) {
            let in_record = gt.structure.record.iter().any(|f| std::ptr::eq(f, *field));
            if index != last || in_record {
                return Err(invalid_corpus(
                    "only the final ground-truth field may run to the end",
                ));
            }
        }
    }
    let mut bytes = 0u64;
    let mut expanded = 0u64;
    for sample in &gt.samples {
        relative_path(&sample.path)?;
        if sample.size > SAMPLE_READ_CAP as u64 {
            return Err(invalid_corpus("sample exceeds its byte limit"));
        }
        bytes = bytes
            .checked_add(sample.size)
            .ok_or_else(|| invalid_corpus("sample size overflow"))?;
        let count = expanded_field_count(gt, sample.record_count)?;
        expanded = expanded
            .checked_add(count)
            .ok_or_else(|| invalid_corpus("field count overflow"))?;
        if bytes > CORPUS_READ_CAP || expanded > MAX_TRUTH_FIELDS {
            return Err(invalid_corpus(
                "corpus exceeds its aggregate byte or field limit",
            ));
        }
    }
    Ok(())
}

fn expanded_field_count(gt: &GroundTruth, records: u64) -> std::io::Result<u64> {
    if records > MAX_TRUTH_FIELDS || (records > 0 && gt.structure.record.is_empty()) {
        return Err(invalid_corpus("invalid ground-truth record count"));
    }
    let fixed = (gt.structure.header.len() + gt.structure.trailer.len()) as u64;
    let count = records
        .checked_mul(gt.structure.record.len() as u64)
        .and_then(|count| count.checked_add(fixed))
        .filter(|&count| count <= MAX_TRUTH_FIELDS)
        .ok_or_else(|| invalid_corpus("ground truth exceeds its expanded field limit"))?;
    Ok(count)
}

/// Read one sample within its format directory, rejecting oversized files and
/// mismatches with the manifest's declared size instead of silently truncating.
///
/// # Errors
///
/// Returns an error for invalid paths, non-regular files, size mismatches, or I/O failures.
pub fn read_sample_in(
    corpus_dir: &Path,
    format: &str,
    sample: &SampleEntry,
) -> std::io::Result<Vec<u8>> {
    let root = format_directory(corpus_dir, format)?;
    let path = confined_file(&root, &sample.path)?;
    if sample.size > SAMPLE_READ_CAP as u64 {
        return Err(invalid_corpus("sample exceeds its byte limit"));
    }
    let data = read_bounded(&path, SAMPLE_READ_CAP)?;
    if data.len() as u64 != sample.size {
        return Err(invalid_corpus("sample size differs from its manifest"));
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loading_hostile_manifests_fails_before_sample_reads() {
        let root = std::env::temp_dir().join(format!("sextant-manifest-{}", std::process::id()));
        let dir = root.join("hostile");
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = dir.join("ground_truth.json");
        let mut gt = load_ground_truth("tlv").unwrap();
        gt.samples[0].record_count = u64::MAX;
        std::fs::write(&manifest, serde_json::to_vec(&gt).unwrap()).unwrap();
        assert!(
            load_ground_truth_in(&root, "hostile")
                .unwrap_err()
                .to_string()
                .contains("record count")
        );
        std::fs::File::create(&manifest)
            .unwrap()
            .set_len(MANIFEST_READ_CAP as u64 + 1)
            .unwrap();
        assert!(
            load_ground_truth_in(&root, "hostile")
                .unwrap_err()
                .to_string()
                .contains("byte limit")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unbounded_ground_truth_and_declared_sample_budgets() {
        let original = load_ground_truth("tlv").expect("fixture");
        let mut gt = original.clone();
        gt.samples[0].record_count = u64::MAX;
        assert!(validate_ground_truth(&gt).is_err());
        gt = original.clone();
        gt.samples = vec![gt.samples[0].clone(); MAX_SAMPLES + 1];
        assert!(validate_ground_truth(&gt).is_err());
        gt = original.clone();
        gt.samples[0].size = SAMPLE_READ_CAP as u64 + 1;
        assert!(validate_ground_truth(&gt).is_err());
        gt = original;
        gt.structure.header[0].role = "x".repeat(257);
        assert!(validate_ground_truth(&gt).is_err());
    }

    #[test]
    fn sample_reads_reject_path_escape_and_size_mismatch() {
        let gt = load_ground_truth("tlv").expect("fixture");
        let mut sample = gt.samples[0].clone();
        sample.size += 1;
        assert!(read_sample("tlv", &sample).is_err());
        sample.path = "../png/ground_truth.json".into();
        assert!(read_sample("tlv", &sample).is_err());
        sample.path = corpus_dir()
            .join("png/ground_truth.json")
            .display()
            .to_string();
        assert!(read_sample("tlv", &sample).is_err());
    }

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
