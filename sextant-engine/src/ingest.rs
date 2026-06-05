//! Sample ingestion (FR-1, FR-3, FR-4, FR-5).
//!
//! Ingestion turns the user's inputs, which may be files, directories, or glob
//! patterns, into a normalized [`SampleSet`]: an ordered list of byte buffers,
//! each carrying [`Provenance`] (its path, retained length, full on-disk size,
//! and offset within its source). This is the first stage of the pipeline in
//! PRD Section 9 and the input that statistical inference and the executor later
//! consume.
//!
//! # Robustness (FR-4)
//!
//! The corpus includes pathological inputs and ingestion must handle every one
//! without crashing: empty files, single-byte files, very large files, several
//! identical files, and a set with a single sample. Large files are never read
//! whole; ingestion reads at most the per-sample cap and records the true size
//! in provenance, so a multi-gigabyte file costs only the capped number of
//! bytes. Distinct files with identical bytes are kept as distinct samples; only
//! the same path referenced twice is de-duplicated.
//!
//! # Byte caps (FR-5)
//!
//! Two configurable caps bound memory: a per-sample cap clips any single sample,
//! and a total-input cap stops ingestion once the set would grow past it. When a
//! cap takes effect it is surfaced to the user through a [`Notice`], and a
//! clipped sample additionally records its full size in [`Provenance`] so the
//! truncation is visible.
//!
//! ```
//! use sextant_engine::IngestOptions;
//!
//! let options = IngestOptions::default();
//! // Directory recursion is opt-in (FR-1): a directory yields its top-level
//! // files unless recursion is requested.
//! assert!(!options.recursive);
//! ```

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use glob::glob;

/// The default per-sample byte cap: 64 MiB. Large enough for the corpus formats,
/// small enough that a single pathological file cannot exhaust memory (FR-5).
pub const DEFAULT_MAX_BYTES_PER_SAMPLE: usize = 64 << 20;

/// The default total-input byte cap: 1 GiB. Bounds the memory a whole run may
/// retain across all samples (FR-5).
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 1 << 30;

/// Options that govern ingestion: the byte caps (FR-5) and whether directory
/// inputs are traversed recursively (FR-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestOptions {
    /// The most bytes retained from any single sample. A larger file is clipped
    /// to this many bytes and its full size is recorded in [`Provenance`].
    pub max_bytes_per_sample: usize,
    /// The most bytes retained across the whole set. Once reached, later samples
    /// are skipped so the run's memory stays bounded.
    pub max_total_bytes: usize,
    /// Whether to descend into subdirectories of a directory input. Off by
    /// default: a directory yields only its top-level files unless asked (FR-1).
    pub recursive: bool,
}

impl Default for IngestOptions {
    fn default() -> Self {
        Self {
            max_bytes_per_sample: DEFAULT_MAX_BYTES_PER_SAMPLE,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            recursive: false,
        }
    }
}

impl IngestOptions {
    /// Set the per-sample byte cap (builder style).
    #[must_use]
    pub fn with_max_bytes_per_sample(mut self, cap: usize) -> Self {
        self.max_bytes_per_sample = cap;
        self
    }

    /// Set the total-input byte cap (builder style).
    #[must_use]
    pub fn with_max_total_bytes(mut self, cap: usize) -> Self {
        self.max_total_bytes = cap;
        self
    }

    /// Set whether directory inputs are traversed recursively (builder style).
    #[must_use]
    pub fn with_recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }
}

/// Where a sample came from and how much of it was kept (FR-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// The path the sample was read from, as it was resolved from the input.
    pub path: PathBuf,
    /// The number of bytes retained in the sample set, after any per-sample cap.
    pub length: usize,
    /// The sample's full size on disk in bytes, before any cap. When this
    /// exceeds `length`, the per-sample cap clipped the sample.
    pub original_length: u64,
    /// The byte offset of the sample within its source. Always zero for a file;
    /// reserved for payloads extracted from a capture at a nonzero offset, which
    /// arrives with pcap ingestion in a later step.
    pub offset: u64,
}

impl Provenance {
    /// Whether the per-sample byte cap clipped this sample, so fewer bytes were
    /// retained than the file holds.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        (self.length as u64) < self.original_length
    }
}

/// One normalized sample: its retained bytes and its [`Provenance`] (FR-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    /// Where the sample came from and how much was kept.
    pub provenance: Provenance,
    /// The retained sample bytes, clipped to the per-sample cap.
    pub data: Vec<u8>,
}

impl Sample {
    /// The sample bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// The path the sample was read from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.provenance.path
    }

    /// The number of retained bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the sample has no retained bytes (an empty file, for example).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// An ordered set of normalized samples plus aggregate accounting (FR-3, FR-5).
///
/// Samples appear in a deterministic order: inputs are processed in the order
/// given, and the paths within each directory or glob expansion are sorted, so a
/// repeated run over the same inputs yields the same set (NFR-6).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SampleSet {
    /// The samples, in ingestion order.
    pub samples: Vec<Sample>,
    /// The total number of retained bytes across the set.
    pub total_bytes: usize,
    /// Notices about caps that were applied, to be surfaced to the user (FR-5).
    pub notices: Vec<Notice>,
}

impl SampleSet {
    /// The number of samples.
    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Whether the set has no samples.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// The samples as raw byte slices, in order, ready for the scorer and the
    /// statistical pass which operate over `&[&[u8]]`.
    #[must_use]
    pub fn as_byte_slices(&self) -> Vec<&[u8]> {
        self.samples
            .iter()
            .map(|sample| sample.data.as_slice())
            .collect()
    }
}

/// A heads-up about a cap that took effect during ingestion, surfaced to the
/// user so byte limits are never silent (FR-5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// One or more samples were clipped to the per-sample byte cap.
    SamplesTruncated {
        /// How many samples were clipped.
        count: usize,
        /// The per-sample cap, in bytes.
        cap: usize,
    },
    /// Ingestion stopped at the total-input cap, leaving later samples out.
    TotalCapReached {
        /// The total-input cap, in bytes.
        cap: usize,
        /// How many samples were skipped because of the cap.
        skipped: usize,
    },
}

impl fmt::Display for Notice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Notice::SamplesTruncated { count, cap } => write!(
                f,
                "{count} sample(s) were clipped to the per-sample cap of {cap} bytes"
            ),
            Notice::TotalCapReached { cap, skipped } => write!(
                f,
                "reached the total-input cap of {cap} bytes; skipped {skipped} sample(s)"
            ),
        }
    }
}

/// Why ingestion could not produce a sample set.
#[derive(Debug)]
pub enum IngestError {
    /// No inputs were supplied at all.
    NoInputs,
    /// A literal (non-glob) input path does not exist.
    PathNotFound {
        /// The missing path.
        path: PathBuf,
    },
    /// A glob pattern was malformed.
    BadPattern {
        /// The offending pattern.
        pattern: String,
        /// A human-readable explanation from the glob matcher.
        message: String,
    },
    /// An I/O error occurred while reading a path.
    Io {
        /// The path being read when the error occurred.
        path: PathBuf,
        /// The underlying I/O error.
        source: io::Error,
    },
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IngestError::NoInputs => write!(f, "no inputs were provided"),
            IngestError::PathNotFound { path } => {
                write!(f, "input path not found: {}", path.display())
            }
            IngestError::BadPattern { pattern, message } => {
                write!(f, "invalid glob pattern {pattern:?}: {message}")
            }
            IngestError::Io { path, source } => {
                write!(f, "could not read {}: {source}", path.display())
            }
        }
    }
}

impl Error for IngestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            IngestError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Ingest a set of inputs (files, directories, and glob patterns) into an
/// ordered, normalized [`SampleSet`] with provenance and enforced byte caps
/// (FR-1, FR-3, FR-4, FR-5).
///
/// Inputs are resolved in order. An input containing a glob metacharacter
/// (`*`, `?`, or `[`) is expanded against the filesystem; any other input is a
/// literal path. A literal directory yields its files, descending into
/// subdirectories only when [`IngestOptions::recursive`] is set (FR-1). The same
/// file referenced more than once is ingested only once; distinct files with
/// identical bytes are kept as distinct samples (FR-4).
///
/// # Errors
///
/// Returns [`IngestError::NoInputs`] when `inputs` is empty,
/// [`IngestError::PathNotFound`] when a literal path does not exist,
/// [`IngestError::BadPattern`] for a malformed glob, or [`IngestError::Io`] for
/// an underlying read failure. A glob or directory that matches nothing is not
/// an error; it simply contributes no samples.
pub fn ingest<S: AsRef<str>>(
    inputs: &[S],
    options: &IngestOptions,
) -> Result<SampleSet, IngestError> {
    if inputs.is_empty() {
        return Err(IngestError::NoInputs);
    }

    // Resolve every input to an ordered, de-duplicated list of file paths.
    let mut resolved: Vec<PathBuf> = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    for input in inputs {
        resolve_input(input.as_ref(), options.recursive, &mut resolved, &mut seen)?;
    }

    read_samples(&resolved, options)
}

/// Resolve one input string to zero or more file paths, appended to `out`.
fn resolve_input(
    input: &str,
    recursive: bool,
    out: &mut Vec<PathBuf>,
    seen: &mut BTreeSet<PathBuf>,
) -> Result<(), IngestError> {
    if is_glob(input) {
        let matches = glob(input).map_err(|error| IngestError::BadPattern {
            pattern: input.to_string(),
            message: error.to_string(),
        })?;
        // Collect and sort so the expansion order is deterministic (NFR-6).
        let mut paths: Vec<PathBuf> = Vec::new();
        for entry in matches {
            let path = entry.map_err(|error| IngestError::Io {
                path: error.path().to_path_buf(),
                source: error.into_error(),
            })?;
            paths.push(path);
        }
        paths.sort();
        for path in paths {
            add_existing_path(&path, recursive, out, seen)?;
        }
        Ok(())
    } else {
        let path = PathBuf::from(input);
        let metadata = fs::metadata(&path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                IngestError::PathNotFound { path: path.clone() }
            } else {
                IngestError::Io {
                    path: path.clone(),
                    source,
                }
            }
        })?;
        dispatch_path(&path, &metadata, recursive, out, seen)
    }
}

/// Add a path that a glob already proved to exist, classifying it as a file or
/// directory.
fn add_existing_path(
    path: &Path,
    recursive: bool,
    out: &mut Vec<PathBuf>,
    seen: &mut BTreeSet<PathBuf>,
) -> Result<(), IngestError> {
    let metadata = fs::metadata(path).map_err(|source| IngestError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    dispatch_path(path, &metadata, recursive, out, seen)
}

/// Route a path to file collection or directory traversal based on its kind.
/// Anything that is neither a regular file nor a directory (a socket or device,
/// for example) is skipped rather than treated as a sample.
fn dispatch_path(
    path: &Path,
    metadata: &fs::Metadata,
    recursive: bool,
    out: &mut Vec<PathBuf>,
    seen: &mut BTreeSet<PathBuf>,
) -> Result<(), IngestError> {
    if metadata.is_dir() {
        collect_dir(path, recursive, out, seen)
    } else {
        if metadata.is_file() {
            push_unique(path, out, seen);
        }
        Ok(())
    }
}

/// Collect the regular files in a directory, sorted for determinism. Descends
/// into subdirectories only when `recursive` is set (FR-1).
fn collect_dir(
    dir: &Path,
    recursive: bool,
    out: &mut Vec<PathBuf>,
    seen: &mut BTreeSet<PathBuf>,
) -> Result<(), IngestError> {
    let reader = fs::read_dir(dir).map_err(|source| IngestError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let mut entries: Vec<PathBuf> = Vec::new();
    for entry in reader {
        let entry = entry.map_err(|source| IngestError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        entries.push(entry.path());
    }
    entries.sort();

    for entry in entries {
        // Skip entries that cannot be stat'd (a broken symlink, a race) rather
        // than failing the whole run.
        let Ok(metadata) = fs::metadata(&entry) else {
            continue;
        };
        if metadata.is_dir() {
            if recursive {
                collect_dir(&entry, recursive, out, seen)?;
            }
        } else if metadata.is_file() {
            push_unique(&entry, out, seen);
        }
    }
    Ok(())
}

/// Append a path the first time its canonical form is seen, so the same file
/// referenced twice yields a single sample while distinct files are all kept.
fn push_unique(path: &Path, out: &mut Vec<PathBuf>, seen: &mut BTreeSet<PathBuf>) {
    let key = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if seen.insert(key) {
        out.push(path.to_path_buf());
    }
}

/// Read each resolved path into a sample, applying the per-sample and total
/// byte caps and collecting notices for any cap that took effect (FR-5).
fn read_samples(paths: &[PathBuf], options: &IngestOptions) -> Result<SampleSet, IngestError> {
    let mut set = SampleSet::default();
    let mut total: usize = 0;
    let mut truncated = 0usize;
    let mut skipped = 0usize;
    let mut total_cap_hit = false;

    for path in paths {
        if total_cap_hit {
            skipped += 1;
            continue;
        }

        let metadata = fs::metadata(path).map_err(|source| IngestError::Io {
            path: path.clone(),
            source,
        })?;
        let original_length = metadata.len();
        // Bytes we would keep from this sample, before the total cap is checked.
        // Computed in u64 so a file larger than usize on a 32-bit target cannot
        // wrap, then clamped to usize since it never exceeds the per-sample cap.
        let per_sample_cap = options.max_bytes_per_sample as u64;
        let keep = original_length.min(per_sample_cap) as usize;

        // Stop before reading if this sample would push the set past the total
        // cap, so a doomed read is never even performed.
        let fits = match total.checked_add(keep) {
            Some(running) => running <= options.max_total_bytes,
            None => false,
        };
        if !fits {
            total_cap_hit = true;
            skipped += 1;
            continue;
        }

        let data = read_capped(path, keep).map_err(|source| IngestError::Io {
            path: path.clone(),
            source,
        })?;
        let length = data.len();
        total += length;
        if (length as u64) < original_length {
            truncated += 1;
        }

        set.samples.push(Sample {
            provenance: Provenance {
                path: path.clone(),
                length,
                original_length,
                offset: 0,
            },
            data,
        });
    }

    set.total_bytes = total;
    if truncated > 0 {
        set.notices.push(Notice::SamplesTruncated {
            count: truncated,
            cap: options.max_bytes_per_sample,
        });
    }
    if skipped > 0 {
        set.notices.push(Notice::TotalCapReached {
            cap: options.max_total_bytes,
            skipped,
        });
    }
    Ok(set)
}

/// Read at most `cap` bytes from a file. A very large file is never read whole:
/// the [`Read::take`] limit bounds both the bytes read and the allocation, so a
/// multi-gigabyte file costs only `cap` bytes of memory (FR-4).
fn read_capped(path: &Path, cap: usize) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut data = Vec::new();
    file.take(cap as u64).read_to_end(&mut data)?;
    Ok(data)
}

/// Whether an input string is a glob pattern rather than a literal path. The
/// metacharacters are `*`, `?`, and `[`.
fn is_glob(input: &str) -> bool {
    input.contains(['*', '?', '['])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_glob_metacharacters() {
        assert!(is_glob("*.png"));
        assert!(is_glob("sample_0?.tlv"));
        assert!(is_glob("file_[0-9].bin"));
        assert!(!is_glob("corpus/png/samples"));
        assert!(!is_glob("plain_file.bin"));
    }

    #[test]
    fn default_options_are_bounded_and_not_recursive() {
        let options = IngestOptions::default();
        assert_eq!(options.max_bytes_per_sample, DEFAULT_MAX_BYTES_PER_SAMPLE);
        assert_eq!(options.max_total_bytes, DEFAULT_MAX_TOTAL_BYTES);
        assert!(!options.recursive);
    }

    #[test]
    fn no_inputs_is_an_error() {
        let inputs: [&str; 0] = [];
        assert!(matches!(
            ingest(&inputs, &IngestOptions::default()),
            Err(IngestError::NoInputs)
        ));
    }

    #[test]
    fn truncation_is_reflected_in_provenance() {
        let provenance = Provenance {
            path: PathBuf::from("x"),
            length: 4,
            original_length: 100,
            offset: 0,
        };
        assert!(provenance.is_truncated());

        let whole = Provenance {
            path: PathBuf::from("x"),
            length: 100,
            original_length: 100,
            offset: 0,
        };
        assert!(!whole.is_truncated());
    }

    #[test]
    fn notice_messages_avoid_dashes() {
        let truncated = Notice::SamplesTruncated { count: 2, cap: 16 }.to_string();
        let capped = Notice::TotalCapReached {
            cap: 32,
            skipped: 1,
        }
        .to_string();
        for message in [truncated, capped] {
            assert!(!message.contains('\u{2014}'), "em dash in: {message}");
            assert!(!message.contains('\u{2013}'), "en dash in: {message}");
        }
    }
}
