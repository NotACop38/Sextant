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
//! # Traversal safety (FR-24, NFR-2)
//!
//! Directory inputs and glob patterns are expanded by one bounded walker. It
//! reads each directory entry's own type and never follows a symbolic link it
//! finds, so a link cycle cannot loop and a link cannot pull in files from
//! outside the selected tree. A link named explicitly as an input, or as the
//! literal leading directories of a glob, is still honored. The walk stops with
//! a [`Notice`] once it has examined [`IngestOptions::max_walk_entries`]
//! directory entries or resolved [`IngestOptions::max_input_files`] files.
//!
//! Only regular files become samples. FIFOs, sockets, and devices are skipped
//! with a notice, and every file is checked again through its open handle, which
//! is opened without blocking where the platform allows, so a path swapped for a
//! FIFO after it was listed cannot hang the run.
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
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use glob::{MatchOptions, Pattern};

/// The default per-sample byte cap: 64 MiB. Large enough for the corpus formats,
/// small enough that a single pathological file cannot exhaust memory (FR-5).
pub const DEFAULT_MAX_BYTES_PER_SAMPLE: usize = 64 << 20;

/// The default total-input byte cap: 1 GiB. Bounds the memory a whole run may
/// retain across all samples (FR-5).
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 1 << 30;

/// The default cap on directory entries examined while expanding directory and
/// glob inputs: one million. Bounds the time a huge or hostile tree can cost
/// (FR-24).
pub const DEFAULT_MAX_WALK_ENTRIES: usize = 1_000_000;

/// The default cap on input files resolved in one run: 100,000. Bounds the
/// memory the resolved path list holds (FR-24).
pub const DEFAULT_MAX_INPUT_FILES: usize = 100_000;

/// Options that govern ingestion: the byte caps (FR-5), whether directory
/// inputs are traversed recursively (FR-1), and the traversal limits (FR-24).
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
    /// The most directory entries that expanding directory and glob inputs may
    /// examine, across all inputs. Once reached, expansion stops and a
    /// [`Notice::WalkLimitReached`] is recorded.
    pub max_walk_entries: usize,
    /// The most files that inputs may resolve to, across all inputs. Once
    /// reached, later matches are skipped and a [`Notice::FileLimitReached`] is
    /// recorded.
    pub max_input_files: usize,
}

impl Default for IngestOptions {
    fn default() -> Self {
        Self {
            max_bytes_per_sample: DEFAULT_MAX_BYTES_PER_SAMPLE,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            recursive: false,
            max_walk_entries: DEFAULT_MAX_WALK_ENTRIES,
            max_input_files: DEFAULT_MAX_INPUT_FILES,
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

    /// Set the cap on directory entries examined during expansion (builder
    /// style).
    #[must_use]
    pub fn with_max_walk_entries(mut self, limit: usize) -> Self {
        self.max_walk_entries = limit;
        self
    }

    /// Set the cap on files the inputs may resolve to (builder style).
    #[must_use]
    pub fn with_max_input_files(mut self, limit: usize) -> Self {
        self.max_input_files = limit;
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
    /// Notices about caps, limits, and skipped inputs, to be surfaced to the
    /// user (FR-5).
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

/// A heads-up about a cap or limit that took effect, or an input that was
/// skipped, during ingestion. Surfaced to the user so nothing is dropped
/// silently (FR-5).
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
    /// Expanding directories and globs stopped after examining the maximum
    /// number of directory entries, so later matches were not considered.
    WalkLimitReached {
        /// The entry limit ([`IngestOptions::max_walk_entries`]).
        limit: usize,
    },
    /// The inputs resolved to more files than the limit allows, so later
    /// matches were skipped.
    FileLimitReached {
        /// The file limit ([`IngestOptions::max_input_files`]).
        limit: usize,
    },
    /// Symbolic links found while walking a directory or glob were not
    /// followed.
    SymlinksSkipped {
        /// How many links were skipped.
        count: usize,
    },
    /// Inputs that are not regular files (a FIFO, socket, or device, including
    /// a file replaced by one during the run) were skipped.
    NotRegularFilesSkipped {
        /// How many inputs were skipped.
        count: usize,
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
            Notice::WalkLimitReached { limit } => write!(
                f,
                "stopped expanding directories and globs after examining {limit} directory \
                 entries; later matches were not considered, so narrow the inputs"
            ),
            Notice::FileLimitReached { limit } => write!(
                f,
                "the inputs matched more than {limit} files; later matches were skipped"
            ),
            Notice::SymlinksSkipped { count } => write!(
                f,
                "skipped {count} symbolic link(s) found while walking directories or globs; \
                 name a link as an input to include it"
            ),
            Notice::NotRegularFilesSkipped { count } => write!(
                f,
                "skipped {count} input(s) that are not regular files (for example a FIFO, \
                 socket, or device)"
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
/// Inputs are resolved in order. An input that names an existing path is taken
/// literally, even when its name contains a glob metacharacter; otherwise an
/// input containing `*`, `?`, or `[` is expanded as a glob. A directory yields
/// its regular files, descending into subdirectories only when
/// [`IngestOptions::recursive`] is set (FR-1). Symbolic links found while
/// walking are never followed. The same file referenced more than once is
/// ingested only once; distinct files with identical bytes are kept as distinct
/// samples (FR-4).
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
    let mut resolver = Resolver::new(options);
    for input in inputs {
        if resolver.exhausted() {
            break;
        }
        resolver.resolve(input.as_ref())?;
    }

    let (mut set, swapped) = read_samples(&resolver.files, options)?;
    let mut notices = resolver.notices(swapped);
    notices.append(&mut set.notices);
    set.notices = notices;
    Ok(set)
}

/// Read at most `cap` bytes from the regular file at `path`, returning them
/// with the file's full size in bytes (FR-5, FR-24).
///
/// The file is checked through its open handle, not just its path, and is
/// opened without blocking where the platform allows, so a FIFO, socket, or
/// device, including one swapped in for a file, is refused instead of stalling
/// the read. A very large file costs only `cap` bytes of memory.
///
/// # Errors
///
/// Returns an [`io::Error`] of kind [`io::ErrorKind::InvalidInput`] when `path`
/// is not a regular file, or the underlying error when it cannot be opened or
/// read.
pub fn read_regular_file(path: &Path, cap: usize) -> io::Result<(Vec<u8>, u64)> {
    let Some((file, length)) = open_regular_file(path)? else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    };
    Ok((read_up_to(file, cap)?, length))
}

/// The match options the glob crate uses for a single path component: case
/// sensitive, with a leading dot matched by wildcards like any other character.
const MATCH_OPTIONS: MatchOptions = MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

/// One component of a path pattern, matched against directory entry names.
#[derive(Debug, Clone)]
enum Segment {
    /// `**`: zero or more directory levels.
    AnyDirs,
    /// Any single name, including one that is not valid UTF-8 (plain directory
    /// traversal).
    AnyName,
    /// A glob component such as `*.bin`, matched against the entry name.
    Name(Pattern),
}

/// What kind of entry counts as a match of the final segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    /// Regular files only (directory traversal).
    Files,
    /// Files or directories (a glob; a matched directory contributes its files).
    Any,
    /// Directories only (a glob that ends in a path separator).
    Dirs,
}

/// A glob pattern split into the literal directory it starts from and the
/// segments matched below it.
struct GlobPlan {
    /// The literal leading directories (empty for the current directory).
    root: PathBuf,
    /// The pattern components from the first one with a metacharacter on.
    segments: Vec<Segment>,
    /// Which entries a full match may be.
    want: Want,
}

impl GlobPlan {
    /// Split and compile a glob pattern.
    fn parse(pattern: &str) -> Result<Self, IngestError> {
        let bad = |message: String| IngestError::BadPattern {
            pattern: pattern.to_string(),
            message,
        };
        // Validate the whole pattern with the glob crate's own parser, so a
        // malformed pattern is reported the same way it always was.
        Pattern::new(pattern).map_err(|error| bad(error.to_string()))?;

        let mut root = PathBuf::new();
        let mut segments = Vec::new();
        for component in Path::new(pattern).components() {
            let text = component.as_os_str().to_str().unwrap_or_default();
            if segments.is_empty() && !is_glob(text) {
                root.push(component);
                continue;
            }
            match component {
                // `a/./b` names the same directory as `a/b`.
                Component::CurDir => {}
                Component::Normal(_) if text == "**" => {
                    if !matches!(segments.last(), Some(Segment::AnyDirs)) {
                        segments.push(Segment::AnyDirs);
                    }
                }
                Component::Normal(_) => {
                    let compiled = Pattern::new(text).map_err(|error| bad(error.to_string()))?;
                    segments.push(Segment::Name(compiled));
                }
                // Climbing out of a matched directory would leave the tree the
                // walk is confined to.
                Component::ParentDir => return Err(bad(PARENT_AFTER_WILDCARD.to_owned())),
                Component::RootDir | Component::Prefix(_) => {
                    return Err(bad("a root or drive prefix after a wildcard".to_owned()));
                }
            }
        }
        let want = if pattern.ends_with(std::path::is_separator) {
            Want::Dirs
        } else {
            Want::Any
        };
        Ok(Self {
            root,
            segments,
            want,
        })
    }
}

/// The segments that walk a directory input for its regular files.
fn directory_segments(recursive: bool) -> Vec<Segment> {
    if recursive {
        vec![Segment::AnyDirs, Segment::AnyName]
    } else {
        vec![Segment::AnyName]
    }
}

/// One directory being walked: its sorted entries still to visit and the
/// pattern states that reached it.
struct Frame {
    dir: PathBuf,
    entries: std::vec::IntoIter<(OsString, fs::FileType)>,
    states: Vec<usize>,
}

/// Resolves inputs to file paths under the traversal limits, recording what it
/// skipped so the caller can surface it.
struct Resolver<'o> {
    options: &'o IngestOptions,
    files: Vec<PathBuf>,
    seen: BTreeSet<PathBuf>,
    visited: usize,
    walk_limit_hit: bool,
    file_limit_hit: bool,
    symlinks_skipped: usize,
    not_regular: usize,
}

impl<'o> Resolver<'o> {
    fn new(options: &'o IngestOptions) -> Self {
        Self {
            options,
            files: Vec::new(),
            seen: BTreeSet::new(),
            visited: 0,
            walk_limit_hit: false,
            file_limit_hit: false,
            symlinks_skipped: 0,
            not_regular: 0,
        }
    }

    /// Whether a traversal limit has stopped resolution.
    fn exhausted(&self) -> bool {
        self.walk_limit_hit || self.file_limit_hit
    }

    /// The notices resolution produced, plus `swapped` files that stopped being
    /// regular files between resolution and reading.
    fn notices(&self, swapped: usize) -> Vec<Notice> {
        let mut notices = Vec::new();
        if self.walk_limit_hit {
            notices.push(Notice::WalkLimitReached {
                limit: self.options.max_walk_entries,
            });
        }
        if self.file_limit_hit {
            notices.push(Notice::FileLimitReached {
                limit: self.options.max_input_files,
            });
        }
        if self.symlinks_skipped > 0 {
            notices.push(Notice::SymlinksSkipped {
                count: self.symlinks_skipped,
            });
        }
        let not_regular = self.not_regular + swapped;
        if not_regular > 0 {
            notices.push(Notice::NotRegularFilesSkipped { count: not_regular });
        }
        notices
    }

    /// Resolve one input string to zero or more file paths.
    fn resolve(&mut self, input: &str) -> Result<(), IngestError> {
        // A `..` after a wildcard is refused before the input is tried as a
        // literal path. Windows resolves `..` lexically, so `root/*/../file`
        // exists there whenever `root/file` does, although `*` names nothing;
        // refusing it everywhere keeps the rule the same on every platform.
        if is_glob(input) && climbs_out_of_a_wildcard(input) {
            return Err(IngestError::BadPattern {
                pattern: input.to_string(),
                message: PARENT_AFTER_WILDCARD.to_owned(),
            });
        }
        let literal = Path::new(input);
        // A path that exists is always taken literally, even when its name holds
        // a glob metacharacter such as `[`, so such a file can still be named.
        match fs::metadata(literal) {
            Ok(metadata) => self.add_path(literal, &metadata),
            Err(_) if is_glob(input) => self.expand_glob(input),
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                Err(IngestError::PathNotFound {
                    path: literal.to_path_buf(),
                })
            }
            Err(source) => Err(IngestError::Io {
                path: literal.to_path_buf(),
                source,
            }),
        }
    }

    /// Add a path named explicitly: a regular file becomes a sample, a directory
    /// contributes its files, and anything else is skipped.
    fn add_path(&mut self, path: &Path, metadata: &fs::Metadata) -> Result<(), IngestError> {
        if metadata.is_dir() {
            self.walk_directory(path)
        } else {
            if metadata.is_file() {
                self.push_file(path);
            } else {
                self.not_regular += 1;
            }
            Ok(())
        }
    }

    /// Collect the regular files of a directory, descending into subdirectories
    /// only when recursion is on (FR-1).
    fn walk_directory(&mut self, dir: &Path) -> Result<(), IngestError> {
        let segments = directory_segments(self.options.recursive);
        self.walk(dir, &segments, Want::Files)
    }

    /// Expand a glob pattern against the filesystem.
    fn expand_glob(&mut self, pattern: &str) -> Result<(), IngestError> {
        let plan = GlobPlan::parse(pattern)?;
        // The literal leading directories were named by the user, so they are
        // followed even through a symlink; nothing below them is.
        let listing = if plan.root.as_os_str().is_empty() {
            Path::new(".")
        } else {
            plan.root.as_path()
        };
        match fs::metadata(listing) {
            Ok(metadata) if metadata.is_dir() => self.walk(&plan.root, &plan.segments, plan.want),
            // A root that is missing or is not a directory matches nothing.
            _ => Ok(()),
        }
    }

    /// Walk the tree under `root`, matching entries against `segments`.
    ///
    /// The walk is iterative, visits entries in sorted order (so the result is
    /// deterministic, NFR-6), charges every entry against the walk budget, and
    /// never follows a symbolic link: a link cycle cannot loop and a link cannot
    /// lead outside `root` (FR-24).
    fn walk(&mut self, root: &Path, segments: &[Segment], want: Want) -> Result<(), IngestError> {
        let start = closure(segments, vec![0]);
        // A pattern that can end at the root itself (such as `dir/**`) matches
        // the root directory.
        if start.contains(&segments.len()) && want != Want::Files {
            self.walk_directory(root)?;
        }
        if !start.iter().any(|&state| state < segments.len()) {
            return Ok(());
        }
        let Some(entries) = self.list(root)? else {
            return Ok(());
        };
        let mut stack = vec![Frame {
            dir: root.to_path_buf(),
            entries: entries.into_iter(),
            states: start,
        }];
        while let Some(frame) = stack.last_mut() {
            if self.exhausted() {
                break;
            }
            let Some((name, file_type)) = frame.entries.next() else {
                stack.pop();
                continue;
            };
            let path = frame.dir.join(&name);
            if file_type.is_symlink() {
                // Never followed during a walk. It is counted when it would have
                // mattered had it been a file or a directory.
                if !step(segments, &frame.states, &name, true).is_empty() {
                    self.symlinks_skipped += 1;
                }
                continue;
            }
            let is_dir = file_type.is_dir();
            let next = step(segments, &frame.states, &name, is_dir);
            if next.is_empty() {
                continue;
            }
            if next.contains(&segments.len()) {
                if is_dir {
                    if want != Want::Files {
                        self.walk_directory(&path)?;
                    }
                } else if want != Want::Dirs {
                    if file_type.is_file() {
                        self.push_file(&path);
                    } else {
                        self.not_regular += 1;
                    }
                }
            }
            if is_dir && next.iter().any(|&state| state < segments.len()) {
                if let Some(entries) = self.list(&path)? {
                    stack.push(Frame {
                        dir: path,
                        entries: entries.into_iter(),
                        states: next,
                    });
                }
            }
        }
        Ok(())
    }

    /// List a directory's entries sorted by name, charging each one against the
    /// walk budget. Returns `None` once the budget is spent.
    fn list(&mut self, dir: &Path) -> Result<Option<Vec<(OsString, fs::FileType)>>, IngestError> {
        let target = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        let io_error = |source| IngestError::Io {
            path: target.to_path_buf(),
            source,
        };
        let reader = fs::read_dir(target).map_err(io_error)?;
        let mut entries = Vec::new();
        for entry in reader {
            if self.visited >= self.options.max_walk_entries {
                self.walk_limit_hit = true;
                return Ok(None);
            }
            self.visited += 1;
            let entry = entry.map_err(io_error)?;
            // `file_type` describes the entry itself, with the semantics of
            // `symlink_metadata`: a link is reported as a link, never as its
            // target. An entry that cannot be typed (a race) is skipped.
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            entries.push((entry.file_name(), file_type));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Some(entries))
    }

    /// Append a file the first time its canonical form is seen, so the same file
    /// referenced twice yields a single sample while distinct files are all kept.
    fn push_file(&mut self, path: &Path) {
        let key = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if self.seen.contains(&key) {
            return;
        }
        if self.files.len() >= self.options.max_input_files {
            self.file_limit_hit = true;
            return;
        }
        self.seen.insert(key);
        self.files.push(path.to_path_buf());
    }
}

/// The pattern states reached after consuming one directory entry.
fn step(segments: &[Segment], states: &[usize], name: &OsStr, is_dir: bool) -> Vec<usize> {
    let text = name.to_str();
    let mut next = Vec::new();
    for &state in states {
        match segments.get(state) {
            Some(Segment::AnyDirs) => {
                if is_dir {
                    next.push(state);
                }
            }
            Some(Segment::AnyName) => next.push(state + 1),
            Some(Segment::Name(pattern)) => {
                // Like the glob crate, a name that is not valid UTF-8 never
                // matches a pattern component.
                if text.is_some_and(|text| pattern.matches_with(text, MATCH_OPTIONS)) {
                    next.push(state + 1);
                }
            }
            None => {}
        }
    }
    closure(segments, next)
}

/// Close a set of pattern states under `**` matching zero directories: a state
/// on `**` also stands on the segment after it.
fn closure(segments: &[Segment], mut states: Vec<usize>) -> Vec<usize> {
    let mut index = 0;
    while index < states.len() {
        let state = states[index];
        if matches!(segments.get(state), Some(Segment::AnyDirs)) && !states.contains(&(state + 1)) {
            states.push(state + 1);
        }
        index += 1;
    }
    states.sort_unstable();
    states.dedup();
    states
}

/// Read each resolved path into a sample, applying the per-sample and total
/// byte caps and collecting notices for any cap that took effect (FR-5). Also
/// returns how many paths were no longer regular files when they were opened.
fn read_samples(
    paths: &[PathBuf],
    options: &IngestOptions,
) -> Result<(SampleSet, usize), IngestError> {
    let mut set = SampleSet::default();
    let mut total: usize = 0;
    let mut truncated = 0usize;
    let mut skipped = 0usize;
    let mut swapped = 0usize;
    let mut total_cap_hit = false;

    for path in paths {
        if total_cap_hit {
            skipped += 1;
            continue;
        }

        let io_error = |source| IngestError::Io {
            path: path.clone(),
            source,
        };
        // The path was a regular file when it was listed, but it may have been
        // replaced since, so the opened handle is checked again.
        let Some((file, original_length)) = open_regular_file(path).map_err(io_error)? else {
            swapped += 1;
            continue;
        };
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

        let data = read_up_to(file, keep).map_err(io_error)?;
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
    Ok((set, swapped))
}

/// Open `path` for reading when it is a regular file, returning the handle and
/// the file's size from the handle's own metadata. Returns `Ok(None)` for
/// anything else.
///
/// The path is checked first so devices and FIFOs are not opened at all in the
/// ordinary case, and the opened handle is checked again because the path may
/// have been replaced in between. The open itself is non-blocking where the
/// platform allows, so a FIFO swapped in at the last moment cannot stall it
/// waiting for a writer.
fn open_regular_file(path: &Path) -> io::Result<Option<(fs::File, u64)>> {
    if !fs::metadata(path)?.is_file() {
        return Ok(None);
    }
    let file = open_for_reading(path)?;
    let metadata = file.metadata()?;
    if metadata.is_file() {
        Ok(Some((file, metadata.len())))
    } else {
        Ok(None)
    }
}

/// Open a path read-only, without blocking on a FIFO where the platform's
/// non-blocking flag is known. The flag has no effect on regular files.
fn open_for_reading(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(flag) = nonblocking_open_flag() {
            options.custom_flags(flag);
        }
    }
    options.open(path)
}

/// The platform's `O_NONBLOCK` open flag, when it is known.
///
/// The engine has no `libc` dependency, so the value is spelled out for the
/// platform families Sextant ships on: Linux and Android on their common
/// architectures, where it is octal 4000, and the Apple and BSD systems, where
/// it is 4. Elsewhere this returns `None` and the open blocks as usual; the path
/// and handle checks around it still apply.
#[cfg(unix)]
fn nonblocking_open_flag() -> Option<i32> {
    if cfg!(all(
        any(target_os = "linux", target_os = "android"),
        any(
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "s390x",
            target_arch = "loongarch64",
        )
    )) {
        Some(0o4000)
    } else if cfg!(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    )) {
        Some(0x0004)
    } else {
        None
    }
}

/// Read at most `cap` bytes from an open file. A very large file is never read
/// whole: the [`Read::take`] limit bounds both the bytes read and the
/// allocation, so a multi-gigabyte file costs only `cap` bytes of memory (FR-4).
fn read_up_to(file: fs::File, cap: usize) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    file.take(cap as u64).read_to_end(&mut data)?;
    Ok(data)
}

/// Whether an input string is a glob pattern rather than a literal path. The
/// metacharacters are `*`, `?`, and `[`.
fn is_glob(input: &str) -> bool {
    input.contains(['*', '?', '['])
}

/// Why a pattern that climbs out of a wildcard component is refused.
const PARENT_AFTER_WILDCARD: &str = "a `..` component after a wildcard is not supported";

/// Whether a `..` component follows the first component that holds a glob
/// metacharacter, the same test [`GlobPlan::parse`] applies.
fn climbs_out_of_a_wildcard(input: &str) -> bool {
    Path::new(input)
        .components()
        .skip_while(|component| !component.as_os_str().to_str().is_some_and(is_glob))
        .any(|component| component == Component::ParentDir)
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
    fn glob_plan_splits_the_literal_root_from_the_pattern() {
        let plan = GlobPlan::parse("corpus/tlv/**/*.tlv").expect("valid pattern");
        assert_eq!(plan.root, PathBuf::from("corpus/tlv"));
        assert_eq!(plan.segments.len(), 2);
        assert!(matches!(plan.segments[0], Segment::AnyDirs));
        assert_eq!(plan.want, Want::Any);

        let relative = GlobPlan::parse("*.png").expect("valid pattern");
        assert!(relative.root.as_os_str().is_empty());
        assert_eq!(relative.segments.len(), 1);

        // Consecutive `**` collapse, and a trailing separator wants directories.
        let dirs = GlobPlan::parse("root/**/**/").expect("valid pattern");
        assert_eq!(dirs.segments.len(), 1);
        assert_eq!(dirs.want, Want::Dirs);
    }

    #[test]
    fn a_parent_component_is_detected_only_after_a_wildcard() {
        assert!(climbs_out_of_a_wildcard("root/*/../secret"));
        assert!(climbs_out_of_a_wildcard("root/a[1]/b/../c"));
        assert!(!climbs_out_of_a_wildcard("../corpus/*.bin"));
        assert!(!climbs_out_of_a_wildcard("root/../corpus/sample[1].bin"));
        assert!(!climbs_out_of_a_wildcard("root/**/*.bin"));
    }

    #[test]
    fn glob_plan_rejects_a_parent_component_after_a_wildcard() {
        assert!(matches!(
            GlobPlan::parse("root/*/../secret"),
            Err(IngestError::BadPattern { .. })
        ));
        // A parent component in the literal root is an ordinary path.
        assert!(GlobPlan::parse("../corpus/*.bin").is_ok());
    }

    #[test]
    fn default_options_are_bounded_and_not_recursive() {
        let options = IngestOptions::default();
        assert_eq!(options.max_bytes_per_sample, DEFAULT_MAX_BYTES_PER_SAMPLE);
        assert_eq!(options.max_total_bytes, DEFAULT_MAX_TOTAL_BYTES);
        assert_eq!(options.max_walk_entries, DEFAULT_MAX_WALK_ENTRIES);
        assert_eq!(options.max_input_files, DEFAULT_MAX_INPUT_FILES);
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

    /// A unique scratch directory under the system temp directory.
    #[cfg(unix)]
    fn scratch(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "sextant-ingest-unit-{tag}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create scratch dir");
        root
    }

    #[cfg(unix)]
    #[test]
    fn recursive_ingest_does_not_follow_a_symlink_cycle() {
        let root = scratch("symlink");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).expect("create dirs");
        fs::write(nested.join("real.bin"), b"data").expect("write file");
        // A symlink inside the tree that points back at the root would loop
        // forever if the walker followed it.
        std::os::unix::fs::symlink(&root, nested.join("loop")).expect("symlink");

        let result = ingest(
            &[root.to_string_lossy().into_owned()],
            &IngestOptions::default().with_recursive(true),
        );
        let _ = fs::remove_dir_all(&root);

        let set = result.expect("ingest terminates without following the cycle");
        // The one real file is ingested exactly once; the symlink is skipped.
        assert_eq!(set.len(), 1);
        assert_eq!(set.samples[0].data, b"data");
        assert!(set.notices.contains(&Notice::SymlinksSkipped { count: 1 }));
    }

    /// Create a FIFO with the system `mkfifo` tool; `None` when it is missing.
    #[cfg(unix)]
    fn make_fifo(path: &Path) -> Option<()> {
        let status = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .ok()?;
        status.success().then_some(())
    }

    /// Run `work` on a helper thread and fail if it does not finish promptly,
    /// so a blocking open fails the test instead of hanging the suite.
    #[cfg(unix)]
    fn finishes_promptly<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(work());
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("the operation blocked on a FIFO")
    }

    #[cfg(unix)]
    #[test]
    fn a_file_swapped_for_a_fifo_before_reading_is_skipped_without_blocking() {
        let root = scratch("fifo-swap");
        let fifo = root.join("sample.bin");
        if make_fifo(&fifo).is_none() {
            let _ = fs::remove_dir_all(&root);
            eprintln!("skipping: mkfifo is not available");
            return;
        }
        // Resolution saw a regular file at this path; by the time it is read
        // the path is a FIFO with no writer. Reading must neither block nor
        // treat it as a sample.
        let paths = vec![fifo.clone()];
        let (set, swapped) = finishes_promptly(move || {
            read_samples(&paths, &IngestOptions::default()).expect("read completes")
        });
        assert!(set.is_empty());
        assert_eq!(swapped, 1);

        // The non-blocking open itself returns at once on a FIFO, and the
        // handle's metadata exposes it, even with the path pre-check bypassed.
        let target = fifo.clone();
        let is_file = finishes_promptly(move || {
            open_for_reading(&target)
                .and_then(|file| file.metadata())
                .map(|metadata| metadata.is_file())
        });
        let _ = fs::remove_dir_all(&root);
        if nonblocking_open_flag().is_some() {
            assert!(!is_file.expect("non-blocking open of a FIFO succeeds"));
        }
    }

    #[test]
    fn notice_messages_avoid_dashes() {
        let notices = [
            Notice::SamplesTruncated { count: 2, cap: 16 },
            Notice::TotalCapReached {
                cap: 32,
                skipped: 1,
            },
            Notice::WalkLimitReached { limit: 10 },
            Notice::FileLimitReached { limit: 10 },
            Notice::SymlinksSkipped { count: 3 },
            Notice::NotRegularFilesSkipped { count: 1 },
        ];
        for notice in notices {
            let message = notice.to_string();
            assert!(!message.contains('\u{2014}'), "em dash in: {message}");
            assert!(!message.contains('\u{2013}'), "en dash in: {message}");
        }
    }
}
