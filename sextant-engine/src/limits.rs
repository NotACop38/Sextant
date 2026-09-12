//! Resource limits for the executor (FR-24, NFR-2).
//!
//! Sextant parses untrusted, potentially hostile input, so the executor must
//! never panic, hang, or allocate without bound on any input. [`Limits`] caps
//! recursion depth, array length, parsed field instances, owned output bytes,
//! a unit of total work (which bounds time without a
//! clock), and an optional wall-clock deadline. When any cap is reached the
//! executor stops with a localized failure rather than continuing.

use std::time::Duration;

/// Caps that bound the executor's recursion, allocation, and run time (FR-24).
///
/// The defaults are generous enough for the corpus formats yet still bound every
/// dimension, so even an adversarial IR or sample cannot exhaust resources. A
/// caller can tighten any field; fuzzing, for example, drops [`Limits::timeout`]
/// to stay deterministic and relies on [`Limits::max_steps`] instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// The deepest nesting of structures and arrays the executor will enter.
    /// Reaching it stops the parse rather than recursing further.
    pub max_depth: usize,
    /// The most elements a single array may produce before the parse stops.
    pub max_array_elements: usize,
    /// The most field instances a single execution may produce in total.
    pub max_total_fields: usize,
    /// The byte budget for owned parse results and parsing metadata. Accounting
    /// includes string copies, decoded previews, checks and conservative vector
    /// capacity allowances, and is cumulative even when partial results drop.
    /// Inspect uses this same cap separately for its annotations and output.
    pub max_output_bytes: usize,
    /// The most units of work a single execution may perform. One unit is
    /// charged per field, constraint, lookup comparison and byte compared while
    /// scanning or hashing. Output allocation charges one unit per 64 bytes.
    /// This bounds run time even when the wall-clock cap is off.
    pub max_steps: u64,
    /// An optional wall-clock cap. When set, the executor stops once the
    /// deadline passes. It is left unset for deterministic fuzzing.
    pub timeout: Option<Duration>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_array_elements: 1 << 24,
            max_total_fields: 1 << 20,
            max_output_bytes: 64 << 20,
            max_steps: 50_000_000,
            timeout: Some(Duration::from_secs(5)),
        }
    }
}

impl Limits {
    /// Limits suited to fuzzing: no wall-clock cap, so runs are deterministic,
    /// with tight work, depth, array, and field caps so any single input
    /// finishes quickly regardless of content.
    #[must_use]
    pub fn for_fuzzing() -> Self {
        Self {
            max_depth: 32,
            max_array_elements: 1 << 16,
            max_total_fields: 1 << 16,
            max_output_bytes: 4 << 20,
            max_steps: 2_000_000,
            timeout: None,
        }
    }

    /// Set the wall-clock timeout (builder style).
    ///
    /// Prefer this over assigning [`Limits::timeout`] through
    /// `Option::map` at a call site: passing `None` into a setter that took
    /// `Option<Duration>` used to clear the default five-second cap when a CLI
    /// flag was omitted.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Clear the wall-clock timeout so only the work cap bounds run time.
    ///
    /// Used by deterministic fuzzing and by callers that intentionally want no
    /// clock deadline. Omitting a CLI `--timeout` flag must not call this.
    #[must_use]
    pub fn clear_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    /// Set the recursion-depth cap (builder style).
    #[must_use]
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }
}
