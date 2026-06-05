//! Format Hypothesis IR for Sextant.
//!
//! This crate defines the intermediate representation that describes a
//! hypothesized binary format: [`Structure`]s, [`Field`]s, [`Kind`]s, size and
//! count rules, [`Role`]s, [`Constraint`]s, [`Evidence`], and [`Confidence`]. It
//! also provides lossless JSON serialization (FR-19) and semantic validation.
//!
//! The IR is intentionally close to Kaitai Struct semantics so that export is
//! faithful, with added confidence and evidence metadata (PRD Section 10). It is
//! the single object the executor consumes and the exporters read.
//!
//! # Lossless JSON round-trip (FR-19)
//!
//! Any [`Format`] serializes to JSON and deserializes back to an equal value:
//!
//! ```
//! use sextant_ir::fixtures;
//!
//! let format = fixtures::png_ground_truth();
//! let json = format.to_json().expect("serialize");
//! let parsed = sextant_ir::Format::from_json(&json).expect("deserialize");
//! assert_eq!(format, parsed);
//! ```
//!
//! # Validation
//!
//! Deserialization is purely structural. Semantic rules (no dangling
//! references, no overlapping fixed fields, sane sizes) are checked separately
//! so that even a malformed IR round-trips and is then reported with clear,
//! located errors:
//!
//! ```
//! use sextant_ir::fixtures;
//!
//! let format = fixtures::png_ground_truth();
//! assert!(format.validate().is_ok());
//! ```

pub mod bytes;
pub mod fixtures;
pub mod model;
pub mod primitives;
pub mod validate;

pub use bytes::{Bytes, HexError};
pub use model::{
    ChecksumSpec, Constraint, CountRule, CoveredRange, EnumDef, EnumVariant, Evidence, Field,
    FieldOffset, Format, Kind, Metadata, RangeAnchor, SampleSupport, SizeRule, Structure,
};
pub use primitives::{
    ChecksumAlgorithm, Confidence, ConfidenceError, Endianness, FieldRef, Role, Signedness,
    StringEncoding,
};
pub use validate::{ValidationError, ValidationErrorKind, ValidationReport};

impl Format {
    /// Validate the format against Sextant's semantic rules.
    ///
    /// Checks that every length, count, offset, and checksum reference resolves
    /// in scope to an appropriate field, that fixed fields do not overlap, and
    /// that all sizes, widths, ranges, and confidences are sane. Returns the
    /// full [`ValidationReport`] when anything is wrong (FR-19 acceptance).
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationReport`] listing every problem found when the IR is
    /// not semantically well-formed.
    pub fn validate(&self) -> Result<(), ValidationReport> {
        let report = validate::validate(self);
        if report.is_ok() { Ok(()) } else { Err(report) }
    }
}
