//! Leaf value types used throughout the Format Hypothesis IR.
//!
//! These are the small, self-contained building blocks: byte order, signedness,
//! string encodings, checksum algorithms, semantic roles, field references, and
//! the confidence scalar. Keeping them in one place lets the composite model in
//! [`crate::model`] stay focused on structure.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Byte order for a multi-byte integer or enum field.
///
/// A [`Format`](crate::Format) carries a default endianness that individual
/// fields may override (FR-16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endianness {
    /// Least-significant byte first.
    Little,
    /// Most-significant byte first.
    Big,
}

/// Whether an integer field is interpreted as signed or unsigned (FR-16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signedness {
    /// Non-negative values only.
    Unsigned,
    /// Two's-complement signed values.
    Signed,
}

/// Text encoding for a string field (FR-16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    /// Seven-bit ASCII.
    Ascii,
    /// UTF-8.
    Utf8,
    /// UTF-16, little-endian.
    Utf16Le,
    /// UTF-16, big-endian.
    Utf16Be,
    /// ISO 8859-1 (Latin-1).
    Latin1,
}

/// A checksum or hash algorithm that verifies a covered byte range (FR-10,
/// FR-17). This is the minimum algorithm set the verification substrate must
/// support; more can be added without changing the IR shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumAlgorithm {
    /// CRC-32 (the IEEE polynomial, as used by PNG and zlib).
    Crc32,
    /// CRC-16.
    Crc16,
    /// A simple additive checksum (sum of bytes modulo the field width).
    Additive,
    /// A bytewise XOR checksum.
    Xor,
}

/// The semantic role a field plays in a format (FR-17, FR-18, PRD Section 10).
///
/// Roles are descriptive metadata. A role does not by itself change how a field
/// is parsed; the [`Kind`](crate::Kind), [`SizeRule`](crate::SizeRule), and
/// [`Constraint`](crate::Constraint) do that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// A magic number or signature (an invariant constant prefix).
    Magic,
    /// A format or structure version.
    Version,
    /// A length that governs the size of another field.
    Length,
    /// A count that governs the number of elements in an array.
    Count,
    /// An offset that points at where another structure begins.
    Offset,
    /// A message type or function code that discriminates protocol messages.
    MessageType,
    /// A sequence, transaction, or request identifier that orders or pairs
    /// protocol messages.
    Sequence,
    /// A checksum or hash value.
    Checksum,
    /// A timestamp.
    Timestamp,
    /// A set of bit flags.
    Flags,
    /// An enumerated value.
    Enum,
    /// Reserved or padding bytes with no interpreted meaning.
    Reserved,
    /// Opaque payload or content bytes.
    Payload,
    /// A field whose role has not been determined.
    Unknown,
}

/// A reference to another field by name.
///
/// Length, count, offset, and checksum relationships point at the field they
/// depend on by its name (FR-17). Validation resolves every reference and
/// rejects dangling ones (FR-19 acceptance, Step 2). A field must be named to
/// be referenced.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FieldRef(pub String);

impl FieldRef {
    /// Create a reference to a field with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The referenced field name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for FieldRef {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for FieldRef {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Display for FieldRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The error returned when constructing a [`Confidence`] from a value outside
/// the inclusive range 0.0 to 1.0, or from a non-finite value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ConfidenceError {
    /// The rejected value.
    pub value: f64,
}

impl fmt::Display for ConfidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "confidence must be a finite value in 0.0 to 1.0, got {}",
            self.value
        )
    }
}

impl std::error::Error for ConfidenceError {}

/// A confidence value in the inclusive range 0.0 to 1.0 (FR-18).
///
/// Deserialization is permissive so that any structurally valid IR round-trips
/// losslessly (FR-19); a value outside the range is caught later by
/// [`Format::validate`](crate::Format::validate) with a clear error rather than
/// failing to parse.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Confidence(f64);

impl Confidence {
    /// The lowest confidence (0.0).
    pub const NONE: Confidence = Confidence(0.0);
    /// Full confidence (1.0), used for verified relationships and invariants.
    pub const CERTAIN: Confidence = Confidence(1.0);

    /// Create a confidence, rejecting non-finite values and values outside
    /// 0.0 to 1.0.
    ///
    /// # Errors
    ///
    /// Returns [`ConfidenceError`] when `value` is not a finite number in the
    /// inclusive range 0.0 to 1.0.
    pub fn new(value: f64) -> Result<Self, ConfidenceError> {
        if value.is_finite() && (0.0..=1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ConfidenceError { value })
        }
    }

    /// Create a confidence by clamping `value` into 0.0 to 1.0. A non-finite
    /// value (`NaN` or either infinity) clamps to 0.0, so a broken confidence
    /// calculation degrades to the conservative low value rather than to
    /// [`Confidence::CERTAIN`].
    #[must_use]
    pub fn clamped(value: f64) -> Self {
        if value.is_finite() {
            Self(value.clamp(0.0, 1.0))
        } else {
            Self(0.0)
        }
    }

    /// The underlying value.
    #[must_use]
    pub fn get(self) -> f64 {
        self.0
    }

    /// Whether the stored value is a finite number in 0.0 to 1.0.
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.0.is_finite() && (0.0..=1.0).contains(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_new_accepts_in_range() {
        assert!(Confidence::new(0.0).is_ok());
        assert!(Confidence::new(0.5).is_ok());
        assert!(Confidence::new(1.0).is_ok());
    }

    #[test]
    fn confidence_new_rejects_out_of_range_and_non_finite() {
        assert!(Confidence::new(-0.1).is_err());
        assert!(Confidence::new(1.1).is_err());
        assert!(Confidence::new(f64::NAN).is_err());
        assert!(Confidence::new(f64::INFINITY).is_err());
    }

    #[test]
    fn confidence_clamped_bounds_value() {
        assert_eq!(Confidence::clamped(-5.0).get(), 0.0);
        assert_eq!(Confidence::clamped(5.0).get(), 1.0);
        assert_eq!(Confidence::clamped(f64::NAN).get(), 0.0);
        assert_eq!(Confidence::clamped(0.25).get(), 0.25);
    }

    #[test]
    fn confidence_clamped_treats_non_finite_as_zero() {
        // A non-finite value must degrade to the conservative low value, not
        // become CERTAIN.
        assert_eq!(Confidence::clamped(f64::INFINITY).get(), 0.0);
        assert_eq!(Confidence::clamped(f64::NEG_INFINITY).get(), 0.0);
    }

    #[test]
    fn field_ref_round_trips_as_a_plain_string() {
        let value = FieldRef::new("length");
        let json = serde_json::to_string(&value).expect("serialize");
        assert_eq!(json, "\"length\"");
        let back: FieldRef = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, value);
    }
}
