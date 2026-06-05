//! The composite Format Hypothesis IR (PRD Section 10, FR-13 to FR-19).
//!
//! A [`Format`] is the single object the executor consumes and the exporters
//! read. It is a tree of [`Structure`]s and [`Field`]s, where each field has a
//! [`Kind`], an optional [`SizeRule`], optional cross-field relationships, a
//! [`Confidence`], and an [`Evidence`] record.
//!
//! Every optional and collection member is omitted from JSON when empty and
//! defaulted on read, so the representation stays compact while round-tripping
//! losslessly (FR-19): `from_json(to_json(ir)) == ir`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::bytes::Bytes;
use crate::primitives::{
    ChecksumAlgorithm, Confidence, Endianness, FieldRef, Role, Signedness, StringEncoding,
};

/// A complete hypothesized binary format (FR-13).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Format {
    /// A short name for the format, for example `png` or `tlv`.
    pub name: String,
    /// The default byte order, which integer and enum fields inherit unless
    /// they override it (FR-16).
    pub endianness: Endianness,
    /// The root structure parsed from the start of each sample.
    pub root: Structure,
    /// Named enumerations referenced by [`Kind::Enum`] fields.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub enums: BTreeMap<String, EnumDef>,
    /// Free-form metadata about the format and how it was inferred.
    #[serde(default, skip_serializing_if = "Metadata::is_empty")]
    pub metadata: Metadata,
}

impl Format {
    /// Serialize the format to pretty-printed JSON (FR-19).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`serde_json::Error`] if serialization fails,
    /// which should not happen for a well-formed in-memory value.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Serialize the format to compact JSON (FR-19).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`serde_json::Error`] if serialization fails.
    pub fn to_json_compact(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize a format from JSON (FR-19).
    ///
    /// This is structural only and does not check semantic validity; call
    /// [`Format::validate`](crate::Format::validate) afterward.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`serde_json::Error`] if the text is not a valid
    /// JSON encoding of a [`Format`].
    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

/// An ordered list of fields (FR-13).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Structure {
    /// The fields, in parse order.
    pub fields: Vec<Field>,
}

impl Structure {
    /// Create a structure from a list of fields.
    #[must_use]
    pub fn new(fields: Vec<Field>) -> Self {
        Self { fields }
    }
}

/// A single field in a structure (PRD Section 10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Field {
    /// The field name. Optional, because a detector may not have a name yet,
    /// but required for a field that is referenced by a relationship.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// What kind of value the field holds.
    pub kind: Kind,
    /// How the field's size is determined. Omitted when the kind implies the
    /// size (integers and enums from their width, structs from their fields,
    /// arrays from their count rule).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<SizeRule>,
    /// An explicit start position relative to the enclosing structure. When
    /// omitted the field follows the previous field sequentially. An explicit
    /// offset enables absolute positioning and lets validation detect
    /// overlapping fixed fields (FR-17).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<FieldOffset>,
    /// The field's semantic role, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    /// Constraints the field's value must satisfy (FR-17).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<Constraint>,
    /// How confident the hypothesis is in this field (FR-18).
    pub confidence: Confidence,
    /// What evidence supports the hypothesis (FR-18).
    #[serde(default, skip_serializing_if = "Evidence::is_empty")]
    pub evidence: Evidence,
}

impl Field {
    /// Create a field with the given kind and confidence and no other metadata.
    #[must_use]
    pub fn new(kind: Kind, confidence: Confidence) -> Self {
        Self {
            name: None,
            kind,
            size: None,
            offset: None,
            role: None,
            constraints: Vec::new(),
            confidence,
            evidence: Evidence::default(),
        }
    }

    /// Set the field name (builder style).
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the size rule (builder style).
    #[must_use]
    pub fn with_size(mut self, size: SizeRule) -> Self {
        self.size = Some(size);
        self
    }

    /// Set the role (builder style).
    #[must_use]
    pub fn with_role(mut self, role: Role) -> Self {
        self.role = Some(role);
        self
    }
}

/// The kind of value a field holds (FR-16).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Kind {
    /// An integer with an explicit byte width, signedness, and optional
    /// endianness override.
    Integer {
        /// Width in bytes (1, 2, 4, or 8).
        width: u8,
        /// Signed or unsigned interpretation.
        signed: Signedness,
        /// Endianness override; inherits the format default when omitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        endianness: Option<Endianness>,
    },
    /// A run of raw bytes. The size is given by the field's [`SizeRule`].
    Bytes,
    /// A text string in the given encoding. The size is given by the field's
    /// [`SizeRule`].
    String {
        /// The text encoding.
        encoding: StringEncoding,
    },
    /// An enumerated integer whose meanings are listed in a named
    /// [`EnumDef`] on the format.
    Enum {
        /// The name of the referenced enum (resolved against `Format::enums`).
        #[serde(rename = "enum")]
        enum_ref: String,
        /// Width in bytes (1, 2, 4, or 8).
        width: u8,
        /// Endianness override; inherits the format default when omitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        endianness: Option<Endianness>,
    },
    /// A nested structure. Its size is the sum of its fields.
    Struct {
        /// The nested structure.
        structure: Structure,
    },
    /// A repeated element. The number of elements is given by the
    /// [`CountRule`].
    Array {
        /// The element, described as a field in its own right.
        element: Box<Field>,
        /// How many elements there are.
        count: CountRule,
    },
    /// Opaque or high-entropy bytes that were not decomposed further. The size
    /// is given by the field's [`SizeRule`].
    Opaque,
}

/// How a field's size in bytes is determined (FR-14, PRD Section 10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum SizeRule {
    /// A fixed number of bytes.
    Fixed {
        /// The size in bytes.
        bytes: u64,
    },
    /// Derived from the value of a referenced length field.
    Derived {
        /// The length field that gives this field's size.
        length_field: FieldRef,
    },
    /// Read until a terminator byte sequence is seen.
    Delimited {
        /// The terminator byte sequence.
        terminator: Bytes,
        /// Whether the terminator is part of the field's bytes.
        #[serde(default)]
        include_terminator: bool,
    },
    /// Read to the end of the buffer or enclosing parent.
    ToEnd,
}

/// How many elements an array has (FR-15, PRD Section 10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum CountRule {
    /// A fixed number of elements.
    Fixed {
        /// The number of elements.
        count: u64,
    },
    /// Taken from the value of a referenced count field.
    FromField {
        /// The count field that gives the number of elements.
        count_field: FieldRef,
    },
    /// Bounded by a referenced length field that gives the array's total byte
    /// length; the array reads elements until that many bytes are consumed.
    BoundedBy {
        /// The length field that gives the array's total byte length.
        length_field: FieldRef,
    },
    /// Read elements until the end of the buffer or enclosing parent.
    ToEnd,
}

/// An explicit start position for a field (FR-17).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum FieldOffset {
    /// An absolute byte offset relative to the start of the enclosing
    /// structure.
    Absolute {
        /// The offset in bytes.
        bytes: u64,
    },
    /// A position taken from the value of a referenced offset field.
    Derived {
        /// The offset field that gives this field's position.
        offset_field: FieldRef,
    },
}

/// A constraint a field's value must satisfy (FR-17, PRD Section 10).
///
/// This enum is externally tagged (for example `{"int_range": {"min": 0,
/// "max": 7}}`) rather than internally tagged like the other IR enums, because
/// serde's internal-tag buffering does not support the `i128` bounds that
/// [`Constraint::IntRange`] needs to cover the full 64-bit integer range.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Constraint {
    /// The field must equal a fixed constant (used for magic and signatures).
    Constant {
        /// The expected bytes.
        value: Bytes,
    },
    /// The field's integer value must fall within an inclusive range.
    IntRange {
        /// The inclusive lower bound.
        min: i128,
        /// The inclusive upper bound.
        max: i128,
    },
    /// The field is a checksum over a covered byte range.
    Checksum {
        /// The checksum algorithm and the range it covers.
        spec: ChecksumSpec,
    },
}

/// A checksum specification: an algorithm plus the byte range it covers,
/// expressed relative to fields (FR-17, PRD Section 10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChecksumSpec {
    /// The checksum or hash algorithm.
    pub algorithm: ChecksumAlgorithm,
    /// The byte range the checksum covers.
    pub covered: CoveredRange,
}

/// A byte range covered by a checksum, expressed as two field-relative anchors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoveredRange {
    /// Where the covered range begins.
    pub from: RangeAnchor,
    /// Where the covered range ends.
    pub to: RangeAnchor,
}

/// One end of a [`CoveredRange`], anchored to a named field (FR-17).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "anchor", rename_all = "snake_case")]
pub enum RangeAnchor {
    /// The start of the named field's bytes.
    FieldStart {
        /// The anchor field.
        field: FieldRef,
    },
    /// The end of the named field's bytes (exclusive).
    FieldEnd {
        /// The anchor field.
        field: FieldRef,
    },
}

impl RangeAnchor {
    /// The field this anchor points at.
    #[must_use]
    pub fn field(&self) -> &FieldRef {
        match self {
            RangeAnchor::FieldStart { field } | RangeAnchor::FieldEnd { field } => field,
        }
    }
}

/// Why a field was hypothesized the way it was (FR-18, PRD Section 10).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Evidence {
    /// Which detector or source proposed the field (for example a statistical
    /// detector, a model pass, or `hand-authored`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector: Option<String>,
    /// How many samples agree with the hypothesis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support: Option<SampleSupport>,
    /// A rationale supplied by a language model, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_rationale: Option<String>,
    /// Any additional human-readable notes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl Evidence {
    /// Whether this record carries no information (used to omit it from JSON).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.detector.is_none()
            && self.support.is_none()
            && self.model_rationale.is_none()
            && self.notes.is_empty()
    }
}

/// Cross-sample agreement supporting a hypothesis (FR-18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleSupport {
    /// How many samples agree with the hypothesis.
    pub agreeing: u64,
    /// How many samples were considered.
    pub total: u64,
}

/// A named enumeration of integer values (FR-16, PRD Section 10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnumDef {
    /// The underlying integer width in bytes, if fixed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u8>,
    /// The known values and their meanings.
    pub variants: Vec<EnumVariant>,
}

/// One value in an [`EnumDef`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnumVariant {
    /// The integer value. `i128` holds the full signed and unsigned 64-bit
    /// range.
    pub value: i128,
    /// The symbolic name.
    pub name: String,
    /// An optional human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Free-form metadata about a format (PRD Section 10, "global metadata").
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Metadata {
    /// A human-readable description of the format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The format version this hypothesis targets, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Where the hypothesis came from (a specification, a corpus, a run).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Any additional key-value metadata.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, String>,
}

impl Metadata {
    /// Whether this record carries no information (used to omit it from JSON).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.description.is_none()
            && self.version.is_none()
            && self.source.is_none()
            && self.extra.is_empty()
    }
}
