//! The machine-readable inference report (FR-34).
//!
//! A [`Report`] is the single JSON document an inference run produces. It carries
//! the chosen Format Hypothesis IR (which embeds each field's confidence and
//! evidence), the verified fit [`Score`] and its breakdown, a flattened field map
//! for display, the refinement history, and run metadata. The structure is
//! described by the JSON Schema committed at `schemas/report.schema.json`, and
//! every report serialized by [`Report::to_json`] validates against it.
//!
//! The report is fully serializable to and from JSON (FR-19, FR-34): the chosen
//! IR round-trips through `sextant-ir`, and the score, refinement, and metadata
//! round-trip through the derives here. The `inspect` view (FR-35) reads a report
//! back from disk and renders a sample through it.

use serde::{Deserialize, Serialize};
use sextant_ir::{Field, Format, Kind, Role, SizeRule};

use crate::refine::RefineStep;
use crate::scorer::Score;

/// The version of the report JSON structure (FR-34).
///
/// It is written into every report as `schema_version` and matches the `$id`
/// version of the committed JSON Schema. Bump it when the structure changes in a
/// way that is not backward compatible.
pub const REPORT_SCHEMA_VERSION: &str = "1.0";

/// Cap on report JSON size when loading from disk for `inspect` / `export`.
/// Bounds memory before serde parses the document (FR-24).
pub const DEFAULT_MAX_REPORT_BYTES: usize = 16 << 20;

/// Metadata about an inference run, recorded in the report for reproducibility
/// (FR-34, PRD Section 13: tool version, inputs, configuration, model usage).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunMetadata {
    /// The tool version that produced the report.
    pub tool_version: String,
    /// How many samples were analyzed.
    pub sample_count: usize,
    /// The total number of sample bytes analyzed.
    pub total_bytes: usize,
    /// Whether the run was statistics-only with the language model disabled. In
    /// this mode no bytes leave the machine (NFR-4).
    pub no_llm: bool,
}

/// One row of the flattened field map: a single field rendered for display, with
/// its nesting depth so a reader can see the tree (FR-34, FR-35 groundwork).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldMapEntry {
    /// The field's nesting depth (zero at the root).
    pub depth: usize,
    /// The field name, or `"(unnamed)"` when the IR did not name it.
    pub name: String,
    /// A short human-readable description of the field's role.
    pub role: String,
    /// A short human-readable description of the field's kind and byte order.
    pub kind: String,
    /// A short human-readable description of how the field's size is determined.
    pub size: String,
    /// The field's confidence, in the range 0 to 1.
    pub confidence: f64,
}

/// The machine-readable result of an inference run (FR-34).
///
/// This is the canonical JSON report. It is built by the orchestrator at the end
/// of a run and is the document `sextant inspect` and the exporters read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// The version of the report structure (see [`REPORT_SCHEMA_VERSION`]).
    pub schema_version: String,
    /// Metadata about the run.
    pub metadata: RunMetadata,
    /// The chosen, refined Format Hypothesis IR. Each field carries its own
    /// confidence and evidence (FR-18).
    pub format: Format,
    /// The verified fit score of the chosen IR over the sample set, with its
    /// per-dimension and per-sample breakdown (FR-23).
    pub score: Score,
    /// The chosen IR's fields, flattened for display, in parse order.
    pub field_map: Vec<FieldMapEntry>,
    /// The refinement steps that were accepted, in order (FR-28).
    pub refinement: Vec<RefineStep>,
}

impl Report {
    /// Build a report from a chosen IR, its score, the refinement history, and
    /// run metadata. The flattened field map is derived from the IR.
    #[must_use]
    pub fn build(
        format: Format,
        score: Score,
        refinement: Vec<RefineStep>,
        metadata: RunMetadata,
    ) -> Self {
        let mut field_map = Vec::new();
        for field in &format.root.fields {
            flatten_field(field, 0, &mut field_map);
        }
        Self {
            schema_version: REPORT_SCHEMA_VERSION.to_owned(),
            metadata,
            format,
            score,
            field_map,
            refinement,
        }
    }

    /// Serialize the report to pretty-printed JSON (FR-19, FR-34).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`serde_json::Error`] if serialization fails,
    /// which should not happen for a well-formed in-memory value.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize a report from JSON (FR-19, FR-34).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`serde_json::Error`] if the text is not a valid
    /// JSON encoding of a [`Report`].
    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

/// Append a field and its descendants to the flattened field map.
fn flatten_field(field: &Field, depth: usize, out: &mut Vec<FieldMapEntry>) {
    out.push(FieldMapEntry {
        depth,
        name: field.name.clone().unwrap_or_else(|| "(unnamed)".to_owned()),
        role: role_label(field.role),
        kind: kind_label(&field.kind),
        size: size_label(field),
        confidence: field.confidence.get(),
    });
    match &field.kind {
        Kind::Struct { structure } => {
            for child in &structure.fields {
                flatten_field(child, depth + 1, out);
            }
        }
        Kind::Array { element, .. } => {
            flatten_field(element, depth + 1, out);
        }
        _ => {}
    }
}

/// A short label for a field role.
#[must_use]
pub(crate) fn role_label(role: Option<Role>) -> String {
    let label = match role {
        Some(Role::Magic) => "magic",
        Some(Role::Version) => "version",
        Some(Role::Length) => "length",
        Some(Role::Count) => "count",
        Some(Role::Offset) => "offset",
        Some(Role::MessageType) => "message type",
        Some(Role::Sequence) => "sequence",
        Some(Role::Checksum) => "checksum",
        Some(Role::Timestamp) => "timestamp",
        Some(Role::Flags) => "flags",
        Some(Role::Enum) => "enum",
        Some(Role::Reserved) => "reserved",
        Some(Role::Payload) => "payload",
        Some(Role::Unknown) | None => "unknown",
    };
    label.to_owned()
}

/// A short label for a field kind, including byte order for integers.
#[must_use]
pub(crate) fn kind_label(kind: &Kind) -> String {
    match kind {
        Kind::Integer {
            width, endianness, ..
        } => {
            let order = match endianness {
                Some(sextant_ir::Endianness::Big) => " big-endian",
                Some(sextant_ir::Endianness::Little) => " little-endian",
                None => "",
            };
            format!("u{}{}", u16::from(*width) * 8, order)
        }
        Kind::Bytes => "bytes".to_owned(),
        Kind::String { .. } => "string".to_owned(),
        Kind::Enum { width, .. } => format!("enum (u{})", u16::from(*width) * 8),
        Kind::Struct { .. } => "struct".to_owned(),
        Kind::Array { .. } => "array".to_owned(),
        Kind::Opaque => "opaque".to_owned(),
    }
}

/// A short label for how a field's size is determined.
#[must_use]
pub(crate) fn size_label(field: &Field) -> String {
    if let Kind::Array { count, .. } = &field.kind {
        return match count {
            sextant_ir::CountRule::Fixed { count } => format!("{count} elements"),
            sextant_ir::CountRule::FromField { count_field } => {
                format!("count from {count_field}")
            }
            sextant_ir::CountRule::BoundedBy { length_field } => {
                format!("bounded by {length_field}")
            }
            sextant_ir::CountRule::ToEnd => "to end".to_owned(),
        };
    }
    match &field.size {
        Some(SizeRule::Fixed { bytes }) => format!("{bytes} bytes"),
        Some(SizeRule::Derived { length_field }) => format!("derived from {length_field}"),
        Some(SizeRule::Delimited { .. }) => "delimited".to_owned(),
        Some(SizeRule::ToEnd) => "to end".to_owned(),
        None => match &field.kind {
            Kind::Integer { width, .. } | Kind::Enum { width, .. } => format!("{width} bytes"),
            Kind::Struct { .. } => "from fields".to_owned(),
            _ => "unspecified".to_owned(),
        },
    }
}
