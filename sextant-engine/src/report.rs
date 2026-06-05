//! The draft report object produced by an inference run (FR-34, partial).
//!
//! Step 6 wires the end-to-end pipeline into an in-memory [`DraftReport`]: the
//! chosen Format Hypothesis IR, its verified fit [`Score`], a flattened field
//! map for display, the refinement history, and run metadata. The full
//! machine-readable JSON report and its schema arrive in Step 7; this object is
//! the structured result the rest of the tool reads in the meantime.

use sextant_ir::{Field, Format, Kind, Role, SizeRule};

use crate::refine::RefineStep;
use crate::scorer::Score;

/// Metadata about an inference run, recorded in the report for reproducibility.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq)]
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

/// The structured result of an inference run (FR-34, partial; completed in
/// Step 7).
#[derive(Debug, Clone)]
pub struct DraftReport {
    /// The chosen, refined Format Hypothesis IR.
    pub format: Format,
    /// The verified fit score of the chosen IR over the sample set.
    pub score: Score,
    /// The chosen IR's fields, flattened for display.
    pub field_map: Vec<FieldMapEntry>,
    /// The refinement steps that were accepted, in order (FR-28).
    pub refinement: Vec<RefineStep>,
    /// Metadata about the run.
    pub metadata: RunMetadata,
}

impl DraftReport {
    /// Build a draft report from a chosen IR, its score, the refinement history,
    /// and run metadata. The field map is derived from the IR.
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
            format,
            score,
            field_map,
            refinement,
            metadata,
        }
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
fn role_label(role: Option<Role>) -> String {
    let label = match role {
        Some(Role::Magic) => "magic",
        Some(Role::Version) => "version",
        Some(Role::Length) => "length",
        Some(Role::Count) => "count",
        Some(Role::Offset) => "offset",
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
fn kind_label(kind: &Kind) -> String {
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
fn size_label(field: &Field) -> String {
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
