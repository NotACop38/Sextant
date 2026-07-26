//! The annotated hex view (`sextant inspect`, FR-35).
//!
//! [`render`] reads a sample through a [`Report`]: it executes the report's
//! chosen IR against the sample with the native executor, then renders an
//! annotated view that pairs every parsed field with its offset, size, name,
//! role, type, decoded value, and confidence, followed by a hex dump in which
//! each field's bytes can optionally be colored (FR-35).
//!
//! Rendering is pure and bounded. The executor enforces the resource limits
//! (FR-24), and the decoded values shown are previews capped in length, so a
//! hostile sample cannot make the view allocate without bound. Color assignment
//! uses a compact list of byte ranges rather than a dense per-byte map, so a
//! multi-megabyte sample cannot force an `O(sample_len)` color allocation.
//! With color off the output is plain text, which is what the snapshot tests pin.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use sextant_ir::{Field, Kind};

use crate::executor::{FieldInstance, Value, execute};
use crate::limits::Limits;
use crate::report::{Report, kind_label, role_label};

/// How many bytes of a value to show as a preview in the annotation table. The
/// field's full range is always reported; only the rendered preview is capped so
/// the view stays compact and bounded (FR-24).
const VALUE_PREVIEW_BYTES: usize = 16;

/// How many bytes per row in the hex dump.
const HEX_COLUMNS: usize = 16;

/// The ANSI foreground color codes cycled through to distinguish adjacent fields
/// when color is enabled. Chosen to read on both light and dark terminals.
const PALETTE: [&str; 6] = [
    "\x1b[36m", // cyan
    "\x1b[32m", // green
    "\x1b[33m", // yellow
    "\x1b[35m", // magenta
    "\x1b[34m", // blue
    "\x1b[31m", // red
];

/// The ANSI reset sequence.
const RESET: &str = "\x1b[0m";

/// Options controlling the annotated hex view.
#[derive(Debug, Clone, Default)]
pub struct InspectOptions {
    /// Whether to color each field's bytes in the hex dump and its name in the
    /// table. Off by default so the output is plain, snapshot-friendly text.
    pub color: bool,
    /// The executor resource limits used to parse the sample (FR-24).
    pub limits: Limits,
}

/// One annotated field row in the view.
struct Row {
    depth: usize,
    offset: usize,
    size: usize,
    name: String,
    role: String,
    type_label: String,
    value: String,
    confidence: f64,
    /// The palette color assigned to this field's bytes, when it is a leaf.
    color: Option<usize>,
}

/// A sparse record of which leaf field owns each painted byte range.
///
/// Later paints overwrite earlier ones on overlap. Memory is proportional to
/// the number of leaf ranges, not the sample length.
#[derive(Debug, Default)]
struct ByteColors {
    /// `(start, end, palette_index)` ranges in paint order.
    ranges: Vec<(usize, usize, usize)>,
}

impl ByteColors {
    fn paint(&mut self, start: usize, end: usize, index: usize) {
        if start < end {
            self.ranges.push((start, end, index));
        }
    }

    /// Flatten painted ranges into non-overlapping segments for linear rendering.
    fn segments(&self, len: usize) -> Vec<(usize, usize, Option<usize>)> {
        if len == 0 {
            return Vec::new();
        }
        if self.ranges.is_empty() {
            return vec![(0, len, None)];
        }
        let mut points = BTreeSet::new();
        points.insert(0);
        points.insert(len);
        for &(start, end, _) in &self.ranges {
            points.insert(start.min(len));
            points.insert(end.min(len));
        }
        let points: Vec<usize> = points.into_iter().collect();
        let mut segments = Vec::new();
        for window in points.windows(2) {
            let (a, b) = (window[0], window[1]);
            if a >= b {
                continue;
            }
            let color = self
                .ranges
                .iter()
                .rev()
                .find(|(start, end, _)| a >= *start && a < *end)
                .map(|(_, _, index)| *index);
            segments.push((a, b, color));
        }
        segments
    }

    fn color_at(&self, offset: usize) -> Option<usize> {
        self.ranges
            .iter()
            .rev()
            .find(|(start, end, _)| offset >= *start && offset < *end)
            .map(|(_, _, index)| *index)
    }
}

/// Render `sample` through `report` as an annotated hex view (FR-35).
///
/// The output has three parts: a one-line header naming the format and its fit
/// score, a table of annotated fields (offset, size, name, role, type, value,
/// confidence), and a hex dump. When [`InspectOptions::color`] is set, each
/// field's bytes in the dump and its name in the table are colored.
#[must_use]
pub fn render(report: &Report, sample: &[u8], options: &InspectOptions) -> String {
    let execution = execute(&report.format, sample, &options.limits);

    // Build the annotation rows and a sparse per-range color map by walking the
    // IR and the parsed instances together. Color ranges are only recorded when
    // color output is requested, so a huge sample with color off stays cheap.
    let mut rows = Vec::new();
    let mut byte_color = ByteColors::default();
    let mut leaf_counter = 0usize;
    walk(
        &report.format.root.fields,
        &execution.fields,
        sample,
        0,
        &mut rows,
        options.color.then_some(&mut byte_color),
        &mut leaf_counter,
    );

    let mut out = String::new();
    render_header(&mut out, report, sample, &execution.failure);
    render_table(&mut out, &rows, options.color);
    render_hex(&mut out, sample, &byte_color, options.color);
    out
}

/// Render the one-line header with the format name, fit score, and sample size.
fn render_header(
    out: &mut String,
    report: &Report,
    sample: &[u8],
    failure: &Option<crate::executor::ParseFailure>,
) {
    let _ = writeln!(
        out,
        "Format: {} (fit score {:.3})",
        report.format.name, report.score.overall
    );
    let _ = writeln!(out, "Sample: {} bytes", sample.len());
    if let Some(failure) = failure {
        let _ = writeln!(
            out,
            "Note: the parse stopped at offset {} ({:?}); fields past that point are not shown.",
            failure.offset, failure.reason
        );
    }
    let _ = writeln!(out);
}

/// Render the annotated field table.
fn render_table(out: &mut String, rows: &[Row], color: bool) {
    let _ = writeln!(
        out,
        "{:>8}  {:>6}  {:<24}  {:<10}  {:<16}  {:<22}  {:>10}",
        "Offset", "Size", "Name", "Role", "Type", "Value", "Confidence"
    );
    let _ = writeln!(
        out,
        "{}  {}  {}  {}  {}  {}  {}",
        "-".repeat(8),
        "-".repeat(6),
        "-".repeat(24),
        "-".repeat(10),
        "-".repeat(16),
        "-".repeat(22),
        "-".repeat(10),
    );
    for row in rows {
        let indented = format!("{}{}", "  ".repeat(row.depth), row.name);
        // The color escapes do not occupy display columns, so compute the name's
        // visible width from the uncolored text and pad to it manually; padding
        // through `{:<24}` would miscount the escape bytes and break alignment.
        let display_len = row.depth * 2 + row.name.chars().count();
        let rendered = if color {
            colorize(&indented, row.color)
        } else {
            indented
        };
        let padded = format!(
            "{rendered}{}",
            " ".repeat(24usize.saturating_sub(display_len))
        );
        let _ = writeln!(
            out,
            "{:>8}  {:>6}  {}  {:<10}  {:<16}  {:<22}  {:>10.2}",
            row.offset,
            row.size,
            padded,
            row.role,
            truncate(&row.type_label, 16),
            truncate(&row.value, 22),
            row.confidence,
        );
    }
    let _ = writeln!(out);
}

/// Render the hex dump, optionally coloring each byte by the field that owns it.
fn render_hex(out: &mut String, sample: &[u8], byte_color: &ByteColors, color: bool) {
    let _ = writeln!(out, "Hex:");
    if sample.is_empty() {
        let _ = writeln!(out, "  (empty sample)");
        return;
    }
    // Precompute segments so a large sample with color walks ranges linearly
    // instead of scanning the paint list once per byte.
    let segments = if color {
        byte_color.segments(sample.len())
    } else {
        Vec::new()
    };
    let mut segment_index = 0usize;
    let mut offset = 0;
    while offset < sample.len() {
        let end = (offset + HEX_COLUMNS).min(sample.len());
        let mut hex = String::new();
        let mut ascii = String::new();
        for (column, &byte) in sample[offset..end].iter().enumerate() {
            if column == HEX_COLUMNS / 2 {
                hex.push(' ');
            }
            let byte_offset = offset + column;
            let pair = format!("{byte:02x} ");
            if color {
                while segment_index + 1 < segments.len() && byte_offset >= segments[segment_index].1
                {
                    segment_index += 1;
                }
                let paint = segments
                    .get(segment_index)
                    .and_then(|(start, end, color)| {
                        (*start <= byte_offset && byte_offset < *end).then_some(*color)
                    })
                    .flatten()
                    .or_else(|| byte_color.color_at(byte_offset));
                hex.push_str(&colorize(&pair, paint));
            } else {
                hex.push_str(&pair);
            }
            let glyph = if byte.is_ascii_graphic() || byte == b' ' {
                byte as char
            } else {
                '.'
            };
            if color {
                let paint = segments
                    .get(segment_index)
                    .and_then(|(start, end, color)| {
                        (*start <= byte_offset && byte_offset < *end).then_some(*color)
                    })
                    .flatten()
                    .or_else(|| byte_color.color_at(byte_offset));
                ascii.push_str(&colorize(&glyph.to_string(), paint));
            } else {
                ascii.push(glyph);
            }
        }
        // Pad the hex column so the ascii gutter lines up on short final rows.
        let hex_width = HEX_COLUMNS * 3 + 1;
        let plain_hex_len = (end - offset) * 3 + usize::from(end - offset > HEX_COLUMNS / 2);
        let pad = hex_width.saturating_sub(plain_hex_len);
        let _ = writeln!(out, "{offset:08x}  {hex}{} |{ascii}|", " ".repeat(pad));
        offset = end;
    }
}

/// Wrap `text` in an ANSI color from the palette, or return it unchanged when
/// the field has no assigned color.
fn colorize(text: &str, color: Option<usize>) -> String {
    match color {
        Some(index) => format!("{}{text}{RESET}", PALETTE[index % PALETTE.len()]),
        None => text.to_owned(),
    }
}

/// Walk the IR fields and their parsed instances in lockstep, emitting a [`Row`]
/// for each and recording leaf byte ranges in `byte_color` when present.
fn walk(
    fields: &[Field],
    instances: &[FieldInstance],
    sample: &[u8],
    depth: usize,
    rows: &mut Vec<Row>,
    byte_color: Option<&mut ByteColors>,
    leaf_counter: &mut usize,
) {
    // Re-borrow through a single mutable option for the recursive walk.
    let mut color = byte_color;
    for (field, instance) in fields.iter().zip(instances.iter()) {
        emit_row(
            field,
            instance,
            sample,
            depth,
            rows,
            color.as_deref_mut(),
            leaf_counter,
        );
    }
}

/// Emit the row for one field instance and recurse into its children.
fn emit_row(
    field: &Field,
    instance: &FieldInstance,
    sample: &[u8],
    depth: usize,
    rows: &mut Vec<Row>,
    mut byte_color: Option<&mut ByteColors>,
    leaf_counter: &mut usize,
) {
    let size = instance.end.saturating_sub(instance.start);
    let is_leaf = !matches!(instance.value, Value::Struct(_) | Value::Array(_));
    let color = if is_leaf {
        let index = *leaf_counter;
        *leaf_counter += 1;
        if let Some(map) = byte_color.as_mut() {
            map.paint(instance.start, instance.end, index);
        }
        Some(index)
    } else {
        None
    };

    rows.push(Row {
        depth,
        offset: instance.start,
        size,
        name: instance
            .name
            .clone()
            .or_else(|| field.name.clone())
            .unwrap_or_else(|| "(unnamed)".to_owned()),
        role: role_label(instance.role.or(field.role)),
        type_label: kind_label(&field.kind),
        value: value_preview(&instance.value, sample, instance.start, instance.end),
        confidence: field.confidence.get(),
        color,
    });

    match (&field.kind, &instance.value) {
        (Kind::Struct { structure }, Value::Struct(children)) => {
            walk(
                &structure.fields,
                children,
                sample,
                depth + 1,
                rows,
                byte_color,
                leaf_counter,
            );
        }
        (Kind::Array { element, .. }, Value::Array(elements)) => {
            for element_instance in elements {
                emit_row(
                    element,
                    element_instance,
                    sample,
                    depth + 1,
                    rows,
                    byte_color.as_deref_mut(),
                    leaf_counter,
                );
            }
        }
        _ => {}
    }
}

/// Build a short, human-readable preview of a decoded value.
fn value_preview(value: &Value, sample: &[u8], start: usize, end: usize) -> String {
    match value {
        Value::Integer(int) => {
            if *int >= 0 {
                format!("{int} (0x{int:x})")
            } else {
                int.to_string()
            }
        }
        Value::Enum { value, name } => match name {
            Some(name) => format!("{name} ({value})"),
            None => value.to_string(),
        },
        Value::Text(text) => format!("{:?}", truncate(text, VALUE_PREVIEW_BYTES * 2)),
        Value::Bytes => hex_preview(sample, start, end),
        Value::Opaque => format!("<opaque {} bytes>", end.saturating_sub(start)),
        Value::Struct(children) => format!("{{{} fields}}", children.len()),
        Value::Array(elements) => format!("[{} elements]", elements.len()),
    }
}

/// A hex preview of `sample[start..end]`, capped at [`VALUE_PREVIEW_BYTES`].
fn hex_preview(sample: &[u8], start: usize, end: usize) -> String {
    let lo = start.min(sample.len());
    let hi = end.min(sample.len());
    let slice = &sample[lo..hi];
    let shown = &slice[..slice.len().min(VALUE_PREVIEW_BYTES)];
    let mut out = String::with_capacity(shown.len() * 3);
    for (index, byte) in shown.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{byte:02x}");
    }
    if slice.len() > VALUE_PREVIEW_BYTES {
        out.push_str(" ...");
    }
    if out.is_empty() {
        out.push_str("(empty)");
    }
    out
}

/// Truncate `text` to `max` characters, appending an ellipsis marker when cut.
fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let keep = max.saturating_sub(3);
    let mut out: String = text.chars().take(keep).collect();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::{IngestOptions, ingest};
    use crate::orchestrate::{InferenceOptions, infer};
    use std::path::PathBuf;

    fn tlv_report_and_sample() -> (Report, Vec<u8>) {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("engine crate has a parent")
            .join("corpus")
            .join("tlv");
        let set = ingest(
            &[dir.join("samples").to_string_lossy().into_owned()],
            &IngestOptions::default(),
        )
        .expect("ingest tlv");
        let report = infer(&set, &InferenceOptions::default());
        let sample = std::fs::read(dir.join("samples").join("sample_01.tlv")).expect("read sample");
        (report, sample)
    }

    #[test]
    fn render_includes_offsets_names_and_values() {
        let (report, sample) = tlv_report_and_sample();
        let view = render(&report, &sample, &InspectOptions::default());
        assert!(view.contains("Offset"));
        assert!(view.contains("Confidence"));
        assert!(view.contains("Hex:"));
        // The magic field's ascii is visible in the dump gutter.
        assert!(view.contains("STLV") || view.contains("|STLV"));
    }

    #[test]
    fn color_adds_escapes_and_plain_does_not() {
        let (report, sample) = tlv_report_and_sample();
        let plain = render(&report, &sample, &InspectOptions::default());
        assert!(!plain.contains('\x1b'), "plain output must have no escapes");
        let colored = render(
            &report,
            &sample,
            &InspectOptions {
                color: true,
                ..InspectOptions::default()
            },
        );
        assert!(colored.contains('\x1b'), "color output must have escapes");
    }

    #[test]
    fn empty_sample_does_not_panic() {
        let (report, _) = tlv_report_and_sample();
        let view = render(&report, &[], &InspectOptions::default());
        assert!(view.contains("(empty sample)"));
    }

    #[test]
    fn sparse_color_map_does_not_allocate_per_sample_byte() {
        // A hostile sample must not force a dense color vector of sample.len().
        let mut colors = ByteColors::default();
        colors.paint(0, 1 << 20, 0);
        assert_eq!(colors.ranges.len(), 1);
        let segments = colors.segments(1 << 20);
        assert!(segments.len() <= 3);
    }
}
