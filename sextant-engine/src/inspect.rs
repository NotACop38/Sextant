//! The annotated hex view (`sextant inspect`, FR-35).
//!
//! [`render`] reads a sample through a [`Report`]: it executes the report's
//! chosen IR against the sample with the native executor, then renders an
//! annotated view that pairs every parsed field with its offset, size, name,
//! role, type, decoded value, and confidence, followed by a hex dump in which
//! each field's bytes can optionally be colored (FR-35).
//!
//! Rendering is pure and bounded. The executor enforces the resource limits
//! (FR-24), and annotation storage and rendered output each obey its output byte
//! budget. A truncated view says so explicitly. Color assignment
//! uses a compact list of byte ranges rather than a dense per-byte map, so a
//! multi-megabyte sample cannot force an `O(sample_len)` color allocation.
//! With color off the output is plain text, which is what the snapshot tests pin.

use std::collections::BTreeSet;
use std::fmt;
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

/// A bounded writer that rejects further formatting once its byte budget is
/// exhausted. Allocation capacity also stays within that budget.
struct Output {
    text: String,
    limit: usize,
    truncated: bool,
}

impl fmt::Write for Output {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.truncated {
            return Err(fmt::Error);
        }
        let available = self.limit.saturating_sub(self.text.len());
        let mut take = text.len().min(available);
        while !text.is_char_boundary(take) {
            take -= 1;
        }
        let needed = self.text.len() + take;
        if needed > self.text.capacity() {
            let capacity = self
                .text
                .capacity()
                .saturating_mul(2)
                .max(64)
                .max(needed)
                .min(self.limit);
            if self
                .text
                .try_reserve_exact(capacity - self.text.len())
                .is_err()
            {
                self.truncated = true;
                return Err(fmt::Error);
            }
        }
        self.text.push_str(&text[..take]);
        if take < text.len() {
            self.truncated = true;
            return Err(fmt::Error);
        }
        Ok(())
    }
}

impl Output {
    fn finish(mut self) -> String {
        if self.truncated {
            const MARKER: &str = "\n[inspect output truncated: byte limit reached]\n";
            let marker = &MARKER[..MARKER.len().min(self.limit)];
            let mut keep = self.text.len().min(self.limit - marker.len());
            while !self.text.is_char_boundary(keep) {
                keep -= 1;
            }
            self.text.truncate(keep);
            self.truncated = false;
            let _ = self.write_str(marker);
        }
        self.text
    }
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
        // Sweep endpoints while an ordered set tracks active paint indices.
        // The highest index wins, preserving last-paint-wins in O(n log n).
        let mut events = Vec::new();
        for (paint, &(start, end, _)) in self.ranges.iter().enumerate() {
            let (start, end) = (start.min(len), end.min(len));
            if start < end {
                events.push((start, true, paint));
                events.push((end, false, paint));
            }
        }
        events.sort_unstable();
        let mut active = BTreeSet::new();
        let mut segments = Vec::new();
        let mut previous = 0;
        let mut event = 0;
        while event < events.len() {
            let point = events[event].0;
            if previous < point {
                let color = active.last().map(|&paint: &usize| self.ranges[paint].2);
                segments.push((previous, point, color));
            }
            while event < events.len() && events[event].0 == point {
                let (_, starts, paint) = events[event];
                if starts {
                    active.insert(paint);
                } else {
                    active.remove(&paint);
                }
                event += 1;
            }
            previous = point;
        }
        if previous < len {
            let color = active.last().map(|&paint| self.ranges[paint].2);
            segments.push((previous, len, color));
        }
        segments
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
    let mut annotations = Annotations {
        rows: Vec::new(),
        byte_color: ByteColors::default(),
        leaf_counter: 0,
        remaining: options.limits.max_output_bytes,
        truncated: false,
        color: options.color,
    };
    annotations.walk(&report.format.root.fields, &execution.fields, sample, 0);

    let mut out = Output {
        text: String::new(),
        limit: options.limits.max_output_bytes,
        truncated: false,
    };
    render_header(&mut out, report, sample, &execution.failure);
    render_table(&mut out, &annotations.rows, options.color);
    if annotations.truncated {
        let _ = writeln!(
            out,
            "Note: annotation rows truncated by the output byte budget."
        );
    }
    render_hex(&mut out, sample, &annotations.byte_color, options.color);
    out.finish()
}

/// Render the one-line header with the format name, fit score, and sample size.
fn render_header(
    out: &mut Output,
    report: &Report,
    sample: &[u8],
    failure: &Option<crate::executor::ParseFailure>,
) {
    let _ = writeln!(
        out,
        "Format: {} (fit score {:.3})",
        label_preview(&report.format.name, 128),
        report.score.overall
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
fn render_table(out: &mut Output, rows: &[Row], color: bool) {
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
        if out.truncated {
            break;
        }
        let depth = row.depth.min(64);
        let indented = format!("{}{}", "  ".repeat(depth), row.name);
        // The color escapes do not occupy display columns, so compute the name's
        // visible width from the uncolored text and pad to it manually; padding
        // through `{:<24}` would miscount the escape bytes and break alignment.
        let display_len = depth * 2 + row.name.chars().count();
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
fn render_hex(out: &mut Output, sample: &[u8], byte_color: &ByteColors, color: bool) {
    if out.truncated {
        return;
    }
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
    while offset < sample.len() && !out.truncated {
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
                    .flatten();
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
                    .flatten();
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

/// Annotation storage is budgeted before constructing rows. The allowance
/// covers vector growth, short strings, paint ranges, endpoint events, active
/// sweep nodes and segments. No source label is copied in full.
struct Annotations {
    rows: Vec<Row>,
    byte_color: ByteColors,
    leaf_counter: usize,
    remaining: usize,
    truncated: bool,
    color: bool,
}

impl Annotations {
    fn walk(&mut self, fields: &[Field], instances: &[FieldInstance], sample: &[u8], depth: usize) {
        for (field, instance) in fields.iter().zip(instances) {
            if !self.emit_row(field, instance, sample, depth) {
                break;
            }
        }
    }

    fn emit_row(
        &mut self,
        field: &Field,
        instance: &FieldInstance,
        sample: &[u8],
        depth: usize,
    ) -> bool {
        const ROW_STORAGE_BYTES: usize = 4096;
        if self.remaining < ROW_STORAGE_BYTES {
            self.truncated = true;
            return false;
        }
        self.remaining -= ROW_STORAGE_BYTES;
        let size = instance.end.saturating_sub(instance.start);
        let is_leaf = !matches!(instance.value, Value::Struct(_) | Value::Array(_));
        let color = if is_leaf {
            let index = self.leaf_counter;
            self.leaf_counter += 1;
            if self.color {
                self.byte_color.paint(instance.start, instance.end, index);
            }
            Some(index)
        } else {
            None
        };
        let name = instance
            .name
            .as_deref()
            .or(field.name.as_deref())
            .unwrap_or("(unnamed)");
        self.rows.push(Row {
            depth,
            offset: instance.start,
            size,
            name: label_preview(name, 64),
            role: role_label(instance.role.or(field.role)),
            type_label: kind_label(&field.kind),
            value: value_preview(&instance.value, sample, instance.start, instance.end),
            confidence: field.confidence.get(),
            color,
        });
        match (&field.kind, &instance.value) {
            (Kind::Struct { structure }, Value::Struct(children)) => {
                self.walk(&structure.fields, children, sample, depth + 1);
            }
            (Kind::Array { element, .. }, Value::Array(elements)) => {
                for child in elements {
                    if !self.emit_row(element, child, sample, depth + 1) {
                        break;
                    }
                }
            }
            _ => {}
        }
        !self.truncated
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
            Some(name) => format!("{} ({value})", label_preview(name, VALUE_PREVIEW_BYTES * 2)),
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

/// Display untrusted names without terminal controls or embedded line breaks.
/// Only a bounded prefix is visited, and escapes count against the preview cap.
fn label_preview(text: &str, max: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    for ch in text.chars() {
        if ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}') {
            for escaped in ch.escape_default() {
                out.push(escaped);
                count += 1;
                if count > max {
                    return truncate(&out, max);
                }
            }
        } else {
            out.push(ch);
            count += 1;
            if count > max {
                return truncate(&out, max);
            }
        }
    }
    out
}

/// Truncate `text` to `max` characters, appending an ellipsis marker when cut.
fn truncate(text: &str, max: usize) -> String {
    if text.chars().take(max.saturating_add(1)).count() <= max {
        return text.to_owned();
    }
    let keep = max.saturating_sub(3);
    let mut out: String = text.chars().take(keep).collect();
    out.push_str(&"..."[..max.min(3)]);
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

    #[test]
    fn color_sweep_preserves_overlaps_gaps_and_last_paint_precedence() {
        let mut colors = ByteColors::default();
        for (start, end, paint) in [(2, 9, 0), (4, 7, 1), (6, 10, 2), (10, 11, 3), (20, 30, 4)] {
            colors.paint(start, end, paint);
        }
        let segments = colors.segments(12);
        for offset in 0..12 {
            let expected = colors
                .ranges
                .iter()
                .rev()
                .find(|&&(start, end, _)| start <= offset && offset < end)
                .map(|&(_, _, index)| index);
            let actual = segments
                .iter()
                .find(|&&(start, end, _)| start <= offset && offset < end)
                .expect("every byte, including gaps, has a segment")
                .2;
            assert_eq!(actual, expected, "offset {offset}");
        }
        assert!(colors.segments(0).is_empty());
        assert_eq!(ByteColors::default().segments(12), vec![(0, 12, None)]);
    }

    #[test]
    fn color_sweep_handles_many_disjoint_ranges() {
        let mut colors = ByteColors::default();
        for index in 0..100_000 {
            colors.paint(index * 2, index * 2 + 1, index % PALETTE.len());
        }
        let segments = colors.segments(200_000);
        assert_eq!(segments.len(), 200_000);
        for (index, pair) in segments.chunks_exact(2).enumerate() {
            assert_eq!(
                pair[0],
                (index * 2, index * 2 + 1, Some(index % PALETTE.len()))
            );
            assert_eq!(pair[1], (index * 2 + 1, index * 2 + 2, None));
        }
    }

    #[test]
    fn inspect_caps_hex_output_and_large_unicode_headers() {
        let (mut report, _) = tlv_report_and_sample();
        report.format.name = "é".repeat(65536);
        report.format.root.fields = vec![
            Field::new(Kind::Opaque, sextant_ir::Confidence::CERTAIN)
                .with_size(sextant_ir::SizeRule::ToEnd),
        ];
        let options = InspectOptions {
            color: true,
            limits: Limits {
                max_output_bytes: 4096,
                ..Limits::default()
            },
        };
        let view = render(&report, &vec![0; 1 << 20], &options);
        assert!(view.len() <= 4096);
        assert!(view.contains("inspect output truncated"));
        assert!(view.contains("Format:"));
    }

    #[test]
    fn inspect_caps_annotation_storage_and_enum_previews() {
        let (mut report, _) = tlv_report_and_sample();
        report.format.root.fields = vec![Field::new(
            Kind::Array {
                element: Box::new(Field::new(
                    Kind::Integer {
                        width: 1,
                        signed: sextant_ir::Signedness::Unsigned,
                        endianness: None,
                    },
                    sextant_ir::Confidence::CERTAIN,
                )),
                count: sextant_ir::CountRule::Fixed { count: 64 },
            },
            sextant_ir::Confidence::CERTAIN,
        )];
        let options = InspectOptions {
            limits: Limits {
                max_output_bytes: 65536,
                ..Limits::default()
            },
            ..InspectOptions::default()
        };
        assert!(execute(&report.format, &[0; 64], &options.limits).succeeded());
        let view = render(&report, &[0; 64], &options);
        assert!(view.len() <= 65536);
        assert!(view.contains("annotation rows truncated"));
        let preview = value_preview(
            &Value::Enum {
                value: 1,
                name: Some("v".repeat(65536)),
            },
            &[],
            0,
            0,
        );
        assert!(preview.len() < 64);
    }

    #[test]
    fn output_budget_respects_small_limits_and_utf8_boundaries() {
        for limit in 0..80 {
            let mut out = Output {
                text: String::new(),
                limit,
                truncated: false,
            };
            let _ = write!(out, "{}", "é".repeat(100));
            let view = out.finish();
            assert!(view.len() <= limit);
        }
    }

    #[test]
    fn inspect_escapes_controls_in_names_and_preserves_ordinary_unicode() {
        let (mut report, _) = tlv_report_and_sample();
        report.format.name = "Café\x1b]52;c;payload\x07\nformat".to_owned();
        report.format.root.fields = vec![
            Field::new(Kind::Opaque, sextant_ir::Confidence::CERTAIN)
                .with_size(sextant_ir::SizeRule::ToEnd)
                .with_name("field\n\x1b[31m"),
        ];
        let view = render(&report, &[0], &InspectOptions::default());
        assert!(!view.contains('\x1b'));
        assert!(!view.contains('\x07'));
        assert!(view.contains("Café\\u{1b}]52;c;payload\\u{7}\\nformat"));
        assert!(view.contains("field\\n\\u{1b}[31m"));
        let preview = value_preview(
            &Value::Enum {
                value: 1,
                name: Some("名\n\x1b".to_owned()),
            },
            &[],
            0,
            0,
        );
        assert_eq!(preview, "名\\n\\u{1b} (1)");
        assert_eq!(
            value_preview(&Value::Text("line\nnext".to_owned()), &[], 0, 0),
            "\"line\\nnext\""
        );
        for max in 0..64 {
            let preview = label_preview(&"\x1b".repeat(100), max);
            assert!(preview.chars().count() <= max);
        }
    }
}
