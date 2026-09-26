//! Typed segmentation of fixed-offset regions (FR-7, FR-9, FR-16).
//!
//! A region that sits at the same offset in every row (a header, a trailer, or
//! the pooled records of a fixed-size array) is split into typed pieces:
//! constants, integers with an inferred width and byte order, printable text,
//! and raw bytes.
//!
//! Varying bytes are split by dynamic programming over a description-length
//! cost, so a boundary appears only where it pays for itself:
//!
//! - every piece costs a fixed [`PIECE_BITS`], so bytes are never split without
//!   evidence;
//! - a varying integer costs the base-two logarithm of the range of values it
//!   takes in every row, so a small value's zero high bytes are absorbed into
//!   one wider field, while two adjacent small fields, whose combined reading
//!   would be enormous, stay apart;
//! - an integer that absorbs a nonzero constant byte more significant than its
//!   varying bytes pays [`PIECE_BITS`] per such byte, because that byte most
//!   likely belongs to a neighboring field;
//! - a multi-byte integer that does not start on a multiple of its width relative
//!   to the structure start pays [`MISALIGNED_BITS`], a soft preference that
//!   packed formats still overcome, and a misaligned eight-byte integer pays
//!   much more, because 64-bit fields are almost always aligned;
//! - widths other than four bytes, the most common header field width, pay a
//!   small prior cost;
//! - raw bytes cost eight bits each per row.
//!
//! The whole region is segmented once with little-endian integers and once with
//! big-endian integers, and the cheaper reading wins: a format rarely mixes
//! byte orders, and a single order resolves the ambiguity between a
//! little-endian value followed by zeros and a big-endian value preceded by
//! them.
//!
//! A boundary inside an invariant run cannot be observed, so constants are cut
//! by rule rather than by cost. Printable runs of three or more bytes become
//! text constants, unless they adjoin varying text, in which case they are part
//! of that text field, and runs made of whole four-character codes are split
//! into those codes. A binary run is cut where a new value visibly begins (a
//! nonzero byte after a zero byte, for little-endian), each value takes the
//! smallest natural width that holds its significant bytes (preferring four
//! bytes), and each run of zero bytes becomes one reserved piece.
//!
//! Segmentation proposes a layout; it proves nothing. Every candidate built
//! from it is executed and scored like any other hypothesis (FR-26).

/// The fixed cost of one piece, in bits: the price of a boundary.
pub const PIECE_BITS: f64 = 16.0;
/// The extra cost of a two- or four-byte integer that is not naturally
/// aligned. Packed headers misalign fields routinely, so this is small.
pub const MISALIGNED_BITS: f64 = 2.0;
/// The extra cost of an eight-byte integer that is not naturally aligned.
/// Formats with 64-bit fields almost always align them, so a misaligned
/// eight-byte reading is more likely a narrower value followed by zero bytes.
const MISALIGNED_WIDE_BITS: f64 = 24.0;
/// The prior cost of a varying integer by width, in bits: four-byte fields are
/// the most common in binary headers, so the others pay a little more.
const fn width_prior(width: usize) -> f64 {
    if width == 4 { 0.0 } else { 4.0 }
}
/// Bits per raw byte per row.
const RAW_BITS: f64 = 8.0;
/// The most rows whose values are examined. Larger inputs are sampled at an
/// even stride so segmentation work stays bounded (FR-24).
const MAX_ROWS: usize = 256;
/// The row count at which additional rows stop adding weight to data costs.
/// Beyond it, range estimates from more rows would let tiny data savings
/// outvote the boundary prior, so they are capped.
const MAX_WEIGHT_ROWS: usize = 16;
/// The longest region segmented. Longer regions are segmented up to this bound
/// and the caller treats the rest as payload.
pub const MAX_REGION: usize = 1024;
/// The longest raw-bytes piece the dynamic program proposes at one position.
const MAX_BYTES_PIECE: usize = 64;
/// The shortest invariant printable run treated as a text constant. Four
/// characters is the shortest common tag (a four-character code); shorter
/// printable runs are too often binary values that happen to be printable.
const MIN_TEXT_CONSTANT: usize = 4;
/// The fewest varying printable columns a varying text field must contain, so
/// small integers that happen to be printable are not read as text.
const MIN_TEXT_VARYING: usize = 3;

/// How a piece of a segmented region is typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentKind {
    /// Bytes that are identical in every row.
    Constant {
        /// The invariant bytes.
        bytes: Vec<u8>,
        /// Whether the bytes are printable ASCII text.
        text: bool,
    },
    /// A varying unsigned integer, or a constant one when `constant` is set.
    Integer {
        /// Width in bytes (1, 2, 4, or 8).
        width: u8,
        /// Whether the integer is big-endian.
        big_endian: bool,
        /// The value every row holds, when the integer is invariant.
        constant: Option<Vec<u8>>,
    },
    /// Varying text: printable ASCII, optionally padded with trailing zero
    /// bytes, in every row.
    Text,
    /// Varying bytes with no cheaper interpretation.
    Bytes,
}

/// One typed piece of a segmented region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The piece's offset relative to the region start.
    pub offset: usize,
    /// The piece's length in bytes.
    pub len: usize,
    /// How the piece is typed.
    pub kind: SegmentKind,
}

impl Segment {
    /// The offset just past the piece.
    #[must_use]
    pub fn end(&self) -> usize {
        self.offset + self.len
    }
}

/// A piece the caller requires, such as a length field a relationship detector
/// found. Segmentation places it exactly and types the gaps around it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Forced {
    /// The piece's offset relative to the region start.
    pub offset: usize,
    /// The integer width in bytes.
    pub width: u8,
    /// Whether the integer is big-endian.
    pub big_endian: bool,
}

/// How a region ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extent {
    /// Every byte of the region is covered by pieces.
    Exact,
    /// The pieces cover a prefix; the rest of each row is left to a payload
    /// that the caller models separately. The dynamic program chooses where
    /// the typed prefix ends by comparing each piece with leaving its bytes raw.
    Prefix,
}

/// The result of segmenting a region.
#[derive(Debug, Clone, PartialEq)]
pub struct Segmentation {
    /// The typed pieces, in order, without gaps.
    pub segments: Vec<Segment>,
    /// The byte order the integers were read in.
    pub big_endian: bool,
    /// The description cost of the chosen split, in bits. Comparable between
    /// segmentations of the same rows and region.
    pub cost: f64,
}

impl Segmentation {
    /// The offset just past the last piece.
    #[must_use]
    pub fn end(&self) -> usize {
        self.segments.last().map_or(0, Segment::end)
    }
}

/// Segment `rows[..][0..len]` into typed pieces.
///
/// `base` is the region's offset within its structure, used only for the
/// alignment preference. `magic` is the length of a leading signature the
/// caller has already identified; it becomes one constant piece. Rows shorter
/// than `len` are ignored, and `len` is capped at [`MAX_REGION`]. With
/// [`Extent::Prefix`] the pieces may cover less than `len`.
#[must_use]
pub fn segment(
    rows: &[&[u8]],
    len: usize,
    base: usize,
    magic: usize,
    forced: &[Forced],
    extent: Extent,
) -> Segmentation {
    let len = len.min(MAX_REGION);
    let rows = sample_rows(rows, len);
    if rows.is_empty() || len == 0 {
        return Segmentation {
            segments: Vec::new(),
            big_endian: false,
            cost: 0.0,
        };
    }
    let columns = Columns::new(&rows, len);
    let little = segment_with(&columns, len, base, magic, forced, extent, false);
    let big = segment_with(&columns, len, base, magic, forced, extent, true);
    if big.1 < little.1 {
        Segmentation {
            segments: big.0,
            big_endian: true,
            cost: big.1,
        }
    } else {
        Segmentation {
            segments: little.0,
            big_endian: false,
            cost: little.1,
        }
    }
}

/// Take at most [`MAX_ROWS`] rows at an even stride, keeping only rows that
/// hold the whole region.
fn sample_rows<'a>(rows: &[&'a [u8]], len: usize) -> Vec<&'a [u8]> {
    let usable: Vec<&[u8]> = rows
        .iter()
        .copied()
        .filter(|row| row.len() >= len)
        .collect();
    if usable.len() <= MAX_ROWS {
        return usable;
    }
    let step = usable.len().div_ceil(MAX_ROWS);
    usable.into_iter().step_by(step).collect()
}

/// Per-column facts shared by every piece decision.
struct Columns<'a> {
    rows: Vec<&'a [u8]>,
    /// The shared byte when every row agrees at this column.
    invariant: Vec<Option<u8>>,
    /// Whether every row holds a printable byte or a zero byte here.
    texty: Vec<bool>,
    /// The weight data costs carry, from the row count.
    weight: f64,
}

impl<'a> Columns<'a> {
    fn new(rows: &[&'a [u8]], len: usize) -> Self {
        let mut invariant = Vec::with_capacity(len);
        let mut texty = Vec::with_capacity(len);
        for column in 0..len {
            let first = rows[0][column];
            invariant.push(rows.iter().all(|row| row[column] == first).then_some(first));
            texty.push(
                rows.iter()
                    .all(|row| is_printable(row[column]) || row[column] == 0),
            );
        }
        Self {
            rows: rows.to_vec(),
            invariant,
            texty,
            weight: rows.len().min(MAX_WEIGHT_ROWS) as f64,
        }
    }

    fn constant(&self, start: usize, end: usize) -> Vec<u8> {
        self.invariant[start..end]
            .iter()
            .map(|byte| byte.unwrap_or(0))
            .collect()
    }

    /// The span of values `[offset, offset + width)` takes across the rows.
    fn span(&self, offset: usize, width: usize, big: bool) -> u64 {
        let mut min = u64::MAX;
        let mut max = 0u64;
        for row in &self.rows {
            let value = read_uint(&row[offset..offset + width], big);
            min = min.min(value);
            max = max.max(value);
        }
        max - min
    }

    /// The cost of reading `[offset, offset + width)` as a varying integer.
    fn integer_bits(&self, offset: usize, width: usize, big: bool) -> f64 {
        // Each row is coded uniformly within the range the rows span. The
        // model cost of the range is folded into the piece cost.
        let span = self.span(offset, width, big) as f64 + 1.0;
        let mut bits = self.weight * span.log2();
        // A low half that spans most of its range (a hash or checksum) under
        // a high half with a small range is two fields, not one wide value:
        // merging them costs no extra bits, because random low bytes already
        // pay for the whole range, so the merge must pay here instead.
        if width >= 4 {
            let half = width / 2;
            let (low, high) = if big {
                (offset + half, offset)
            } else {
                (offset, offset + half)
            };
            let half_bits = 8 * half as u32;
            let low_span = self.span(low, half, big);
            let high_span = self.span(high, half, big);
            if low_span >= 1u64 << (half_bits - 1)
                && high_span > 0
                && high_span < 1u64 << (half_bits / 2)
            {
                bits += PIECE_BITS;
            }
        }
        // Penalize nonzero invariant bytes more significant than every varying
        // byte: the value's high part would be a constant from another field.
        let significance: Vec<usize> = if big {
            (offset..offset + width).collect()
        } else {
            (offset..offset + width).rev().collect()
        };
        for column in significance {
            match self.invariant[column] {
                None => break,
                Some(0) => {}
                Some(_) => bits += PIECE_BITS,
            }
        }
        bits
    }
}

fn is_printable(byte: u8) -> bool {
    (0x20..0x7f).contains(&byte)
}

fn read_uint(bytes: &[u8], big: bool) -> u64 {
    let mut value = 0u64;
    if big {
        for &byte in bytes {
            value = (value << 8) | u64::from(byte);
        }
    } else {
        for (index, &byte) in bytes.iter().enumerate() {
            value |= u64::from(byte) << (8 * index);
        }
    }
    value
}

/// Segment the region in one byte order, returning the pieces and their cost.
fn segment_with(
    columns: &Columns<'_>,
    len: usize,
    base: usize,
    magic: usize,
    forced: &[Forced],
    extent: Extent,
    big: bool,
) -> (Vec<Segment>, f64) {
    let mut fixed: Vec<Segment> = Vec::new();
    let magic = magic.min(len);
    if magic > 0 && columns.invariant[..magic].iter().all(Option::is_some) {
        fixed.push(Segment {
            offset: 0,
            len: magic,
            kind: SegmentKind::Constant {
                bytes: columns.constant(0, magic),
                text: false,
            },
        });
    }
    let mut forced: Vec<Forced> = forced
        .iter()
        .copied()
        .filter(|piece| {
            piece.offset >= fixed.last().map_or(0, Segment::end)
                && piece.offset + usize::from(piece.width) <= len
                && matches!(piece.width, 1 | 2 | 4 | 8)
        })
        .collect();
    forced.sort_by_key(|piece| piece.offset);
    let mut cursor = fixed.last().map_or(0, Segment::end);
    for piece in forced {
        if piece.offset < cursor {
            continue;
        }
        fixed.push(Segment {
            offset: piece.offset,
            len: usize::from(piece.width),
            kind: SegmentKind::Integer {
                width: piece.width,
                big_endian: piece.big_endian,
                constant: None,
            },
        });
        cursor = piece.offset + usize::from(piece.width);
    }
    // Text spans are fixed in place next: their boundaries come from the
    // printable-then-padding shape of each row, which integer costs cannot see.
    let mut gaps = Vec::new();
    let mut cursor = 0;
    for piece in &fixed {
        gaps.push((cursor, piece.offset));
        cursor = piece.end();
    }
    gaps.push((cursor, len));
    for &(start, end) in &gaps {
        fixed.extend(text_spans(columns, start, end));
    }
    fixed.sort_by_key(|piece| piece.offset);

    let mut out = Vec::new();
    let mut cost = 0.0;
    let mut cursor = 0;
    for piece in fixed {
        let (segments, gap_cost) =
            dynamic_segments(columns, cursor, piece.offset, base, big, Extent::Exact);
        out.extend(segments);
        cost += gap_cost + PIECE_BITS;
        cursor = piece.end();
        out.push(piece);
    }
    let (segments, tail_cost) = dynamic_segments(columns, cursor, len, base, big, extent);
    out.extend(segments);
    (out, cost + tail_cost)
}

/// Find text pieces in `[start, end)`.
///
/// Invariant printable runs of at least [`MIN_TEXT_CONSTANT`] bytes become text
/// constants, and a run made of two or more whole four-character codes is split
/// into those codes. In the columns that remain, a run in which every row reads
/// as printable ASCII followed only by zero padding, with at least four bytes
/// and [`MIN_TEXT_VARYING`] varying printable columns, becomes a text piece;
/// such runs are split wherever every row starts new text right after padding.
fn text_spans(columns: &Columns<'_>, start: usize, end: usize) -> Vec<Segment> {
    let mut constants = Vec::new();
    let mut column = start;
    // A column where every row holds printable text but the rows differ, next
    // to another such column: an invariant run touching one is the constant
    // prefix or suffix of a varying text field, not a text constant of its
    // own. A lone varying printable column is usually a small integer.
    let printable_varies = |c: usize| {
        columns.invariant[c].is_none() && columns.rows.iter().all(|row| is_printable(row[c]))
    };
    let varying_printable = |c: usize| {
        printable_varies(c)
            && ((c > start && printable_varies(c - 1)) || (c + 1 < end && printable_varies(c + 1)))
    };
    while column < end {
        let printable_constant = |c: usize| columns.invariant[c].is_some_and(is_printable);
        if !printable_constant(column) {
            column += 1;
            continue;
        }
        let run_end = (column..end)
            .find(|&c| !printable_constant(c))
            .unwrap_or(end);
        let run = run_end - column;
        let touches_varying_text = (column > start && varying_printable(column - 1))
            || (run_end < end && varying_printable(run_end));
        if run >= MIN_TEXT_CONSTANT && !touches_varying_text {
            let piece = if run >= 8 && run % 4 == 0 { 4 } else { run };
            for offset in (column..run_end).step_by(piece) {
                constants.push(Segment {
                    offset,
                    len: piece,
                    kind: SegmentKind::Constant {
                        bytes: columns.constant(offset, offset + piece),
                        text: true,
                    },
                });
            }
        }
        column = run_end;
    }

    let mut out = Vec::new();
    let mut cursor = start;
    for constant in constants {
        out.extend(varying_text_in(columns, cursor, constant.offset));
        cursor = constant.end();
        out.push(constant);
    }
    out.extend(varying_text_in(columns, cursor, end));
    out
}

/// Find varying text pieces among the printable-or-zero runs of `[start, end)`.
fn varying_text_in(columns: &Columns<'_>, start: usize, end: usize) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut column = start;
    while column < end {
        if !columns.texty[column] {
            column += 1;
            continue;
        }
        let run_end = (column..end).find(|&c| !columns.texty[c]).unwrap_or(end);
        out.extend(varying_text(columns, column, run_end));
        column = run_end;
    }
    out
}

/// Split one run of printable-or-zero columns into text pieces.
fn varying_text(columns: &Columns<'_>, start: usize, end: usize) -> Vec<Segment> {
    // A new string starts where every row has padding before a printable byte.
    let mut cuts = vec![start];
    for column in start + 1..end {
        if columns
            .rows
            .iter()
            .all(|row| row[column - 1] == 0 && is_printable(row[column]))
        {
            cuts.push(column);
        }
    }
    cuts.push(end);
    let mut out = Vec::new();
    for window in cuts.windows(2) {
        let (piece_start, piece_end) = (window[0], window[1]);
        if piece_end - piece_start < 4 {
            continue;
        }
        let shaped = columns.rows.iter().all(|row| {
            let bytes = &row[piece_start..piece_end];
            let text = bytes.iter().take_while(|&&byte| is_printable(byte)).count();
            text > 0 && bytes[text..].iter().all(|&byte| byte == 0)
        });
        let varying_text_columns = (piece_start..piece_end)
            .filter(|&c| {
                columns.invariant[c].is_none()
                    && columns.rows.iter().all(|row| is_printable(row[c]))
            })
            .count();
        if shaped && varying_text_columns >= MIN_TEXT_VARYING {
            out.push(Segment {
                offset: piece_start,
                len: piece_end - piece_start,
                kind: SegmentKind::Text,
            });
        }
    }
    out
}

/// The first constant piece of the invariant run starting at `at`, cut by the
/// value-shape rule described in the module documentation.
fn constant_piece(columns: &Columns<'_>, at: usize, end: usize, big: bool) -> Segment {
    let run_end = (at..end)
        .find(|&column| columns.invariant[column].is_none())
        .unwrap_or(end);
    let bytes = columns.constant(at, run_end);
    let leading_zeros = bytes.iter().take_while(|&&byte| byte == 0).count();
    let len = if leading_zeros == bytes.len() {
        // A run of zero bytes is one reserved piece.
        bytes.len()
    } else if big {
        // Big-endian: zero high bytes, then the significant bytes, up to the
        // next zero. If that span is not a natural width, the value takes the
        // natural width that holds its significant bytes and the extra leading
        // zeros become their own piece.
        let significant = bytes[leading_zeros..]
            .iter()
            .take_while(|&&byte| byte != 0)
            .count();
        let total = leading_zeros + significant;
        let width = natural_width(significant, total);
        if width < total { total - width } else { total }
    } else if leading_zeros > 0 {
        // Little-endian zeros before a value belong to no value: padding.
        leading_zeros
    } else {
        // Little-endian: significant low bytes, then zero high bytes, up to the
        // next nonzero byte.
        let significant = bytes.iter().take_while(|&&byte| byte != 0).count();
        let available = significant
            + bytes[significant..]
                .iter()
                .take_while(|&&byte| byte == 0)
                .count();
        natural_width(significant, available)
    };
    let piece = bytes[..len.max(1)].to_vec();
    let kind = if matches!(piece.len(), 1 | 2 | 4 | 8) {
        SegmentKind::Integer {
            width: piece.len() as u8,
            big_endian: big,
            constant: Some(piece.clone()),
        }
    } else {
        SegmentKind::Constant {
            bytes: piece.clone(),
            text: false,
        }
    };
    Segment {
        offset: at,
        len: piece.len(),
        kind,
    }
}

/// The natural integer width for a constant with `significant` nonzero bytes
/// in a span of `available` bytes that ends where the next value starts. A
/// span that is itself a natural width of at most four bytes is kept whole;
/// otherwise four bytes are preferred when they hold the value, then the
/// smallest natural width that does. A value with no natural width keeps the
/// whole span.
fn natural_width(significant: usize, available: usize) -> usize {
    if matches!(available, 1 | 2 | 4) {
        return available;
    }
    if significant <= 4 && available >= 4 {
        return 4;
    }
    [1usize, 2, 4, 8]
        .into_iter()
        .find(|&width| width >= significant && width <= available)
        .unwrap_or(available)
}

/// One option the dynamic program considers at a position.
struct Piece {
    len: usize,
    cost: f64,
    kind: SegmentKind,
}

/// Choose the cheapest typed split of `[start, end)` by dynamic programming,
/// returning the pieces and their total cost.
fn dynamic_segments(
    columns: &Columns<'_>,
    start: usize,
    end: usize,
    base: usize,
    big: bool,
    extent: Extent,
) -> (Vec<Segment>, f64) {
    if start >= end {
        return (Vec::new(), 0.0);
    }
    let len = end - start;
    // best[i] is the cheapest cost of typing [start, start + i).
    let mut best = vec![f64::INFINITY; len + 1];
    let mut back: Vec<Option<Segment>> = vec![None; len + 1];
    best[0] = 0.0;
    for i in 0..len {
        if !best[i].is_finite() {
            continue;
        }
        let at = start + i;
        for piece in pieces(columns, at, end, base, big) {
            let next = i + piece.len;
            let cost = best[i] + piece.cost;
            if cost < best[next] {
                best[next] = cost;
                back[next] = Some(Segment {
                    offset: at,
                    len: piece.len,
                    kind: piece.kind,
                });
            }
        }
    }

    // In prefix mode the typed prefix may stop at any position; the bytes
    // after it are left raw to the caller's payload. Ties stop early: typing
    // bytes needs evidence, not a draw.
    let raw_after = |i: usize| RAW_BITS * columns.weight * (len - i) as f64;
    let stop = match extent {
        Extent::Exact => len,
        Extent::Prefix => (0..=len)
            .filter(|&i| best[i].is_finite())
            .min_by(|&a, &b| {
                (best[a] + raw_after(a))
                    .partial_cmp(&(best[b] + raw_after(b)))
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(a.cmp(&b))
            })
            .unwrap_or(0),
    };
    let cost = best[stop] + raw_after(stop);
    let mut out = Vec::new();
    let mut i = stop;
    while i > 0 {
        let Some(segment) = back[i].clone() else {
            break;
        };
        i -= segment.len;
        out.push(segment);
    }
    out.reverse();
    (out, cost)
}

/// Every typed piece that could start at `at` without passing `end`.
fn pieces(columns: &Columns<'_>, at: usize, end: usize, base: usize, big: bool) -> Vec<Piece> {
    let mut out = Vec::new();
    let align = |width: usize| match width {
        _ if width == 1 || (base + at) % width == 0 => 0.0,
        8 => MISALIGNED_WIDE_BITS,
        _ => MISALIGNED_BITS,
    };
    if columns.invariant[at].is_some() {
        let piece = constant_piece(columns, at, end, big);
        out.push(Piece {
            len: piece.len,
            cost: PIECE_BITS,
            kind: piece.kind,
        });
    }
    for width in [1usize, 2, 4, 8] {
        if at + width > end {
            break;
        }
        if columns.invariant[at..at + width]
            .iter()
            .all(Option::is_some)
        {
            continue;
        }
        out.push(Piece {
            len: width,
            cost: PIECE_BITS
                + width_prior(width)
                + align(width)
                + columns.integer_bits(at, width, big),
            kind: SegmentKind::Integer {
                width: width as u8,
                big_endian: big,
                constant: None,
            },
        });
    }
    // Raw bytes, for data no integer reading makes cheaper.
    for len in 1..=MAX_BYTES_PIECE.min(end - at) {
        if columns.invariant[at..at + len].iter().all(Option::is_some) {
            continue;
        }
        out.push(Piece {
            len,
            cost: PIECE_BITS + RAW_BITS * columns.weight * len as f64,
            kind: SegmentKind::Bytes,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(samples: &[Vec<u8>]) -> Vec<&[u8]> {
        samples.iter().map(Vec::as_slice).collect()
    }

    fn describe(segmentation: &Segmentation) -> Vec<(usize, usize, String)> {
        segmentation
            .segments
            .iter()
            .map(|segment| {
                let kind = match &segment.kind {
                    SegmentKind::Constant { text: true, .. } => "text-const".to_owned(),
                    SegmentKind::Constant { .. } => "const".to_owned(),
                    SegmentKind::Integer {
                        width,
                        big_endian,
                        constant,
                    } => format!(
                        "{}u{}{}",
                        if constant.is_some() { "const-" } else { "" },
                        u32::from(*width) * 8,
                        if *big_endian { "be" } else { "le" }
                    ),
                    SegmentKind::Text => "text".to_owned(),
                    SegmentKind::Bytes => "bytes".to_owned(),
                };
                (segment.offset, segment.len, kind)
            })
            .collect()
    }

    fn exact(samples: &[Vec<u8>], len: usize, base: usize) -> Vec<(usize, usize, String)> {
        describe(&segment(&rows(samples), len, base, 0, &[], Extent::Exact))
    }

    #[test]
    fn small_values_with_zero_high_bytes_read_as_wide_little_endian_integers() {
        let samples: Vec<Vec<u8>> = [3u32, 70, 12, 200, 9]
            .iter()
            .map(|&v| v.to_le_bytes().to_vec())
            .collect();
        assert_eq!(exact(&samples, 4, 0), vec![(0, 4, "u32le".to_owned())]);
    }

    #[test]
    fn big_endian_values_are_recognized_by_their_small_range() {
        let samples: Vec<Vec<u8>> = [3u32, 700, 12, 2000, 9]
            .iter()
            .map(|&v| v.to_be_bytes().to_vec())
            .collect();
        let segmentation = segment(&rows(&samples), 4, 0, 0, &[], Extent::Exact);
        assert!(segmentation.big_endian);
        assert_eq!(describe(&segmentation), vec![(0, 4, "u32be".to_owned())]);
    }

    #[test]
    fn adjacent_small_fields_are_not_merged_into_one_integer() {
        // A u16 channel count, then a u32 sample rate: merging them would make
        // the values enormous, so the split wins.
        let make = |channels: u16, rate: u32| {
            let mut out = channels.to_le_bytes().to_vec();
            out.extend_from_slice(&rate.to_le_bytes());
            out
        };
        let samples = vec![
            make(1, 8000),
            make(2, 16000),
            make(1, 11025),
            make(2, 22050),
        ];
        assert_eq!(
            exact(&samples, 6, 0),
            vec![(0, 2, "u16le".to_owned()), (2, 4, "u32le".to_owned())]
        );
    }

    #[test]
    fn a_random_value_is_not_merged_with_a_small_neighbor() {
        // A CRC-like random u32 followed by a small u32 length.
        let samples: Vec<Vec<u8>> = [
            (0x9A31_7C02u32, 6u32),
            (0x13E8_44F1, 31),
            (0xD0C2_9A7B, 14),
            (0x4F1D_E38C, 25),
            (0x86B7_05DA, 18),
        ]
        .iter()
        .map(|&(crc, len)| {
            let mut out = crc.to_le_bytes().to_vec();
            out.extend_from_slice(&len.to_le_bytes());
            out
        })
        .collect();
        assert_eq!(
            exact(&samples, 8, 0),
            vec![(0, 4, "u32le".to_owned()), (4, 4, "u32le".to_owned())]
        );
    }

    #[test]
    fn packed_little_endian_header_constants_split_at_value_starts() {
        // A varying u32 at offset 2, zero padding, then the constants 54 and 40
        // as u32 values, then a varying u32: a BMP-like packed header.
        let make = |size: u32, width: u32| {
            let mut out = b"BM".to_vec();
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&54u32.to_le_bytes());
            out.extend_from_slice(&40u32.to_le_bytes());
            out.extend_from_slice(&width.to_le_bytes());
            out
        };
        let samples = vec![make(58, 1), make(70, 2), make(78, 3), make(90, 4)];
        let found = describe(&segment(&rows(&samples), 22, 0, 2, &[], Extent::Exact));
        assert_eq!(
            found,
            vec![
                (0, 2, "const".to_owned()),
                (2, 4, "u32le".to_owned()),
                (6, 4, "const-u32le".to_owned()),
                (10, 4, "const-u32le".to_owned()),
                (14, 4, "const-u32le".to_owned()),
                (18, 4, "u32le".to_owned()),
            ]
        );
    }

    #[test]
    fn four_character_codes_split_and_binary_constants_follow_value_shape() {
        // "WAVEfmt " then the constants 16 (u32) and 1 (u16), then a varying
        // u16 channel count.
        let make = |channels: u16| {
            let mut out = b"WAVEfmt ".to_vec();
            out.extend_from_slice(&16u32.to_le_bytes());
            out.extend_from_slice(&1u16.to_le_bytes());
            out.extend_from_slice(&channels.to_le_bytes());
            out
        };
        let samples = vec![make(1), make(2), make(1)];
        assert_eq!(
            exact(&samples, 16, 8),
            vec![
                (0, 4, "text-const".to_owned()),
                (4, 4, "text-const".to_owned()),
                (8, 4, "const-u32le".to_owned()),
                (12, 2, "const-u16le".to_owned()),
                (14, 2, "u16le".to_owned()),
            ]
        );
    }

    #[test]
    fn invariant_text_inside_printable_looking_integers_is_found() {
        // A small length whose low byte is printable, then "WAVE".
        let make = |length: u32| {
            let mut out = length.to_le_bytes().to_vec();
            out.extend_from_slice(b"WAVE");
            out
        };
        let samples = vec![make(0x54), make(0x64), make(0x4c)];
        let found = exact(&samples, 8, 4);
        assert_eq!(found[1], (4, 4, "text-const".to_owned()), "{found:?}");
    }

    #[test]
    fn padded_text_fields_split_where_new_text_starts() {
        let make = |name: &str, mode: &str| {
            let mut out = name.as_bytes().to_vec();
            out.resize(12, 0);
            out.extend_from_slice(mode.as_bytes());
            out.resize(20, 0);
            out
        };
        let samples = vec![
            make("a.txt", "0000644"),
            make("notes.md", "0000755"),
            make("x.cfg", "0000600"),
        ];
        let found = exact(&samples, 20, 0);
        assert_eq!(found[0], (0, 12, "text".to_owned()), "{found:?}");
        assert_eq!(found[1], (12, 8, "text".to_owned()), "{found:?}");
    }

    #[test]
    fn forced_pieces_and_magic_are_kept_exactly() {
        let samples: Vec<Vec<u8>> = (0u8..4).map(|v| vec![0xAA, 0xBB, v, v, 0, 7]).collect();
        let forced = [Forced {
            offset: 2,
            width: 2,
            big_endian: true,
        }];
        let segmentation = segment(&rows(&samples), 6, 0, 2, &forced, Extent::Exact);
        let found = describe(&segmentation);
        assert_eq!(found[0], (0, 2, "const".to_owned()));
        assert_eq!(found[1], (2, 2, "u16be".to_owned()));
        assert_eq!(segmentation.end(), 6);
    }

    #[test]
    fn prefix_mode_leaves_random_payload_untyped() {
        // A constant tag and a small counter, then noise.
        let samples: Vec<Vec<u8>> = (0u8..6)
            .map(|v| {
                let mut out = vec![0x7E, 0x7E, v, 0];
                out.extend((0..32).map(|k| (u32::from(v) * 97 + k * 61) as u8 ^ 0x5A));
                out
            })
            .collect();
        let segmentation = segment(&rows(&samples), 36, 0, 0, &[], Extent::Prefix);
        assert!(
            segmentation.end() <= 4,
            "noise should stay raw, got {:?}",
            describe(&segmentation)
        );
    }

    #[test]
    fn exact_mode_covers_every_byte_and_degenerate_inputs_are_safe() {
        let samples = vec![vec![1u8, 2, 3], vec![4u8, 5, 6]];
        let segmentation = segment(&rows(&samples), 3, 0, 0, &[], Extent::Exact);
        assert_eq!(segmentation.end(), 3);
        assert!(
            segment(&[], 4, 0, 0, &[], Extent::Exact)
                .segments
                .is_empty()
        );
        assert!(
            segment(&rows(&samples), 0, 0, 0, &[], Extent::Exact)
                .segments
                .is_empty()
        );
        // Rows shorter than the region are ignored rather than indexed.
        assert!(
            segment(&rows(&samples), 10, 0, 0, &[], Extent::Exact)
                .segments
                .is_empty()
        );
        // A magic longer than the region, or one that varies, is ignored.
        assert_eq!(
            segment(&rows(&samples), 3, 0, 9, &[], Extent::Exact).end(),
            3
        );
    }
}
