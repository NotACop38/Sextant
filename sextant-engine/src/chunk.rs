//! Repeating length-prefixed record detection (FR-7, FR-9, FR-10).
//!
//! Many real formats are a short header followed by a run of records, each of
//! which carries its own length: PNG chunks (a four-byte big-endian length, a
//! four-byte type, the data, and a CRC-32), the Sextant TLV records (a tag, a
//! two-byte length, and the value), and countless others. A single fixed-offset
//! length field cannot describe this; the array is the structure.
//!
//! [`detect_chunks`] searches for a record template that, replayed from a header
//! boundary, consumes every sample exactly to its end. The template has a small
//! number of parameters: a header length, optional bytes before the length
//! field, the length field width and byte order, optional bytes between the
//! length and the data it governs, and optional trailing bytes (often a
//! per-record checksum). Every candidate template is replayed against every
//! sample; only a template that lands exactly on the end of all samples, with at
//! least one record everywhere and more than one somewhere, is kept. The
//! executor and scorer remain the final authority (FR-26); this detector only
//! proposes the layout.
//!
//! When a template's trailing bytes verify as a checksum over the record (the
//! PNG CRC-32 case), that is recorded too: it both raises confidence and breaks
//! ties toward the layout a human would recognize as correct.

use sextant_ir::ChecksumAlgorithm;

use crate::checksum;

/// The header lengths the search tries. A record array begins after a short
/// header (a magic, perhaps a version and a count), so only small header
/// boundaries are worth testing. Bounding this keeps detection cheap.
const MAX_HEADER_LEN: usize = 16;
/// The most bytes the search will hypothesize before the length field inside a
/// record (for example a one-byte tag).
const MAX_PRE: usize = 4;
/// The most bytes the search will hypothesize between the length field and the
/// data it governs, or trailing after the data.
const MAX_GAP: usize = 8;
/// The length field widths the search hypothesizes, in bytes.
const WIDTHS: [u8; 3] = [1, 2, 4];
/// A hard cap on records produced by one replay, so an adversarial input cannot
/// drive an unbounded loop during detection (NFR-2).
const MAX_RECORDS: usize = 1 << 20;

/// Where a per-record checksum's covered range begins, relative to one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkChecksumStart {
    /// The covered range begins at the first byte of the record.
    RecordStart,
    /// The covered range begins just after the length field (the PNG case, where
    /// the CRC covers the chunk type and data but not the length).
    AfterLength,
}

/// A per-record checksum that verifies across every record of every sample
/// (FR-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkChecksum {
    /// The algorithm that reproduces each record's trailing value.
    pub algorithm: ChecksumAlgorithm,
    /// Where the covered range begins within a record.
    pub start: ChunkChecksumStart,
    /// Whether the stored checksum value is big-endian (PNG stores its CRC-32
    /// big-endian, for example).
    pub big_endian: bool,
}

/// A detected repeating length-prefixed record layout (FR-9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkLayout {
    /// The header length: the byte offset at which the record array begins.
    pub header_len: usize,
    /// Bytes inside each record before the length field (for example a tag).
    pub pre: usize,
    /// The length field width in bytes.
    pub width: u8,
    /// Whether the length field is big-endian.
    pub big_endian: bool,
    /// Bytes between the length field and the data it governs (for example a
    /// chunk type).
    pub mid: usize,
    /// Bytes trailing after the data (often a per-record checksum).
    pub tail: usize,
    /// A per-record checksum over the trailing bytes, when one verifies.
    pub checksum: Option<ChunkChecksum>,
    /// The number of records found in each sample, in sample order.
    pub record_counts: Vec<usize>,
}

impl ChunkLayout {
    /// The total number of records across all samples. Used to prefer the
    /// layout that explains the most structure.
    fn total_records(&self) -> usize {
        self.record_counts.iter().sum()
    }
}

/// Read an unsigned integer of `width` bytes at `offset`, honoring byte order.
/// Returns `None` when the field would run past the end of `data`.
fn read_uint(data: &[u8], offset: usize, width: u8, big: bool) -> Option<u64> {
    let width = usize::from(width);
    let end = offset.checked_add(width)?;
    if end > data.len() {
        return None;
    }
    let mut value = 0u64;
    if big {
        for &byte in &data[offset..end] {
            value = (value << 8) | u64::from(byte);
        }
    } else {
        for (index, &byte) in data[offset..end].iter().enumerate() {
            value |= u64::from(byte) << (8 * index);
        }
    }
    Some(value)
}

/// A record template: the geometry of one length-prefixed record, shared by
/// every record of a layout. Grouping these parameters keeps the detection
/// functions readable and their signatures small.
#[derive(Debug, Clone, Copy)]
struct Template {
    /// Bytes inside each record before the length field.
    pre: usize,
    /// The length field width in bytes.
    width: u8,
    /// Whether the length field is big-endian.
    big: bool,
    /// Bytes between the length field and the data it governs.
    mid: usize,
    /// Bytes trailing after the data.
    tail: usize,
}

impl Template {
    /// The fixed bytes of one record, excluding its variable-length data.
    fn fixed(&self) -> Option<usize> {
        self.pre
            .checked_add(usize::from(self.width))?
            .checked_add(self.mid)?
            .checked_add(self.tail)
    }

    /// The offset of the data field within a record.
    fn data_offset(&self) -> usize {
        self.pre + usize::from(self.width) + self.mid
    }
}

/// One record's geometry inside a sample, recovered during a replay.
#[derive(Debug, Clone, Copy)]
struct Record {
    /// The record's start offset.
    start: usize,
    /// The decoded length value that governs the data field.
    length: u64,
}

/// Replay a record template across one sample. Returns the records when the
/// template consumes the sample exactly to its end, otherwise `None`.
fn replay(sample: &[u8], header_len: usize, template: Template) -> Option<Vec<Record>> {
    if header_len > sample.len() {
        return None;
    }
    let fixed = template.fixed()?;
    let mut records = Vec::new();
    let mut cursor = header_len;
    while cursor < sample.len() {
        let length = read_uint(sample, cursor + template.pre, template.width, template.big)?;
        let data_len = usize::try_from(length).ok()?;
        let record_size = fixed.checked_add(data_len)?;
        // A record must make progress, otherwise the replay would loop forever.
        if record_size == 0 {
            return None;
        }
        let end = cursor.checked_add(record_size)?;
        if end > sample.len() {
            return None;
        }
        records.push(Record {
            start: cursor,
            length,
        });
        if records.len() > MAX_RECORDS {
            return None;
        }
        cursor = end;
    }
    if cursor == sample.len() && !records.is_empty() {
        Some(records)
    } else {
        None
    }
}

/// The checksum algorithms worth testing for a trailing field of `tail` bytes.
fn algorithms_for_tail(tail: usize) -> &'static [ChecksumAlgorithm] {
    match tail {
        4 => &[
            ChecksumAlgorithm::Crc32,
            ChecksumAlgorithm::Additive,
            ChecksumAlgorithm::Xor,
        ],
        2 => &[
            ChecksumAlgorithm::Crc16,
            ChecksumAlgorithm::Additive,
            ChecksumAlgorithm::Xor,
        ],
        _ => &[ChecksumAlgorithm::Additive, ChecksumAlgorithm::Xor],
    }
}

/// Test whether the trailing `tail` bytes of every record verify as a checksum
/// over a covered range, for one (algorithm, start) hypothesis.
fn checksum_holds(
    samples: &[&[u8]],
    records: &[Vec<Record>],
    template: Template,
    algorithm: ChecksumAlgorithm,
    start: ChunkChecksumStart,
    big: bool,
) -> bool {
    let tail = template.tail as u8;
    for (sample, sample_records) in samples.iter().zip(records) {
        for record in sample_records {
            let data_len = record.length as usize;
            let cover_start = match start {
                ChunkChecksumStart::RecordStart => record.start,
                ChunkChecksumStart::AfterLength => {
                    record.start + template.pre + usize::from(template.width)
                }
            };
            let tail_start = record.start + template.data_offset() + data_len;
            if cover_start >= tail_start || tail_start + template.tail > sample.len() {
                return false;
            }
            // The stored checksum is decoded in the byte order under test, then
            // compared numerically against the recomputed checksum.
            let Some(stored) = read_uint(sample, tail_start, tail, big) else {
                return false;
            };
            let data = &sample[cover_start..tail_start];
            if !checksum::verify(algorithm, data, stored, tail) {
                return false;
            }
        }
    }
    true
}

/// Find a per-record checksum for a replayed template, if one verifies. The
/// most specific covered range (after the length field, as PNG uses) is tried
/// before the whole record, and a true CRC before the weaker additive and XOR
/// checks.
fn find_checksum(
    samples: &[&[u8]],
    records: &[Vec<Record>],
    template: Template,
) -> Option<ChunkChecksum> {
    if template.tail == 0 {
        return None;
    }
    for start in [
        ChunkChecksumStart::AfterLength,
        ChunkChecksumStart::RecordStart,
    ] {
        for &algorithm in algorithms_for_tail(template.tail) {
            for big in [true, false] {
                if checksum_holds(samples, records, template, algorithm, start, big) {
                    return Some(ChunkChecksum {
                        algorithm,
                        start,
                        big_endian: big,
                    });
                }
            }
        }
    }
    None
}

/// A sort key that ranks competing layouts. Higher is better. A verifying
/// checksum dominates (it is a hard relationship), then the layout that explains
/// the most records, then a wider length field, then the tightest record
/// padding, then the earliest header boundary.
fn layout_key(layout: &ChunkLayout) -> (u8, usize, u8, i64, i64) {
    let padding = (layout.pre + layout.mid + layout.tail) as i64;
    (
        u8::from(layout.checksum.is_some()),
        layout.total_records(),
        layout.width,
        -padding,
        -(layout.header_len as i64),
    )
}

/// Detect a repeating length-prefixed record layout shared by every sample
/// (FR-9). Returns the best-scoring layout, or `None` when no template consumes
/// every sample exactly.
///
/// At least two samples are required so that a coincidental alignment in a
/// single sample cannot invent a structure. A layout is accepted only when it
/// replays to the exact end of every sample, finds at least one record in each,
/// and more than one record somewhere, so a single non-repeating payload is not
/// mistaken for an array.
#[must_use]
pub fn detect_chunks(samples: &[&[u8]]) -> Option<ChunkLayout> {
    if samples.len() < 2 {
        return None;
    }
    let common_len = samples.iter().map(|s| s.len()).min().unwrap_or(0);
    let max_header = common_len.min(MAX_HEADER_LEN);

    let mut best: Option<ChunkLayout> = None;
    for header_len in 0..=max_header {
        for pre in 0..=MAX_PRE {
            for &width in &WIDTHS {
                for big in [false, true] {
                    if width == 1 && big {
                        continue;
                    }
                    for mid in 0..=MAX_GAP {
                        for tail in 0..=MAX_GAP {
                            let template = Template {
                                pre,
                                width,
                                big,
                                mid,
                                tail,
                            };
                            let Some(records) = replay_all(samples, header_len, template) else {
                                continue;
                            };
                            let record_counts: Vec<usize> = records.iter().map(Vec::len).collect();
                            if record_counts.iter().copied().max().unwrap_or(0) < 2 {
                                continue;
                            }
                            let checksum = find_checksum(samples, &records, template);
                            let layout = ChunkLayout {
                                header_len,
                                pre,
                                width,
                                big_endian: big,
                                mid,
                                tail,
                                checksum,
                                record_counts,
                            };
                            if best
                                .as_ref()
                                .is_none_or(|current| layout_key(&layout) > layout_key(current))
                            {
                                best = Some(layout);
                            }
                        }
                    }
                }
            }
        }
    }
    best
}

/// Replay a template across every sample, returning the per-sample records only
/// when all samples consume exactly.
fn replay_all(
    samples: &[&[u8]],
    header_len: usize,
    template: Template,
) -> Option<Vec<Vec<Record>>> {
    let mut all = Vec::with_capacity(samples.len());
    for sample in samples {
        all.push(replay(sample, header_len, template)?);
    }
    Some(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum;

    #[test]
    fn detects_png_like_chunk_array() {
        // signature(8) then [len(u32be) type(4) data crc(u32be)] chunks.
        let make = |chunks: &[(&[u8; 4], &[u8])]| {
            let mut data = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
            for (kind, payload) in chunks {
                data.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                data.extend_from_slice(*kind);
                data.extend_from_slice(payload);
                let mut crc_input = kind.to_vec();
                crc_input.extend_from_slice(payload);
                data.extend_from_slice(&checksum::crc32(&crc_input).to_be_bytes());
            }
            data
        };
        let samples = [
            make(&[(b"IHDR", &[1, 2, 3]), (b"IDAT", &[9, 9]), (b"IEND", &[])]),
            make(&[(b"IHDR", &[4, 5, 6]), (b"IDAT", &[7; 10]), (b"IEND", &[])]),
            make(&[(b"IHDR", &[0, 0, 0]), (b"IDAT", &[1]), (b"IEND", &[])]),
        ];
        let slices: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
        let layout = detect_chunks(&slices).expect("a chunk layout");
        assert_eq!(layout.header_len, 8);
        assert_eq!(layout.pre, 0);
        assert_eq!(layout.width, 4);
        assert!(layout.big_endian);
        assert_eq!(layout.mid, 4);
        assert_eq!(layout.tail, 4);
        let checksum = layout.checksum.expect("a verified per-record checksum");
        assert_eq!(checksum.algorithm, ChecksumAlgorithm::Crc32);
        assert_eq!(checksum.start, ChunkChecksumStart::AfterLength);
        assert_eq!(layout.record_counts, vec![3, 3, 3]);
    }

    #[test]
    fn detects_tlv_like_records() {
        // magic(4) version(1) count(1) then [tag(1) len(u16le) value] records.
        let make = |records: &[(&u8, &[u8])]| {
            let mut data = b"STLV".to_vec();
            data.push(1);
            data.push(records.len() as u8);
            for (tag, value) in records {
                data.push(**tag);
                data.extend_from_slice(&(value.len() as u16).to_le_bytes());
                data.extend_from_slice(value);
            }
            data
        };
        let samples = [
            make(&[(&1, &[0xAA, 0xBB]), (&2, &[0xCC])]),
            make(&[(&3, &[1, 2, 3]), (&4, &[4]), (&5, &[5, 6])]),
            make(&[(&7, &[9, 9, 9, 9])]),
        ];
        let slices: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
        let layout = detect_chunks(&slices).expect("a chunk layout");
        assert_eq!(layout.pre, 1);
        assert_eq!(layout.width, 2);
        assert!(!layout.big_endian);
        assert_eq!(layout.mid, 0);
        assert_eq!(layout.tail, 0);
        assert_eq!(layout.record_counts, vec![2, 3, 1]);
    }

    #[test]
    fn rejects_a_single_non_repeating_payload() {
        // A magic and one to-end payload is not a record array.
        let samples = [b"STOT\x07hello".to_vec(), b"STOT\x09bye".to_vec()];
        let slices: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
        // No template should produce more than one record per sample here, so
        // detection declines (or, if it finds a degenerate one-record layout,
        // the max-records-below-two guard rejects it).
        let layout = detect_chunks(&slices);
        assert!(layout.is_none() || layout.unwrap().record_counts.iter().max() == Some(&1));
    }

    #[test]
    fn single_sample_is_not_enough() {
        let samples = [b"only one".to_vec()];
        let slices: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
        assert!(detect_chunks(&slices).is_none());
    }

    #[test]
    fn hostile_input_never_panics() {
        let cases: Vec<Vec<&[u8]>> = vec![
            vec![&[], &[]],
            vec![&[0xFF; 3], &[0x00; 5]],
            vec![&[0xFF, 0xFF, 0xFF, 0xFF], &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF]],
        ];
        for case in cases {
            let _ = detect_chunks(&case);
        }
    }
}
