//! Repeating length-prefixed record detection (FR-7, FR-9, FR-10).
//!
//! Many real formats are a short header followed by a run of records, each of
//! which carries its own length: PNG chunks (a four-byte big-endian length, a
//! four-byte type, the data, and a CRC-32), RIFF chunks (a four-character tag
//! and a little-endian size), capture file records (timestamps, then a length),
//! and tag-length-value encodings. A single fixed-offset length field cannot
//! describe this; the array is the structure.
//!
//! [`detect_chunk_layouts`] searches for record templates that, replayed from a
//! header boundary, consume every sample exactly to its end. A template has a
//! header length, the bytes before the length field inside a record, the
//! length field's width and byte order, and a number of fixed bytes after it
//! that are split between a middle section (before the data) and a tail (after
//! it, often a checksum). Every consistent layout is returned, and the
//! candidate builder lets the executor and the structure measure choose among
//! them (FR-26); this module only proposes.
//!
//! # Bounded work
//!
//! A replay's record boundaries depend only on the header length, the offset
//! and reading of the length field, and the total fixed bytes per record, so
//! each such geometry is replayed once and the middle and tail split is
//! enumerated afterwards. A replay stops early when its first records are
//! degenerate (every length zero, or every length equal), and the whole search
//! is capped at a number of replay steps proportional to the input size, so an
//! adversarial or low-entropy input cannot make detection slow (FR-24, NFR-3).

use sextant_ir::ChecksumAlgorithm;

use crate::checksum;

/// The header lengths the search tries.
const MAX_HEADER_LEN: usize = 64;
/// The most bytes before the length field inside a record (for example a tag,
/// or a pair of timestamps).
const MAX_PRE: usize = 8;
/// The most fixed bytes after the length field, split between the middle
/// section and the tail.
const MAX_AFTER: usize = 16;
/// The length field widths the search hypothesizes, in bytes.
const WIDTHS: [u8; 3] = [1, 2, 4];
/// A hard cap on records produced by one replay (NFR-2).
const MAX_RECORDS: usize = 1 << 20;
/// How many leading records a replay inspects before giving up on a length
/// sequence that never changes: a field that is always zero, or always the same
/// value, is not evidence of a length prefix.
const DEGENERATE_PREFIX: usize = 64;
/// Replay steps allowed per input byte, plus a fixed allowance. Detection stops
/// and returns what it found once the budget is spent. A genuine layout needs
/// one step per record, far below one step per byte, so the budget only binds
/// when many templates replay deep into data that almost fits, such as sparse
/// or low-entropy input.
const STEPS_PER_BYTE: usize = 4;
const BASE_STEPS: usize = 1 << 20;
/// The most layouts returned.
const MAX_LAYOUTS: usize = 64;

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
    /// Whether the stored checksum value is big-endian.
    pub big_endian: bool,
}

/// A detected repeating length-prefixed record layout (FR-9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkLayout {
    /// The header length: the byte offset at which the record array begins.
    pub header_len: usize,
    /// Bytes inside each record before the length field.
    pub pre: usize,
    /// The length field width in bytes.
    pub width: u8,
    /// Whether the length field is big-endian.
    pub big_endian: bool,
    /// Bytes between the length field and the data it governs.
    pub mid: usize,
    /// Bytes trailing after the data.
    pub tail: usize,
    /// A per-record checksum over the trailing bytes, when one verifies.
    pub checksum: Option<ChunkChecksum>,
    /// The number of records found in each sample, in sample order.
    pub record_counts: Vec<usize>,
}

impl ChunkLayout {
    /// The fixed bytes of one record, excluding its data.
    #[must_use]
    pub fn fixed(&self) -> usize {
        self.pre + usize::from(self.width) + self.mid + self.tail
    }

    /// The total number of records across all samples.
    #[must_use]
    pub fn total_records(&self) -> usize {
        self.record_counts.iter().sum()
    }
}

/// Read an unsigned integer of `width` bytes at `offset`, honoring byte order.
fn read_uint(data: &[u8], offset: usize, width: u8, big: bool) -> Option<u64> {
    let end = offset.checked_add(usize::from(width))?;
    let bytes = data.get(offset..end)?;
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
    Some(value)
}

/// The geometry that determines record boundaries.
#[derive(Debug, Clone, Copy)]
struct Geometry {
    header_len: usize,
    pre: usize,
    width: u8,
    big: bool,
    fixed: usize,
}

/// The start and governed length of one record.
#[derive(Debug, Clone, Copy)]
struct Record {
    start: usize,
    length: usize,
}

/// A replay outcome.
enum Replay {
    /// The template consumed the sample exactly.
    Exact(Vec<Record>),
    /// The template did not fit the sample.
    Mismatch,
    /// The work budget ran out.
    Exhausted,
}

/// A shared step budget for the whole search.
struct Budget {
    remaining: usize,
}

impl Budget {
    fn spend(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }
}

/// Replay a geometry across one sample.
fn replay(sample: &[u8], geometry: Geometry, budget: &mut Budget) -> Replay {
    if geometry.header_len > sample.len() {
        return Replay::Mismatch;
    }
    let mut records = Vec::new();
    let mut cursor = geometry.header_len;
    let mut first_length = None;
    let mut all_equal = true;
    while cursor < sample.len() {
        if !budget.spend() {
            return Replay::Exhausted;
        }
        let Some(length) = read_uint(sample, cursor + geometry.pre, geometry.width, geometry.big)
        else {
            return Replay::Mismatch;
        };
        let Ok(length) = usize::try_from(length) else {
            return Replay::Mismatch;
        };
        let Some(end) = cursor
            .checked_add(geometry.fixed)
            .and_then(|end| end.checked_add(length))
        else {
            return Replay::Mismatch;
        };
        if end > sample.len() || end == cursor {
            return Replay::Mismatch;
        }
        match first_length {
            None => first_length = Some(length),
            Some(first) if first != length => all_equal = false,
            Some(_) => {}
        }
        records.push(Record {
            start: cursor,
            length,
        });
        if (records.len() >= DEGENERATE_PREFIX && all_equal) || records.len() > MAX_RECORDS {
            return Replay::Mismatch;
        }
        cursor = end;
    }
    if records.is_empty() {
        Replay::Mismatch
    } else {
        Replay::Exact(records)
    }
}

/// The checksum algorithms worth testing for a tail of `tail` bytes.
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
        1 => &[ChecksumAlgorithm::Additive, ChecksumAlgorithm::Xor],
        _ => &[],
    }
}

/// Find a per-record checksum in the tail, if one verifies over every record.
/// The most specific covered range (after the length field, as PNG uses) is
/// tried before the whole record, and a true CRC before the weaker sums.
fn find_checksum(
    samples: &[&[u8]],
    records: &[Vec<Record>],
    geometry: Geometry,
    mid: usize,
    tail: usize,
) -> Option<ChunkChecksum> {
    let algorithms = algorithms_for_tail(tail);
    if algorithms.is_empty() {
        return None;
    }
    // One-byte sums verify by chance too often with few records.
    let total: usize = records.iter().map(Vec::len).sum();
    let data_offset = geometry.pre + usize::from(geometry.width) + mid;
    for start in [
        ChunkChecksumStart::AfterLength,
        ChunkChecksumStart::RecordStart,
    ] {
        for &algorithm in algorithms {
            if tail == 1 && total < 4 {
                continue;
            }
            for big in [true, false] {
                let holds = samples.iter().zip(records).all(|(sample, records)| {
                    records.iter().all(|record| {
                        let cover = match start {
                            ChunkChecksumStart::RecordStart => record.start,
                            ChunkChecksumStart::AfterLength => {
                                record.start + geometry.pre + usize::from(geometry.width)
                            }
                        };
                        let tail_start = record.start + data_offset + record.length;
                        if cover >= tail_start {
                            return false;
                        }
                        read_uint(sample, tail_start, tail as u8, big).is_some_and(|stored| {
                            checksum::verify(
                                algorithm,
                                &sample[cover..tail_start],
                                stored,
                                tail as u8,
                            )
                        })
                    })
                });
                if holds {
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

/// Detect every repeating length-prefixed record layout shared by the samples
/// (FR-9), best first by a cheap preference: a verified checksum, then more
/// records, then fewer fixed bytes, then an earlier header boundary.
///
/// At least two samples are required, so a coincidental alignment in one
/// sample cannot invent a structure. A layout is accepted only when it replays
/// to the exact end of every sample, finds a record in each, more than one
/// record somewhere, and more than one distinct length value.
#[must_use]
pub fn detect_chunk_layouts(samples: &[&[u8]]) -> Vec<ChunkLayout> {
    if samples.len() < 2 {
        return Vec::new();
    }
    let total_bytes: usize = samples.iter().map(|sample| sample.len()).sum();
    let mut budget = Budget {
        remaining: total_bytes
            .saturating_mul(STEPS_PER_BYTE)
            .saturating_add(BASE_STEPS),
    };
    // Replay the shortest sample first: mismatches surface fastest there.
    let mut order: Vec<usize> = (0..samples.len()).collect();
    order.sort_by_key(|&index| samples[index].len());
    let common_len = samples.iter().map(|sample| sample.len()).min().unwrap_or(0);

    let mut layouts = Vec::new();
    'search: for header_len in 0..=common_len.min(MAX_HEADER_LEN) {
        for pre in 0..=MAX_PRE {
            for &width in &WIDTHS {
                for big in [false, true] {
                    if width == 1 && big {
                        continue;
                    }
                    for after in 0..=MAX_AFTER {
                        let geometry = Geometry {
                            header_len,
                            pre,
                            width,
                            big,
                            fixed: pre + usize::from(width) + after,
                        };
                        let mut records = vec![Vec::new(); samples.len()];
                        let mut consistent = true;
                        for &index in &order {
                            match replay(samples[index], geometry, &mut budget) {
                                Replay::Exact(found) => records[index] = found,
                                Replay::Mismatch => {
                                    consistent = false;
                                    break;
                                }
                                Replay::Exhausted => break 'search,
                            }
                        }
                        if !consistent {
                            continue;
                        }
                        let counts: Vec<usize> = records.iter().map(Vec::len).collect();
                        let distinct_lengths = records
                            .iter()
                            .flatten()
                            .map(|record| record.length)
                            .collect::<std::collections::BTreeSet<_>>()
                            .len();
                        if counts.iter().copied().max().unwrap_or(0) < 2 || distinct_lengths < 2 {
                            continue;
                        }
                        for mid in 0..=after {
                            let tail = after - mid;
                            layouts.push(ChunkLayout {
                                header_len,
                                pre,
                                width,
                                big_endian: big,
                                mid,
                                tail,
                                checksum: find_checksum(samples, &records, geometry, mid, tail),
                                record_counts: counts.clone(),
                            });
                        }
                        if layouts.len() >= 4 * MAX_LAYOUTS {
                            break 'search;
                        }
                    }
                }
            }
        }
    }
    layouts.sort_by_key(|layout| {
        (
            std::cmp::Reverse(layout.checksum.is_some()),
            std::cmp::Reverse(layout.total_records()),
            layout.fixed(),
            layout.header_len,
            std::cmp::Reverse(layout.width),
        )
    });
    layouts.truncate(MAX_LAYOUTS);
    layouts
}

/// The single most preferred layout, or `None` when no template consumes every
/// sample exactly. See [`detect_chunk_layouts`].
#[must_use]
pub fn detect_chunks(samples: &[&[u8]]) -> Option<ChunkLayout> {
    detect_chunk_layouts(samples).into_iter().next()
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
        let layouts = detect_chunk_layouts(&slices);
        assert!(
            layouts.iter().any(|layout| layout.header_len == 6
                && layout.pre == 1
                && layout.width == 2
                && !layout.big_endian
                && layout.mid == 0
                && layout.tail == 0
                && layout.record_counts == vec![2, 3, 1]),
            "the TLV layout must be among {layouts:?}"
        );
    }

    #[test]
    fn detects_records_with_a_long_prefix_before_the_length() {
        // Two u32 timestamps, a u32 length, a u32 copy of it, then data.
        let make = |sizes: &[usize]| {
            let mut data = vec![0xAB; 24];
            for (index, &size) in sizes.iter().enumerate() {
                data.extend_from_slice(&(1_700_000_000u32 + index as u32).to_le_bytes());
                data.extend_from_slice(&(index as u32 * 7).to_le_bytes());
                data.extend_from_slice(&(size as u32).to_le_bytes());
                data.extend_from_slice(&(size as u32).to_le_bytes());
                data.extend(std::iter::repeat_n(0x5A, size));
            }
            data
        };
        let samples = [make(&[4, 12]), make(&[1, 30, 8]), make(&[20, 2, 2, 9])];
        let slices: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
        let layouts = detect_chunk_layouts(&slices);
        assert!(
            layouts
                .iter()
                .any(|layout| layout.header_len == 24 && layout.pre == 8 && layout.mid == 4),
            "{layouts:?}"
        );
    }

    #[test]
    fn rejects_a_single_non_repeating_payload() {
        let samples = [b"STOT\x07hello".to_vec(), b"STOT\x09bye".to_vec()];
        let slices: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
        assert!(
            detect_chunk_layouts(&slices)
                .iter()
                .all(|layout| layout.record_counts.iter().max() >= Some(&2))
        );
    }

    #[test]
    fn single_sample_is_not_enough() {
        let samples = [b"only one".to_vec()];
        let slices: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
        assert!(detect_chunks(&slices).is_none());
    }

    #[test]
    fn degenerate_low_entropy_input_is_fast_and_finds_nothing() {
        // All-zero samples replay every template to the end in the old search.
        let zeros = vec![0u8; 256 * 1024];
        let samples = [zeros.as_slice(), zeros.as_slice(), zeros.as_slice()];
        let started = std::time::Instant::now();
        let layouts = detect_chunk_layouts(&samples);
        assert!(layouts.is_empty(), "{layouts:?}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn hostile_input_never_panics() {
        let cases: Vec<Vec<&[u8]>> = vec![
            vec![&[], &[]],
            vec![&[0xFF; 3], &[0x00; 5]],
            vec![&[0xFF, 0xFF, 0xFF, 0xFF], &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF]],
            vec![&[0x01; 300], &[0x01; 301]],
        ];
        for case in cases {
            let _ = detect_chunk_layouts(&case);
        }
    }
}
