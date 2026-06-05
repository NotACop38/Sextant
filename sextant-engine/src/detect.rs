//! Field detectors for the statistical inference pass (FR-8 to FR-11).
//!
//! Each detector takes the sample set (and the positional [`Alignment`] when it
//! helps) and returns structured findings that the candidate builder turns into
//! IR fields. Detection is deliberately conservative: a relationship is reported
//! only when it holds across every sample, so a coincidence in one sample cannot
//! invent a field. The executor and scorer are the final authority (FR-26); a
//! detector that over-reports is corrected when its candidate fails to verify.
//!
//! The detectors are:
//!
//! - [`detect_magic`]: an invariant signature prefix (FR-8).
//! - [`detect_int_fields`]: length, count, and total-size relationships across
//!   endianness and width hypotheses (FR-9).
//! - [`detect_offsets`]: header fields that point at an invariant downstream
//!   marker (FR-9).
//! - [`detect_trailing_checksum`]: a trailing checksum over a plausible covered
//!   range (FR-10).
//! - [`detect_bitfields`]: sub-byte packed fields, found with `bitvec` so the
//!   engine never assumes byte-aligned fields only (FR-11).

use bitvec::prelude::*;
use sextant_ir::ChecksumAlgorithm;

use crate::align::Alignment;
use crate::checksum;

/// The shortest invariant prefix accepted as a magic signature, in bytes.
const MIN_MAGIC_LEN: usize = 2;
/// The longest invariant prefix kept as a magic signature. A longer run is
/// truncated so a whole low-entropy header is not swallowed into the magic.
const MAX_MAGIC_LEN: usize = 64;
/// The integer widths, in bytes, the detectors hypothesize (FR-9).
const INT_WIDTHS: [usize; 4] = [1, 2, 4, 8];
/// The largest fixed record size a count relationship will hypothesize.
const MAX_RECORD_SIZE: u64 = 1024;
/// The deepest header offset the integer and offset detectors scan to. Header
/// length, count, and offset fields sit near the start; bounding the scan keeps
/// detection cheap and avoids reaching into payload bytes.
const MAX_HEADER_SCAN: usize = 64;
/// The trailing-byte amounts a derived-length relationship may leave for a
/// suffix (for example a four-byte CRC), tried in this order.
const TRAILING_CANDIDATES: [usize; 4] = [0, 4, 2, 1];

/// Decode an unsigned integer of `width` bytes at `offset` in `data`.
///
/// Returns `None` when the field would run past the end of `data` or the width
/// is unsupported. Used by every numeric detector so endianness and bounds are
/// handled in one place.
#[must_use]
fn read_uint(data: &[u8], offset: usize, width: usize, big: bool) -> Option<u64> {
    if !matches!(width, 1 | 2 | 4 | 8) {
        return None;
    }
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

/// An invariant signature found at the start of every sample (FR-8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Magic {
    /// The signature bytes, shared by every sample.
    pub bytes: Vec<u8>,
}

impl Magic {
    /// The signature length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the signature has no bytes (never true for a returned finding).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Detect a magic or signature prefix: the invariant leading bytes shared by
/// every sample (FR-8).
///
/// Returns `None` when fewer than two samples are given, when the first byte
/// already varies, or when the invariant run is shorter than [`MIN_MAGIC_LEN`].
/// A run longer than [`MAX_MAGIC_LEN`] is truncated.
#[must_use]
pub fn detect_magic<S: AsRef<[u8]>>(samples: &[S], alignment: &Alignment) -> Option<Magic> {
    let prefix = alignment.invariant_prefix_len().min(MAX_MAGIC_LEN);
    if prefix < MIN_MAGIC_LEN {
        return None;
    }
    let first = samples.first()?.as_ref();
    if first.len() < prefix {
        return None;
    }
    Some(Magic {
        bytes: first[..prefix].to_vec(),
    })
}

/// The relationship an integer field satisfies across the sample set (FR-9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntRelation {
    /// The field's value equals the whole sample length (a total-size field).
    TotalLength,
    /// The field's value is the byte length of the payload that immediately
    /// follows it, leaving `trailing` bytes for a suffix such as a checksum.
    DerivedLength {
        /// How many bytes follow the payload before the sample ends.
        trailing: usize,
    },
    /// The field's value is a count of fixed-size records that fill the rest of
    /// the sample, each `record_size` bytes long.
    Count {
        /// The size of one record in bytes.
        record_size: u64,
    },
}

/// A detected integer field and the relationship it satisfies (FR-9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntField {
    /// The field's byte offset from the start of the sample.
    pub offset: usize,
    /// The field width in bytes (1, 2, 4, or 8).
    pub width: u8,
    /// Whether the field is big-endian.
    pub big_endian: bool,
    /// The relationship the field's value satisfies in every sample.
    pub relation: IntRelation,
    /// The field's decoded value in each sample, in sample order.
    pub values: Vec<u64>,
}

impl IntField {
    /// The offset just past the field's last byte.
    #[must_use]
    pub fn end(&self) -> usize {
        self.offset + usize::from(self.width)
    }
}

/// Detect header integer fields whose value tracks the sample length, the
/// payload length, or a record count, across width and endianness hypotheses
/// (FR-9).
///
/// Every candidate offset up to [`MAX_HEADER_SCAN`], each width in
/// [`INT_WIDTHS`], and both byte orders are tried. A relationship is reported
/// only when it holds for all samples and the field's value is not constant, so
/// an invariant header constant is never mistaken for a length or count.
#[must_use]
pub fn detect_int_fields<S: AsRef<[u8]>>(samples: &[S]) -> Vec<IntField> {
    let lens: Vec<usize> = samples.iter().map(|s| s.as_ref().len()).collect();
    let mut findings = Vec::new();
    if samples.len() < 2 {
        return findings;
    }
    let common_len = lens.iter().copied().min().unwrap_or(0);
    let lens_vary = lens.iter().min() != lens.iter().max();
    let scan_end = common_len.min(MAX_HEADER_SCAN);

    for width in INT_WIDTHS {
        if width > common_len {
            continue;
        }
        for offset in 0..=scan_end.saturating_sub(width) {
            for big in [false, true] {
                // Width-one fields are endianness-free; emit them once.
                if width == 1 && big {
                    continue;
                }
                let Some(values) = decode_column(samples, offset, width, big) else {
                    continue;
                };
                let values_vary = values.iter().min() != values.iter().max();
                let field_end = offset + width;

                if lens_vary && values_vary && values_match_lengths(&values, &lens) {
                    findings.push(make_field(
                        offset,
                        width,
                        big,
                        IntRelation::TotalLength,
                        &values,
                    ));
                }
                if values_vary {
                    if let Some(trailing) = derived_length_trailing(&values, &lens, field_end) {
                        findings.push(make_field(
                            offset,
                            width,
                            big,
                            IntRelation::DerivedLength { trailing },
                            &values,
                        ));
                    }
                    if let Some(record_size) = count_record_size(&values, &lens, field_end) {
                        findings.push(make_field(
                            offset,
                            width,
                            big,
                            IntRelation::Count { record_size },
                            &values,
                        ));
                    }
                }
            }
        }
    }
    findings
}

fn make_field(
    offset: usize,
    width: usize,
    big: bool,
    relation: IntRelation,
    values: &[u64],
) -> IntField {
    IntField {
        offset,
        width: width as u8,
        big_endian: big,
        relation,
        values: values.to_vec(),
    }
}

/// Decode the same field in every sample, or `None` if it does not fit one.
fn decode_column<S: AsRef<[u8]>>(
    samples: &[S],
    offset: usize,
    width: usize,
    big: bool,
) -> Option<Vec<u64>> {
    samples
        .iter()
        .map(|sample| read_uint(sample.as_ref(), offset, width, big))
        .collect()
}

fn values_match_lengths(values: &[u64], lens: &[usize]) -> bool {
    values
        .iter()
        .zip(lens)
        .all(|(&value, &len)| value == len as u64)
}

/// The trailing-byte count for which `value + field_end + trailing == len` holds
/// in every sample, if any.
fn derived_length_trailing(values: &[u64], lens: &[usize], field_end: usize) -> Option<usize> {
    TRAILING_CANDIDATES.into_iter().find(|&trailing| {
        values.iter().zip(lens).all(|(&value, &len)| {
            (value as u128) + field_end as u128 + trailing as u128 == len as u128
        })
    })
}

/// The smallest fixed record size for which `value * record_size == len -
/// field_end` holds in every sample, if any.
fn count_record_size(values: &[u64], lens: &[usize], field_end: usize) -> Option<u64> {
    // At least one sample must hold a non-zero count, otherwise every record
    // size trivially "fits" zero records and the relationship is meaningless.
    if values.iter().all(|&value| value == 0) {
        return None;
    }
    (1..=MAX_RECORD_SIZE).find(|&record_size| {
        values.iter().zip(lens).all(|(&value, &len)| {
            let remainder = (len as u128).saturating_sub(field_end as u128);
            (value as u128) * (record_size as u128) == remainder
        })
    })
}

/// A header field that points at an invariant marker further into the sample
/// (FR-9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffsetField {
    /// The pointing field's byte offset.
    pub offset: usize,
    /// The pointing field width in bytes.
    pub width: u8,
    /// Whether the pointing field is big-endian.
    pub big_endian: bool,
    /// The invariant marker byte found at every pointed-to location.
    pub marker: u8,
    /// Each sample's decoded pointer value, in sample order.
    pub values: Vec<u64>,
}

/// Detect header fields that hold an in-bounds offset pointing at an invariant
/// downstream marker byte (FR-9).
///
/// This recognizes a "data offset" or pointer field: in every sample the value
/// lands past the field itself and before the sample's end, the values vary, and
/// the byte at each pointed-to position is the same across samples. The corpus
/// formats do not use pointers, so this commonly returns nothing; it exists so
/// the offset case of FR-9 is covered and tested.
#[must_use]
pub fn detect_offsets<S: AsRef<[u8]>>(samples: &[S]) -> Vec<OffsetField> {
    let lens: Vec<usize> = samples.iter().map(|s| s.as_ref().len()).collect();
    let mut findings = Vec::new();
    if samples.len() < 2 {
        return findings;
    }
    let common_len = lens.iter().copied().min().unwrap_or(0);
    let scan_end = common_len.min(MAX_HEADER_SCAN);

    for width in INT_WIDTHS {
        if width > common_len {
            continue;
        }
        for offset in 0..=scan_end.saturating_sub(width) {
            for big in [false, true] {
                if width == 1 && big {
                    continue;
                }
                let Some(values) = decode_column(samples, offset, width, big) else {
                    continue;
                };
                let field_end = offset + width;
                let values_vary = values.iter().min() != values.iter().max();
                if !values_vary {
                    continue;
                }
                let in_bounds = values.iter().zip(&lens).all(|(&value, &len)| {
                    let target = value as usize;
                    value == target as u64 && target >= field_end && target < len
                });
                if !in_bounds {
                    continue;
                }
                if let Some(marker) = invariant_marker(samples, &values) {
                    findings.push(OffsetField {
                        offset,
                        width: width as u8,
                        big_endian: big,
                        marker,
                        values,
                    });
                }
            }
        }
    }
    findings
}

/// The byte every sample holds at its own pointer position, if they agree.
fn invariant_marker<S: AsRef<[u8]>>(samples: &[S], values: &[u64]) -> Option<u8> {
    let mut marker = None;
    for (sample, &value) in samples.iter().zip(values) {
        let byte = *sample.as_ref().get(value as usize)?;
        match marker {
            None => marker = Some(byte),
            Some(existing) if existing == byte => {}
            Some(_) => return None,
        }
    }
    marker
}

/// Where a checksum's covered range begins (FR-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumStart {
    /// The covered range begins at offset zero (the whole sample before the
    /// checksum).
    SampleStart,
    /// The covered range begins just after the magic signature.
    AfterMagic {
        /// The magic length, where coverage starts.
        offset: usize,
    },
}

/// A trailing checksum field and the range it verifies (FR-10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumField {
    /// The checksum field width in bytes.
    pub width: u8,
    /// Whether the stored checksum is big-endian.
    pub big_endian: bool,
    /// The algorithm that reproduces the stored value.
    pub algorithm: ChecksumAlgorithm,
    /// Where the covered range begins.
    pub start: ChecksumStart,
}

/// Detect a trailing checksum: a field at the end of each sample whose stored
/// value equals a checksum recomputed over a plausible covered range (FR-10).
///
/// Widths four, two, and one are tried with both byte orders. For each, the
/// algorithms appropriate to the width (CRC-32, CRC-16, an additive checksum,
/// and an XOR checksum) are recomputed over the bytes from the sample start, and
/// from just after `magic_len`, up to the checksum field. The most specific
/// match is returned first. A match must hold for every sample.
#[must_use]
pub fn detect_trailing_checksum<S: AsRef<[u8]>>(
    samples: &[S],
    magic_len: usize,
) -> Vec<ChecksumField> {
    let lens: Vec<usize> = samples.iter().map(|s| s.as_ref().len()).collect();
    let mut findings = Vec::new();
    if samples.len() < 2 {
        return findings;
    }

    for width in [4usize, 2, 1] {
        if lens.iter().any(|&len| len < width) {
            continue;
        }
        for big in [false, true] {
            if width == 1 && big {
                continue;
            }
            let stored: Option<Vec<u64>> = samples
                .iter()
                .zip(&lens)
                .map(|(sample, &len)| read_uint(sample.as_ref(), len - width, width, big))
                .collect();
            let Some(stored) = stored else { continue };

            for start in checksum_starts(magic_len) {
                for algorithm in algorithms_for_width(width) {
                    if checksum_holds(samples, &lens, &stored, width, algorithm, start) {
                        findings.push(ChecksumField {
                            width: width as u8,
                            big_endian: big,
                            algorithm,
                            start,
                        });
                    }
                }
            }
        }
    }
    findings
}

fn checksum_starts(magic_len: usize) -> Vec<ChecksumStart> {
    let mut starts = vec![ChecksumStart::SampleStart];
    if magic_len > 0 {
        starts.push(ChecksumStart::AfterMagic { offset: magic_len });
    }
    starts
}

fn algorithms_for_width(width: usize) -> Vec<ChecksumAlgorithm> {
    let mut algorithms = Vec::new();
    if width == 4 {
        algorithms.push(ChecksumAlgorithm::Crc32);
    }
    if width == 2 {
        algorithms.push(ChecksumAlgorithm::Crc16);
    }
    algorithms.push(ChecksumAlgorithm::Additive);
    algorithms.push(ChecksumAlgorithm::Xor);
    algorithms
}

fn checksum_holds<S: AsRef<[u8]>>(
    samples: &[S],
    lens: &[usize],
    stored: &[u64],
    width: usize,
    algorithm: ChecksumAlgorithm,
    start: ChecksumStart,
) -> bool {
    let from = match start {
        ChecksumStart::SampleStart => 0,
        ChecksumStart::AfterMagic { offset } => offset,
    };
    samples
        .iter()
        .zip(lens)
        .zip(stored)
        .all(|((sample, &len), &value)| {
            let to = len - width;
            // A covered range that begins after the checksum field, or an empty
            // range, is not a real checksum here.
            if from >= to {
                return false;
            }
            let data = &sample.as_ref()[from..to];
            checksum::verify(algorithm, data, value, width as u8)
        })
}

/// A sub-byte packed field: a header byte whose bits are partly constant and
/// partly varying across the samples (FR-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bitfield {
    /// The byte offset of the field.
    pub offset: usize,
    /// The bits that are the same in every sample (a one marks a constant bit).
    pub constant_mask: u8,
    /// The value of the constant bits (zero where a bit varies).
    pub constant_value: u8,
    /// The bits that vary across samples (a one marks a varying bit).
    pub varying_mask: u8,
    /// The contiguous runs of varying bits, each `(lsb, width)`, low bit first.
    /// These are the candidate packed sub-fields.
    pub groups: Vec<(u8, u8)>,
}

/// Detect sub-byte packed fields in the header (FR-11), using `bitvec` to track,
/// per bit position, whether a bit ever changes across the samples.
///
/// A byte is reported when some of its bits are constant and some vary, the
/// signature of packed flags or a small packed integer sharing a byte with other
/// data. A byte whose bits are all constant is an ordinary constant, and a byte
/// whose bits all vary is an ordinary integer; neither is a packed field, so
/// neither is reported. The scan covers offsets from `magic_len` up to
/// `header_end` and never assumes a field is byte-aligned.
#[must_use]
pub fn detect_bitfields<S: AsRef<[u8]>>(
    samples: &[S],
    magic_len: usize,
    header_end: usize,
) -> Vec<Bitfield> {
    let mut findings = Vec::new();
    if samples.len() < 2 {
        return findings;
    }
    let common_len = samples.iter().map(|s| s.as_ref().len()).min().unwrap_or(0);
    let end = header_end.min(common_len);

    for offset in magic_len..end {
        let bytes: Vec<u8> = samples.iter().map(|s| s.as_ref()[offset]).collect();
        let Some(first) = bytes.first().copied() else {
            continue;
        };

        // A bit is "varying" once any sample differs from the first sample at
        // that bit position. The eight-bit presence set is held in a bitvec so
        // the sub-byte analysis never falls back to whole-byte reasoning.
        let mut varying: BitVec<u8, Lsb0> = BitVec::repeat(false, 8);
        for &byte in &bytes[1..] {
            let diff = byte ^ first;
            for bit in 0..8usize {
                if (diff >> bit) & 1 == 1 {
                    varying.set(bit, true);
                }
            }
        }

        let varying_mask = mask_from_bits(&varying);
        let constant_mask = !varying_mask;
        // Report only a genuine mix of constant and varying bits.
        if varying_mask == 0 || constant_mask == 0 {
            continue;
        }
        findings.push(Bitfield {
            offset,
            constant_mask,
            constant_value: first & constant_mask,
            varying_mask,
            groups: bit_groups(varying_mask),
        });
    }
    findings
}

fn mask_from_bits(bits: &BitSlice<u8, Lsb0>) -> u8 {
    let mut mask = 0u8;
    for bit in 0..8usize {
        if bits[bit] {
            mask |= 1 << bit;
        }
    }
    mask
}

/// Split a mask into contiguous runs of set bits, each `(lsb, width)`.
fn bit_groups(mask: u8) -> Vec<(u8, u8)> {
    let mut groups = Vec::new();
    let mut bit = 0u8;
    while bit < 8 {
        if (mask >> bit) & 1 == 1 {
            let lsb = bit;
            let mut width = 0u8;
            while bit < 8 && (mask >> bit) & 1 == 1 {
                width += 1;
                bit += 1;
            }
            groups.push((lsb, width));
        } else {
            bit += 1;
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::align::align;

    #[test]
    fn detects_a_magic_prefix() {
        let samples: [&[u8]; 3] = [b"SCMA\x01", b"SCMA\x02", b"SCMA\x07"];
        let alignment = align(&samples);
        let magic = detect_magic(&samples, &alignment).expect("magic");
        assert_eq!(magic.bytes, b"SCMA");
    }

    #[test]
    fn no_magic_without_an_invariant_prefix() {
        let samples: [&[u8]; 2] = [b"abcd", b"wxyz"];
        let alignment = align(&samples);
        assert!(detect_magic(&samples, &alignment).is_none());
    }

    #[test]
    fn detects_a_total_length_field() {
        // magic (4) + u32le total length == sample length + payload.
        let mut a = b"STOT".to_vec();
        a.extend_from_slice(&11u32.to_le_bytes());
        a.extend_from_slice(&[0xDE, 0xAD, 0xBE]);
        let mut b = b"STOT".to_vec();
        b.extend_from_slice(&9u32.to_le_bytes());
        b.push(0x99);
        let samples = [a, b];
        let fields = detect_int_fields(&samples);
        assert!(fields.iter().any(|field| {
            field.offset == 4
                && field.width == 4
                && !field.big_endian
                && field.relation == IntRelation::TotalLength
        }));
    }

    #[test]
    fn detects_a_count_field_and_record_size() {
        // magic (4) + u8 count + count records of four bytes each.
        let make = |count: u8| {
            let mut data = b"SCMA".to_vec();
            data.push(count);
            for index in 0..count {
                data.extend_from_slice(&[index, index, 0, 0]);
            }
            data
        };
        let samples = [make(1), make(3), make(2)];
        let fields = detect_int_fields(&samples);
        let found = fields.iter().find(|field| {
            matches!(field.relation, IntRelation::Count { record_size: 4 }) && field.offset == 4
        });
        assert!(found.is_some(), "count field not detected: {fields:?}");
    }

    #[test]
    fn detects_a_derived_length_with_trailing_checksum_space() {
        // magic (4) + u16le payload length + payload + 4 trailing bytes.
        let make = |payload: &[u8]| {
            let mut data = b"SDLP".to_vec();
            data.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            data.extend_from_slice(payload);
            data.extend_from_slice(&[0; 4]);
            data
        };
        let samples = [make(&[1, 2, 3]), make(&[9; 7]), make(&[4])];
        let fields = detect_int_fields(&samples);
        assert!(fields.iter().any(|field| {
            field.offset == 4 && field.relation == IntRelation::DerivedLength { trailing: 4 }
        }));
    }

    #[test]
    fn detects_a_trailing_crc32() {
        // Build SDLP-like samples with a real CRC-32 over everything before it.
        let make = |payload: &[u8]| {
            let mut data = b"SDLP".to_vec();
            data.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            data.extend_from_slice(payload);
            let crc = checksum::crc32(&data);
            data.extend_from_slice(&crc.to_le_bytes());
            data
        };
        let samples = [make(&[1, 2, 3, 4, 5]), make(&[7; 9]), make(&[0xAB])];
        let found = detect_trailing_checksum(&samples, 4);
        assert!(
            found.iter().any(|c| c.algorithm == ChecksumAlgorithm::Crc32
                && c.width == 4
                && !c.big_endian
                && c.start == ChecksumStart::SampleStart),
            "crc32 not detected: {found:?}"
        );
    }

    #[test]
    fn detects_a_packed_flags_byte() {
        // Offset 4 byte: high five bits constant 0b10100, low three bits vary.
        let make = |low: u8| vec![b'S', b'C', b'M', b'A', 0xA0 | (low & 0x07)];
        let samples = [make(1), make(5), make(2), make(0)];
        let fields = detect_bitfields(&samples, 4, 5);
        let field = fields.iter().find(|f| f.offset == 4).expect("bitfield");
        assert_eq!(field.constant_mask, 0xF8);
        assert_eq!(field.constant_value, 0xA0);
        assert_eq!(field.varying_mask, 0x07);
        assert_eq!(field.groups, vec![(0, 3)]);
    }

    #[test]
    fn all_varying_byte_is_not_a_bitfield() {
        let samples = [vec![0u8], vec![0xFFu8], vec![0x0Fu8]];
        // Whole byte varies across samples: an ordinary integer, not packed.
        assert!(detect_bitfields(&samples, 0, 1).is_empty());
    }

    #[test]
    fn detects_an_offset_pointer_to_an_invariant_marker() {
        // magic (2) + u16le offset pointing at a 0x5A marker byte.
        let make = |filler: usize| {
            let mut data = b"PT".to_vec();
            let target = 4 + filler; // after the 2-byte magic and 2-byte offset
            data.extend_from_slice(&(target as u16).to_le_bytes());
            data.extend(std::iter::repeat_n(0u8, filler));
            data.push(0x5A);
            data
        };
        let samples = [make(1), make(3), make(2)];
        let found = detect_offsets(&samples);
        assert!(
            found.iter().any(|o| o.offset == 2 && o.marker == 0x5A),
            "offset pointer not detected: {found:?}"
        );
    }
}
