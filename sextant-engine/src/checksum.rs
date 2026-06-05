//! Native checksum algorithms for the verification substrate (FR-10, FR-17).
//!
//! The executor and scorer verify checksum constraints by recomputing a
//! checksum over the covered byte range and comparing it to the value stored in
//! the checksum field. This module implements the minimum algorithm set Sextant
//! must support: CRC-32, CRC-16, an additive checksum, and a bytewise XOR
//! checksum. Every algorithm is implemented in safe Rust with no external
//! dependency, so it runs offline and under `--no-llm` (FR-21).
//!
//! # Algorithm definitions
//!
//! - [`ChecksumAlgorithm::Crc32`] is CRC-32/ISO-HDLC: the reflected polynomial
//!   `0xEDB88320`, initial value `0xFFFFFFFF`, and a final XOR of `0xFFFFFFFF`.
//!   This is the CRC used by PNG and zlib, so a PNG chunk CRC verifies exactly.
//! - [`ChecksumAlgorithm::Crc16`] is CRC-16/ARC: the reflected polynomial
//!   `0xA001`, initial value `0x0000`, and no final XOR. This is the most common
//!   plain "CRC-16". Other CRC-16 variants can be added later without changing
//!   the IR, since the algorithm is named in the IR rather than hard-coded here.
//! - [`ChecksumAlgorithm::Additive`] is the sum of every covered byte, reduced
//!   modulo two to the power of eight times the field width.
//! - [`ChecksumAlgorithm::Xor`] folds every covered byte together with XOR into
//!   a single byte, then zero-extends to the field width.

use sextant_ir::ChecksumAlgorithm;

/// The CRC-32/ISO-HDLC lookup table (reflected polynomial `0xEDB88320`).
///
/// Built once at compile time so verification stays fast on large samples.
static CRC32_TABLE: [u32; 256] = build_crc32_table();

/// The CRC-16/ARC lookup table (reflected polynomial `0xA001`).
static CRC16_TABLE: [u16; 256] = build_crc16_table();

const fn build_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0usize;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
}

const fn build_crc16_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut index = 0usize;
    while index < 256 {
        let mut crc = index as u16;
        let mut bit = 0;
        while bit < 8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
}

/// Compute the CRC-32/ISO-HDLC checksum of `data` (the PNG and zlib CRC).
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[index];
    }
    crc ^ 0xFFFF_FFFF
}

/// Compute the CRC-16/ARC checksum of `data`.
#[must_use]
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in data {
        let index = ((crc ^ u16::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC16_TABLE[index];
    }
    crc
}

/// Compute the additive checksum of `data`: the sum of every byte, reduced
/// modulo two to the power of eight times `width` bytes.
///
/// A `width` of zero or eight or more is treated as a full 64-bit sum, which
/// cannot overflow because each byte adds at most 255 and the count of bytes is
/// bounded by the sample length.
#[must_use]
pub fn additive(data: &[u8], width: u8) -> u64 {
    let sum = data
        .iter()
        .fold(0u64, |acc, &byte| acc.wrapping_add(u64::from(byte)));
    mask_to_width(sum, width)
}

/// Compute the bytewise XOR checksum of `data`: every byte folded together with
/// XOR. The result is a single byte, zero-extended to a `u64`.
#[must_use]
pub fn xor(data: &[u8]) -> u64 {
    u64::from(data.iter().fold(0u8, |acc, &byte| acc ^ byte))
}

/// Compute the checksum named by `algorithm` over `data`, returning the result
/// reduced to `width` bytes so it can be compared against a stored field value.
#[must_use]
pub fn compute(algorithm: ChecksumAlgorithm, data: &[u8], width: u8) -> u64 {
    let raw = match algorithm {
        ChecksumAlgorithm::Crc32 => u64::from(crc32(data)),
        ChecksumAlgorithm::Crc16 => u64::from(crc16(data)),
        ChecksumAlgorithm::Additive => additive(data, width),
        ChecksumAlgorithm::Xor => xor(data),
    };
    mask_to_width(raw, width)
}

/// Whether the checksum named by `algorithm` over `data` matches `stored`, both
/// compared at the given field `width` so a wider stored field does not reject a
/// narrower natural checksum result.
#[must_use]
pub fn verify(algorithm: ChecksumAlgorithm, data: &[u8], stored: u64, width: u8) -> bool {
    compute(algorithm, data, width) == mask_to_width(stored, width)
}

/// Reduce `value` to its low `width` bytes. A `width` of zero or eight or more
/// keeps the full 64-bit value.
fn mask_to_width(value: u64, width: u8) -> u64 {
    if width == 0 || width >= 8 {
        value
    } else {
        let bits = u32::from(width) * 8;
        value & ((1u64 << bits) - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_standard_check_value() {
        // The canonical CRC-32 check value for the ASCII string "123456789".
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn crc32_of_iend_is_the_known_png_constant() {
        // Every PNG IEND chunk carries this CRC over the four type bytes and an
        // empty data field, so this constant pins the PNG CRC behaviour.
        assert_eq!(crc32(b"IEND"), 0xAE42_6082);
    }

    #[test]
    fn crc32_of_empty_is_zero() {
        assert_eq!(crc32(b""), 0x0000_0000);
    }

    #[test]
    fn crc16_matches_the_standard_arc_check_value() {
        // The canonical CRC-16/ARC check value for "123456789".
        assert_eq!(crc16(b"123456789"), 0xBB3D);
    }

    #[test]
    fn additive_sums_bytes_and_masks_to_width() {
        assert_eq!(additive(&[0x01, 0x02, 0x03], 1), 0x06);
        // 0xFF + 0xFF = 0x1FE; a one-byte additive checksum keeps 0xFE.
        assert_eq!(additive(&[0xFF, 0xFF], 1), 0xFE);
        // A two-byte additive checksum keeps the full sum.
        assert_eq!(additive(&[0xFF, 0xFF], 2), 0x01FE);
    }

    #[test]
    fn xor_folds_every_byte() {
        assert_eq!(xor(&[0x0F, 0xF0]), 0xFF);
        assert_eq!(xor(&[0xAA, 0xAA]), 0x00);
        assert_eq!(xor(b""), 0x00);
    }

    #[test]
    fn verify_compares_at_the_field_width() {
        let data = b"IEND";
        assert!(verify(ChecksumAlgorithm::Crc32, data, 0xAE42_6082, 4));
        assert!(!verify(ChecksumAlgorithm::Crc32, data, 0x0000_0000, 4));
        // A wider stored value with extra high bytes still matches at width 4.
        assert!(verify(
            ChecksumAlgorithm::Crc32,
            data,
            0xFFFF_FFFF_AE42_6082,
            4
        ));
    }

    #[test]
    fn compute_dispatches_each_algorithm() {
        assert_eq!(compute(ChecksumAlgorithm::Crc32, b"IEND", 4), 0xAE42_6082);
        assert_eq!(compute(ChecksumAlgorithm::Crc16, b"123456789", 2), 0xBB3D);
        assert_eq!(compute(ChecksumAlgorithm::Additive, &[1, 2, 3], 1), 6);
        assert_eq!(compute(ChecksumAlgorithm::Xor, &[0x0F, 0xF0], 1), 0xFF);
    }
}
