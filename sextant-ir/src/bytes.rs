//! A byte string serialized as lowercase hexadecimal.
//!
//! Magic constants and delimiters are stored as raw bytes but written to JSON
//! as a hex string so the IR stays readable and hand-authorable (FR-19). The
//! codec is implemented here in safe Rust with no extra dependency.

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A sequence of raw bytes that serializes to and from a lowercase hex string.
///
/// An empty value serializes to an empty string. Decoding rejects an odd-length
/// string or any non-hexadecimal character.
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    /// Create a [`Bytes`] from anything that converts into a byte vector.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// The bytes as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// The number of bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Encode the bytes as a lowercase hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }

    /// Decode a lowercase or uppercase hex string into [`Bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`HexError`] when the string has an odd length or contains a
    /// character that is not a hexadecimal digit.
    pub fn from_hex(text: &str) -> Result<Self, HexError> {
        decode_hex(text).map(Self)
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for Bytes {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

/// An error decoding a hex string into [`Bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    /// The string has an odd number of characters, so it cannot pair into
    /// bytes.
    OddLength {
        /// The offending length.
        length: usize,
    },
    /// A character at the given index is not a hexadecimal digit.
    InvalidChar {
        /// The zero-based index of the bad character.
        index: usize,
        /// The bad character.
        ch: char,
    },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HexError::OddLength { length } => {
                write!(f, "hex string has an odd length of {length} characters")
            }
            HexError::InvalidChar { index, ch } => {
                write!(f, "invalid hex character {ch:?} at index {index}")
            }
        }
    }
}

impl std::error::Error for HexError {}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn decode_hex(text: &str) -> Result<Vec<u8>, HexError> {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() % 2 != 0 {
        return Err(HexError::OddLength {
            length: chars.len(),
        });
    }
    let mut out = Vec::with_capacity(chars.len() / 2);
    for (pair_index, pair) in chars.chunks_exact(2).enumerate() {
        let index = pair_index * 2;
        let hi = hex_value(pair[0], index)?;
        let lo = hex_value(pair[1], index + 1)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_value(ch: char, index: usize) -> Result<u8, HexError> {
    ch.to_digit(16)
        .map(|value| value as u8)
        .ok_or(HexError::InvalidChar { index, ch })
}

impl Serialize for Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HexVisitor;

        impl Visitor<'_> for HexVisitor {
            type Value = Bytes;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a lowercase or uppercase hexadecimal string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                decode_hex(value).map(Bytes).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(HexVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let original = Bytes::new(vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
        let hex = original.to_hex();
        assert_eq!(hex, "89504e470d0a1a0a");
        assert_eq!(Bytes::from_hex(&hex).expect("decode"), original);
    }

    #[test]
    fn serde_round_trip_through_json() {
        let original = Bytes::new(b"STLV".to_vec());
        let json = serde_json::to_string(&original).expect("serialize");
        assert_eq!(json, "\"53544c56\"");
        let back: Bytes = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, original);
    }

    #[test]
    fn empty_bytes_is_an_empty_string() {
        let json = serde_json::to_string(&Bytes::default()).expect("serialize");
        assert_eq!(json, "\"\"");
        let back: Bytes = serde_json::from_str("\"\"").expect("deserialize");
        assert!(back.is_empty());
    }

    #[test]
    fn odd_length_is_rejected() {
        assert_eq!(
            Bytes::from_hex("abc"),
            Err(HexError::OddLength { length: 3 })
        );
    }

    #[test]
    fn invalid_character_is_rejected_with_its_index() {
        let err = serde_json::from_str::<Bytes>("\"00zz\"").expect_err("must reject");
        assert!(err.to_string().contains("invalid hex character"));
    }

    #[test]
    fn direct_hex_decode_reports_the_actual_invalid_index() {
        assert_eq!(
            Bytes::from_hex("00zz"),
            Err(HexError::InvalidChar { index: 2, ch: 'z' })
        );
    }

    #[test]
    fn uppercase_hex_decodes() {
        assert_eq!(
            Bytes::from_hex("DEADBEEF").expect("decode"),
            Bytes::new(vec![0xde, 0xad, 0xbe, 0xef])
        );
    }
}
