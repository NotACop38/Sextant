//! Exporters for Sextant (FR-36 to FR-38).
//!
//! This crate turns a verified Format Hypothesis IR into an editable parser in
//! one of four target formats:
//!
//! - Kaitai Struct (`.ksy`), the primary export and the cross-validation target
//!   (FR-36);
//! - ImHex pattern (`.hexpat`), Wireshark Lua dissector (`.lua`), and 010 Editor
//!   binary template (`.bt`) (FR-37).
//!
//! Exporters read the [`Format`] only; they never re-run inference, never reach
//! the network, and never bypass the IR. They are deterministic: the same IR
//! always produces byte-identical output.
//!
//! ```
//! use sextant_export::{export, ExportFormat};
//!
//! let format = sextant_ir::fixtures::tlv_ground_truth();
//! let ksy = export(&format, ExportFormat::Kaitai).expect("export tlv");
//! assert!(ksy.contains("meta:"));
//! ```
//!
//! # Optional Kaitai cross-validation (FR-38)
//!
//! [`crossval::cross_validate`] compiles the generated `.ksy` with the Kaitai
//! compiler and parses every sample through it as an independent check. It is an
//! optional cross-check, reported separately, and is never invoked by the core
//! inference pipeline. When the compiler or its runtime is absent it reports
//! [`crossval::CrossValidation::Skipped`] rather than failing.

#![forbid(unsafe_code)]

mod bt;
pub mod crossval;
mod imhex;
mod kaitai;
mod naming;
mod wireshark;

use std::fmt;

use sextant_ir::{Bytes, Endianness, Format, Signedness};

/// A target parser format an IR can be exported to (FR-36, FR-37).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// Kaitai Struct specification (`.ksy`), the primary export (FR-36).
    Kaitai,
    /// ImHex pattern (`.hexpat`) (FR-37).
    ImHex,
    /// Wireshark Lua dissector (`.lua`) (FR-37).
    Wireshark,
    /// 010 Editor binary template (`.bt`) (FR-37).
    Bt,
}

impl ExportFormat {
    /// Every supported format, in a stable order.
    pub const ALL: [ExportFormat; 4] = [
        ExportFormat::Kaitai,
        ExportFormat::ImHex,
        ExportFormat::Wireshark,
        ExportFormat::Bt,
    ];

    /// Parse the format selector accepted on the command line.
    ///
    /// Accepts the names used in the PRD CLI specification (Section 14):
    /// `kaitai`, `imhex`, `wireshark`, and `010`. Matching is case-insensitive
    /// and a few common aliases are allowed.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "kaitai" | "ksy" | "kaitai-struct" => Some(ExportFormat::Kaitai),
            "imhex" | "hexpat" | "pattern" => Some(ExportFormat::ImHex),
            "wireshark" | "lua" | "dissector" => Some(ExportFormat::Wireshark),
            "010" | "bt" | "010editor" | "010-editor" => Some(ExportFormat::Bt),
            _ => None,
        }
    }

    /// The canonical selector name for this format.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ExportFormat::Kaitai => "kaitai",
            ExportFormat::ImHex => "imhex",
            ExportFormat::Wireshark => "wireshark",
            ExportFormat::Bt => "010",
        }
    }

    /// The conventional file extension for this format, without the dot.
    #[must_use]
    pub fn extension(self) -> &'static str {
        match self {
            ExportFormat::Kaitai => "ksy",
            ExportFormat::ImHex => "hexpat",
            ExportFormat::Wireshark => "lua",
            ExportFormat::Bt => "bt",
        }
    }
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// An error produced while exporting an IR.
///
/// Exporters are best-effort and degrade gracefully (an unrepresentable
/// construct is emitted as a comment rather than failing), so this is reserved
/// for the rare case where the IR cannot be rendered at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError {
    /// The IR uses a construct the target format cannot represent.
    Unsupported {
        /// The target format.
        format: ExportFormat,
        /// What could not be represented.
        detail: String,
    },
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExportError::Unsupported { format, detail } => {
                write!(f, "cannot export to {format}: {detail}")
            }
        }
    }
}

impl std::error::Error for ExportError {}

/// Export `format` to the given target as a single source string (FR-36, FR-37).
///
/// The output is the complete parser file (a `.ksy`, `.hexpat`, `.lua`, or
/// `.bt`). It is deterministic and never performs any I/O.
///
/// # Errors
///
/// Returns [`ExportError`] only when the IR uses a construct the target cannot
/// represent at all; ordinary fields always export.
pub fn export(format: &Format, target: ExportFormat) -> Result<String, ExportError> {
    match target {
        ExportFormat::Kaitai => Ok(kaitai::export(format)),
        ExportFormat::ImHex => Ok(imhex::export(format)),
        ExportFormat::Wireshark => Ok(wireshark::export(format)),
        ExportFormat::Bt => Ok(bt::export(format)),
    }
}

/// Decode a constant byte sequence as an unsigned integer of `width` bytes in
/// `order`. Used to render an integer field's magic or version constant as a
/// numeric literal. Bytes beyond eight are ignored so the shift cannot overflow.
#[must_use]
pub(crate) fn const_as_u64(value: &Bytes, width: u8, order: Endianness) -> u64 {
    let bytes = value.as_slice();
    let bytes = if bytes.len() > 8 { &bytes[..8] } else { bytes };
    let take = bytes.len().min(usize::from(width.max(1)));
    let bytes = &bytes[..take.min(bytes.len())];
    let mut acc: u64 = 0;
    match order {
        Endianness::Big => {
            for &byte in bytes {
                acc = (acc << 8) | u64::from(byte);
            }
        }
        Endianness::Little => {
            for (index, &byte) in bytes.iter().enumerate() {
                acc |= u64::from(byte) << (8 * index);
            }
        }
    }
    acc
}

/// The sign prefix letter an integer width uses in Kaitai and similar targets.
#[must_use]
pub(crate) fn sign_letter(signed: Signedness) -> char {
    match signed {
        Signedness::Unsigned => 'u',
        Signedness::Signed => 's',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_selector_round_trips() {
        for target in ExportFormat::ALL {
            let parsed = ExportFormat::parse(target.name()).expect("name parses");
            assert_eq!(parsed, target);
        }
    }

    #[test]
    fn format_selector_accepts_aliases_case_insensitively() {
        assert_eq!(ExportFormat::parse("KAITAI"), Some(ExportFormat::Kaitai));
        assert_eq!(ExportFormat::parse("hexpat"), Some(ExportFormat::ImHex));
        assert_eq!(ExportFormat::parse("lua"), Some(ExportFormat::Wireshark));
        assert_eq!(ExportFormat::parse("bt"), Some(ExportFormat::Bt));
        assert_eq!(ExportFormat::parse("nope"), None);
    }

    #[test]
    fn const_decodes_in_both_orders() {
        let bytes = Bytes::new(vec![0x01, 0x00]);
        assert_eq!(const_as_u64(&bytes, 2, Endianness::Little), 1);
        assert_eq!(const_as_u64(&bytes, 2, Endianness::Big), 0x0100);
    }
}
