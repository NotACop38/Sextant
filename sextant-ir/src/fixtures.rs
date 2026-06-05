//! Hand-authored ground-truth IR fixtures.
//!
//! These are committed Format Hypothesis IRs that later steps reuse: Step 3
//! executes them against corpus samples and expects a near-perfect score, and
//! the exporters round-trip them. Authoring them by hand proves the IR can
//! represent a real format (Step 2 acceptance) before any inference exists.

use crate::Format;

/// The hand-authored ground-truth IR for PNG, the file-format showcase
/// (PRD Section 15), as JSON.
///
/// PNG exercises a magic signature, big-endian length-prefixed chunks, a
/// repeated chunk array, and a CRC-32 over each chunk's type and data.
pub const PNG_GROUND_TRUTH_JSON: &str = include_str!("../fixtures/png.json");

/// Parse the hand-authored PNG ground-truth IR.
///
/// # Panics
///
/// Panics if the embedded fixture is not valid IR JSON. This cannot happen for
/// the committed fixture and is covered by a test in this crate.
#[must_use]
pub fn png_ground_truth() -> Format {
    Format::from_json(PNG_GROUND_TRUTH_JSON)
        .expect("the committed PNG fixture must be valid IR JSON")
}

/// The hand-authored ground-truth IR for the custom TLV container (the seed
/// corpus format), as JSON.
///
/// TLV exercises a magic signature, a constant version byte, a record count, and
/// an array of records whose count comes from the count field and whose value
/// size is derived from a per-record length field. It has no checksum, so it
/// complements PNG in the executor and scorer tests.
pub const TLV_GROUND_TRUTH_JSON: &str = include_str!("../fixtures/tlv.json");

/// Parse the hand-authored TLV ground-truth IR.
///
/// # Panics
///
/// Panics if the embedded fixture is not valid IR JSON. This cannot happen for
/// the committed fixture and is covered by a test in this crate.
#[must_use]
pub fn tlv_ground_truth() -> Format {
    Format::from_json(TLV_GROUND_TRUTH_JSON)
        .expect("the committed TLV fixture must be valid IR JSON")
}
