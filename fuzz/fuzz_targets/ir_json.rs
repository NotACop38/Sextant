#![no_main]
//! Fuzz target: deserialize untrusted JSON as a Format Hypothesis IR and as a
//! report (FR-19, NFR-2).
//!
//! `inspect` and `export` read report JSON that the user may have hand-edited,
//! and the IR's own JSON form is a documented interchange format, so both
//! deserializers face hostile input directly. Neither may panic on any text.
//! When a Format does parse, validation must also be panic-free, and the value
//! must survive a serialize and reparse round trip unchanged (FR-19).

use libfuzzer_sys::fuzz_target;
use sextant_engine::Report;
use sextant_ir::Format;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(format) = Format::from_json(text) {
        let _ = format.validate();
        let json = format
            .to_json()
            .expect("a deserialized Format always serializes");
        let again = Format::from_json(&json).expect("a serialized Format always reparses");
        assert_eq!(format, again, "Format JSON round trip must be lossless");
    }
    let _ = Report::from_json(text);
});
