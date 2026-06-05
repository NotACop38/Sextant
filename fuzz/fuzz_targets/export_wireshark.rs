#![no_main]
//! Fuzz target: feed an arbitrary Format Hypothesis IR to the Wireshark exporter
//! (FR-37, NFR-2).
//!
//! Exporters read untrusted, machine-generated IR, so they must never panic on
//! any hypothesis. This target builds an arbitrary [`Format`] (including hostile
//! field names, unusual widths, dangling references, and oversized sizes) and
//! exports it to a Wireshark Lua dissector under libFuzzer's coverage-guided
//! search. Any panic is a finding. Export is deterministic, so the same IR is
//! exported twice and the outputs must match.

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use sextant_export::{export, ExportFormat};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(format) = sextant_fuzz::arbitrary_format(&mut u) else {
        return;
    };
    if let Ok(output) = export(&format, ExportFormat::Wireshark) {
        let again = export(&format, ExportFormat::Wireshark).expect("re-export is infallible");
        assert_eq!(output, again, "Wireshark export is not deterministic");
    }
});
