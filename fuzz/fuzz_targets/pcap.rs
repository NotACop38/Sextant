#![no_main]
//! Fuzz target: feed arbitrary bytes to the capture reader and protocol pass
//! (FR-2, FR-24, NFR-2).
//!
//! Captures are untrusted input, so the pcap and pcapng reader, the message
//! clustering, and the protocol inference must never panic, hang, or allocate
//! without bound on any bytes. This target reads the input as a capture on a
//! port taken from the first bytes, then, when any messages come out, runs the
//! full protocol pass under tight, deterministic limits and checks that the
//! chosen IR executes on every extracted message without overrunning. libFuzzer
//! drives the byte stream; any panic, abort, or out-of-memory is a finding. The
//! in-tree tests in `sextant-engine/src/pcap.rs` and `tests/protocol.rs` assert
//! the same invariants on stable.

use libfuzzer_sys::fuzz_target;
use sextant_engine::{
    execute, extract_messages, infer_protocol, ExtractOptions, Limits, Transport,
};

fuzz_target!(|data: &[u8]| {
    // Derive the selector from the first bytes so the fuzzer can explore both
    // transports and many ports; the rest is parsed as the capture.
    let transport = if data.first().is_some_and(|b| b & 1 == 0) {
        Transport::Tcp
    } else {
        Transport::Udp
    };
    let port = match data.get(1..3) {
        Some(bytes) => u16::from_le_bytes([bytes[0], bytes[1]]),
        None => 0,
    };
    let options = ExtractOptions { transport, port };

    let Ok(messages) = extract_messages(data, &options) else {
        return;
    };
    if messages.is_empty() {
        return;
    }

    let limits = Limits::for_fuzzing();
    let inference = infer_protocol(&messages, transport, port, &limits);
    // The chosen IR must be valid and must execute on every message without a
    // leaf overrun (FR-24).
    assert!(inference.report.format.validate().is_ok());
    for message in &messages {
        let execution = execute(&inference.report.format, &message.data, &limits);
        for &(start, end) in &execution.leaf_ranges {
            assert!(start <= end && end <= message.data.len());
        }
    }
    assert!(inference.report.score.overall.is_finite());
    assert!((0.0..=1.0).contains(&inference.report.score.overall));
});
