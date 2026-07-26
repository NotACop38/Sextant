//! Malformed-capture tests for the pcap reader (FR-2, NFR-2).
//!
//! The nightly fuzz target covers the same surface with coverage-guided
//! search; these deterministic cases pin the behavior on the classic
//! truncation and framing mistakes so a regression fails fast, on stable, in
//! every CI run.

use sextant_engine::{ExtractOptions, PcapError, Transport, extract_messages};

const OPTIONS: ExtractOptions = ExtractOptions::new(Transport::Tcp, 502);

/// A classic little-endian pcap global header (24 bytes) with the Ethernet
/// link type.
fn classic_header() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes()); // major
    bytes.extend_from_slice(&4u16.to_le_bytes()); // minor
    bytes.extend_from_slice(&0u32.to_le_bytes()); // thiszone
    bytes.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    bytes.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    bytes.extend_from_slice(&1u32.to_le_bytes()); // linktype: Ethernet
    bytes
}

#[test]
fn empty_input_is_an_unknown_format() {
    assert_eq!(
        extract_messages(&[], &OPTIONS),
        Err(PcapError::UnknownFormat)
    );
}

#[test]
fn input_shorter_than_a_magic_is_an_unknown_format() {
    assert_eq!(
        extract_messages(&[0xa1, 0xb2], &OPTIONS),
        Err(PcapError::UnknownFormat)
    );
}

#[test]
fn garbage_magic_is_an_unknown_format() {
    assert_eq!(
        extract_messages(b"GIF89a, definitely not a capture", &OPTIONS),
        Err(PcapError::UnknownFormat)
    );
}

#[test]
fn classic_magic_with_a_truncated_global_header_is_truncated() {
    let bytes = &classic_header()[..12];
    assert_eq!(
        extract_messages(bytes, &OPTIONS),
        Err(PcapError::Truncated { offset: 12 })
    );
}

#[test]
fn header_only_capture_yields_no_messages() {
    let messages = extract_messages(&classic_header(), &OPTIONS).expect("an empty capture reads");
    assert!(messages.is_empty());
}

#[test]
fn truncated_record_header_yields_the_complete_records_only() {
    // A record header is 16 bytes; eight trailing garbage bytes are an
    // incomplete header and must be ignored, not parsed or panicked on.
    let mut bytes = classic_header();
    bytes.extend_from_slice(&[0u8; 8]);
    let messages = extract_messages(&bytes, &OPTIONS).expect("a cut capture reads");
    assert!(messages.is_empty());
}

#[test]
fn record_declaring_more_bytes_than_remain_stops_cleanly() {
    let mut bytes = classic_header();
    bytes.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
    bytes.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    bytes.extend_from_slice(&4096u32.to_le_bytes()); // incl_len: way past the end
    bytes.extend_from_slice(&4096u32.to_le_bytes()); // orig_len
    bytes.extend_from_slice(&[0xAA; 10]); // only ten bytes actually present
    let messages = extract_messages(&bytes, &OPTIONS).expect("a cut record reads");
    assert!(messages.is_empty());
}

#[test]
fn record_declaring_the_maximum_length_does_not_allocate_or_panic() {
    let mut bytes = classic_header();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // incl_len: 4 GiB
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    let messages = extract_messages(&bytes, &OPTIONS).expect("an absurd record reads");
    assert!(messages.is_empty());
}

#[test]
fn pcapng_with_a_truncated_section_header_errors_cleanly() {
    // The pcapng Section Header Block type alone, with no length or byte-order
    // magic behind it.
    let bytes = 0x0a0d_0d0au32.to_be_bytes();
    let result = extract_messages(&bytes, &OPTIONS);
    assert!(result.is_err(), "got {result:?}");
}

#[test]
fn every_prefix_of_a_real_capture_reads_or_fails_cleanly() {
    // Truncating a valid capture at every byte is the classic source of
    // out-of-bounds reads in frame parsers. Every prefix must produce either
    // a clean message list or a clean error.
    let capture = include_bytes!("../../corpus/modbus/samples/session_01.pcap");
    for end in 0..=capture.len() {
        let _ = extract_messages(&capture[..end], &OPTIONS);
    }
}

#[test]
fn flipping_each_header_byte_of_a_real_capture_never_panics() {
    let capture = include_bytes!("../../corpus/modbus/samples/session_01.pcap");
    let scan = capture.len().min(128);
    for index in 0..scan {
        let mut copy = capture.to_vec();
        copy[index] ^= 0xFF;
        let _ = extract_messages(&copy, &OPTIONS);
    }
}
