//! End-to-end protocol inference over the corpus captures (Step 11, FR-2).
//!
//! These tests read the committed Modbus/TCP and toy protocol captures, extract
//! the transport payloads, and run the protocol inference pipeline. They cover
//! the Step 11 acceptance criteria: a field map is produced for each capture,
//! message clustering separates the toy protocol's message types, and the chosen
//! IR parses every message cleanly (generality 1.0), which is what the generated
//! Wireshark dissector, a faithful translation of that IR, decodes.

use std::path::PathBuf;

use sextant_engine::{
    ExtractOptions, Limits, Transport, cluster_messages, extract_messages, infer_protocol,
};
use sextant_ir::Role;

/// Read a committed capture file from the corpus.
fn read_capture(format: &str, name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("engine crate has a parent")
        .join("corpus")
        .join(format)
        .join("samples")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// Extract the messages for a capture on the given transport and port.
fn extract(
    format: &str,
    name: &str,
    transport: Transport,
    port: u16,
) -> Vec<sextant_engine::ExtractedMessage> {
    let bytes = read_capture(format, name);
    extract_messages(&bytes, &ExtractOptions::new(transport, port)).expect("parse capture")
}

#[test]
fn modbus_capture_yields_protocol_field_map() {
    let messages = extract("modbus", "session_01.pcap", Transport::Tcp, 502);
    assert!(!messages.is_empty(), "no Modbus messages were extracted");

    let inference = infer_protocol(&messages, Transport::Tcp, 502, &Limits::default());
    // The IR parses every message to a clean end, which is what the exported
    // dissector decodes (FR-2 acceptance: the dissector decodes the capture).
    assert_eq!(
        inference.report.score.generality, 1.0,
        "not every Modbus message parsed: {:?}",
        inference.report.score
    );
    assert!(
        inference.report.score.overall >= 0.9,
        "weak Modbus fit: {}",
        inference.report.score.overall
    );

    let roles: Vec<Role> = inference
        .report
        .format
        .root
        .fields
        .iter()
        .filter_map(|field| field.role)
        .collect();
    assert!(roles.contains(&Role::Length), "no length field: {roles:?}");
    assert!(
        roles.contains(&Role::MessageType),
        "no message-type field (function code): {roles:?}"
    );
    assert!(
        roles.contains(&Role::Sequence),
        "no sequence field (transaction id): {roles:?}"
    );

    // The message type lands on the Modbus function code at byte offset 7.
    let discriminant = inference
        .clustering
        .discriminant
        .expect("a message-type discriminant");
    assert_eq!(discriminant.offset, 7, "function code is at MBAP offset 7");

    // Requests and responses are paired: one response per request.
    assert!(
        !inference.associations.is_empty(),
        "no request/response pairs were associated"
    );
}

#[test]
fn toy_capture_clusters_message_types() {
    let messages = extract("toy", "session_01.pcap", Transport::Tcp, 9000);
    assert!(!messages.is_empty(), "no toy messages were extracted");

    // Clustering separates the three distinct message types (PING, DATA, BYE).
    let clustering = cluster_messages(&messages);
    assert!(
        clustering.clusters.len() >= 2,
        "clustering did not separate message types: {} cluster(s)",
        clustering.clusters.len()
    );
    let discriminant = clustering
        .discriminant
        .as_ref()
        .expect("a message-type discriminant");
    assert_eq!(discriminant.offset, 0, "the toy type byte is at offset 0");
    assert_eq!(
        discriminant.values,
        vec![1, 2, 3],
        "the three toy message types are 1, 2, and 3"
    );

    let inference = infer_protocol(&messages, Transport::Tcp, 9000, &Limits::default());
    assert_eq!(
        inference.report.score.generality, 1.0,
        "not every toy message parsed: {:?}",
        inference.report.score
    );
    let roles: Vec<Role> = inference
        .report
        .format
        .root
        .fields
        .iter()
        .filter_map(|field| field.role)
        .collect();
    assert!(
        roles.contains(&Role::MessageType),
        "no message type: {roles:?}"
    );
    assert!(roles.contains(&Role::Sequence), "no sequence: {roles:?}");
    assert!(roles.contains(&Role::Length), "no length: {roles:?}");
}

#[test]
fn udp_selector_finds_nothing_in_a_tcp_capture() {
    // The captures are TCP; asking for UDP yields no messages, not an error.
    let bytes = read_capture("toy", "session_01.pcap");
    let messages = extract_messages(&bytes, &ExtractOptions::new(Transport::Udp, 9000))
        .expect("parse capture");
    assert!(messages.is_empty());
}
