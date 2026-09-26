//! End-to-end protocol inference over the corpus captures (Step 11, FR-2).
//!
//! These tests read the committed Modbus/TCP and toy protocol captures, extract
//! the transport payloads, and run the protocol inference pipeline. They cover
//! the Step 11 acceptance criteria: a field map is produced for each capture,
//! message clustering separates the toy protocol's message types, and the chosen
//! IR parses every message cleanly (generality 1.0), which is what the generated
//! Wireshark dissector, a faithful translation of that IR, decodes.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use sextant_engine::protocol::Population;
use sextant_engine::{
    Direction, Endpoint, ExtractOptions, ExtractedMessage, Flow, Limits, Transport,
    cluster_messages, extract_messages, infer_protocol,
};
use sextant_ir::{Field, Role, SampleSupport};

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

/// The field with `role` in an inferred format.
fn field_with_role(fields: &[Field], role: Role) -> &Field {
    fields
        .iter()
        .find(|field| field.role == Some(role))
        .unwrap_or_else(|| panic!("no {role:?} field"))
}

#[test]
fn modbus_evidence_records_the_population_each_detector_tested() {
    let messages = extract("modbus", "session_01.pcap", Transport::Tcp, 502);
    assert_eq!(messages.len(), 24);
    let inference = infer_protocol(&messages, Transport::Tcp, 502, &Limits::default());
    let fields = &inference.report.format.root.fields;

    // The transaction id was tested on the 12 requests only, not all 24.
    let sequence = field_with_role(fields, Role::Sequence);
    assert_eq!(
        sequence.evidence.support,
        Some(SampleSupport {
            agreeing: 12,
            total: 12
        })
    );
    assert!(
        sequence
            .evidence
            .notes
            .iter()
            .any(|note| note.contains("12 request(s)")),
        "notes were {:?}",
        sequence.evidence.notes
    );

    // The function code was found by clustering the requests.
    let message_type = field_with_role(fields, Role::MessageType);
    assert_eq!(
        message_type.evidence.support,
        Some(SampleSupport {
            agreeing: 12,
            total: 12
        })
    );
    assert_eq!(inference.clustering.population, Population::Requests);
    assert_eq!(inference.clustering.clustered(), 12);

    // The length relationship was tested on every message.
    let length = field_with_role(fields, Role::Length);
    assert_eq!(
        length.evidence.support,
        Some(SampleSupport {
            agreeing: 24,
            total: 24
        })
    );
}

/// A message on the flow between the client port and server port 7000.
fn message(client_port: u16, to_server: bool, data: Vec<u8>, index: usize) -> ExtractedMessage {
    let client = Endpoint {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        port: client_port,
    };
    let server = Endpoint {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        port: 7000,
    };
    let (source, destination, direction) = if to_server {
        (client, server, Direction::ToServer)
    } else {
        (server, client, Direction::FromServer)
    };
    ExtractedMessage {
        data,
        direction,
        flow: Flow::canonical(client, server),
        source,
        destination,
        timestamp_micros: index as u64,
        capture_offset: index as u64,
        index,
    }
}

/// A big-endian message: a constant marker, a 16-bit sequence, a 16-bit
/// payload length, then the payload.
fn framed(sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x7e];
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[test]
fn the_sequence_fallback_pools_requests_and_never_mixes_in_responses() {
    // Four short connections, one request and its echoing response each. No
    // flow has enough requests alone, so the requests are pooled across flows
    // in capture order. Mixing in the responses (1, 1, 2, 2, ...) would repeat
    // every value and hide the sequence.
    let bodies: [&[u8]; 4] = [b"a", b"bbbb", b"cc", b"ddddddd"];
    let mut messages = Vec::new();
    for (round, body) in bodies.iter().enumerate() {
        let sequence = round as u16 + 1;
        let port = 40001 + round as u16;
        messages.push(message(port, true, framed(sequence, body), messages.len()));
        messages.push(message(
            port,
            false,
            framed(sequence, b"ok"),
            messages.len(),
        ));
    }
    let inference = infer_protocol(&messages, Transport::Tcp, 7000, &Limits::default());
    let fields = &inference.report.format.root.fields;
    let sequence = field_with_role(fields, Role::Sequence);
    assert_eq!(
        sequence.evidence.support,
        Some(SampleSupport {
            agreeing: 4,
            total: 4
        })
    );
    assert!(
        sequence
            .evidence
            .notes
            .iter()
            .any(|note| note.contains("pooled across flows")),
        "notes were {:?}",
        sequence.evidence.notes
    );
}

#[test]
fn one_outlier_short_message_does_not_hide_the_message_types() {
    let mut messages = extract("modbus", "session_01.pcap", Transport::Tcp, 502);
    // A stray one-byte request, such as a keep-alive that slipped through.
    let mut stray = messages[0].clone();
    stray.data = vec![0];
    messages.insert(2, stray);
    for (index, message) in messages.iter_mut().enumerate() {
        message.index = index;
    }

    let clustering = cluster_messages(&messages);
    let discriminant = clustering
        .discriminant
        .as_ref()
        .expect("the function code is still found");
    assert_eq!(discriminant.offset, 7);
    assert_eq!(discriminant.values, vec![0x01, 0x03, 0x06]);
    assert_eq!(clustering.population, Population::Requests);
    assert_eq!(clustering.clustered(), 12);
    assert_eq!(clustering.excluded_short, 1);

    // Every message is still scored, including the one left out of detection.
    let inference = infer_protocol(&messages, Transport::Tcp, 502, &Limits::default());
    assert_eq!(inference.message_count, 25);
    assert_eq!(inference.report.score.samples.len(), 25);
}

#[test]
fn udp_selector_finds_nothing_in_a_tcp_capture() {
    // The captures are TCP; asking for UDP yields no messages, not an error.
    let bytes = read_capture("toy", "session_01.pcap");
    let messages = extract_messages(&bytes, &ExtractOptions::new(Transport::Udp, 9000))
        .expect("parse capture");
    assert!(messages.is_empty());
}
