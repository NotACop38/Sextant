//! Capture extraction regressions (FR-2, FR-5, NFR-2).
//!
//! Crafted captures pin how the reader treats packets the capture cut short,
//! TCP keep-alive probes and retransmissions, flows whose two endpoints share
//! the selected port, the message cap, the supported link types, pcapng
//! interface options and packet blocks, and damaged later blocks.

use sextant_engine::pcap::{CaptureNotice, Extraction, extract_capture};
use sextant_engine::{Direction, ExtractOptions, PcapError, Transport};

const CLIENT: [u8; 4] = [10, 0, 0, 1];
const SERVER: [u8; 4] = [10, 0, 0, 2];
const CLIENT_PORT: u16 = 40000;
const PORT: u16 = 502;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

fn u16_bytes(value: u16, big_endian: bool) -> [u8; 2] {
    if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    }
}

fn u32_bytes(value: u32, big_endian: bool) -> [u8; 4] {
    if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    }
}

/// A TCP header (no options) followed by `payload`.
fn tcp(src_port: u16, dst_port: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // ack
    out.push(0x50); // data offset: five words
    out.push(flags);
    out.extend_from_slice(&65535u16.to_be_bytes()); // window
    out.extend_from_slice(&0u16.to_be_bytes()); // checksum
    out.extend_from_slice(&0u16.to_be_bytes()); // urgent
    out.extend_from_slice(payload);
    out
}

/// A UDP header whose length field is `length` (normally eight plus the
/// payload), followed by `payload`.
fn udp(src_port: u16, dst_port: u16, length: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// An IPv4 header whose total length is `total` (normally twenty plus the
/// transport bytes), followed by `transport`.
fn ipv4_with_total(
    src: [u8; 4],
    dst: [u8; 4],
    protocol: u8,
    total: u16,
    transport: &[u8],
) -> Vec<u8> {
    let mut out = vec![0x45, 0];
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]);
    out.extend_from_slice(&src);
    out.extend_from_slice(&dst);
    out.extend_from_slice(transport);
    out
}

fn ipv4(src: [u8; 4], dst: [u8; 4], protocol: u8, transport: &[u8]) -> Vec<u8> {
    ipv4_with_total(src, dst, protocol, (20 + transport.len()) as u16, transport)
}

/// An IPv6 header carrying `transport` between two fixed addresses.
fn ipv6(protocol: u8, transport: &[u8]) -> Vec<u8> {
    let mut out = vec![0x60, 0, 0, 0];
    out.extend_from_slice(&(transport.len() as u16).to_be_bytes());
    out.push(protocol);
    out.push(64);
    let mut source = [0u8; 16];
    source[15] = 1;
    let mut destination = [0u8; 16];
    destination[15] = 2;
    out.extend_from_slice(&source);
    out.extend_from_slice(&destination);
    out.extend_from_slice(transport);
    out
}

fn ethernet(ethertype: u16, network: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 12];
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(network);
    out
}

/// An Ethernet frame carrying a TCP segment between two endpoints.
fn tcp_frame(
    src: ([u8; 4], u16),
    dst: ([u8; 4], u16),
    seq: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    ethernet(
        0x0800,
        &ipv4(src.0, dst.0, 6, &tcp(src.1, dst.1, seq, flags, payload)),
    )
}

/// A client request to the server port.
fn request(seq: u32, payload: &[u8]) -> Vec<u8> {
    tcp_frame(
        (CLIENT, CLIENT_PORT),
        (SERVER, PORT),
        seq,
        PSH | ACK,
        payload,
    )
}

/// A server response to the client.
fn response(seq: u32, payload: &[u8]) -> Vec<u8> {
    tcp_frame(
        (SERVER, PORT),
        (CLIENT, CLIENT_PORT),
        seq,
        PSH | ACK,
        payload,
    )
}

/// A classic pcap global header with an arbitrary link-type field.
fn classic_header(big_endian: bool, linktype_field: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u32_bytes(0xa1b2_c3d4, big_endian));
    out.extend_from_slice(&u16_bytes(2, big_endian));
    out.extend_from_slice(&u16_bytes(4, big_endian));
    out.extend_from_slice(&[0; 8]); // thiszone, sigfigs
    out.extend_from_slice(&u32_bytes(65535, big_endian));
    out.extend_from_slice(&u32_bytes(linktype_field, big_endian));
    out
}

/// One classic pcap record: `captured` is the stored frame, `original` its
/// declared length on the wire.
fn classic_record(big_endian: bool, captured: &[u8], original: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0; 8]); // timestamp
    out.extend_from_slice(&u32_bytes(captured.len() as u32, big_endian));
    out.extend_from_slice(&u32_bytes(original as u32, big_endian));
    out.extend_from_slice(captured);
    out
}

/// A little-endian classic capture of complete frames.
fn classic(linktype: u32, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = classic_header(false, linktype);
    for frame in frames {
        out.extend_from_slice(&classic_record(false, frame, frame.len()));
    }
    out
}

fn extract(bytes: &[u8]) -> Extraction {
    extract_capture(bytes, &ExtractOptions::new(Transport::Tcp, PORT)).expect("capture reads")
}

fn payloads(extraction: &Extraction) -> Vec<&[u8]> {
    extraction
        .messages
        .iter()
        .map(|message| message.data.as_slice())
        .collect()
}

#[test]
fn packets_cut_by_the_snapshot_length_are_skipped_and_counted() {
    let first = request(100, b"complete-1");
    let cut = request(110, b"truncated-two");
    let last = request(123, b"complete-3");
    let mut bytes = classic_header(false, 1);
    bytes.extend_from_slice(&classic_record(false, &first, first.len()));
    // Only part of this packet was captured: its original length is larger.
    // Its partial payload must not pose as a complete message.
    bytes.extend_from_slice(&classic_record(false, &cut[..cut.len() - 3], cut.len()));
    bytes.extend_from_slice(&classic_record(false, &last, last.len()));
    let extraction = extract(&bytes);
    assert_eq!(payloads(&extraction), [&b"complete-1"[..], b"complete-3"]);
    assert_eq!(extraction.truncated_packets, 1);
    assert!(
        extraction
            .notices()
            .contains(&CaptureNotice::TruncatedPackets { count: 1 })
    );

    // A record cut short only in trailing bytes still declares a longer
    // original length, so it is skipped as well rather than trusted.
    let mut bytes = classic_header(false, 1);
    bytes.extend_from_slice(&classic_record(false, &first, first.len() + 4));
    assert!(extract(&bytes).messages.is_empty());
}

#[test]
fn an_ip_total_length_beyond_the_captured_bytes_is_skipped() {
    let segment = tcp(CLIENT_PORT, PORT, 1, PSH | ACK, b"short-by-ten");
    let lying = ethernet(
        0x0800,
        &ipv4_with_total(
            CLIENT,
            SERVER,
            6,
            (20 + segment.len() + 10) as u16,
            &segment,
        ),
    );
    let extraction = extract(&classic(1, &[lying, request(50, b"fine")]));
    assert_eq!(payloads(&extraction), [&b"fine"[..]]);
    assert_eq!(extraction.truncated_packets, 1);
}

#[test]
fn a_udp_length_beyond_the_captured_bytes_is_skipped() {
    let long = udp(CLIENT_PORT, PORT, 8 + 20, b"only-ten!!");
    let exact = udp(CLIENT_PORT, PORT, 8 + 4, b"good");
    let frames = [
        ethernet(0x0800, &ipv4(CLIENT, SERVER, 17, &long)),
        ethernet(0x0800, &ipv4(CLIENT, SERVER, 17, &exact)),
    ];
    let extraction = extract_capture(
        &classic(1, &frames),
        &ExtractOptions::new(Transport::Udp, PORT),
    )
    .expect("capture reads");
    assert_eq!(payloads(&extraction), [&b"good"[..]]);
    assert_eq!(extraction.truncated_packets, 1);
}

#[test]
fn cut_packets_on_other_ports_are_not_counted() {
    let other = tcp_frame(
        (CLIENT, CLIENT_PORT),
        (SERVER, 80),
        1,
        PSH | ACK,
        b"web-traffic",
    );
    let mut bytes = classic_header(false, 1);
    bytes.extend_from_slice(&classic_record(
        false,
        &other[..other.len() - 4],
        other.len(),
    ));
    let extraction = extract(&bytes);
    assert!(extraction.messages.is_empty());
    assert_eq!(extraction.truncated_packets, 0);
}

#[test]
fn ipv6_segments_are_extracted_and_cut_ones_counted() {
    let segment = tcp(CLIENT_PORT, PORT, 7, PSH | ACK, b"over-ipv6");
    let whole = ethernet(0x86dd, &ipv6(6, &segment));
    let mut cut = whole.clone();
    cut.truncate(whole.len() - 2);
    let mut bytes = classic_header(false, 1);
    bytes.extend_from_slice(&classic_record(false, &whole, whole.len()));
    bytes.extend_from_slice(&classic_record(false, &cut, cut.len()));
    let extraction = extract(&bytes);
    assert_eq!(payloads(&extraction), [&b"over-ipv6"[..]]);
    // The second frame's IPv6 payload length runs past the captured bytes.
    assert_eq!(extraction.truncated_packets, 1);
}

#[test]
fn tcp_keepalive_probes_are_dropped() {
    let frames = [
        request(1000, b"hello"),
        // One garbage byte at the sequence number just before the next
        // expected one: a keep-alive probe, not a message.
        request(1004, &[0]),
        request(1005, b"world"),
    ];
    let extraction = extract(&classic(1, &frames));
    assert_eq!(payloads(&extraction), [&b"hello"[..], b"world"]);
    assert_eq!(extraction.keepalives_dropped, 1);
    assert!(
        extraction
            .notices()
            .contains(&CaptureNotice::KeepAlivesDropped { count: 1 })
    );
}

#[test]
fn a_one_byte_message_that_advances_the_stream_is_kept() {
    let frames = [request(1000, b"hello"), request(1005, b"!")];
    let extraction = extract(&classic(1, &frames));
    assert_eq!(payloads(&extraction), [&b"hello"[..], b"!"]);
    assert_eq!(extraction.keepalives_dropped, 0);
}

#[test]
fn a_syn_occupies_a_sequence_number_for_keepalive_detection() {
    let frames = [
        tcp_frame((CLIENT, CLIENT_PORT), (SERVER, PORT), 999, SYN, b""),
        // The SYN occupied 999, so a one-byte probe at 999 re-sends the byte
        // before the next expected sequence number.
        tcp_frame((CLIENT, CLIENT_PORT), (SERVER, PORT), 999, ACK, &[0]),
        request(1000, b"data"),
    ];
    let extraction = extract(&classic(1, &frames));
    assert_eq!(payloads(&extraction), [&b"data"[..]]);
    assert_eq!(extraction.keepalives_dropped, 1);
}

#[test]
fn exact_tcp_retransmissions_are_dropped() {
    let frames = [
        request(1000, b"hello"),
        request(1000, b"hello"),
        // The same sequence number with different bytes is not an exact copy.
        request(1000, b"HELLO"),
        // The opposite direction has its own sequence space.
        response(1000, b"hello"),
        request(1005, b"next"),
    ];
    let extraction = extract(&classic(1, &frames));
    assert_eq!(
        payloads(&extraction),
        [&b"hello"[..], b"HELLO", b"hello", b"next"]
    );
    assert_eq!(extraction.retransmissions_dropped, 1);
    assert!(
        extraction
            .notices()
            .contains(&CaptureNotice::RetransmissionsDropped { count: 1 })
    );
}

#[test]
fn flows_between_two_endpoints_on_the_selected_port_are_oriented_by_the_first_sender() {
    let a = ([10, 0, 0, 1], 500);
    let b = ([10, 0, 0, 2], 500);
    let frames = [
        tcp_frame(b, a, 1, PSH | ACK, b"from-b-first"),
        tcp_frame(a, b, 1, PSH | ACK, b"from-a"),
        tcp_frame(b, a, 13, PSH | ACK, b"from-b-again"),
    ];
    let extraction = extract_capture(
        &classic(1, &frames),
        &ExtractOptions::new(Transport::Tcp, 500),
    )
    .expect("capture reads");
    let directions: Vec<Direction> = extraction.messages.iter().map(|m| m.direction).collect();
    // The side that sent first is the client, so its messages are requests.
    assert_eq!(
        directions,
        [
            Direction::ToServer,
            Direction::FromServer,
            Direction::ToServer
        ]
    );

    // A SYN-ACK seen first names its destination as the client.
    let frames = [
        tcp_frame(b, a, 7, SYN | ACK, b""),
        tcp_frame(a, b, 1, PSH | ACK, b"request"),
        tcp_frame(b, a, 8, PSH | ACK, b"response"),
        tcp_frame(a, b, 8, FIN | ACK, b""),
    ];
    let extraction = extract_capture(
        &classic(1, &frames),
        &ExtractOptions::new(Transport::Tcp, 500),
    )
    .expect("capture reads");
    let directions: Vec<Direction> = extraction.messages.iter().map(|m| m.direction).collect();
    assert_eq!(directions, [Direction::ToServer, Direction::FromServer]);
}

#[test]
fn the_message_cap_flag_means_a_further_message_existed() {
    let frames = [
        request(1, b"one"),
        request(4, b"two"),
        request(7, b"three"),
        // A keep-alive after the last message is not a further message.
        request(11, &[0]),
    ];
    let bytes = classic(1, &frames);
    let mut options = ExtractOptions::new(Transport::Tcp, PORT);

    options.max_messages = 3;
    let exact = extract_capture(&bytes, &options).expect("capture reads");
    assert_eq!(exact.messages.len(), 3);
    assert!(!exact.message_cap_reached, "exactly three messages existed");

    options.max_messages = 2;
    let capped = extract_capture(&bytes, &options).expect("capture reads");
    assert_eq!(capped.messages.len(), 2);
    assert!(capped.message_cap_reached);

    options.max_messages = 0;
    let none = extract_capture(&bytes, &options).expect("capture reads");
    assert!(none.messages.is_empty());
    assert!(none.message_cap_reached);
}

/// An IPv4 packet carrying a request, for link types with no Ethernet header.
fn raw_request() -> Vec<u8> {
    ipv4(
        CLIENT,
        SERVER,
        6,
        &tcp(CLIENT_PORT, PORT, 1, PSH | ACK, b"raw"),
    )
}

#[test]
fn bsd_loopback_family_is_read_in_the_file_byte_order() {
    for big_endian in [false, true] {
        let mut frame = u32_bytes(2, big_endian).to_vec();
        frame.extend_from_slice(&raw_request());
        let mut bytes = classic_header(big_endian, 0);
        bytes.extend_from_slice(&classic_record(big_endian, &frame, frame.len()));
        let extraction = extract(&bytes);
        assert_eq!(
            payloads(&extraction),
            [&b"raw"[..]],
            "big-endian file: {big_endian}"
        );
    }

    // A family written in the other byte order (a capture moved between hosts)
    // is recognized by its nonzero upper bits and swapped back.
    let mut frame = 2u32.to_be_bytes().to_vec();
    frame.extend_from_slice(&raw_request());
    let extraction = extract(&classic(0, &[frame]));
    assert_eq!(payloads(&extraction), [&b"raw"[..]]);

    // Darwin's IPv6 family, 30.
    let mut frame = 30u32.to_le_bytes().to_vec();
    frame.extend_from_slice(&ipv6(6, &tcp(CLIENT_PORT, PORT, 1, PSH | ACK, b"six")));
    let extraction = extract(&classic(0, &[frame]));
    assert_eq!(payloads(&extraction), [&b"six"[..]]);
}

#[test]
fn openbsd_loopback_family_is_in_network_order() {
    let mut frame = 2u32.to_be_bytes().to_vec();
    frame.extend_from_slice(&raw_request());
    let extraction = extract(&classic(108, &[frame]));
    assert_eq!(payloads(&extraction), [&b"raw"[..]]);
}

#[test]
fn raw_ip_link_types_are_supported() {
    for linktype in [12, 14, 101, 228] {
        let extraction = extract(&classic(linktype, &[raw_request()]));
        assert_eq!(payloads(&extraction), [&b"raw"[..]], "link type {linktype}");
    }
    let six = ipv6(6, &tcp(CLIENT_PORT, PORT, 1, PSH | ACK, b"six"));
    let extraction = extract(&classic(229, &[six.clone()]));
    assert_eq!(payloads(&extraction), [&b"six"[..]]);
    // The version-specific link types refuse the other IP version.
    assert!(extract(&classic(228, &[six])).messages.is_empty());
    assert!(extract(&classic(229, &[raw_request()])).messages.is_empty());

    // Link type 12 is OpenBSD's loopback as well, so a frame that is not IP is
    // tried as a network-order address family.
    let mut frame = 2u32.to_be_bytes().to_vec();
    frame.extend_from_slice(&raw_request());
    assert_eq!(payloads(&extract(&classic(12, &[frame]))), [&b"raw"[..]]);
}

#[test]
fn linux_cooked_captures_are_supported() {
    // Version 1: the protocol sits at offset 14 of a 16-byte header.
    let mut v1 = vec![0u8; 14];
    v1.extend_from_slice(&0x0800u16.to_be_bytes());
    v1.extend_from_slice(&raw_request());
    assert_eq!(payloads(&extract(&classic(113, &[v1]))), [&b"raw"[..]]);

    // Version 2: the protocol leads a 20-byte header.
    let mut v2 = 0x0800u16.to_be_bytes().to_vec();
    v2.extend_from_slice(&[0u8; 18]);
    v2.extend_from_slice(&raw_request());
    assert_eq!(payloads(&extract(&classic(276, &[v2]))), [&b"raw"[..]]);
}

#[test]
fn the_link_type_field_is_masked_to_its_low_16_bits() {
    // Frame check sequence information in the upper bits must not hide the
    // Ethernet link type.
    let field = 1 | (1 << 26) | (4 << 28);
    let mut bytes = classic_header(false, field);
    let frame = request(1, b"with-fcs-bits");
    bytes.extend_from_slice(&classic_record(false, &frame, frame.len()));
    assert_eq!(payloads(&extract(&bytes)), [&b"with-fcs-bits"[..]]);
}

/// A pcapng block with a correct trailing length.
fn ng_block(big_endian: bool, block_type: u32, body: &[u8]) -> Vec<u8> {
    let mut padded = body.to_vec();
    while padded.len() % 4 != 0 {
        padded.push(0);
    }
    let total = 12 + padded.len() as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&u32_bytes(block_type, big_endian));
    out.extend_from_slice(&u32_bytes(total, big_endian));
    out.extend_from_slice(&padded);
    out.extend_from_slice(&u32_bytes(total, big_endian));
    out
}

fn ng_section(big_endian: bool) -> Vec<u8> {
    let mut body = u32_bytes(0x1a2b_3c4d, big_endian).to_vec();
    body.extend_from_slice(&u16_bytes(1, big_endian));
    body.extend_from_slice(&u16_bytes(0, big_endian));
    body.extend_from_slice(&[0xff; 8]); // section length unknown
    ng_block(big_endian, 0x0a0d_0d0a, &body)
}

/// An Interface Description Block with the given options (code, value).
fn ng_interface(
    big_endian: bool,
    linktype: u16,
    snaplen: u32,
    options: &[(u16, &[u8])],
) -> Vec<u8> {
    let mut body = u16_bytes(linktype, big_endian).to_vec();
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&u32_bytes(snaplen, big_endian));
    for (code, value) in options {
        body.extend_from_slice(&u16_bytes(*code, big_endian));
        body.extend_from_slice(&u16_bytes(value.len() as u16, big_endian));
        body.extend_from_slice(value);
        while body.len() % 4 != 0 {
            body.push(0);
        }
    }
    body.extend_from_slice(&[0, 0, 0, 0]); // opt_endofopt
    ng_block(big_endian, 1, &body)
}

fn ng_enhanced(big_endian: bool, timestamp: u64, frame: &[u8]) -> Vec<u8> {
    let mut body = u32_bytes(0, big_endian).to_vec();
    body.extend_from_slice(&u32_bytes((timestamp >> 32) as u32, big_endian));
    body.extend_from_slice(&u32_bytes(timestamp as u32, big_endian));
    body.extend_from_slice(&u32_bytes(frame.len() as u32, big_endian));
    body.extend_from_slice(&u32_bytes(frame.len() as u32, big_endian));
    body.extend_from_slice(frame);
    ng_block(big_endian, 6, &body)
}

#[test]
fn pcapng_obsolete_packet_blocks_are_read() {
    for big_endian in [false, true] {
        let frame = request(1, b"old-style");
        let mut body = u16_bytes(0, big_endian).to_vec(); // interface id
        body.extend_from_slice(&u16_bytes(0, big_endian)); // drops count
        body.extend_from_slice(&u32_bytes(0, big_endian)); // timestamp high
        body.extend_from_slice(&u32_bytes(42, big_endian)); // timestamp low
        body.extend_from_slice(&u32_bytes(frame.len() as u32, big_endian));
        body.extend_from_slice(&u32_bytes(frame.len() as u32, big_endian));
        body.extend_from_slice(&frame);
        let mut bytes = ng_section(big_endian);
        bytes.extend_from_slice(&ng_interface(big_endian, 1, 0, &[]));
        bytes.extend_from_slice(&ng_block(big_endian, 2, &body));
        let extraction = extract(&bytes);
        assert_eq!(payloads(&extraction), [&b"old-style"[..]]);
        assert_eq!(extraction.messages[0].timestamp_micros, 42);
    }
}

#[test]
fn pcapng_timestamps_honor_the_interface_resolution_and_offset() {
    // Nanosecond units (if_tsresol 9) and a 100-second offset (if_tsoffset).
    let offset = 100i64.to_le_bytes();
    let options: [(u16, &[u8]); 2] = [(9, &[9]), (14, &offset)];
    let mut bytes = ng_section(false);
    bytes.extend_from_slice(&ng_interface(false, 1, 0, &options));
    bytes.extend_from_slice(&ng_enhanced(false, 1_500_000_000, &request(1, b"timed")));
    let extraction = extract(&bytes);
    assert_eq!(extraction.messages[0].timestamp_micros, 101_500_000);

    // Binary units: 2 to the minus 10th of a second.
    let mut bytes = ng_section(true);
    bytes.extend_from_slice(&ng_interface(true, 1, 0, &[(9, &[0x80 | 10])]));
    bytes.extend_from_slice(&ng_enhanced(true, 3 << 10, &request(1, b"binary")));
    let extraction = extract(&bytes);
    assert_eq!(extraction.messages[0].timestamp_micros, 3_000_000);
}

#[test]
fn a_pcapng_simple_packet_cut_by_the_snapshot_length_is_skipped() {
    // A Simple Packet Block stores the original length and at most a
    // snapshot length of data; the interface's snapshot length is 60 bytes.
    let frame = request(1, b"longer-than-the-snapshot");
    let snaplen = 60usize;
    let mut body = (frame.len() as u32).to_le_bytes().to_vec(); // original length
    body.extend_from_slice(&frame[..snaplen]);
    let whole = request(100, b"fits");
    assert!(whole.len() <= snaplen);
    let mut whole_body = (whole.len() as u32).to_le_bytes().to_vec();
    whole_body.extend_from_slice(&whole);
    let mut bytes = ng_section(false);
    bytes.extend_from_slice(&ng_interface(false, 1, snaplen as u32, &[]));
    bytes.extend_from_slice(&ng_block(false, 3, &whole_body));
    bytes.extend_from_slice(&ng_block(false, 3, &body));
    let extraction = extract(&bytes);
    assert_eq!(payloads(&extraction), [&b"fits"[..]]);
    assert_eq!(extraction.truncated_packets, 1);
}

/// A capture of one good packet followed by a damaged block made by `damage`.
fn capture_with_damaged_second_packet(damage: impl Fn(&mut Vec<u8>)) -> (Vec<u8>, usize) {
    let mut bytes = ng_section(false);
    bytes.extend_from_slice(&ng_interface(false, 1, 0, &[]));
    bytes.extend_from_slice(&ng_enhanced(false, 0, &request(1, b"kept")));
    let damaged_at = bytes.len();
    let mut second = ng_enhanced(false, 0, &request(5, b"lost"));
    damage(&mut second);
    bytes.extend_from_slice(&second);
    (bytes, damaged_at)
}

#[test]
fn a_later_pcapng_block_with_a_bad_trailer_keeps_earlier_messages() {
    let (bytes, damaged_at) = capture_with_damaged_second_packet(|block| {
        let end = block.len();
        block[end - 4] ^= 0xff;
    });
    let extraction = extract(&bytes);
    assert_eq!(payloads(&extraction), [&b"kept"[..]]);
    assert_eq!(extraction.framing_stopped_at, Some(damaged_at));
    assert!(
        extraction
            .notices()
            .contains(&CaptureNotice::FramingStopped { offset: damaged_at })
    );
}

#[test]
fn a_later_pcapng_block_with_an_unaligned_length_keeps_earlier_messages() {
    let (bytes, damaged_at) = capture_with_damaged_second_packet(|block| {
        block[4..8].copy_from_slice(&13u32.to_le_bytes());
    });
    let extraction = extract(&bytes);
    assert_eq!(payloads(&extraction), [&b"kept"[..]]);
    assert_eq!(extraction.framing_stopped_at, Some(damaged_at));
}

#[test]
fn a_later_pcapng_block_cut_mid_write_keeps_earlier_messages() {
    let (bytes, damaged_at) = capture_with_damaged_second_packet(|block| {
        block.truncate(block.len() - 6);
    });
    let extraction = extract(&bytes);
    assert_eq!(payloads(&extraction), [&b"kept"[..]]);
    assert_eq!(extraction.framing_stopped_at, Some(damaged_at));
}

#[test]
fn a_later_pcapng_section_with_a_bad_magic_keeps_earlier_messages() {
    let mut bytes = ng_section(false);
    bytes.extend_from_slice(&ng_interface(false, 1, 0, &[]));
    bytes.extend_from_slice(&ng_enhanced(false, 0, &request(1, b"kept")));
    let damaged_at = bytes.len();
    let mut section = ng_section(false);
    section[8..12].copy_from_slice(b"XXXX");
    bytes.extend_from_slice(&section);
    let extraction = extract(&bytes);
    assert_eq!(payloads(&extraction), [&b"kept"[..]]);
    assert_eq!(extraction.framing_stopped_at, Some(damaged_at));
}

#[test]
fn a_pcapng_leading_block_with_a_bad_trailer_is_an_error() {
    let mut bytes = ng_section(false);
    let end = bytes.len();
    bytes[end - 1] ^= 0xff;
    assert_eq!(
        extract_capture(&bytes, &ExtractOptions::new(Transport::Tcp, PORT)),
        Err(PcapError::Corrupt { offset: 0 })
    );
}

#[test]
fn a_cut_classic_record_is_reported() {
    let mut bytes = classic(1, &[request(1, b"kept")]);
    let cut_at = bytes.len();
    let lost = request(5, b"lost");
    bytes.extend_from_slice(&classic_record(false, &lost, lost.len())[..20]);
    let extraction = extract(&bytes);
    assert_eq!(payloads(&extraction), [&b"kept"[..]]);
    assert_eq!(extraction.framing_stopped_at, Some(cut_at));
}

#[test]
fn every_prefix_of_a_crafted_pcapng_reads_or_fails_cleanly() {
    let (bytes, _) = capture_with_damaged_second_packet(|_| {});
    for end in 0..=bytes.len() {
        let _ = extract_capture(&bytes[..end], &ExtractOptions::new(Transport::Tcp, PORT));
    }
}
