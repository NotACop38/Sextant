//! Packet-capture reading and payload extraction (FR-2, PRD Section 6.2).
//!
//! [`extract_messages`] reads a `.pcap` or `.pcapng` capture and pulls out the
//! transport payloads that match a transport (TCP or UDP) and a port. Each
//! extracted payload becomes a protocol message with its direction (toward or
//! away from the selected port), its flow (the unordered endpoint pair, so a
//! request and its response share a flow), its capture timestamp, and its byte
//! offset within the file. Those messages are the protocol equivalent of the
//! sample set that file-format inference consumes.
//!
//! The reader is native, safe Rust with no external pcap dependency. It is
//! bounded and never panics on any input: a truncated record, a malformed
//! length, or an unknown link type yields fewer messages or a localized error,
//! not a crash. Both classic pcap (microsecond and nanosecond timestamp
//! variants, either byte order) and pcapng (section and interface blocks, either
//! byte order) are supported, over Ethernet, raw IP, BSD loopback, and Linux
//! cooked-capture link layers, carrying IPv4 or IPv6 and TCP or UDP.
//!
//! TCP stream reassembly is out of scope for v1: each captured segment payload
//! is treated as one message, which matches the captured-sample model in the
//! PRD non-goals (Section 3.2). Synthetic protocol captures send one message per
//! segment, so this is exact for the corpus.

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The transport a capture extraction targets (FR-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Transmission Control Protocol (IP protocol number 6).
    Tcp,
    /// User Datagram Protocol (IP protocol number 17).
    Udp,
}

impl Transport {
    /// The IP protocol number this transport uses.
    #[must_use]
    pub fn protocol_number(self) -> u8 {
        match self {
            Transport::Tcp => 6,
            Transport::Udp => 17,
        }
    }

    /// Parse a transport name (`tcp` or `udp`), case-insensitively.
    #[must_use]
    pub fn parse(name: &str) -> Option<Transport> {
        match name.to_ascii_lowercase().as_str() {
            "tcp" => Some(Transport::Tcp),
            "udp" => Some(Transport::Udp),
            _ => None,
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Transport::Tcp => f.write_str("tcp"),
            Transport::Udp => f.write_str("udp"),
        }
    }
}

/// What to pull out of a capture: the transport and the port (FR-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractOptions {
    /// The transport to follow.
    pub transport: Transport,
    /// The port that identifies the protocol. A datagram is kept when either its
    /// source or its destination port equals this value.
    pub port: u16,
}

/// Which way a message travels relative to the selected port (FR-2).
///
/// A datagram whose destination port is the selected port is a request toward
/// the server; one whose source port is the selected port is a response from it.
/// This is what lets the protocol pass associate requests with responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Toward the selected port (a request to the listening side).
    ToServer,
    /// Away from the selected port (a response from the listening side).
    FromServer,
}

/// One transport endpoint: an IP address and a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Endpoint {
    /// The IP address.
    pub addr: IpAddr,
    /// The transport port.
    pub port: u16,
}

/// A bidirectional flow: the two endpoints in a canonical order so a request and
/// its response, which travel in opposite directions, share the same flow key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Flow {
    /// The lower endpoint (by address then port).
    pub low: Endpoint,
    /// The higher endpoint.
    pub high: Endpoint,
}

impl Flow {
    /// Build a canonical flow from two endpoints, ordering them so a request and
    /// its response (which travel in opposite directions) share one flow key.
    #[must_use]
    pub fn canonical(a: Endpoint, b: Endpoint) -> Self {
        if a <= b {
            Flow { low: a, high: b }
        } else {
            Flow { low: b, high: a }
        }
    }
}

/// One transport payload extracted from a capture (FR-2, FR-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedMessage {
    /// The transport payload bytes (the protocol message).
    pub data: Vec<u8>,
    /// Which way the message travels relative to the selected port.
    pub direction: Direction,
    /// The bidirectional flow the message belongs to.
    pub flow: Flow,
    /// The source endpoint of this datagram.
    pub source: Endpoint,
    /// The destination endpoint of this datagram.
    pub destination: Endpoint,
    /// The capture timestamp in microseconds since the Unix epoch.
    pub timestamp_micros: u64,
    /// The byte offset of the packet record within the capture file.
    pub capture_offset: u64,
    /// The zero-based index of this message among the kept messages.
    pub index: usize,
}

/// Why a capture could not be read (FR-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcapError {
    /// The input is too short or does not begin with a known capture magic.
    UnknownFormat,
    /// The capture declares a byte-order or block magic that is not recognized.
    BadMagic {
        /// The four magic bytes that were read.
        magic: u32,
    },
    /// The capture is internally truncated at the given byte offset.
    Truncated {
        /// Where the parser ran out of bytes.
        offset: usize,
    },
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcapError::UnknownFormat => {
                f.write_str("not a recognized pcap or pcapng capture (bad or missing magic)")
            }
            PcapError::BadMagic { magic } => {
                write!(f, "unrecognized capture magic {magic:#010x}")
            }
            PcapError::Truncated { offset } => {
                write!(f, "capture is truncated at byte offset {offset}")
            }
        }
    }
}

impl Error for PcapError {}

/// The byte order a capture stores its integer fields in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteOrder {
    Little,
    Big,
}

impl ByteOrder {
    fn u16(self, bytes: [u8; 2]) -> u16 {
        match self {
            ByteOrder::Little => u16::from_le_bytes(bytes),
            ByteOrder::Big => u16::from_be_bytes(bytes),
        }
    }

    fn u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            ByteOrder::Little => u32::from_le_bytes(bytes),
            ByteOrder::Big => u32::from_be_bytes(bytes),
        }
    }
}

/// Classic pcap, microsecond timestamps, big-endian.
const PCAP_MAGIC_US_BE: u32 = 0xa1b2_c3d4;
/// Classic pcap, microsecond timestamps, little-endian (the common case).
const PCAP_MAGIC_US_LE: u32 = 0xd4c3_b2a1;
/// Classic pcap, nanosecond timestamps, big-endian.
const PCAP_MAGIC_NS_BE: u32 = 0xa1b2_3c4d;
/// Classic pcap, nanosecond timestamps, little-endian.
const PCAP_MAGIC_NS_LE: u32 = 0x4d3c_b2a1;
/// pcapng Section Header Block type (also the file's first four bytes).
const PCAPNG_SHB_TYPE: u32 = 0x0a0d_0d0a;
/// pcapng byte-order magic, read in the file's own order.
const PCAPNG_BYTE_ORDER_MAGIC: u32 = 0x1a2b_3c4d;

/// Link-layer header types this reader understands (a subset of the registry).
mod linktype {
    /// BSD loopback: a 4-byte address-family header.
    pub const NULL: u32 = 0;
    /// Ethernet II.
    pub const ETHERNET: u32 = 1;
    /// Raw IP: the packet begins with the IP header.
    pub const RAW: u32 = 101;
    /// Linux cooked capture v1: a 16-byte pseudo-header.
    pub const LINUX_SLL: u32 = 113;
}

/// Read a capture and extract the transport payloads that match `options`
/// (FR-2). The returned messages are in capture order, each indexed from zero.
///
/// # Errors
///
/// Returns [`PcapError`] when the bytes are not a recognized capture or are
/// truncated in their framing. Individual packets that cannot be parsed (an
/// unknown link type, a non-IP frame, a transport that does not match) are
/// skipped, not errors: a capture mixing protocols still yields just the
/// matching messages.
pub fn extract_messages(
    bytes: &[u8],
    options: &ExtractOptions,
) -> Result<Vec<ExtractedMessage>, PcapError> {
    let magic = peek_u32(bytes).ok_or(PcapError::UnknownFormat)?;
    if magic == PCAPNG_SHB_TYPE {
        read_pcapng(bytes, options)
    } else if matches!(
        magic,
        PCAP_MAGIC_US_BE | PCAP_MAGIC_US_LE | PCAP_MAGIC_NS_BE | PCAP_MAGIC_NS_LE
    ) {
        read_classic(bytes, options)
    } else {
        Err(PcapError::UnknownFormat)
    }
}

/// Read the first four bytes as a native-order `u32` for magic detection.
fn peek_u32(bytes: &[u8]) -> Option<u32> {
    bytes.get(0..4).map(|slice| {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(slice);
        u32::from_ne_bytes(buf)
    })
}

/// Read a classic libpcap capture (a 24-byte global header followed by records).
fn read_classic(
    bytes: &[u8],
    options: &ExtractOptions,
) -> Result<Vec<ExtractedMessage>, PcapError> {
    if bytes.len() < 24 {
        return Err(PcapError::Truncated {
            offset: bytes.len(),
        });
    }
    // Read the magic in a fixed order; its value names both the byte order the
    // rest of the file uses and the timestamp resolution.
    let raw_magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let (order, nanos) = match raw_magic {
        PCAP_MAGIC_US_BE => (ByteOrder::Big, false),
        PCAP_MAGIC_NS_BE => (ByteOrder::Big, true),
        PCAP_MAGIC_US_LE => (ByteOrder::Little, false),
        PCAP_MAGIC_NS_LE => (ByteOrder::Little, true),
        _ => return Err(PcapError::UnknownFormat),
    };
    let linktype = order.u32([bytes[20], bytes[21], bytes[22], bytes[23]]);

    let mut messages = Vec::new();
    let mut cursor = 24usize;
    let mut kept = 0usize;
    while cursor + 16 <= bytes.len() {
        let record_offset = cursor;
        let ts_sec = order.u32([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]);
        let ts_frac = order.u32([
            bytes[cursor + 4],
            bytes[cursor + 5],
            bytes[cursor + 6],
            bytes[cursor + 7],
        ]);
        let incl_len = order.u32([
            bytes[cursor + 8],
            bytes[cursor + 9],
            bytes[cursor + 10],
            bytes[cursor + 11],
        ]) as usize;
        cursor += 16;
        let end = cursor
            .checked_add(incl_len)
            .ok_or(PcapError::Truncated { offset: cursor })?;
        if end > bytes.len() {
            // A truncated final record: stop cleanly rather than erroring, so a
            // capture cut mid-write still yields its complete records.
            break;
        }
        let frame = &bytes[cursor..end];
        let timestamp_micros = timestamp_micros(ts_sec, ts_frac, nanos);
        if let Some((data, source, destination, direction)) =
            payload_from_frame(linktype, frame, options)
        {
            messages.push(ExtractedMessage {
                data: data.to_vec(),
                direction,
                flow: Flow::canonical(source, destination),
                source,
                destination,
                timestamp_micros,
                capture_offset: record_offset as u64,
                index: kept,
            });
            kept += 1;
        }
        cursor = end;
    }
    Ok(messages)
}

/// Combine a seconds and fractional-seconds field into microseconds since the
/// epoch, saturating rather than overflowing.
fn timestamp_micros(ts_sec: u32, ts_frac: u32, nanos: bool) -> u64 {
    let micros = if nanos {
        u64::from(ts_frac) / 1000
    } else {
        u64::from(ts_frac)
    };
    u64::from(ts_sec)
        .saturating_mul(1_000_000)
        .saturating_add(micros)
}

/// Read a pcapng capture: a stream of blocks, starting with a Section Header
/// Block that fixes the byte order, with Interface Description Blocks giving the
/// link type and Enhanced or Simple Packet Blocks carrying frames.
fn read_pcapng(bytes: &[u8], options: &ExtractOptions) -> Result<Vec<ExtractedMessage>, PcapError> {
    // A pcapng capture holds at least one complete block, and every block is at
    // least 12 bytes, so the Section Header Block magic alone is not a capture.
    // Truncation after the first block is tolerated below, the same way the
    // classic reader keeps the complete records of a capture cut mid-write.
    if bytes.len() < 12 {
        return Err(PcapError::Truncated {
            offset: bytes.len(),
        });
    }
    let mut messages = Vec::new();
    let mut cursor = 0usize;
    let mut order = ByteOrder::Little;
    let mut interfaces: Vec<u32> = Vec::new();
    let mut kept = 0usize;

    while cursor + 8 <= bytes.len() {
        let block_offset = cursor;
        // The block type is stored in the section's byte order, but the Section
        // Header Block itself is identified by its order-independent type value.
        let type_le = u32::from_le_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]);
        let is_shb = type_le == PCAPNG_SHB_TYPE;
        if is_shb {
            order = pcapng_section_order(bytes, cursor)?;
            // Interface ids are scoped to their section, so a new section starts
            // its interface table fresh; otherwise a later section's interface 0
            // would inherit the previous section's link type.
            interfaces.clear();
        }
        let total_len = order.u32([
            bytes[cursor + 4],
            bytes[cursor + 5],
            bytes[cursor + 6],
            bytes[cursor + 7],
        ]) as usize;
        // Every pcapng block is at least 12 bytes (type, length, trailing
        // length) and 32-bit aligned. A shorter or unaligned length is corrupt.
        if total_len < 12 || total_len % 4 != 0 {
            return Err(PcapError::Truncated { offset: cursor });
        }
        let end = block_offset
            .checked_add(total_len)
            .ok_or(PcapError::Truncated { offset: cursor })?;
        if end > bytes.len() {
            break;
        }
        let block_type = order.u32([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]);
        let body = &bytes[block_offset + 8..end - 4];
        match block_type {
            // Interface Description Block: link type is the first 2 bytes.
            0x0000_0001 => {
                let link = body
                    .get(0..2)
                    .map_or(linktype::ETHERNET, |b| u32::from(order.u16([b[0], b[1]])));
                interfaces.push(link);
            }
            // Enhanced Packet Block: interface id, timestamp high and low,
            // captured length, original length, then the frame.
            0x0000_0006 => {
                if let Some(message) =
                    pcapng_enhanced_packet(body, order, &interfaces, options, block_offset, kept)
                {
                    messages.push(message);
                    kept += 1;
                }
            }
            // Simple Packet Block: original length, then the frame. It has no
            // interface id, so it uses the first declared interface's link type.
            0x0000_0003 => {
                let link = interfaces.first().copied().unwrap_or(linktype::ETHERNET);
                if let Some(frame) = body.get(4..) {
                    if let Some((data, source, destination, direction)) =
                        payload_from_frame(link, frame, options)
                    {
                        messages.push(ExtractedMessage {
                            data: data.to_vec(),
                            direction,
                            flow: Flow::canonical(source, destination),
                            source,
                            destination,
                            timestamp_micros: 0,
                            capture_offset: block_offset as u64,
                            index: kept,
                        });
                        kept += 1;
                    }
                }
            }
            _ => {}
        }
        cursor = end;
    }
    Ok(messages)
}

/// Read the byte order from a Section Header Block's byte-order magic.
fn pcapng_section_order(bytes: &[u8], cursor: usize) -> Result<ByteOrder, PcapError> {
    let magic = bytes
        .get(cursor + 8..cursor + 12)
        .ok_or(PcapError::Truncated { offset: cursor })?;
    let be = u32::from_be_bytes([magic[0], magic[1], magic[2], magic[3]]);
    let le = u32::from_le_bytes([magic[0], magic[1], magic[2], magic[3]]);
    if be == PCAPNG_BYTE_ORDER_MAGIC {
        Ok(ByteOrder::Big)
    } else if le == PCAPNG_BYTE_ORDER_MAGIC {
        Ok(ByteOrder::Little)
    } else {
        Err(PcapError::BadMagic { magic: be })
    }
}

/// Parse one Enhanced Packet Block body into a message, if it matches.
fn pcapng_enhanced_packet(
    body: &[u8],
    order: ByteOrder,
    interfaces: &[u32],
    options: &ExtractOptions,
    block_offset: usize,
    index: usize,
) -> Option<ExtractedMessage> {
    if body.len() < 20 {
        return None;
    }
    let interface_id = order.u32([body[0], body[1], body[2], body[3]]) as usize;
    let ts_high = order.u32([body[4], body[5], body[6], body[7]]);
    let ts_low = order.u32([body[8], body[9], body[10], body[11]]);
    let captured = order.u32([body[12], body[13], body[14], body[15]]) as usize;
    let link = interfaces
        .get(interface_id)
        .copied()
        .unwrap_or(linktype::ETHERNET);
    let frame = body.get(20..20usize.checked_add(captured)?)?;
    let (data, source, destination, direction) = payload_from_frame(link, frame, options)?;
    // pcapng timestamps are a 64-bit count of units (microseconds by default).
    let raw = (u64::from(ts_high) << 32) | u64::from(ts_low);
    Some(ExtractedMessage {
        data: data.to_vec(),
        direction,
        flow: Flow::canonical(source, destination),
        source,
        destination,
        timestamp_micros: raw,
        capture_offset: block_offset as u64,
        index,
    })
}

/// Walk a link-layer frame down to the transport payload, returning it with its
/// endpoints and direction when it matches the requested transport and port.
fn payload_from_frame<'a>(
    linktype: u32,
    frame: &'a [u8],
    options: &ExtractOptions,
) -> Option<(&'a [u8], Endpoint, Endpoint, Direction)> {
    let (ethertype, rest) = strip_link_layer(linktype, frame)?;
    let (protocol, src_ip, dst_ip, l3_payload) = match ethertype {
        0x0800 => parse_ipv4(rest)?,
        0x86dd => parse_ipv6(rest)?,
        _ => return None,
    };
    if protocol != options.transport.protocol_number() {
        return None;
    }
    let (src_port, dst_port, payload) = match options.transport {
        Transport::Tcp => parse_tcp(l3_payload)?,
        Transport::Udp => parse_udp(l3_payload)?,
    };
    if src_port != options.port && dst_port != options.port {
        return None;
    }
    if payload.is_empty() {
        return None;
    }
    let source = Endpoint {
        addr: src_ip,
        port: src_port,
    };
    let destination = Endpoint {
        addr: dst_ip,
        port: dst_port,
    };
    let direction = if dst_port == options.port {
        Direction::ToServer
    } else {
        Direction::FromServer
    };
    Some((payload, source, destination, direction))
}

/// Strip the link-layer header, returning the EtherType (or a synthesized one
/// for link types that carry IP directly) and the network-layer bytes.
fn strip_link_layer(linktype: u32, frame: &[u8]) -> Option<(u16, &[u8])> {
    match linktype {
        linktype::ETHERNET => {
            let mut ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
            let mut offset = 14usize;
            // Skip any 802.1Q VLAN tags, each a 2-byte TPID we already read plus
            // a 2-byte tag, before the real EtherType.
            while ethertype == 0x8100 || ethertype == 0x88a8 {
                ethertype = u16::from_be_bytes([*frame.get(offset + 2)?, *frame.get(offset + 3)?]);
                offset += 4;
            }
            Some((ethertype, frame.get(offset..)?))
        }
        linktype::RAW => Some((ethertype_for_ip(frame)?, frame)),
        linktype::NULL => {
            // A 4-byte host-order address family: 2 is IPv4, 24/28/30 are IPv6.
            let family = frame.get(0..4)?;
            let host = u32::from_ne_bytes([family[0], family[1], family[2], family[3]]);
            let ethertype = match host {
                2 => 0x0800,
                24 | 28 | 30 => 0x86dd,
                _ => return None,
            };
            Some((ethertype, frame.get(4..)?))
        }
        linktype::LINUX_SLL => {
            // The EtherType-like protocol sits at offset 14 in the 16-byte header.
            let ethertype = u16::from_be_bytes([*frame.get(14)?, *frame.get(15)?]);
            Some((ethertype, frame.get(16..)?))
        }
        _ => None,
    }
}

/// Infer an EtherType from the IP version nibble for raw-IP link types.
fn ethertype_for_ip(frame: &[u8]) -> Option<u16> {
    match frame.first()? >> 4 {
        4 => Some(0x0800),
        6 => Some(0x86dd),
        _ => None,
    }
}

/// Parse an IPv4 header, returning the protocol, addresses, and payload.
fn parse_ipv4(bytes: &[u8]) -> Option<(u8, IpAddr, IpAddr, &[u8])> {
    let first = *bytes.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let ihl = (first & 0x0f) as usize * 4;
    if ihl < 20 || bytes.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    // Skip fragmented datagrams. Only the first fragment carries the transport
    // header; a later fragment begins with arbitrary payload that could be
    // misread as ports. The more-fragments flag (0x2000) or a nonzero fragment
    // offset (low 13 bits) marks a fragment, and reassembly is out of scope.
    let frag = u16::from_be_bytes([bytes[6], bytes[7]]);
    if frag & 0x2000 != 0 || frag & 0x1fff != 0 {
        return None;
    }
    let protocol = bytes[9];
    let src = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let dst = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    // Trust the IP total length when it is sane, so trailing Ethernet padding on
    // a short frame is not mistaken for transport payload.
    let end = if total_len >= ihl && total_len <= bytes.len() {
        total_len
    } else {
        bytes.len()
    };
    let payload = bytes.get(ihl..end)?;
    Some((protocol, IpAddr::V4(src), IpAddr::V4(dst), payload))
}

/// Parse a fixed IPv6 header, returning the next-header protocol, addresses, and
/// payload. Extension-header chains are not followed; a packet that uses them is
/// skipped rather than misparsed.
fn parse_ipv6(bytes: &[u8]) -> Option<(u8, IpAddr, IpAddr, &[u8])> {
    if bytes.len() < 40 || bytes[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let next_header = bytes[6];
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).ok()?);
    let end = (40 + payload_len).min(bytes.len());
    let payload = bytes.get(40..end)?;
    Some((next_header, IpAddr::V6(src), IpAddr::V6(dst), payload))
}

/// Parse a TCP header, returning the ports and the payload after the header.
fn parse_tcp(bytes: &[u8]) -> Option<(u16, u16, &[u8])> {
    if bytes.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let data_offset = (bytes[12] >> 4) as usize * 4;
    if data_offset < 20 {
        return None;
    }
    let payload = bytes.get(data_offset..)?;
    Some((src_port, dst_port, payload))
}

/// Parse a UDP header, returning the ports and the datagram payload.
fn parse_udp(bytes: &[u8]) -> Option<(u16, u16, &[u8])> {
    if bytes.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let length = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    // The UDP length covers the header plus data; clamp to the captured bytes so
    // a truncated datagram does not read past the frame.
    let end = if (8..=bytes.len()).contains(&length) {
        length
    } else {
        bytes.len()
    };
    let payload = bytes.get(8..end)?;
    Some((src_port, dst_port, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a classic little-endian pcap with Ethernet + IPv4 + the given
    /// transport, one record per supplied payload and direction.
    fn build_pcap(transport: Transport, port: u16, records: &[(&[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        // A little-endian file stores the canonical magic value in LE byte order.
        out.extend_from_slice(&PCAP_MAGIC_US_BE.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes()); // version major
        out.extend_from_slice(&4u16.to_le_bytes()); // version minor
        out.extend_from_slice(&0u32.to_le_bytes()); // thiszone
        out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        out.extend_from_slice(&linktype::ETHERNET.to_le_bytes());
        for (i, (payload, to_server)) in records.iter().enumerate() {
            let frame = build_frame(transport, port, payload, *to_server);
            out.extend_from_slice(&(i as u32).to_le_bytes()); // ts_sec
            out.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // incl_len
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // orig_len
            out.extend_from_slice(&frame);
        }
        out
    }

    fn build_frame(transport: Transport, port: u16, payload: &[u8], to_server: bool) -> Vec<u8> {
        // The client is 10.0.0.1, the server 10.0.0.2; a response swaps both the
        // ports and the addresses, so a request and its reply share one flow.
        let client = [10u8, 0, 0, 1];
        let server = [10u8, 0, 0, 2];
        let (src_port, dst_port, src_ip, dst_ip) = if to_server {
            (40000u16, port, client, server)
        } else {
            (port, 40000u16, server, client)
        };
        let mut l4 = Vec::new();
        match transport {
            Transport::Tcp => {
                l4.extend_from_slice(&src_port.to_be_bytes());
                l4.extend_from_slice(&dst_port.to_be_bytes());
                l4.extend_from_slice(&0u32.to_be_bytes()); // seq
                l4.extend_from_slice(&0u32.to_be_bytes()); // ack
                l4.push(0x50); // data offset 5 words
                l4.push(0x18); // flags
                l4.extend_from_slice(&0u16.to_be_bytes()); // window
                l4.extend_from_slice(&0u16.to_be_bytes()); // checksum
                l4.extend_from_slice(&0u16.to_be_bytes()); // urgent
            }
            Transport::Udp => {
                l4.extend_from_slice(&src_port.to_be_bytes());
                l4.extend_from_slice(&dst_port.to_be_bytes());
                l4.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
                l4.extend_from_slice(&0u16.to_be_bytes()); // checksum
            }
        }
        l4.extend_from_slice(payload);

        let mut ip = Vec::new();
        let total = 20 + l4.len();
        ip.push(0x45); // version 4, ihl 5
        ip.push(0); // dscp
        ip.extend_from_slice(&(total as u16).to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes()); // id
        ip.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
        ip.push(64); // ttl
        ip.push(transport.protocol_number());
        ip.extend_from_slice(&0u16.to_be_bytes()); // checksum
        ip.extend_from_slice(&src_ip); // src
        ip.extend_from_slice(&dst_ip); // dst
        ip.extend_from_slice(&l4);

        let mut eth = Vec::new();
        eth.extend_from_slice(&[0; 6]); // dst mac
        eth.extend_from_slice(&[0; 6]); // src mac
        eth.extend_from_slice(&0x0800u16.to_be_bytes());
        eth.extend_from_slice(&ip);
        eth
    }

    #[test]
    fn extracts_tcp_payloads_and_directions() {
        let pcap = build_pcap(
            Transport::Tcp,
            502,
            &[(b"request-one", true), (b"response-one", false)],
        );
        let messages = extract_messages(
            &pcap,
            &ExtractOptions {
                transport: Transport::Tcp,
                port: 502,
            },
        )
        .expect("parse pcap");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].data, b"request-one");
        assert_eq!(messages[0].direction, Direction::ToServer);
        assert_eq!(messages[1].direction, Direction::FromServer);
        // The request and response share one canonical flow.
        assert_eq!(messages[0].flow, messages[1].flow);
    }

    #[test]
    fn filters_by_port_and_transport() {
        let pcap = build_pcap(Transport::Tcp, 502, &[(b"keep", true)]);
        // A different port matches nothing.
        let none = extract_messages(
            &pcap,
            &ExtractOptions {
                transport: Transport::Tcp,
                port: 9999,
            },
        )
        .expect("parse");
        assert!(none.is_empty());
        // The wrong transport matches nothing.
        let udp = extract_messages(
            &pcap,
            &ExtractOptions {
                transport: Transport::Udp,
                port: 502,
            },
        )
        .expect("parse");
        assert!(udp.is_empty());
    }

    #[test]
    fn extracts_udp_payloads() {
        let pcap = build_pcap(Transport::Udp, 1234, &[(b"datagram", true)]);
        let messages = extract_messages(
            &pcap,
            &ExtractOptions {
                transport: Transport::Udp,
                port: 1234,
            },
        )
        .expect("parse");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].data, b"datagram");
    }

    #[test]
    fn rejects_non_capture_bytes() {
        assert_eq!(
            extract_messages(
                b"not a pcap file",
                &ExtractOptions {
                    transport: Transport::Tcp,
                    port: 1,
                }
            ),
            Err(PcapError::UnknownFormat)
        );
    }

    #[test]
    fn empty_input_is_unknown_not_a_panic() {
        assert_eq!(
            extract_messages(
                &[],
                &ExtractOptions {
                    transport: Transport::Tcp,
                    port: 1,
                }
            ),
            Err(PcapError::UnknownFormat)
        );
    }

    #[test]
    fn truncated_final_record_is_dropped_cleanly() {
        let mut pcap = build_pcap(Transport::Tcp, 502, &[(b"whole", true)]);
        // Append a record header that promises more bytes than remain.
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&1000u32.to_le_bytes());
        pcap.extend_from_slice(&1000u32.to_le_bytes());
        let messages = extract_messages(
            &pcap,
            &ExtractOptions {
                transport: Transport::Tcp,
                port: 502,
            },
        )
        .expect("parse");
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn transport_parses_names() {
        assert_eq!(Transport::parse("tcp"), Some(Transport::Tcp));
        assert_eq!(Transport::parse("UDP"), Some(Transport::Udp));
        assert_eq!(Transport::parse("sctp"), None);
    }

    #[test]
    fn fragmented_ipv4_packets_are_skipped() {
        // A non-first fragment carries no transport header, so its payload must
        // never be parsed as ports. The IPv4 flags/fragment-offset field sits at
        // global header (24) + record header (16) + Ethernet (14) + 6 = 60.
        let mut pcap = build_pcap(Transport::Tcp, 502, &[(b"fragment", true)]);
        let frag_field = 24 + 16 + 14 + 6;
        // Set a nonzero fragment offset (a later fragment).
        pcap[frag_field] = 0x00;
        pcap[frag_field + 1] = 0x01;
        let messages = extract_messages(
            &pcap,
            &ExtractOptions {
                transport: Transport::Tcp,
                port: 502,
            },
        )
        .expect("parse");
        assert!(messages.is_empty(), "a fragment was parsed as a message");
    }

    /// Build a minimal little-endian pcapng with one Ethernet interface and one
    /// Enhanced Packet Block carrying `frame`.
    fn build_pcapng(frame: &[u8]) -> Vec<u8> {
        fn block(block_type: u32, body: &[u8]) -> Vec<u8> {
            // Pad the body to a 32-bit boundary, as pcapng requires.
            let mut padded = body.to_vec();
            while padded.len() % 4 != 0 {
                padded.push(0);
            }
            let total = 12 + padded.len() as u32;
            let mut out = Vec::new();
            out.extend_from_slice(&block_type.to_le_bytes());
            out.extend_from_slice(&total.to_le_bytes());
            out.extend_from_slice(&padded);
            out.extend_from_slice(&total.to_le_bytes());
            out
        }

        let mut shb_body = Vec::new();
        shb_body.extend_from_slice(&PCAPNG_BYTE_ORDER_MAGIC.to_le_bytes());
        shb_body.extend_from_slice(&1u16.to_le_bytes()); // major
        shb_body.extend_from_slice(&0u16.to_le_bytes()); // minor
        shb_body.extend_from_slice(&(-1i64).to_le_bytes()); // section length unknown

        let mut idb_body = Vec::new();
        idb_body.extend_from_slice(&(linktype::ETHERNET as u16).to_le_bytes());
        idb_body.extend_from_slice(&0u16.to_le_bytes()); // reserved
        idb_body.extend_from_slice(&65535u32.to_le_bytes()); // snaplen

        let mut epb_body = Vec::new();
        epb_body.extend_from_slice(&0u32.to_le_bytes()); // interface id
        epb_body.extend_from_slice(&0u32.to_le_bytes()); // timestamp high
        epb_body.extend_from_slice(&0u32.to_le_bytes()); // timestamp low
        epb_body.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // captured
        epb_body.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // original
        epb_body.extend_from_slice(frame);

        let mut out = block(PCAPNG_SHB_TYPE, &shb_body);
        out.extend_from_slice(&block(0x0000_0001, &idb_body));
        out.extend_from_slice(&block(0x0000_0006, &epb_body));
        out
    }

    #[test]
    fn reads_pcapng_enhanced_packet_blocks() {
        let frame = build_frame(Transport::Tcp, 502, b"modbus-like", true);
        let pcapng = build_pcapng(&frame);
        let messages = extract_messages(
            &pcapng,
            &ExtractOptions {
                transport: Transport::Tcp,
                port: 502,
            },
        )
        .expect("parse pcapng");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].data, b"modbus-like");
        assert_eq!(messages[0].direction, Direction::ToServer);
    }
}
