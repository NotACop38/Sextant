//! Packet-capture reading and payload extraction (FR-2, PRD Section 6.2).
//!
//! [`extract_capture`] reads a `.pcap` or `.pcapng` capture and pulls out the
//! transport payloads that match a transport (TCP or UDP) and a port. Each
//! extracted payload becomes a protocol message with its direction (toward or
//! away from the selected port), its flow (the unordered endpoint pair, so a
//! request and its response share a flow), its capture timestamp, and its byte
//! offset within the file. Those messages are the protocol equivalent of the
//! sample set that file-format inference consumes. [`extract_messages`] is the
//! same reader returning only the messages.
//!
//! The reader is native, safe Rust with no external pcap dependency. It is
//! bounded and never panics on any input: a truncated record, a malformed
//! length, or an unknown link type yields fewer messages or a localized error,
//! not a crash. Both classic pcap (microsecond and nanosecond timestamp
//! variants, either byte order) and pcapng (section, interface, enhanced,
//! simple, and obsolete packet blocks, either byte order, with interface
//! timestamp resolution and offset) are supported, over Ethernet, raw IP
//! (link types 12, 14, 101, 228, and 229), BSD and OpenBSD loopback (0 and
//! 108), and Linux cooked capture v1 and v2 (113 and 276), carrying IPv4 or
//! IPv6 and TCP or UDP.
//!
//! What the reader leaves out is counted in the [`Extraction`] rather than
//! dropped silently:
//!
//! - A packet the capture cut short (its captured length is below its original
//!   length, or its IP or UDP length runs past the captured bytes) is skipped,
//!   because a partial payload would masquerade as a complete message.
//! - TCP keep-alive probes and exact TCP retransmissions are dropped, so a
//!   one-byte probe or a repeated segment does not pose as a protocol message.
//! - When a record or a later block is truncated or corrupt, reading stops
//!   there and the messages already extracted are kept.
//!
//! TCP stream reassembly is out of scope for v1: each captured segment payload
//! is treated as one message, which matches the captured-sample model in the
//! PRD non-goals (Section 3.2). Synthetic protocol captures send one message per
//! segment, so this is exact for the corpus.

use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};
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

/// Default cap on how many transport messages may be extracted from captures in
/// one run. Bounds association, scoring, and refinement work (FR-2, FR-24).
pub const DEFAULT_MAX_MESSAGES: usize = 10_000;

/// What to pull out of a capture: the transport and the port (FR-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractOptions {
    /// The transport to follow.
    pub transport: Transport,
    /// The port that identifies the protocol. A datagram is kept when either its
    /// source or its destination port equals this value.
    pub port: u16,
    /// Stop extracting once this many messages have been kept. Caps memory and
    /// the quadratic-to-linear association work that follows.
    pub max_messages: usize,
}

impl ExtractOptions {
    /// Build options with the default message cap.
    #[must_use]
    pub const fn new(transport: Transport, port: u16) -> Self {
        Self {
            transport,
            port,
            max_messages: DEFAULT_MAX_MESSAGES,
        }
    }
}

/// Which way a message travels relative to the selected port (FR-2).
///
/// A datagram whose destination port is the selected port is a request toward
/// the server; one whose source port is the selected port is a response from it.
/// When both endpoints use the selected port, the endpoint that sent first on
/// the flow is taken as the client. This is what lets the protocol pass
/// associate requests with responses.
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

/// The result of reading one capture: the kept messages plus an account of what
/// was skipped or dropped and whether reading stopped early (FR-2, FR-5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extraction {
    /// The kept messages, in capture order, each indexed from zero.
    pub messages: Vec<ExtractedMessage>,
    /// Packets matching the transport and port that were skipped because the
    /// capture holds fewer bytes than the packet declares: the snapshot length
    /// cut them short, or their IP or UDP length runs past the captured bytes.
    pub truncated_packets: usize,
    /// TCP keep-alive probes that were dropped: segments of at most one byte
    /// that re-send the byte just before the sender's next sequence number.
    pub keepalives_dropped: usize,
    /// Exact TCP retransmissions that were dropped: segments with the same
    /// endpoints, sequence number, and payload as a segment already kept.
    pub retransmissions_dropped: usize,
    /// Whether extraction stopped at [`ExtractOptions::max_messages`] while at
    /// least one more matching message remained in the capture.
    pub message_cap_reached: bool,
    /// The byte offset at which the capture's framing ended early, when a record
    /// or a later block was truncated or corrupt. The complete records before
    /// it were read; nothing after it was.
    pub framing_stopped_at: Option<usize>,
}

impl Extraction {
    /// Notices about packets that were skipped or dropped and about framing that
    /// ended early, to be surfaced to the user so nothing is lost silently
    /// (FR-5). The message cap is reported through
    /// [`Extraction::message_cap_reached`] instead, since it spans captures.
    #[must_use]
    pub fn notices(&self) -> Vec<CaptureNotice> {
        let mut notices = Vec::new();
        if self.truncated_packets > 0 {
            notices.push(CaptureNotice::TruncatedPackets {
                count: self.truncated_packets,
            });
        }
        if self.keepalives_dropped > 0 {
            notices.push(CaptureNotice::KeepAlivesDropped {
                count: self.keepalives_dropped,
            });
        }
        if self.retransmissions_dropped > 0 {
            notices.push(CaptureNotice::RetransmissionsDropped {
                count: self.retransmissions_dropped,
            });
        }
        if let Some(offset) = self.framing_stopped_at {
            notices.push(CaptureNotice::FramingStopped { offset });
        }
        notices
    }
}

/// A heads-up about capture content that extraction skipped, dropped, or could
/// not read (FR-2, FR-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureNotice {
    /// Matching packets were skipped because the capture cut them short.
    TruncatedPackets {
        /// How many packets were skipped.
        count: usize,
    },
    /// TCP keep-alive probes were dropped.
    KeepAlivesDropped {
        /// How many probes were dropped.
        count: usize,
    },
    /// Exact TCP retransmissions were dropped.
    RetransmissionsDropped {
        /// How many retransmissions were dropped.
        count: usize,
    },
    /// The capture's framing was truncated or corrupt at a byte offset, and
    /// reading stopped there.
    FramingStopped {
        /// The byte offset of the record or block that could not be read.
        offset: usize,
    },
}

impl fmt::Display for CaptureNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureNotice::TruncatedPackets { count } => write!(
                f,
                "skipped {count} matching packet(s) that the capture cut short (a snapshot \
                 length, or an IP or UDP length beyond the captured bytes)"
            ),
            CaptureNotice::KeepAlivesDropped { count } => {
                write!(f, "dropped {count} TCP keep-alive probe(s)")
            }
            CaptureNotice::RetransmissionsDropped { count } => {
                write!(f, "dropped {count} exact TCP retransmission(s)")
            }
            CaptureNotice::FramingStopped { offset } => write!(
                f,
                "the capture is truncated or corrupt at byte offset {offset}; only the \
                 complete records before it were read"
            ),
        }
    }
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
    /// The capture's leading block is corrupt: its trailing length does not
    /// match its leading length.
    Corrupt {
        /// The byte offset of the corrupt block.
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
            PcapError::Corrupt { offset } => {
                write!(f, "capture has a corrupt block at byte offset {offset}")
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

    fn i64(self, bytes: [u8; 8]) -> i64 {
        match self {
            ByteOrder::Little => i64::from_le_bytes(bytes),
            ByteOrder::Big => i64::from_be_bytes(bytes),
        }
    }

    /// Read a `u16` at `at`, or `None` past the end.
    fn u16_at(self, bytes: &[u8], at: usize) -> Option<u16> {
        let slice = bytes.get(at..at.checked_add(2)?)?;
        Some(self.u16([slice[0], slice[1]]))
    }

    /// Read a `u32` at `at`, or `None` past the end.
    fn u32_at(self, bytes: &[u8], at: usize) -> Option<u32> {
        let slice = bytes.get(at..at.checked_add(4)?)?;
        Some(self.u32([slice[0], slice[1], slice[2], slice[3]]))
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

/// pcapng block types this reader understands.
mod block {
    /// Interface Description Block.
    pub const INTERFACE: u32 = 0x0000_0001;
    /// Packet Block, the obsolete predecessor of the Enhanced Packet Block.
    pub const OBSOLETE_PACKET: u32 = 0x0000_0002;
    /// Simple Packet Block.
    pub const SIMPLE_PACKET: u32 = 0x0000_0003;
    /// Enhanced Packet Block.
    pub const ENHANCED_PACKET: u32 = 0x0000_0006;
}

/// Link-layer header types this reader understands (a subset of the registry).
mod linktype {
    /// BSD loopback: a 4-byte address family in the capturing host's order.
    pub const NULL: u32 = 0;
    /// Ethernet II.
    pub const ETHERNET: u32 = 1;
    /// Raw IP as most BSDs number it (DLT_RAW). OpenBSD uses this number for
    /// its loopback encapsulation, so a frame that is not IP is also tried as
    /// OpenBSD loopback.
    pub const RAW_12: u32 = 12;
    /// Raw IP as OpenBSD numbers it (DLT_RAW).
    pub const RAW_14: u32 = 14;
    /// Raw IP: the packet begins with the IP header.
    pub const RAW: u32 = 101;
    /// OpenBSD loopback: a 4-byte address family, always in network order.
    pub const LOOP: u32 = 108;
    /// Linux cooked capture v1: a 16-byte pseudo-header.
    pub const LINUX_SLL: u32 = 113;
    /// Raw IPv4 only.
    pub const IPV4: u32 = 228;
    /// Raw IPv6 only.
    pub const IPV6: u32 = 229;
    /// Linux cooked capture v2: a 20-byte pseudo-header led by the protocol.
    pub const LINUX_SLL2: u32 = 276;
}

/// The EtherType for IPv4.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// The EtherType for IPv6.
const ETHERTYPE_IPV6: u16 = 0x86dd;

/// The most interfaces tracked per pcapng section. Real captures declare a
/// handful; the cap only bounds memory against a hostile file.
const MAX_INTERFACES: usize = 65_536;
/// The most TCP directions and same-port flows tracked for keep-alive
/// detection and flow orientation. Bounds memory against a capture crafted
/// with a new flow per packet; flows beyond it are simply not tracked.
const MAX_TRACKED_FLOWS: usize = 65_536;

/// TCP header flags this reader inspects.
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// Read a capture and extract the transport payloads that match `options`
/// (FR-2). The returned messages are in capture order, each indexed from zero.
///
/// This is [`extract_capture`] without the account of skipped and dropped
/// packets.
///
/// # Errors
///
/// Returns [`PcapError`] when the bytes are not a recognized capture or its
/// leading framing is unreadable. See [`extract_capture`].
pub fn extract_messages(
    bytes: &[u8],
    options: &ExtractOptions,
) -> Result<Vec<ExtractedMessage>, PcapError> {
    extract_capture(bytes, options).map(|extraction| extraction.messages)
}

/// Read a capture and extract the transport payloads that match `options`,
/// together with an account of what was skipped or dropped (FR-2, FR-5).
///
/// Individual packets that cannot be parsed (an unknown link type, a non-IP
/// frame, a transport or port that does not match) are skipped, not errors: a
/// capture mixing protocols still yields just the matching messages. Matching
/// packets the capture cut short, TCP keep-alive probes, and exact TCP
/// retransmissions are skipped and counted. A truncated or corrupt record or
/// later block ends reading with the messages extracted so far kept and
/// [`Extraction::framing_stopped_at`] set.
///
/// # Errors
///
/// Returns [`PcapError`] when the bytes are not a recognized capture, or when
/// the file header or leading pcapng block is truncated or corrupt.
pub fn extract_capture(bytes: &[u8], options: &ExtractOptions) -> Result<Extraction, PcapError> {
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

/// How to strip one frame's link layer: the link type and the file's byte
/// order, which the BSD loopback header is stored in.
#[derive(Debug, Clone, Copy)]
struct LinkLayer {
    linktype: u32,
    order: ByteOrder,
}

/// One captured frame and what the capture records about it.
struct Record<'a> {
    /// The captured bytes.
    frame: &'a [u8],
    /// The packet's length on the wire, which exceeds the captured length when
    /// the snapshot length cut the packet short.
    original_len: usize,
    /// The capture timestamp in microseconds since the Unix epoch.
    timestamp_micros: u64,
    /// The byte offset of the record within the capture file.
    offset: usize,
}

/// Read a classic libpcap capture (a 24-byte global header followed by records).
fn read_classic(bytes: &[u8], options: &ExtractOptions) -> Result<Extraction, PcapError> {
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
    // The link-layer type is the low 16 bits of the field; the upper bits can
    // carry frame check sequence information and are not part of the type.
    let linktype = order.u32([bytes[20], bytes[21], bytes[22], bytes[23]]) & 0xffff;
    let link = LinkLayer { linktype, order };

    let mut extractor = Extractor::new(options);
    let mut cursor = 24usize;
    while cursor < bytes.len() {
        let Some(header) = bytes.get(cursor..cursor + 16) else {
            // An incomplete record header: a capture cut mid-write. Keep the
            // complete records before it and say where reading stopped.
            extractor.framing_stopped(cursor);
            break;
        };
        let ts_sec = order.u32([header[0], header[1], header[2], header[3]]);
        let ts_frac = order.u32([header[4], header[5], header[6], header[7]]);
        let incl_len = order.u32([header[8], header[9], header[10], header[11]]) as usize;
        let orig_len = order.u32([header[12], header[13], header[14], header[15]]) as usize;
        let start = cursor + 16;
        let Some(end) = start
            .checked_add(incl_len)
            .filter(|&end| end <= bytes.len())
        else {
            // A record that promises more bytes than remain.
            extractor.framing_stopped(cursor);
            break;
        };
        let record = Record {
            frame: &bytes[start..end],
            original_len: orig_len,
            timestamp_micros: timestamp_micros(ts_sec, ts_frac, nanos),
            offset: cursor,
        };
        if !extractor.record(link, &record) {
            break;
        }
        cursor = end;
    }
    Ok(extractor.finish())
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

/// The unit a pcapng interface counts timestamps in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimestampResolution {
    /// Units of ten to the minus this power of a second (microseconds are 6).
    Decimal(u8),
    /// Units of two to the minus this power of a second.
    Binary(u8),
}

/// What a pcapng Interface Description Block declares about its packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Interface {
    /// The link-layer header type of the interface's packets.
    linktype: u32,
    /// The snapshot length, or zero for no limit.
    snaplen: u32,
    /// The timestamp unit (`if_tsresol`, microseconds by default).
    resolution: TimestampResolution,
    /// Seconds added to every timestamp (`if_tsoffset`, zero by default).
    offset_seconds: i64,
}

impl Default for Interface {
    fn default() -> Self {
        Self {
            linktype: linktype::ETHERNET,
            snaplen: 0,
            resolution: TimestampResolution::Decimal(6),
            offset_seconds: 0,
        }
    }
}

impl Interface {
    /// Parse an Interface Description Block body: the link type, a reserved
    /// field, the snapshot length, then options.
    fn parse(body: &[u8], order: ByteOrder) -> Self {
        let mut interface = Interface {
            linktype: order.u16_at(body, 0).map_or(linktype::ETHERNET, u32::from),
            snaplen: order.u32_at(body, 4).unwrap_or(0),
            ..Interface::default()
        };
        // Each option is a code, a length, and a value padded to 32 bits. The
        // cursor strictly advances, so the loop ends within the body.
        let mut cursor = 8usize;
        while let (Some(code), Some(length)) =
            (order.u16_at(body, cursor), order.u16_at(body, cursor + 2))
        {
            let length = usize::from(length);
            let start = cursor + 4;
            let Some(value) = body.get(start..start + length) else {
                break;
            };
            match (code, value) {
                // opt_endofopt
                (0, _) => break,
                // if_tsresol: the top bit picks a binary or decimal exponent.
                (9, [resolution]) => {
                    interface.resolution = if resolution & 0x80 == 0 {
                        TimestampResolution::Decimal(*resolution)
                    } else {
                        TimestampResolution::Binary(resolution & 0x7f)
                    };
                }
                // if_tsoffset: a signed count of seconds.
                (14, [a, b, c, d, e, f, g, h]) => {
                    interface.offset_seconds = order.i64([*a, *b, *c, *d, *e, *f, *g, *h]);
                }
                _ => {}
            }
            cursor = start + length.next_multiple_of(4);
        }
        interface
    }

    /// Convert a raw timestamp in this interface's units to microseconds since
    /// the epoch, applying its offset and saturating rather than overflowing.
    fn timestamp_micros(&self, raw: u64) -> u64 {
        let micros: u128 = match self.resolution {
            TimestampResolution::Decimal(exponent) => {
                let exponent = u32::from(exponent);
                if exponent <= 6 {
                    u128::from(raw) * 10u128.pow(6 - exponent)
                } else if exponent - 6 <= 19 {
                    u128::from(raw / 10u64.pow(exponent - 6))
                } else {
                    0
                }
            }
            // A shift past the width leaves nothing, rather than panicking.
            TimestampResolution::Binary(exponent) => (u128::from(raw) * 1_000_000)
                .checked_shr(u32::from(exponent))
                .unwrap_or(0),
        };
        // `micros` is below 2 to the 84th, so the signed sum cannot overflow.
        let total = micros as i128 + i128::from(self.offset_seconds) * 1_000_000;
        total.clamp(0, i128::from(u64::MAX)) as u64
    }
}

/// Read a pcapng capture: a stream of blocks, starting with a Section Header
/// Block that fixes the byte order, with Interface Description Blocks giving the
/// link type and timestamp unit, and Enhanced, Simple, or obsolete Packet Blocks
/// carrying frames.
fn read_pcapng(bytes: &[u8], options: &ExtractOptions) -> Result<Extraction, PcapError> {
    // A pcapng capture holds at least one complete block, and every block is at
    // least 12 bytes, so the Section Header Block magic alone is not a capture.
    if bytes.len() < 12 {
        return Err(PcapError::Truncated {
            offset: bytes.len(),
        });
    }
    let mut extractor = Extractor::new(options);
    let mut cursor = 0usize;
    let mut order = ByteOrder::Little;
    let mut interfaces: Vec<Interface> = Vec::new();

    while cursor < bytes.len() {
        let first = cursor == 0;
        let Some(head) = bytes.get(cursor..cursor + 8) else {
            extractor.framing_stopped(cursor);
            break;
        };
        // The Section Header Block is identified by its byte-order independent
        // type value; its byte-order magic fixes the order for the section.
        if u32::from_le_bytes([head[0], head[1], head[2], head[3]]) == PCAPNG_SHB_TYPE {
            match pcapng_section_order(bytes, cursor) {
                Ok(section_order) => {
                    order = section_order;
                    // Interface ids are scoped to their section, so a new
                    // section starts its interface table fresh; otherwise a
                    // later section's interface 0 would inherit the previous
                    // section's link type.
                    interfaces.clear();
                }
                Err(error) if first => return Err(error),
                Err(_) => {
                    extractor.framing_stopped(cursor);
                    break;
                }
            }
        }
        let total_len = order.u32([head[4], head[5], head[6], head[7]]) as usize;
        // Every block is at least 12 bytes (type, length, trailing length), is
        // 32-bit aligned, fits in the file, and repeats its length at its end.
        // A block that breaks any of these ends reading: the leading block is
        // an error, a later one keeps what was already extracted.
        let end = cursor
            .checked_add(total_len)
            .filter(|&end| end <= bytes.len());
        let Some(end) = end.filter(|_| total_len >= 12 && total_len % 4 == 0) else {
            if first {
                return Err(PcapError::Truncated { offset: cursor });
            }
            extractor.framing_stopped(cursor);
            break;
        };
        if order.u32_at(bytes, end - 4) != Some(total_len as u32) {
            if first {
                return Err(PcapError::Corrupt { offset: cursor });
            }
            extractor.framing_stopped(cursor);
            break;
        }
        let block_type = order.u32([head[0], head[1], head[2], head[3]]);
        let body = &bytes[cursor + 8..end - 4];
        let keep_going = match block_type {
            block::INTERFACE => {
                if interfaces.len() < MAX_INTERFACES {
                    interfaces.push(Interface::parse(body, order));
                }
                true
            }
            block::ENHANCED_PACKET => {
                pcapng_packet(&mut extractor, body, order, &interfaces, cursor, false)
            }
            block::OBSOLETE_PACKET => {
                pcapng_packet(&mut extractor, body, order, &interfaces, cursor, true)
            }
            block::SIMPLE_PACKET => {
                pcapng_simple_packet(&mut extractor, body, order, &interfaces, cursor)
            }
            _ => true,
        };
        if !keep_going {
            break;
        }
        cursor = end;
    }
    Ok(extractor.finish())
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

/// Feed an Enhanced Packet Block, or an obsolete Packet Block when `obsolete`,
/// to the extractor. Both hold an interface id, a 64-bit timestamp, the
/// captured and original lengths, then the frame; the obsolete block's
/// interface id is 16 bits, followed by a 16-bit drop count. Returns whether
/// reading should continue.
fn pcapng_packet(
    extractor: &mut Extractor<'_>,
    body: &[u8],
    order: ByteOrder,
    interfaces: &[Interface],
    offset: usize,
    obsolete: bool,
) -> bool {
    let interface_id = if obsolete {
        order.u16_at(body, 0).map(usize::from)
    } else {
        order.u32_at(body, 0).map(|id| id as usize)
    };
    let (Some(interface_id), Some(ts_high), Some(ts_low), Some(captured), Some(original)) = (
        interface_id,
        order.u32_at(body, 4),
        order.u32_at(body, 8),
        order.u32_at(body, 12),
        order.u32_at(body, 16),
    ) else {
        return true;
    };
    // A captured length past the block body is corrupt; skip the packet.
    let Some(frame) = 20usize
        .checked_add(captured as usize)
        .and_then(|end| body.get(20..end))
    else {
        return true;
    };
    let interface = interfaces.get(interface_id).copied().unwrap_or_default();
    let raw = (u64::from(ts_high) << 32) | u64::from(ts_low);
    let record = Record {
        frame,
        original_len: original as usize,
        timestamp_micros: interface.timestamp_micros(raw),
        offset,
    };
    let link = LinkLayer {
        linktype: interface.linktype,
        order,
    };
    extractor.record(link, &record)
}

/// Feed a Simple Packet Block to the extractor: the original length, then the
/// frame padded to 32 bits. It has no interface id, so it uses the first
/// declared interface, and it has no timestamp. Its captured length is the
/// original length clipped to that interface's snapshot length, which also
/// trims the padding so it is not fed to the link-layer parser. Returns whether
/// reading should continue.
fn pcapng_simple_packet(
    extractor: &mut Extractor<'_>,
    body: &[u8],
    order: ByteOrder,
    interfaces: &[Interface],
    offset: usize,
) -> bool {
    let Some(original) = order.u32_at(body, 0) else {
        return true;
    };
    let original = original as usize;
    let data = &body[4..];
    let interface = interfaces.first().copied().unwrap_or_default();
    let snaplen = match interface.snaplen {
        0 => usize::MAX,
        limit => limit as usize,
    };
    let captured = original.min(snaplen).min(data.len());
    let record = Record {
        frame: &data[..captured],
        original_len: original,
        timestamp_micros: 0,
        offset,
    };
    let link = LinkLayer {
        linktype: interface.linktype,
        order,
    };
    extractor.record(link, &record)
}

/// The TCP fields the extractor tracks.
#[derive(Debug, Clone, Copy)]
struct TcpHeader {
    seq: u32,
    flags: u8,
}

/// One parsed transport segment that matches the transport and port.
struct Segment<'a> {
    payload: &'a [u8],
    source: Endpoint,
    destination: Endpoint,
    /// Present for TCP.
    tcp: Option<TcpHeader>,
}

/// What a captured frame turned out to be.
enum Parsed<'a> {
    /// A complete segment on the selected transport and port (its payload may
    /// be empty, such as a bare acknowledgement).
    Segment(Segment<'a>),
    /// A segment on the selected transport and port, carrying payload, that the
    /// capture cut short.
    Truncated,
    /// Anything else: another protocol or port, or an unparseable frame.
    Other,
}

/// How the extractor judges one TCP segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpVerdict {
    /// A new segment.
    New,
    /// A keep-alive probe.
    KeepAlive,
    /// An exact copy of a segment already kept.
    Retransmission,
}

/// Turns captured frames into messages, applying the message cap and the
/// truncation, keep-alive, and retransmission rules.
struct Extractor<'o> {
    options: &'o ExtractOptions,
    out: Extraction,
    /// The sequence number each TCP sender is expected to use next, per
    /// direction (source, destination).
    next_seq: BTreeMap<(Endpoint, Endpoint), u32>,
    /// Kept TCP segments by direction, sequence number, and payload hash, to
    /// recognize an exact retransmission.
    kept_segments: BTreeMap<(Endpoint, Endpoint, u32, u64), usize>,
    /// For a flow whose two endpoints both use the selected port, the endpoint
    /// treated as its client.
    clients: BTreeMap<Flow, Endpoint>,
}

impl<'o> Extractor<'o> {
    fn new(options: &'o ExtractOptions) -> Self {
        Self {
            options,
            out: Extraction::default(),
            next_seq: BTreeMap::new(),
            kept_segments: BTreeMap::new(),
            clients: BTreeMap::new(),
        }
    }

    /// Record that the capture's framing ended early at `offset`.
    fn framing_stopped(&mut self, offset: usize) {
        self.out.framing_stopped_at = Some(offset);
    }

    fn finish(self) -> Extraction {
        self.out
    }

    /// Process one captured frame. Returns `false` when extraction must stop
    /// because the message cap was reached with another message waiting.
    fn record(&mut self, link: LinkLayer, record: &Record<'_>) -> bool {
        let cut_short = record.frame.len() < record.original_len;
        let segment = match parse_frame(link, record.frame, cut_short, self.options) {
            Parsed::Other => return true,
            Parsed::Truncated => {
                self.out.truncated_packets += 1;
                return true;
            }
            Parsed::Segment(segment) => segment,
        };
        // Orient before discarding empty segments, so a SYN establishes which
        // side of a same-port flow is the client.
        let direction = self.direction(&segment);
        if let Some(tcp) = segment.tcp {
            match self.classify_tcp(&segment, tcp) {
                TcpVerdict::KeepAlive => {
                    if !segment.payload.is_empty() {
                        self.out.keepalives_dropped += 1;
                    }
                    return true;
                }
                TcpVerdict::Retransmission => {
                    self.out.retransmissions_dropped += 1;
                    return true;
                }
                TcpVerdict::New => {}
            }
        }
        if segment.payload.is_empty() {
            return true;
        }
        if self.out.messages.len() >= self.options.max_messages {
            self.out.message_cap_reached = true;
            return false;
        }
        let index = self.out.messages.len();
        if let Some(tcp) = segment.tcp {
            let key = (
                segment.source,
                segment.destination,
                tcp.seq,
                payload_hash(segment.payload),
            );
            self.kept_segments.entry(key).or_insert(index);
        }
        self.out.messages.push(ExtractedMessage {
            data: segment.payload.to_vec(),
            direction,
            flow: Flow::canonical(segment.source, segment.destination),
            source: segment.source,
            destination: segment.destination,
            timestamp_micros: record.timestamp_micros,
            capture_offset: record.offset as u64,
            index,
        });
        true
    }

    /// Which way a segment travels. Toward the selected port is a request and
    /// away from it a response; when both endpoints use the selected port, the
    /// endpoint that sent first on the flow (or the target of a first SYN-ACK)
    /// is the client.
    fn direction(&mut self, segment: &Segment<'_>) -> Direction {
        let port = self.options.port;
        if segment.source.port == port && segment.destination.port == port {
            let flow = Flow::canonical(segment.source, segment.destination);
            let client = match self.clients.get(&flow) {
                Some(&client) => client,
                None => {
                    let syn_ack = segment
                        .tcp
                        .is_some_and(|tcp| tcp.flags & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK);
                    let client = if syn_ack {
                        segment.destination
                    } else {
                        segment.source
                    };
                    if self.clients.len() < MAX_TRACKED_FLOWS {
                        self.clients.insert(flow, client);
                    }
                    client
                }
            };
            if segment.source == client {
                Direction::ToServer
            } else {
                Direction::FromServer
            }
        } else if segment.destination.port == port {
            Direction::ToServer
        } else {
            Direction::FromServer
        }
    }

    /// Classify a TCP segment against the sender's sequence tracking and the
    /// segments already kept, then advance the tracking.
    fn classify_tcp(&mut self, segment: &Segment<'_>, tcp: TcpHeader) -> TcpVerdict {
        let key = (segment.source, segment.destination);
        let length = segment.payload.len();
        let control = tcp.flags & (TCP_SYN | TCP_FIN | TCP_RST) != 0;
        // A keep-alive probe re-sends the byte just before the sender's next
        // sequence number, with at most one byte of payload and no SYN, FIN,
        // or RST; it carries no new data.
        let expected = self.next_seq.get(&key).copied();
        if !control && length <= 1 && expected.is_some_and(|next| tcp.seq == next.wrapping_sub(1)) {
            return TcpVerdict::KeepAlive;
        }
        // SYN and FIN each occupy one sequence number. Only a segment that
        // reaches past the current expectation (in modular order) advances it.
        let advance = (length as u32)
            .wrapping_add(u32::from(tcp.flags & TCP_SYN != 0))
            .wrapping_add(u32::from(tcp.flags & TCP_FIN != 0));
        let end = tcp.seq.wrapping_add(advance);
        match self.next_seq.get_mut(&key) {
            Some(next) => {
                if (end.wrapping_sub(*next) as i32) > 0 {
                    *next = end;
                }
            }
            None => {
                if self.next_seq.len() < MAX_TRACKED_FLOWS {
                    self.next_seq.insert(key, end);
                }
            }
        }
        if length > 0 {
            let lookup = (
                segment.source,
                segment.destination,
                tcp.seq,
                payload_hash(segment.payload),
            );
            if let Some(&index) = self.kept_segments.get(&lookup) {
                // Compare the bytes too, so a hash collision is never dropped.
                if self
                    .out
                    .messages
                    .get(index)
                    .is_some_and(|kept| kept.data == segment.payload)
                {
                    return TcpVerdict::Retransmission;
                }
            }
        }
        TcpVerdict::New
    }
}

/// A deterministic hash of a payload, used to index kept TCP segments.
fn payload_hash(payload: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    payload.hash(&mut hasher);
    hasher.finish()
}

/// Walk a link-layer frame down to the transport segment, classifying it as a
/// complete matching segment, a matching segment the capture cut short, or
/// something else. `cut_short` says the capture recorded fewer bytes than the
/// packet had on the wire.
fn parse_frame<'a>(
    link: LinkLayer,
    frame: &'a [u8],
    cut_short: bool,
    options: &ExtractOptions,
) -> Parsed<'a> {
    let Some((ethertype, network)) = strip_link_layer(link, frame) else {
        return Parsed::Other;
    };
    let packet = match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4(network),
        ETHERTYPE_IPV6 => parse_ipv6(network),
        _ => None,
    };
    let Some(packet) = packet else {
        return Parsed::Other;
    };
    if packet.protocol != options.transport.protocol_number() {
        return Parsed::Other;
    }
    let transport = packet.payload;
    // The ports are needed to tell whether the packet matters at all; a packet
    // cut before them cannot be attributed and is not counted.
    let Some(ports) = transport.get(0..4) else {
        return Parsed::Other;
    };
    let src_port = u16::from_be_bytes([ports[0], ports[1]]);
    let dst_port = u16::from_be_bytes([ports[2], ports[3]]);
    if src_port != options.port && dst_port != options.port {
        return Parsed::Other;
    }
    let cut = cut_short || !packet.complete;
    let (payload, tcp) = match options.transport {
        Transport::Tcp => {
            if cut {
                // Some of the segment is missing. It matters only if it
                // declared payload beyond its header.
                let header_len = transport
                    .get(12)
                    .map_or(20, |&byte| usize::from(byte >> 4) * 4);
                return if packet.declared_len > header_len {
                    Parsed::Truncated
                } else {
                    Parsed::Other
                };
            }
            let Some((seq, flags, payload)) = parse_tcp(transport) else {
                return Parsed::Other;
            };
            (payload, Some(TcpHeader { seq, flags }))
        }
        Transport::Udp => {
            let Some(length) = transport.get(4..6) else {
                return if cut && packet.declared_len > 8 {
                    Parsed::Truncated
                } else {
                    Parsed::Other
                };
            };
            let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
            // The UDP length covers the header plus data. One below the header
            // size is malformed; one past the captured bytes is cut short.
            if length < 8 {
                return Parsed::Other;
            }
            if cut || length > transport.len() {
                return if length > 8 {
                    Parsed::Truncated
                } else {
                    Parsed::Other
                };
            }
            (&transport[8..length], None)
        }
    };
    Parsed::Segment(Segment {
        payload,
        source: Endpoint {
            addr: packet.source,
            port: src_port,
        },
        destination: Endpoint {
            addr: packet.destination,
            port: dst_port,
        },
        tcp,
    })
}

/// Strip the link-layer header, returning the EtherType (or a synthesized one
/// for link types that carry IP directly) and the network-layer bytes.
fn strip_link_layer(link: LinkLayer, frame: &[u8]) -> Option<(u16, &[u8])> {
    match link.linktype {
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
        linktype::RAW | linktype::RAW_14 => Some((ethertype_for_ip(frame)?, frame)),
        // DLT_RAW on most BSDs, but OpenBSD's loopback shares the number.
        linktype::RAW_12 => match ethertype_for_ip(frame) {
            Some(ethertype) => Some((ethertype, frame)),
            None => strip_loopback(frame, ByteOrder::Big),
        },
        linktype::IPV4 => (frame.first()? >> 4 == 4).then_some((ETHERTYPE_IPV4, frame)),
        linktype::IPV6 => (frame.first()? >> 4 == 6).then_some((ETHERTYPE_IPV6, frame)),
        // The address family is stored in the capturing host's byte order,
        // which is the order the file itself was written in.
        linktype::NULL => strip_loopback(frame, link.order),
        // OpenBSD loopback always stores the family in network byte order.
        linktype::LOOP => strip_loopback(frame, ByteOrder::Big),
        linktype::LINUX_SLL => {
            // The EtherType-like protocol sits at offset 14 in the 16-byte header.
            let ethertype = u16::from_be_bytes([*frame.get(14)?, *frame.get(15)?]);
            Some((ethertype, frame.get(16..)?))
        }
        linktype::LINUX_SLL2 => {
            // The protocol leads the 20-byte header.
            let ethertype = ByteOrder::Big.u16_at(frame, 0)?;
            Some((ethertype, frame.get(20..)?))
        }
        _ => None,
    }
}

/// Strip a 4-byte loopback address-family header read in `order`. Address
/// families are small numbers, so a value with any of its upper 16 bits set was
/// written in the other byte order (a capture moved between hosts) and is
/// swapped back.
fn strip_loopback(frame: &[u8], order: ByteOrder) -> Option<(u16, &[u8])> {
    let family = order.u32_at(frame, 0)?;
    let family = if family & 0xffff_0000 != 0 {
        family.swap_bytes()
    } else {
        family
    };
    // 2 is IPv4 everywhere; 24, 28, and 30 are IPv6 on NetBSD and OpenBSD,
    // FreeBSD, and Darwin respectively.
    let ethertype = match family {
        2 => ETHERTYPE_IPV4,
        24 | 28 | 30 => ETHERTYPE_IPV6,
        _ => return None,
    };
    Some((ethertype, frame.get(4..)?))
}

/// Infer an EtherType from the IP version nibble for raw-IP link types.
fn ethertype_for_ip(frame: &[u8]) -> Option<u16> {
    match frame.first()? >> 4 {
        4 => Some(ETHERTYPE_IPV4),
        6 => Some(ETHERTYPE_IPV6),
        _ => None,
    }
}

/// A parsed IP header and the transport bytes it carries.
struct IpPacket<'a> {
    protocol: u8,
    source: IpAddr,
    destination: IpAddr,
    /// The transport bytes present in the capture, up to the declared end.
    payload: &'a [u8],
    /// The transport length the IP header declares.
    declared_len: usize,
    /// Whether every declared byte is present in the capture.
    complete: bool,
}

/// Parse an IPv4 header, returning the protocol, addresses, and transport
/// bytes, with whether the capture holds all of them.
fn parse_ipv4(bytes: &[u8]) -> Option<IpPacket<'_>> {
    let first = *bytes.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(first & 0x0f) * 4;
    if ihl < 20 || bytes.len() < ihl {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    // Skip fragmented datagrams. Only the first fragment carries the transport
    // header; a later fragment begins with arbitrary payload that could be
    // misread as ports. The more-fragments flag (0x2000) or a nonzero fragment
    // offset (low 13 bits) marks a fragment, and reassembly is out of scope.
    let frag = u16::from_be_bytes([bytes[6], bytes[7]]);
    if frag & 0x2000 != 0 || frag & 0x1fff != 0 {
        return None;
    }
    let protocol = bytes[9];
    let source = IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]));
    let destination = IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]));
    // The total length bounds the datagram, so trailing Ethernet padding on a
    // short frame is not mistaken for payload. A zero total length is what
    // captures of TCP segmentation offload record for large segments, so the
    // captured bytes are used; any other length below the header is malformed.
    let (end, complete) = if total_len == 0 {
        (bytes.len(), true)
    } else if total_len < ihl {
        return None;
    } else if total_len <= bytes.len() {
        (total_len, true)
    } else {
        (bytes.len(), false)
    };
    let declared_len = if total_len == 0 {
        bytes.len() - ihl
    } else {
        total_len - ihl
    };
    Some(IpPacket {
        protocol,
        source,
        destination,
        payload: &bytes[ihl..end],
        declared_len,
        complete,
    })
}

/// Parse a fixed IPv6 header, returning the next-header protocol, addresses,
/// and transport bytes, with whether the capture holds all of them.
/// Extension-header chains and jumbograms are not followed; a packet that uses
/// them is skipped rather than misparsed.
fn parse_ipv6(bytes: &[u8]) -> Option<IpPacket<'_>> {
    if bytes.len() < 40 || bytes[0] >> 4 != 6 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    if payload_len == 0 {
        return None;
    }
    let protocol = bytes[6];
    let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?));
    let destination = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).ok()?));
    let available = bytes.len() - 40;
    let complete = payload_len <= available;
    let end = 40 + payload_len.min(available);
    Some(IpPacket {
        protocol,
        source,
        destination,
        payload: &bytes[40..end],
        declared_len: payload_len,
        complete,
    })
}

/// Parse a TCP header, returning the sequence number, the flags, and the
/// payload after the header.
fn parse_tcp(bytes: &[u8]) -> Option<(u32, u8, &[u8])> {
    if bytes.len() < 20 {
        return None;
    }
    let seq = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let data_offset = usize::from(bytes[12] >> 4) * 4;
    if data_offset < 20 {
        return None;
    }
    let flags = bytes[13];
    let payload = bytes.get(data_offset..)?;
    Some((seq, flags, payload))
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
        let messages =
            extract_messages(&pcap, &ExtractOptions::new(Transport::Tcp, 502)).expect("parse pcap");
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
        let none =
            extract_messages(&pcap, &ExtractOptions::new(Transport::Tcp, 9999)).expect("parse");
        assert!(none.is_empty());
        // The wrong transport matches nothing.
        let udp =
            extract_messages(&pcap, &ExtractOptions::new(Transport::Udp, 502)).expect("parse");
        assert!(udp.is_empty());
    }

    #[test]
    fn extracts_udp_payloads() {
        let pcap = build_pcap(Transport::Udp, 1234, &[(b"datagram", true)]);
        let messages =
            extract_messages(&pcap, &ExtractOptions::new(Transport::Udp, 1234)).expect("parse");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].data, b"datagram");
    }

    #[test]
    fn rejects_non_capture_bytes() {
        assert_eq!(
            extract_messages(b"not a pcap file", &ExtractOptions::new(Transport::Tcp, 1)),
            Err(PcapError::UnknownFormat)
        );
    }

    #[test]
    fn empty_input_is_unknown_not_a_panic() {
        assert_eq!(
            extract_messages(&[], &ExtractOptions::new(Transport::Tcp, 1)),
            Err(PcapError::UnknownFormat)
        );
    }

    #[test]
    fn truncated_final_record_is_dropped_cleanly() {
        let mut pcap = build_pcap(Transport::Tcp, 502, &[(b"whole", true)]);
        let cut_at = pcap.len();
        // Append a record header that promises more bytes than remain.
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&1000u32.to_le_bytes());
        pcap.extend_from_slice(&1000u32.to_le_bytes());
        let extraction =
            extract_capture(&pcap, &ExtractOptions::new(Transport::Tcp, 502)).expect("parse");
        assert_eq!(extraction.messages.len(), 1);
        // Where reading stopped is reported, not silently dropped.
        assert_eq!(extraction.framing_stopped_at, Some(cut_at));
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
        let messages =
            extract_messages(&pcap, &ExtractOptions::new(Transport::Tcp, 502)).expect("parse");
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
        out.extend_from_slice(&block(block::INTERFACE, &idb_body));
        out.extend_from_slice(&block(block::ENHANCED_PACKET, &epb_body));
        out
    }

    #[test]
    fn reads_pcapng_enhanced_packet_blocks() {
        let frame = build_frame(Transport::Tcp, 502, b"modbus-like", true);
        let pcapng = build_pcapng(&frame);
        let messages = extract_messages(&pcapng, &ExtractOptions::new(Transport::Tcp, 502))
            .expect("parse pcapng");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].data, b"modbus-like");
        assert_eq!(messages[0].direction, Direction::ToServer);
    }

    #[test]
    fn interface_timestamps_honor_resolution_and_offset() {
        let micro = Interface::default();
        assert_eq!(micro.timestamp_micros(1_500_000), 1_500_000);
        let nano = Interface {
            resolution: TimestampResolution::Decimal(9),
            ..Interface::default()
        };
        assert_eq!(nano.timestamp_micros(1_500_000_000), 1_500_000);
        let milli = Interface {
            resolution: TimestampResolution::Decimal(3),
            offset_seconds: 10,
            ..Interface::default()
        };
        assert_eq!(milli.timestamp_micros(1_500), 11_500_000);
        // 2 to the minus 20th of a second: 2 to the 20th units is one second.
        let binary = Interface {
            resolution: TimestampResolution::Binary(20),
            ..Interface::default()
        };
        assert_eq!(binary.timestamp_micros(1 << 20), 1_000_000);
        // Extreme values saturate instead of overflowing or panicking.
        let extreme = Interface {
            resolution: TimestampResolution::Decimal(0),
            offset_seconds: i64::MAX,
            ..Interface::default()
        };
        assert_eq!(extreme.timestamp_micros(u64::MAX), u64::MAX);
        let tiny = Interface {
            resolution: TimestampResolution::Decimal(127),
            offset_seconds: i64::MIN,
            ..Interface::default()
        };
        assert_eq!(tiny.timestamp_micros(u64::MAX), 0);
        let fine = Interface {
            resolution: TimestampResolution::Binary(127),
            ..Interface::default()
        };
        assert_eq!(fine.timestamp_micros(u64::MAX), 0);
    }

    #[test]
    fn capture_notices_avoid_dashes() {
        let notices = [
            CaptureNotice::TruncatedPackets { count: 2 },
            CaptureNotice::KeepAlivesDropped { count: 1 },
            CaptureNotice::RetransmissionsDropped { count: 3 },
            CaptureNotice::FramingStopped { offset: 40 },
        ];
        for notice in notices {
            let message = notice.to_string();
            assert!(!message.contains('\u{2014}'), "em dash in: {message}");
            assert!(!message.contains('\u{2013}'), "en dash in: {message}");
        }
        let error = PcapError::Corrupt { offset: 0 }.to_string();
        assert!(!error.contains('\u{2014}') && !error.contains('\u{2013}'));
    }
}
