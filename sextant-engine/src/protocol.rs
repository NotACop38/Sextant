//! Protocol message clustering, association, and field inference (FR-2,
//! PRD Section 6.2).
//!
//! Where file-format inference works from a set of files, protocol inference
//! works from the messages [`crate::pcap::extract_messages`] pulls out of a
//! capture. This module turns those messages into a verified Format Hypothesis
//! IR with protocol-oriented semantics:
//!
//! - [`cluster_messages`] groups messages by message type, by finding the byte
//!   offset whose value best discriminates the message structure. This separates
//!   distinct message types without being told where the type field is.
//! - [`associate`] pairs requests with responses on the same flow, the basis for
//!   request and response analysis.
//! - [`infer_protocol`] detects the length, message-type, and sequence fields,
//!   assembles a header and payload, and verifies the result against every
//!   message through the same executor and scorer the file-format pipeline uses.
//!   It never returns a hypothesis that scores below the statistics-only
//!   baseline (the non-regression invariant, FR-26).
//!
//! Every function is bounded and panic-free: an empty message set, a single
//! message, or hostile bytes all yield a valid (possibly trivial) result.

use std::collections::BTreeMap;

use sextant_ir::{
    Bytes, Confidence, Constraint, Endianness, EnumDef, EnumVariant, Evidence, Field, FieldRef,
    Format, Kind, Metadata, Role, SampleSupport, Signedness, SizeRule, Structure,
};

use crate::candidate::infer_candidates;
use crate::limits::Limits;
use crate::pcap::{Direction, ExtractedMessage, Flow, Transport};
use crate::refine::refine;
use crate::report::{Report, RunMetadata};
use crate::scorer::{Score, ScoreWeights, score_with};

/// The most leading bytes a discriminant or field detector scans in a message.
const MAX_SCAN: usize = 16;
/// The most distinct values a byte may take and still be treated as a message
/// type rather than a counter or a payload byte.
const MAX_MESSAGE_TYPES: usize = 16;

/// One group of messages that share a message type (FR-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cluster {
    /// The discriminating byte value shared by the group, when clustering found
    /// a discriminant.
    pub type_value: Option<u8>,
    /// The indices of the messages in the group, in capture order.
    pub indices: Vec<usize>,
}

/// The byte offset whose value separates message types, and the values seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discriminant {
    /// The byte offset of the discriminating field.
    pub offset: usize,
    /// The distinct values seen at that offset, ascending.
    pub values: Vec<u8>,
}

/// The result of clustering messages by type (FR-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clustering {
    /// The discriminant the clustering found, or `None` when the messages did
    /// not separate into types (one cluster).
    pub discriminant: Option<Discriminant>,
    /// The clusters, ordered by their discriminating value.
    pub clusters: Vec<Cluster>,
}

/// One request paired with its response on the same flow (FR-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Association {
    /// The index of the request message (toward the selected port).
    pub request: usize,
    /// The index of the response message (away from the selected port).
    pub response: usize,
}

/// Cluster messages into types by finding the most discriminating byte (FR-2).
///
/// The chosen offset is the one whose value best explains the variation in
/// message structure: grouping by it makes the other header bytes most
/// consistent within each group and the message lengths most uniform. A byte
/// that is constant (one value) or unique to each message (a counter) is never a
/// discriminant. When nothing discriminates, every message lands in one cluster.
#[must_use]
pub fn cluster_messages(messages: &[ExtractedMessage]) -> Clustering {
    // When both directions are present, cluster over the requests alone: mixing
    // a request with its differently shaped response blurs the per-type
    // regularity a message type induces. With one direction (or too few
    // requests) every message is used.
    let request_indices: Vec<usize> = messages
        .iter()
        .enumerate()
        .filter(|(_, m)| m.direction == Direction::ToServer)
        .map(|(index, _)| index)
        .collect();
    let population: Vec<usize> =
        if request_indices.len() >= 4 && request_indices.len() < messages.len() {
            request_indices
        } else {
            (0..messages.len()).collect()
        };

    let datas: Vec<&[u8]> = population
        .iter()
        .map(|&index| messages[index].data.as_slice())
        .collect();
    let mut clustering = cluster_slices(&datas);
    // Remap the population-local indices back to original message indices.
    for cluster in &mut clustering.clusters {
        for index in &mut cluster.indices {
            *index = population[*index];
        }
    }
    clustering
}

/// Cluster raw message slices (the testable core of [`cluster_messages`]).
fn cluster_slices(datas: &[&[u8]]) -> Clustering {
    if datas.len() < 2 {
        let indices = (0..datas.len()).collect();
        return Clustering {
            discriminant: None,
            clusters: vec![Cluster {
                type_value: None,
                indices,
            }],
        };
    }
    let min_len = datas.iter().map(|d| d.len()).min().unwrap_or(0);
    let scan = min_len.min(MAX_SCAN);

    // The message type is the categorical byte whose values recur in balanced
    // groups and whose grouping makes the rest of the header most regular. The
    // quality of an offset is its within-type structural consistency weighted by
    // how many messages fall into a recurring (multi-member) group, so a noisy
    // data byte with one dominant value and a stray singleton cannot win on a
    // technicality. Ties break toward fewer types, then the earliest offset. A
    // constant byte (one value) or a near-unique counter is never a type.
    let mut best: Option<(usize, usize, f64)> = None;
    for offset in 0..scan {
        let values: Vec<u8> = datas.iter().map(|d| d[offset]).collect();
        let cardinality = distinct_count(&values);
        if !(2..=MAX_MESSAGE_TYPES).contains(&cardinality) || cardinality == datas.len() {
            continue;
        }
        if !has_recurring_value(&values) {
            continue;
        }
        let quality = structural_consistency(datas, offset, scan) * recurrence_ratio(&values);
        if quality <= 0.0 {
            continue;
        }
        let better = match best {
            None => true,
            Some((_, best_card, best_quality)) => {
                quality > best_quality + 1e-9
                    || ((quality - best_quality).abs() <= 1e-9 && cardinality < best_card)
            }
        };
        if better {
            best = Some((offset, cardinality, quality));
        }
    }

    match best {
        Some((offset, _, _)) => {
            let mut groups: BTreeMap<u8, Vec<usize>> = BTreeMap::new();
            for (index, data) in datas.iter().enumerate() {
                groups.entry(data[offset]).or_default().push(index);
            }
            let values: Vec<u8> = groups.keys().copied().collect();
            let clusters = groups
                .into_iter()
                .map(|(value, indices)| Cluster {
                    type_value: Some(value),
                    indices,
                })
                .collect();
            Clustering {
                discriminant: Some(Discriminant { offset, values }),
                clusters,
            }
        }
        None => Clustering {
            discriminant: None,
            clusters: vec![Cluster {
                type_value: None,
                indices: (0..datas.len()).collect(),
            }],
        },
    }
}

/// How consistent the non-discriminant header bytes become when messages are
/// grouped by the byte at `offset`: the fraction of the other scanned columns
/// that are constant within each group, averaged over the groups that have more
/// than one member. Single-member groups are ignored because their columns are
/// trivially constant and would reward a near-unique counter. A real message
/// type makes the rest of its header regular, so this is high for it.
fn structural_consistency(datas: &[&[u8]], offset: usize, scan: usize) -> f64 {
    if scan <= 1 {
        return 0.0;
    }
    let mut groups: BTreeMap<u8, Vec<usize>> = BTreeMap::new();
    for (index, data) in datas.iter().enumerate() {
        groups.entry(data[offset]).or_default().push(index);
    }
    let mut total = 0.0;
    let mut counted = 0usize;
    for indices in groups.values() {
        if indices.len() < 2 {
            continue;
        }
        let mut constant_columns = 0usize;
        for column in 0..scan {
            if column == offset {
                continue;
            }
            let first = datas[indices[0]][column];
            if indices.iter().all(|&i| datas[i][column] == first) {
                constant_columns += 1;
            }
        }
        total += constant_columns as f64 / (scan - 1) as f64;
        counted += 1;
    }
    if counted == 0 {
        0.0
    } else {
        total / counted as f64
    }
}

/// Whether some value at this column appears in more than one message, so the
/// column is categorical (a recurring type) rather than a per-message counter.
fn has_recurring_value(values: &[u8]) -> bool {
    let mut counts = [0u32; 256];
    for &value in values {
        counts[value as usize] += 1;
    }
    counts.iter().any(|&count| count > 1)
}

/// The fraction of messages whose value at this column is shared by at least one
/// other message (it falls in a recurring group). A real message type partitions
/// the messages into balanced recurring groups, so this is near one; a noisy byte
/// with a dominant value and stray singletons scores lower.
fn recurrence_ratio(values: &[u8]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &value in values {
        counts[value as usize] += 1;
    }
    let recurring = values
        .iter()
        .filter(|&&value| counts[value as usize] >= 2)
        .count();
    recurring as f64 / values.len() as f64
}

/// The number of distinct byte values in a slice.
fn distinct_count(values: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut count = 0usize;
    for &value in values {
        if !seen[value as usize] {
            seen[value as usize] = true;
            count += 1;
        }
    }
    count
}

/// Pair each request with the earliest later response on the same flow (FR-2).
///
/// A request travels toward the selected port and a response away from it; the
/// flow is the unordered endpoint pair, so a request and its reply share it.
/// Each response is matched to at most one request, preserving capture order.
///
/// Runs in linear time in the number of messages: responses are queued per flow,
/// then each request pops the earliest unused later response on its flow. The
/// previous nested scan was quadratic and could dominate on large captures even
/// when [`DEFAULT_MAX_MESSAGES`](crate::pcap::DEFAULT_MAX_MESSAGES) caps `n`.
#[must_use]
pub fn associate(messages: &[ExtractedMessage]) -> Vec<Association> {
    use std::collections::{BTreeMap, VecDeque};

    let mut response_queues: BTreeMap<Flow, VecDeque<usize>> = BTreeMap::new();
    for (index, message) in messages.iter().enumerate() {
        if message.direction == Direction::FromServer {
            response_queues
                .entry(message.flow)
                .or_default()
                .push_back(index);
        }
    }

    let mut associations = Vec::new();
    for (request_index, request) in messages.iter().enumerate() {
        if request.direction != Direction::ToServer {
            continue;
        }
        let Some(queue) = response_queues.get_mut(&request.flow) else {
            continue;
        };
        while let Some(&front) = queue.front() {
            if front <= request_index {
                // A response that arrived before this request cannot answer it.
                queue.pop_front();
                continue;
            }
            queue.pop_front();
            associations.push(Association {
                request: request_index,
                response: front,
            });
            break;
        }
    }
    associations
}

/// The verified outcome of protocol inference (FR-2).
#[derive(Debug, Clone)]
pub struct ProtocolInference {
    /// The machine-readable report carrying the chosen IR and its score.
    pub report: Report,
    /// How the messages clustered by type.
    pub clustering: Clustering,
    /// The request and response pairs found.
    pub associations: Vec<Association>,
    /// How many messages were analyzed.
    pub message_count: usize,
}

/// Infer a verified protocol Format from extracted messages (FR-2).
///
/// The pass detects the length, message-type, and sequence fields, assembles a
/// header and a payload, and scores the result against every message. If the
/// assembled hypothesis does not beat the statistics-only baseline, the baseline
/// is used instead, so enabling protocol semantics never lowers the verified fit
/// (FR-26). The transport and port are recorded in the format metadata so the
/// Wireshark exporter can bind the generated dissector to the port.
#[must_use]
pub fn infer_protocol(
    messages: &[ExtractedMessage],
    transport: Transport,
    port: u16,
    limits: &Limits,
) -> ProtocolInference {
    let clustering = cluster_messages(messages);
    let associations = associate(messages);
    let datas: Vec<&[u8]> = messages.iter().map(|m| m.data.as_slice()).collect();
    let total_bytes: usize = datas.iter().map(|d| d.len()).sum();

    let (format, score) = build_verified(messages, &datas, &clustering, transport, port, limits);

    let metadata = RunMetadata {
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        sample_count: messages.len(),
        total_bytes,
        no_llm: true,
    };
    let report = Report::build(format, score, Vec::new(), metadata);

    ProtocolInference {
        report,
        clustering,
        associations,
        message_count: messages.len(),
    }
}

/// Build the protocol Format and choose it only when it scores at least as well
/// as the statistics-only baseline (the non-regression invariant, FR-26).
fn build_verified(
    messages: &[ExtractedMessage],
    datas: &[&[u8]],
    clustering: &Clustering,
    transport: Transport,
    port: u16,
    limits: &Limits,
) -> (Format, Score) {
    let (mut baseline_format, baseline_score) = baseline_format(datas, limits);

    if let Some(format) = assemble(messages, datas, clustering, transport, port) {
        if format.validate().is_ok() {
            let score = score_with(&format, datas, limits, ScoreWeights::default());
            if score.overall + 1e-9 >= baseline_score.overall {
                return (format, score);
            }
        }
    }
    // The protocol-specific assembly was absent or did not beat the baseline. The
    // baseline still came from a capture, so it carries the transport and port so
    // the Wireshark exporter binds the dissector to the port in this case too.
    set_protocol_metadata(&mut baseline_format, transport, port);
    (baseline_format, baseline_score)
}

/// Record the capture's transport and port in a format's metadata, so the
/// Wireshark exporter binds the generated dissector to the port (Step 11).
fn set_protocol_metadata(format: &mut Format, transport: Transport, port: u16) {
    format
        .metadata
        .extra
        .insert("protocol.transport".to_owned(), transport.to_string());
    format
        .metadata
        .extra
        .insert("protocol.port".to_owned(), port.to_string());
}

/// The statistics-only baseline: the best refined candidate from the file-format
/// pipeline, used as the floor protocol inference must not fall below.
fn baseline_format(datas: &[&[u8]], limits: &Limits) -> (Format, Score) {
    let candidates = infer_candidates(datas, limits);
    let best = candidates
        .into_iter()
        .next()
        .map(|candidate| candidate.format)
        .unwrap_or_else(opaque_format);
    let refined = refine(&best, datas, limits);
    (refined.format, refined.score)
}

/// A trivial opaque-to-end format, the unreachable fallback when even candidate
/// generation yields nothing.
fn opaque_format() -> Format {
    Format {
        name: "protocol".to_owned(),
        endianness: Endianness::Big,
        root: Structure::new(vec![Field {
            name: Some("payload".to_owned()),
            kind: Kind::Opaque,
            size: Some(SizeRule::ToEnd),
            offset: None,
            role: Some(Role::Payload),
            constraints: Vec::new(),
            confidence: Confidence::clamped(0.2),
            evidence: Evidence::default(),
        }]),
        enums: BTreeMap::new(),
        metadata: Metadata::default(),
    }
}

/// A detected length field: its value equals the message length minus a constant
/// header offset `k` (the bytes the length does not count).
#[derive(Debug, Clone, Copy)]
struct LengthField {
    offset: usize,
    width: usize,
    big_endian: bool,
    k: usize,
}

/// A detected sequence or transaction field: an integer that increases across
/// the requests on a flow.
#[derive(Debug, Clone, Copy)]
struct SeqField {
    offset: usize,
    width: usize,
    big_endian: bool,
}

/// Assemble a protocol Format from the detected length, message-type, and
/// sequence fields, plus the constant and variable header bytes between them and
/// a trailing payload. Returns `None` when no protocol field is detected, so the
/// baseline covers that case.
fn assemble(
    messages: &[ExtractedMessage],
    datas: &[&[u8]],
    clustering: &Clustering,
    transport: Transport,
    port: u16,
) -> Option<Format> {
    if datas.is_empty() {
        return None;
    }
    let min_len = datas.iter().map(|d| d.len()).min().unwrap_or(0);
    if min_len == 0 {
        return None;
    }

    let length = detect_length_field(datas, min_len);
    let big_endian_default = length.is_none_or(|l| l.big_endian);
    let msgtype = clustering
        .discriminant
        .as_ref()
        .filter(|d| d.offset < min_len)
        .map(|d| (d.offset, d.values.clone()));
    let seq = detect_sequence_field(
        messages,
        datas,
        min_len,
        length,
        msgtype.as_ref(),
        big_endian_default,
    );

    if length.is_none() && msgtype.is_none() && seq.is_none() {
        return None;
    }

    // Collect the semantic fields by their span, resolving overlaps by
    // precedence: length, then message type, then sequence.
    let mut spans: Vec<(usize, usize, Semantic)> = Vec::new();
    if let Some(length) = length {
        add_span(
            &mut spans,
            length.offset,
            length.width,
            Semantic::Length(length),
        );
    }
    if let Some((offset, values)) = &msgtype {
        add_span(
            &mut spans,
            *offset,
            1,
            Semantic::MessageType(values.clone()),
        );
    }
    if let Some(seq) = seq {
        add_span(&mut spans, seq.offset, seq.width, Semantic::Sequence(seq));
    }
    spans.sort_by_key(|(offset, _, _)| *offset);

    let header_end = spans.iter().map(|(_, end, _)| *end).max().unwrap_or(0);
    let starts: BTreeMap<usize, (usize, Semantic)> = spans
        .iter()
        .cloned()
        .map(|(offset, end, sem)| (offset, (end, sem)))
        .collect();

    let mut enums: BTreeMap<String, EnumDef> = BTreeMap::new();
    let mut fields: Vec<Field> = Vec::new();
    let total = datas.len();
    let mut cursor = 0usize;
    while cursor < header_end {
        if let Some((end, sem)) = starts.get(&cursor) {
            fields.push(semantic_field(sem, &mut enums, total));
            cursor = *end;
            continue;
        }
        // An undetected run: extend it while the column-constant category holds
        // and no semantic field starts.
        let constant = column_constant(datas, cursor);
        let start = cursor;
        cursor += 1;
        while cursor < header_end
            && !starts.contains_key(&cursor)
            && column_constant(datas, cursor) == constant
        {
            cursor += 1;
        }
        fields.push(filler_field(datas, start, cursor, constant, total));
    }

    fields.push(payload_field(length, header_end, total));

    let mut metadata = Metadata {
        source: Some("protocol inference pass".to_owned()),
        description: Some(format!(
            "Inferred from a {transport} capture on port {port}."
        )),
        ..Default::default()
    };
    metadata
        .extra
        .insert("protocol.transport".to_owned(), transport.to_string());
    metadata
        .extra
        .insert("protocol.port".to_owned(), port.to_string());

    Some(Format {
        name: format!("{transport}_{port}"),
        endianness: if big_endian_default {
            Endianness::Big
        } else {
            Endianness::Little
        },
        root: Structure::new(fields),
        enums,
        metadata,
    })
}

/// A detected semantic header field.
#[derive(Debug, Clone)]
enum Semantic {
    Length(LengthField),
    MessageType(Vec<u8>),
    Sequence(SeqField),
}

/// Add a semantic field span unless it overlaps one already accepted (earlier
/// spans, added in precedence order, win).
fn add_span(spans: &mut Vec<(usize, usize, Semantic)>, offset: usize, width: usize, sem: Semantic) {
    let end = offset + width;
    if spans
        .iter()
        .any(|(start, stop, _)| offset < *stop && *start < end)
    {
        return;
    }
    spans.push((offset, end, sem));
}

/// Whether the byte at `offset` is the same across every message.
fn column_constant(datas: &[&[u8]], offset: usize) -> bool {
    let first = datas[0].get(offset).copied();
    first.is_some() && datas.iter().all(|d| d.get(offset).copied() == first)
}

/// Build the IR field for a detected semantic header field.
fn semantic_field(sem: &Semantic, enums: &mut BTreeMap<String, EnumDef>, total: usize) -> Field {
    match sem {
        Semantic::Length(length) => integer_field(
            "length",
            length.width,
            length.big_endian,
            Role::Length,
            0.9,
            total,
            "value tracks the message length (a remaining-length field)",
        ),
        Semantic::Sequence(seq) => integer_field(
            "sequence",
            seq.width,
            seq.big_endian,
            Role::Sequence,
            0.8,
            total,
            "value increases across the requests on a flow (a sequence or transaction id)",
        ),
        Semantic::MessageType(values) => {
            let variants = values
                .iter()
                .map(|&value| EnumVariant {
                    value: i128::from(value),
                    name: format!("type_{value}"),
                    description: None,
                })
                .collect();
            enums.insert(
                "message_type".to_owned(),
                EnumDef {
                    width: Some(1),
                    variants,
                },
            );
            Field {
                name: Some("message_type".to_owned()),
                kind: Kind::Enum {
                    enum_ref: "message_type".to_owned(),
                    width: 1,
                    endianness: None,
                },
                size: None,
                offset: None,
                role: Some(Role::MessageType),
                constraints: Vec::new(),
                confidence: Confidence::clamped(0.85),
                evidence: evidence(
                    total,
                    "byte that discriminates the message type (clustering separated the types here)",
                ),
            }
        }
    }
}

/// Build an integer header field.
fn integer_field(
    name: &str,
    width: usize,
    big_endian: bool,
    role: Role,
    confidence: f64,
    total: usize,
    note: &str,
) -> Field {
    let endianness = if width == 1 {
        None
    } else if big_endian {
        Some(Endianness::Big)
    } else {
        Some(Endianness::Little)
    };
    Field {
        name: Some(name.to_owned()),
        kind: Kind::Integer {
            width: width as u8,
            signed: Signedness::Unsigned,
            endianness,
        },
        size: None,
        offset: None,
        role: Some(role),
        constraints: Vec::new(),
        confidence: Confidence::clamped(confidence),
        evidence: evidence(total, note),
    }
}

/// Build a filler field for an undetected header run: a constant (reserved or,
/// at the start, magic) when the bytes never vary, otherwise an unknown run.
fn filler_field(datas: &[&[u8]], start: usize, end: usize, constant: bool, total: usize) -> Field {
    let width = (end - start) as u64;
    if constant {
        let value = datas[0][start..end].to_vec();
        let (name, role) = if start == 0 {
            ("magic".to_owned(), Role::Magic)
        } else {
            (format!("reserved_{start}"), Role::Reserved)
        };
        Field {
            name: Some(name),
            kind: Kind::Bytes,
            size: Some(SizeRule::Fixed { bytes: width }),
            offset: None,
            role: Some(role),
            constraints: vec![Constraint::Constant {
                value: Bytes::new(value),
            }],
            confidence: Confidence::clamped(0.85),
            evidence: evidence(total, "constant header bytes shared by every message"),
        }
    } else {
        Field {
            name: Some(format!("field_{start}")),
            kind: Kind::Bytes,
            size: Some(SizeRule::Fixed { bytes: width }),
            offset: None,
            role: Some(Role::Unknown),
            constraints: Vec::new(),
            confidence: Confidence::clamped(0.4),
            evidence: evidence(total, "varying header bytes of undetermined role"),
        }
    }
}

/// Build the trailing payload field. When the length field counts exactly the
/// bytes from the header end to the message end, the payload is sized from it (a
/// verified length relationship); otherwise it runs to the end of the message.
fn payload_field(length: Option<LengthField>, header_end: usize, total: usize) -> Field {
    let derived = length.filter(|l| l.k == header_end).is_some();
    let size = if derived {
        SizeRule::Derived {
            length_field: FieldRef::new("length"),
        }
    } else {
        SizeRule::ToEnd
    };
    let note = if derived {
        "payload bytes, sized by the length field"
    } else {
        "payload bytes to the end of the message"
    };
    Field {
        name: Some("payload".to_owned()),
        kind: Kind::Bytes,
        size: Some(size),
        offset: None,
        role: Some(Role::Payload),
        constraints: Vec::new(),
        confidence: Confidence::clamped(0.6),
        evidence: evidence(total, note),
    }
}

/// Build a statistics evidence record with one note.
fn evidence(total: usize, note: &str) -> Evidence {
    Evidence {
        detector: Some("protocol".to_owned()),
        support: (total > 0).then_some(SampleSupport {
            agreeing: total as u64,
            total: total as u64,
        }),
        model_rationale: None,
        notes: vec![note.to_owned()],
    }
}

/// Decode an unsigned integer of `width` bytes at `offset` in `data`.
fn decode_uint(data: &[u8], offset: usize, width: usize, big_endian: bool) -> Option<u64> {
    let end = offset.checked_add(width)?;
    let slice = data.get(offset..end)?;
    let mut value = 0u64;
    if big_endian {
        for &byte in slice {
            value = (value << 8) | u64::from(byte);
        }
    } else {
        for (index, &byte) in slice.iter().enumerate() {
            value |= u64::from(byte) << (8 * index);
        }
    }
    Some(value)
}

/// Detect a remaining-length field: an integer whose value equals the message
/// length minus a constant header offset, holding across every message (FR-2).
///
/// Lengths must vary across the message set, otherwise any constant byte would
/// satisfy the relationship. The genuine length counts exactly the bytes that
/// follow it, so a candidate whose header offset `k` equals the field's own end
/// (`offset + width`) is strongly preferred: that is a length-of-the-remainder,
/// the dominant protocol pattern. Among anchored candidates the latest offset and
/// then the narrowest width win, which trims constant zero high bytes (such as a
/// preceding constant header field) back to the real length. When nothing is
/// anchored, a general candidate is taken at the earliest offset.
fn detect_length_field(datas: &[&[u8]], min_len: usize) -> Option<LengthField> {
    if datas.len() < 2 || distinct_lengths(datas) < 2 {
        return None;
    }
    let mut anchored: Option<LengthField> = None;
    let mut general: Option<LengthField> = None;
    for width in [2usize, 4, 1] {
        if width > min_len {
            continue;
        }
        for offset in 0..=min_len - width {
            for big_endian in [true, false] {
                let Some(found) = length_candidate(datas, offset, width, big_endian, min_len)
                else {
                    continue;
                };
                if found.k == found.offset + found.width {
                    anchored = Some(keep_anchored(anchored, found));
                } else {
                    general = Some(keep_general(general, found));
                }
            }
        }
    }
    anchored.or(general)
}

/// Keep whichever anchored length candidate ranks better: the most natural width
/// (2, then 4, then 1), then the earliest offset. Ranking width first recovers
/// the conventional two-byte length rather than collapsing it to the single low
/// byte that varies or widening it to swallow a preceding constant field, both of
/// which also satisfy the relationship when the high bytes are constant zero.
fn keep_anchored(current: Option<LengthField>, found: LengthField) -> LengthField {
    let key = |l: &LengthField| (width_rank(l.width), l.offset);
    match current {
        Some(current) if key(&current) <= key(&found) => current,
        _ => found,
    }
}

/// Keep whichever general length candidate ranks better (earliest offset, then
/// the most natural width).
fn keep_general(current: Option<LengthField>, found: LengthField) -> LengthField {
    match current {
        Some(current) if better_length(&current, &found) => current,
        _ => found,
    }
}

/// Test one offset, width, and byte order as a remaining-length field.
fn length_candidate(
    datas: &[&[u8]],
    offset: usize,
    width: usize,
    big_endian: bool,
    min_len: usize,
) -> Option<LengthField> {
    let mut k: Option<i128> = None;
    let mut last_value: Option<u64> = None;
    let mut varies = false;
    for data in datas {
        let value = decode_uint(data, offset, width, big_endian)?;
        let this_k = data.len() as i128 - i128::from(value);
        match k {
            Some(existing) if existing != this_k => return None,
            _ => k = Some(this_k),
        }
        if last_value.is_some_and(|previous| previous != value) {
            varies = true;
        }
        last_value = Some(value);
    }
    let k = k?;
    if !(0..=min_len as i128).contains(&k) || !varies {
        return None;
    }
    Some(LengthField {
        offset,
        width,
        big_endian,
        k: k as usize,
    })
}

/// Whether `current` is a better length candidate than `other`.
fn better_length(current: &LengthField, other: &LengthField) -> bool {
    let key = |l: &LengthField| (l.offset, width_rank(l.width), l.k);
    key(current) <= key(other)
}

/// A preference rank for a field width: 2 bytes first, then 4, then 1, then 8.
fn width_rank(width: usize) -> u8 {
    match width {
        2 => 0,
        4 => 1,
        1 => 2,
        _ => 3,
    }
}

/// The number of distinct message lengths.
fn distinct_lengths(datas: &[&[u8]]) -> usize {
    let mut lengths: Vec<usize> = datas.iter().map(|d| d.len()).collect();
    lengths.sort_unstable();
    lengths.dedup();
    lengths.len()
}

/// Detect a sequence or transaction field: an integer that strictly increases
/// across the requests on each flow (FR-2).
///
/// Detection uses the request direction so a transaction id that the response
/// echoes does not break monotonicity. The field must not overlap the length or
/// message-type field. When both byte orders are monotonic (a small counter),
/// the format's prevailing byte order is preferred.
fn detect_sequence_field(
    messages: &[ExtractedMessage],
    datas: &[&[u8]],
    min_len: usize,
    length: Option<LengthField>,
    msgtype: Option<&(usize, Vec<u8>)>,
    prefer_big_endian: bool,
) -> Option<SeqField> {
    // The ordered request indices grouped by flow.
    let mut flows: BTreeMap<_, Vec<usize>> = BTreeMap::new();
    for (index, message) in messages.iter().enumerate() {
        if message.direction == Direction::ToServer {
            flows.entry(message.flow).or_default().push(index);
        }
    }
    // Fall back to all messages, as one flow, when there are too few requests.
    let groups: Vec<Vec<usize>> = if flows.values().map(Vec::len).max().unwrap_or(0) >= 3 {
        flows.into_values().collect()
    } else {
        vec![(0..datas.len()).collect()]
    };

    let scan = min_len.min(MAX_SCAN);
    for width in [2usize, 4, 1] {
        if width > min_len {
            continue;
        }
        for offset in 0..=scan.saturating_sub(width) {
            if overlaps_excluded(offset, width, length, msgtype) {
                continue;
            }
            for big_endian in [prefer_big_endian, !prefer_big_endian] {
                if monotonic_across_flows(datas, &groups, offset, width, big_endian) {
                    return Some(SeqField {
                        offset,
                        width,
                        big_endian,
                    });
                }
            }
        }
    }
    None
}

/// Whether a span overlaps the detected length or message-type field.
fn overlaps_excluded(
    offset: usize,
    width: usize,
    length: Option<LengthField>,
    msgtype: Option<&(usize, Vec<u8>)>,
) -> bool {
    let end = offset + width;
    if let Some(length) = length {
        if offset < length.offset + length.width && length.offset < end {
            return true;
        }
    }
    if let Some((type_offset, _)) = msgtype {
        if offset <= *type_offset && *type_offset < end {
            return true;
        }
    }
    false
}

/// Whether the integer at `offset` strictly increases within every flow group
/// (each group of two or more), and is not constant overall.
fn monotonic_across_flows(
    datas: &[&[u8]],
    groups: &[Vec<usize>],
    offset: usize,
    width: usize,
    big_endian: bool,
) -> bool {
    let mut saw_increase = false;
    let mut saw_distinct = false;
    let mut first_value: Option<u64> = None;
    for group in groups {
        if group.len() < 2 {
            continue;
        }
        let mut previous: Option<u64> = None;
        for &index in group {
            let value = match decode_uint(datas[index], offset, width, big_endian) {
                Some(value) => value,
                None => return false,
            };
            if first_value.is_none() {
                first_value = Some(value);
            } else if first_value != Some(value) {
                saw_distinct = true;
            }
            if let Some(previous) = previous {
                if value <= previous {
                    return false;
                }
                saw_increase = true;
            }
            previous = Some(value);
        }
    }
    saw_increase && saw_distinct
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::{Endpoint, Flow};
    use std::net::{IpAddr, Ipv4Addr};

    fn endpoint(port: u16) -> Endpoint {
        Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port,
        }
    }

    fn message(data: Vec<u8>, to_server: bool, index: usize) -> ExtractedMessage {
        let client = endpoint(40000);
        let server = endpoint(502);
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

    /// A toy message: type, little-endian seq, little-endian length, payload.
    fn toy(msg_type: u8, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![msg_type];
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn toy_messages() -> Vec<ExtractedMessage> {
        // Three message types with different payload shapes; the sequence number
        // is the message index, so requests strictly increase.
        let payloads: [(u8, &[u8]); 6] = [
            (1, b""),
            (2, b"hello-data"),
            (3, b"xy"),
            (1, b""),
            (2, b"more-payload-here"),
            (3, b"zw"),
        ];
        payloads
            .iter()
            .enumerate()
            .map(|(index, (ty, payload))| message(toy(*ty, index as u16, payload), true, index))
            .collect()
    }

    #[test]
    fn clustering_separates_message_types() {
        let messages = toy_messages();
        let clustering = cluster_messages(&messages);
        // Three distinct types, so three clusters discriminated at offset 0.
        assert_eq!(clustering.clusters.len(), 3);
        let discriminant = clustering.discriminant.expect("a discriminant");
        assert_eq!(discriminant.offset, 0);
        // Each cluster holds only its own type byte.
        for cluster in &clustering.clusters {
            let value = cluster.type_value.expect("a type value");
            for &index in &cluster.indices {
                assert_eq!(messages[index].data[0], value);
            }
        }
    }

    #[test]
    fn infer_recovers_protocol_semantics() {
        let messages = toy_messages();
        let inference = infer_protocol(&messages, Transport::Tcp, 8000, &Limits::default());
        assert!(
            inference.report.score.overall >= 0.95,
            "score {}",
            inference.report.score.overall
        );
        let roles: Vec<_> = inference
            .report
            .format
            .root
            .fields
            .iter()
            .filter_map(|f| f.role)
            .collect();
        assert!(roles.contains(&Role::MessageType), "roles: {roles:?}");
        assert!(roles.contains(&Role::Sequence), "roles: {roles:?}");
        assert!(roles.contains(&Role::Length), "roles: {roles:?}");
    }

    #[test]
    fn empty_messages_do_not_panic() {
        let inference = infer_protocol(&[], Transport::Tcp, 1, &Limits::default());
        assert_eq!(inference.message_count, 0);
        assert!(!inference.report.field_map.is_empty());
    }

    #[test]
    fn association_pairs_requests_with_responses() {
        let messages = vec![
            message(toy(1, 0, b""), true, 0),
            message(toy(1, 0, b"ok"), false, 1),
            message(toy(2, 1, b"x"), true, 2),
            message(toy(2, 1, b"done"), false, 3),
        ];
        let associations = associate(&messages);
        assert_eq!(associations.len(), 2);
        assert_eq!(
            associations[0],
            Association {
                request: 0,
                response: 1
            }
        );
        assert_eq!(
            associations[1],
            Association {
                request: 2,
                response: 3
            }
        );
    }

    #[test]
    fn length_field_is_detected_when_lengths_vary() {
        let datas: Vec<Vec<u8>> = vec![toy(1, 0, b""), toy(2, 1, b"abcd"), toy(3, 2, b"xy")];
        let slices: Vec<&[u8]> = datas.iter().map(Vec::as_slice).collect();
        let length = detect_length_field(&slices, 5).expect("a length field");
        assert_eq!(length.offset, 3);
        assert_eq!(length.width, 2);
        assert!(!length.big_endian);
        // The length counts the bytes after the 5-byte header.
        assert_eq!(length.k, 5);
    }
}
