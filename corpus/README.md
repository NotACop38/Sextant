# Sextant ground-truth corpus

This directory holds the sample corpus that Sextant is evaluated against. Each
format lives in its own subdirectory:

```
corpus/
  <format>/
    samples/           raw sample files of the format
    ground_truth.json  the hand-verified description of the format
```

Accuracy is measured by running inference over `samples/` and comparing the
result against `ground_truth.json` (see the `bench` harness). Keeping the
ground truth beside the samples makes every accuracy number reproducible.

## Provenance

Only redistributable data belongs here. Do not commit copyrighted files,
malware, or anything you are not authorized to share. Every entry records its
origin in the `provenance` block of `ground_truth.json`:

| Field | Meaning |
|---|---|
| `source` | How the data was obtained, for example `synthetic` or `public-spec`. |
| `origin` | A human-readable note on where the samples came from. |
| `license` | The license that allows redistribution of the samples. |
| `notes` | Any caveats, such as whether the samples were trimmed. |

## ground_truth.json

Each `ground_truth.json` describes a format independently of Sextant's internal
representation, so the corpus stays stable as the engine evolves.

For file formats the schema records:

- `format`, `display_name`, `description`, and the default `endianness`;
- a `provenance` block (see above);
- a `structure` block with the fixed `header` fields and the repeating `record`
  fields, each giving a name, size, type, and role;
- a `samples` list, each entry giving the file `path`, its `size` in bytes, and
  the number of records it contains.

For protocols (entries with `"kind": "protocol"`) the schema instead records:

- `format`, `display_name`, `description`, `transport`, and `port`;
- a `provenance` block (see above);
- a `message` block: the fields of one protocol message, each with a name,
  offset, size, type, and role (including the protocol roles `message_type` and
  `sequence`);
- a `message_types` list mapping each message-type value to a name;
- a `captures` list, each entry giving the capture `path` and how many messages,
  requests, and responses it contains.

## Formats

### png (showcase)

The Portable Network Graphics file format, the v1 file-format showcase
(PRD Section 15). Each sample is a genuine, viewable PNG produced by
`png/generate.py`, which is the authoritative source for their bytes. They are
tiny truecolor images, so the structure under test is real and the CRC-32 values
are real, while the image content is irrelevant.

Layout (all multi-byte integers big-endian):

| Offset | Size | Field | Role | Notes |
|---|---|---|---|---|
| 0 | 8 | `signature` | magic | The bytes `89 50 4E 47 0D 0A 1A 0A` |

The signature is followed by a sequence of chunks, each:

| Size | Field | Role | Notes |
|---|---|---|---|
| 4 | `length` | length | Big-endian byte length of `data` |
| 4 | `chunk_type` | enum | Four ASCII letters, for example `IHDR`, `IDAT`, `IEND` |
| `length` | `data` | payload | Chunk payload |
| 4 | `crc` | checksum | CRC-32 over `chunk_type` and `data` |

### tlv (custom)

A small controlled tag-length-value container authored for this project. It is
deliberately simple so that the inference pipeline has an unambiguous target
during early development. The samples are produced by `tlv/generate.py`, which
is the authoritative source for their bytes.

Layout (all multi-byte integers little-endian):

| Offset | Size | Field | Role | Notes |
|---|---|---|---|---|
| 0 | 4 | `magic` | magic | ASCII `STLV` |
| 4 | 1 | `version` | version | always `1` |
| 5 | 1 | `record_count` | count | number of records that follow |

Each record that follows the header is:

| Size | Field | Role | Notes |
|---|---|---|---|
| 1 | `tag` | enum | record type |
| 2 | `length` | length | byte length of `value`, little-endian |
| `length` | `value` | payload | opaque value bytes |

### scma (statistical inference)

A small controlled format authored for the Step 5 statistical inference tests.
It pairs a magic signature with a packed flags byte and a record count, so the
pass exercises sub-byte detection (FR-11) and count detection (FR-9) at once. The
samples are produced by `scma/generate.py`, the authoritative source for their
bytes.

Layout (all multi-byte integers little-endian):

| Offset | Size | Field | Role | Notes |
|---|---|---|---|---|
| 0 | 4 | `magic` | magic | ASCII `SCMA` |
| 4 | 1 | `flags` | flags | high five bits constant `0b10100`, low three bits vary |
| 5 | 1 | `count` | count | number of records that follow |

Each record that follows the header is a fixed four bytes:

| Size | Field | Role | Notes |
|---|---|---|---|
| 2 | `id` | enum | little-endian record id |
| 2 | `value` | payload | little-endian record value |

### sdlp (statistical inference)

A small controlled format authored for the Step 5 statistical inference tests.
It exercises derived-length detection (FR-9) and checksum detection (FR-10): a
length field governs a variable payload, and a trailing CRC-32 covers everything
before it. The samples are produced by `sdlp/generate.py`, the authoritative
source for their bytes.

Layout (all multi-byte integers little-endian):

| Offset | Size | Field | Role | Notes |
|---|---|---|---|---|
| 0 | 4 | `magic` | magic | ASCII `SDLP` |
| 4 | 2 | `length` | length | byte length of `payload`, little-endian |
| `length` | `payload` | payload | opaque payload bytes |
| 4 | `crc32` | checksum | CRC-32 over every byte before this field |

### stot (statistical inference)

A small controlled format authored for the Step 5 statistical inference tests.
It exercises total-length detection (FR-9): a header field whose value equals the
whole file size. The samples are produced by `stot/generate.py`, the
authoritative source for their bytes.

Layout (all multi-byte integers little-endian):

| Offset | Size | Field | Role | Notes |
|---|---|---|---|---|
| 0 | 4 | `magic` | magic | ASCII `STOT` |
| 4 | 4 | `total_len` | length | the whole file size in bytes, this field included |
| `total_len - 8` | `payload` | payload | opaque payload bytes to the end |

## Protocols

Protocol entries hold packet captures (`.pcap`) rather than flat sample files.
Inference reads them with a transport and port selector, for example
`sextant infer samples/session_01.pcap --transport tcp --port 502`, which
extracts the transport payloads, clusters them by message type, and infers a
protocol structure. The captures are framed in Ethernet, IPv4, and TCP.

### modbus (showcase)

Modbus/TCP, the protocol showcase (PRD Section 15): a real industrial protocol
with a public specification. The capture is a synthetic, spec-faithful exchange
produced by `modbus/generate.py`, the authoritative source for its bytes. Each
message is an MBAP header followed by a function code and data (all multi-byte
integers big-endian), on TCP port 502:

| Offset | Size | Field | Role | Notes |
|---|---|---|---|---|
| 0 | 2 | `transaction_id` | sequence | request id the response echoes |
| 2 | 2 | `protocol_id` | reserved | always `0000` for Modbus |
| 4 | 2 | `length` | length | number of following bytes (unit id, function, data) |
| 6 | 1 | `unit_id` | reserved | server unit address |
| 7 | 1 | `function_code` | message type | the operation: read coils, read holding registers, write single register |
| 8 | to end | `data` | payload | function-specific bytes |

### toy (custom)

A small controlled request/response protocol authored for this project, produced
by `toy/generate.py`. It exercises message type, sequence, and length at once
(all multi-byte integers little-endian), on TCP port 9000:

| Offset | Size | Field | Role | Notes |
|---|---|---|---|---|
| 0 | 1 | `message_type` | message type | one of PING (1), DATA (2), BYE (3) |
| 1 | 2 | `sequence` | sequence | increments per request; the response echoes it |
| 3 | 2 | `length` | length | byte length of `payload` |
| `5` | `length` | `payload` | payload | opaque payload bytes |
