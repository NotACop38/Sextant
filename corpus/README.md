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
representation, so the corpus stays stable as the engine evolves. The current
schema records:

- `format`, `display_name`, `description`, and the default `endianness`;
- a `provenance` block (see above);
- a `structure` block with the fixed `header` fields and the repeating `record`
  fields, each giving a name, size, type, and role;
- a `samples` list, each entry giving the file `path`, its `size` in bytes, and
  the number of records it contains.

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
