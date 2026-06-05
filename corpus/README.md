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
