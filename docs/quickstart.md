# Quick start

This walkthrough takes a set of unknown binary samples to a field map, an
annotated hex view, and an editable parser spec in three commands. It uses the
bundled TLV (tag-length-value) corpus, so it works on a fresh checkout, and
every command runs fully offline.

If you have not built Sextant yet, see [Installation](installation.md). The
rest of this page assumes the binary at `./target/release/sextant` and runs
from the repository root.

## The samples

The repository ships a ground-truth corpus under `corpus/`. The TLV format is a
small controlled format: a four-byte magic, a version byte, a record count,
then records, each a one-byte tag, a two-byte little-endian length, and that
many value bytes.

```bash
ls corpus/tlv/samples
# sample_01.tlv  sample_02.tlv  sample_03.tlv
```

Pretend you do not know any of that. Sextant works it out from the bytes.

## Step 1: infer

```bash
./target/release/sextant infer corpus/tlv/samples --no-llm --out report.json
```

The output:

```
Ingested 3 samples (61 bytes total).
  corpus/tlv/samples/sample_01.tlv: 21 bytes
  corpus/tlv/samples/sample_02.tlv: 24 bytes
  corpus/tlv/samples/sample_03.tlv: 16 bytes

Best hypothesis: candidate-chunked (fit score 1.000)
  coverage 1.000  consistency 1.000  generality 1.000  structure 0.216
  3 of 3 sample(s) fully verified; 0 checksum check(s) passed
  mode: statistics-only (no language model, no network egress)
Field map:
  magic: magic, bytes, 4 bytes (confidence 1.00)
  version_4: version, u8, 1 bytes (confidence 0.80)
  count: count, u8, 1 bytes (confidence 0.85)
  records: unknown, array, to end (confidence 0.85)
    record: unknown, struct, from fields (confidence 0.75)
      tag: enum, u8, 1 bytes (confidence 0.50)
      length: length, u16 little-endian, 2 bytes (confidence 0.90)
      data: payload, bytes, derived from length (confidence 0.60)
  (confidence describes evidence from these samples, not certainty about field meaning; per-field evidence is in the report JSON)
Refinement: no improving change was found (already converged).

Wrote report to report.json
```

How to read it:

- **Fit score 1.000** means the hypothesis parses every sample to a clean end,
  explains every byte, and contradicts none of its own constraints. Fit alone
  cannot distinguish real structure from a single opaque field, which is why
  the next number exists.
- **Structure 0.216** estimates how much of the samples the hypothesis
  explains: one minus the bits it still needs to reproduce them, relative to
  storing them raw. An opaque hypothesis scores zero. TLV samples are mostly
  arbitrary value bytes, so their ceiling is low.
- **Confidence** is per field and describes evidence from these samples. The
  length relationship holds in every record, so `length` scores high; the
  meaning of the one-byte tag is a guess, so `tag` scores low.

`--no-llm` states that this run is statistics-only with zero network egress.
That is already the default whenever `--provider` is absent. See
[Privacy and the `--no-llm` story](privacy.md).

## Step 2: inspect

Read a sample through the field map you just inferred:

```bash
./target/release/sextant inspect report.json --sample corpus/tlv/samples/sample_01.tlv
```

```
Format: candidate-chunked (fit score 1.000)
Sample: 21 bytes

  Offset    Size  Name                      Role        Type              Value                   Confidence
--------  ------  ------------------------  ----------  ----------------  ----------------------  ----------
       0       4  magic                     magic       bytes             53 54 4c 56                   1.00
       4       1  version_4                 version     u8                1 (0x1)                       0.80
       5       1  count                     count       u8                2 (0x2)                       0.85
       6      15  records                   unknown     array             [2 elements]                  0.85
       6       8    record                  unknown     struct            {3 fields}                    0.75
       6       1      tag                   enum        u8                1 (0x1)                       0.50
       7       2      length                length      u16 little-en...  5 (0x5)                       0.90
       9       5      data                  payload     bytes             68 65 6c 6c 6f                0.60
      14       7    record                  unknown     struct            {3 fields}                    0.75
      14       1      tag                   enum        u8                2 (0x2)                       0.50
      15       2      length                length      u16 little-en...  4 (0x4)                       0.90
      17       4      data                  payload     bytes             2a 00 00 00                   0.60

Hex:
00000000  53 54 4c 56 01 02 01 05  00 68 65 6c 6c 6f 02 04  |STLV.....hello..|
00000010  00 2a 00 00 00                                    |.*...|
```

Add `--color` to highlight each field's bytes in the hex dump.

## Step 3: export

Translate the chosen hypothesis into a parser spec. Kaitai Struct is the
primary target:

```bash
./target/release/sextant export report.json --format kaitai --out tlv.ksy
```

`tlv.ksy` begins:

```yaml
# Structural parser. Checksum and range constraints are not runtime-verified.
# Generated by Sextant. Edit freely.
meta:
  id: candidate_chunked
  endian: le
seq:
  - id: magic
    contents: [0x53, 0x54, 0x4c, 0x56]
    doc: 'role: magic'
  - id: version_4
    type: u1
    valid: 1
    doc: 'role: version'
  - id: count
    type: u1
    doc: 'role: count'
  - id: records
    type: record
    repeat: eos
```

The same report also exports to an ImHex pattern, a Wireshark Lua dissector,
or a 010 Editor template:

```bash
./target/release/sextant export report.json --format imhex     --out tlv.hexpat
./target/release/sextant export report.json --format wireshark --out tlv.lua
./target/release/sextant export report.json --format 010       --out tlv.bt
```

## What just happened

Sextant ingested the samples, generated candidate structures with statistical
inference, executed each candidate natively against every sample, scored the
fit, and kept the best. The export is a translation of a hypothesis that
parsed every sample. Whether the generated parser behaves the same way in its
own runtime is separate evidence: with the Kaitai compiler installed,
`--cross-validate corpus/tlv/samples` checks it (see
[Workflows](workflows.md#optional-kaitai-cross-validation)). [How it works](how-it-works.md) explains the
verification loop in detail.

## Next steps

- [Workflows](workflows.md): every command and option.
- [Examples](examples.md): a script that runs this whole flow, and the recorded
  demo.
