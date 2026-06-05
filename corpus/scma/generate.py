#!/usr/bin/env python3
"""Generate the Sextant SCMA counted-records corpus.

This script is the authoritative, reproducible source for the SCMA samples in
this directory. Re-running it regenerates byte-identical files. SCMA is a small
controlled format authored for the Sextant statistical inference tests. It
exercises a magic signature, a packed flags byte (a sub-byte field), a record
count, and that many fixed-size records.

Layout (all multi-byte integers little-endian):
  magic   "SCMA" (4 bytes)
  flags   u8: the high five bits are the constant pattern 0b10100, the low
          three bits vary from sample to sample (a packed bit field)
  count   u8: how many records follow
  records count repetitions of {id u16, value u16} (four bytes each)
"""

import struct
from pathlib import Path

MAGIC = b"SCMA"
FLAGS_CONSTANT = 0xA0  # high five bits 0b10100, low three bits free


def container(low_flags, records):
    """Encode a list of (id, value) records into an SCMA container."""
    out = bytearray()
    out += MAGIC
    out += struct.pack("<BB", FLAGS_CONSTANT | (low_flags & 0x07), len(records))
    for ident, value in records:
        out += struct.pack("<HH", ident, value)
    return bytes(out)


SAMPLES = {
    "sample_01.scma": (1, [(0x0001, 0x1111), (0x0002, 0x2222)]),
    "sample_02.scma": (
        5,
        [
            (0x0010, 0x00FF),
            (0x0011, 0x01FE),
            (0x0012, 0x02FD),
            (0x0013, 0x03FC),
            (0x0014, 0x04FB),
        ],
    ),
    "sample_03.scma": (2, [(0x00AA, 0xBBCC)]),
    "sample_04.scma": (3, [(0x0100, 0x0200), (0x0300, 0x0400), (0x0500, 0x0600)]),
    "sample_05.scma": (
        4,
        [(0x2001, 0x3001), (0x2002, 0x3002), (0x2003, 0x3003), (0x2004, 0x3004)],
    ),
}


def main():
    here = Path(__file__).resolve().parent
    samples_dir = here / "samples"
    samples_dir.mkdir(exist_ok=True)
    for name, (low_flags, records) in SAMPLES.items():
        data = container(low_flags, records)
        (samples_dir / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes")


if __name__ == "__main__":
    main()
