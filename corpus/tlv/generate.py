#!/usr/bin/env python3
"""Generate the Sextant custom TLV seed corpus.

This script is the authoritative, reproducible source for the binary samples in
this directory. Re-running it regenerates byte-identical files. The format is a
small controlled tag-length-value container documented in ../README.md and
ground_truth.json.

Layout (all multi-byte integers little-endian):
  Header: magic "STLV" (4 bytes), version u8, record_count u8
  Record (repeated record_count times): tag u8, length u16, value (length bytes)
"""

import struct
from pathlib import Path

MAGIC = b"STLV"
VERSION = 1


def container(records):
    """Encode a list of (tag, value) records into a TLV container."""
    out = bytearray()
    out += MAGIC
    out += struct.pack("<BB", VERSION, len(records))
    for tag, value in records:
        out += struct.pack("<BH", tag, len(value))
        out += value
    return bytes(out)


SAMPLES = {
    "sample_01.tlv": [
        (0x01, b"hello"),
        (0x02, struct.pack("<I", 42)),
    ],
    "sample_02.tlv": [
        (0x01, b"abc"),
        (0x02, struct.pack("<I", 256)),
        (0x03, bytes([0xDE, 0xAD])),
    ],
    "sample_03.tlv": [
        (0x01, b"sextant"),
    ],
}


def main():
    here = Path(__file__).resolve().parent
    samples_dir = here / "samples"
    samples_dir.mkdir(exist_ok=True)
    for name, records in SAMPLES.items():
        data = container(records)
        (samples_dir / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes")


if __name__ == "__main__":
    main()
