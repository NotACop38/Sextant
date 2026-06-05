#!/usr/bin/env python3
"""Generate the Sextant SDLP derived-length-payload corpus.

This script is the authoritative, reproducible source for the SDLP samples in
this directory. Re-running it regenerates byte-identical files. SDLP is a small
controlled format authored for the Sextant statistical inference tests. It
exercises a magic signature, a length field that governs a variable payload, and
a trailing CRC-32 over everything before it.

Layout (all multi-byte integers little-endian):
  magic    "SDLP" (4 bytes)
  length   u16: the number of payload bytes that follow
  payload  length bytes
  crc32    u32: CRC-32/ISO-HDLC over every byte before this field
"""

import struct
import zlib
from pathlib import Path

MAGIC = b"SDLP"


def container(payload):
    """Encode a payload into an SDLP container with a trailing CRC-32."""
    out = bytearray()
    out += MAGIC
    out += struct.pack("<H", len(payload))
    out += payload
    crc = zlib.crc32(bytes(out)) & 0xFFFFFFFF
    out += struct.pack("<I", crc)
    return bytes(out)


SAMPLES = {
    "sample_01.sdlp": bytes([0x10, 0x20, 0x30, 0x40, 0x50]),
    "sample_02.sdlp": bytes(range(0x80, 0x8C)),
    "sample_03.sdlp": bytes([0x7F]),
    "sample_04.sdlp": bytes((i * 7 + 3) & 0xFF for i in range(20)),
    "sample_05.sdlp": b"sextant!",
}


def main():
    here = Path(__file__).resolve().parent
    samples_dir = here / "samples"
    samples_dir.mkdir(exist_ok=True)
    for name, payload in SAMPLES.items():
        data = container(payload)
        (samples_dir / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes")


if __name__ == "__main__":
    main()
