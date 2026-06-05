#!/usr/bin/env python3
"""Generate the Sextant STOT total-length corpus.

This script is the authoritative, reproducible source for the STOT samples in
this directory. Re-running it regenerates byte-identical files. STOT is a small
controlled format authored for the Sextant statistical inference tests. It
exercises a magic signature and a total-length field whose value equals the
whole file size, followed by an opaque payload that runs to the end.

Layout (all multi-byte integers little-endian):
  magic       "STOT" (4 bytes)
  total_len   u32: the size of the whole file in bytes, this field included
  payload     the remaining bytes, to the end of the file
"""

import struct
from pathlib import Path

MAGIC = b"STOT"


def container(payload):
    """Encode a payload into an STOT container with a total-length header."""
    total = 8 + len(payload)
    out = bytearray()
    out += MAGIC
    out += struct.pack("<I", total)
    out += payload
    return bytes(out)


SAMPLES = {
    "sample_01.stot": bytes([0xDE, 0xAD, 0xBE]),
    "sample_02.stot": bytes((i * 11 + 5) & 0xFF for i in range(10)),
    "sample_03.stot": bytes([0x99]),
    "sample_04.stot": bytes(range(0x40, 0x50)),
    "sample_05.stot": b"corpus!",
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
