#!/usr/bin/env python3
"""Generate the Sextant gzip corpus.

This script is the authoritative, reproducible source for the gzip samples in
this directory. Re-running it regenerates byte-identical files. Each sample is a
genuine gzip member (RFC 1952) with no optional header fields: a 10-byte header,
a raw DEFLATE stream, then a CRC-32 of the uncompressed data and its length, as
documented in ../README.md and ground_truth.json.

The header is written explicitly rather than with the gzip module so the layout
is pinned by this script. The DEFLATE stream comes from zlib at level 9, and
every file is decompressed with Python's gzip module to prove it is valid.
"""

import gzip
import struct
import zlib
from pathlib import Path

# Header constants: ID1 ID2, CM = 8 (DEFLATE), FLG = 0 (no optional fields),
# XFL = 2 (slowest, maximum compression), OS = 3 (Unix).
SIGNATURE = b"\x1f\x8b"
CM_DEFLATE = 8
FLAGS = 0
XFL_MAX = 2
OS_UNIX = 3


def member(text: bytes, mtime: int) -> bytes:
    """Build one gzip member holding `text`, modified at Unix time `mtime`."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = compressor.compress(text) + compressor.flush()
    header = SIGNATURE + struct.pack("<BBIBB", CM_DEFLATE, FLAGS, mtime, XFL_MAX, OS_UNIX)
    trailer = struct.pack("<II", zlib.crc32(text), len(text) & 0xFFFFFFFF)
    return header + deflated + trailer


def lines(count: int, seed: int) -> bytes:
    """Deterministic, mildly repetitive text so DEFLATE output varies in size."""
    words = [b"sextant", b"bearing", b"horizon", b"azimuth", b"meridian", b"zenith"]
    out = []
    state = seed
    for index in range(count):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(b"%03d %s %s\n" % (index, words[state % len(words)], words[(state >> 8) % len(words)]))
    return b"".join(out)


SAMPLES = {
    "sample_01.gz": member(lines(4, 11), 1_758_000_000),
    "sample_02.gz": member(lines(12, 23), 1_758_086_400),
    "sample_03.gz": member(lines(30, 37), 1_760_000_123),
    "sample_04.gz": member(b"single line of text\n", 1_700_000_000),
    "sample_05.gz": member(lines(64, 53), 1_762_345_678),
}


def main():
    here = Path(__file__).resolve().parent
    samples_dir = here / "samples"
    samples_dir.mkdir(exist_ok=True)
    for name, data in SAMPLES.items():
        # Every sample must decompress with the standard library.
        gzip.decompress(data)
        (samples_dir / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes")


if __name__ == "__main__":
    main()
