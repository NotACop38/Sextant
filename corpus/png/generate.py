#!/usr/bin/env python3
"""Generate the Sextant PNG showcase corpus.

This script is the authoritative, reproducible source for the PNG samples in
this directory. Re-running it regenerates byte-identical files. Each sample is a
genuine, viewable PNG: an eight-byte signature followed by length-prefixed,
CRC-32 checked chunks (IHDR, IDAT, IEND), as documented in ../README.md and
ground_truth.json.

The images are tiny truecolor (RGB, 8-bit) bitmaps. They are real PNGs so the
generated CRC-32 values are real, which is exactly what the Sextant executor and
scorer verify. The image content is irrelevant to the structure under test.
"""

import struct
import zlib
from pathlib import Path

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def chunk(chunk_type: bytes, data: bytes) -> bytes:
    """Encode one PNG chunk: length, type, data, and a CRC-32 over type+data."""
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def png(width: int, height: int, pixels: bytes) -> bytes:
    """Build a truecolor 8-bit PNG from raw RGB pixel bytes (row-major)."""
    if len(pixels) != width * height * 3:
        raise ValueError("pixel buffer does not match the image dimensions")
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw = bytearray()
    stride = width * 3
    for row in range(height):
        raw.append(0)  # filter type 0 (none) for each scanline
        raw += pixels[row * stride : (row + 1) * stride]
    idat = zlib.compress(bytes(raw), 9)
    return PNG_SIGNATURE + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


SAMPLES = {
    # A single red pixel.
    "sample_01.png": png(1, 1, bytes([255, 0, 0])),
    # A two by two block: red, green, blue, white.
    "sample_02.png": png(
        2,
        2,
        bytes([255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255]),
    ),
    # A four by two horizontal gradient.
    "sample_03.png": png(
        4,
        2,
        bytes(
            [
                0, 0, 0, 64, 64, 64, 128, 128, 128, 192, 192, 192,
                32, 0, 0, 96, 0, 0, 160, 0, 0, 224, 0, 0,
            ]
        ),
    ),
}


def main():
    here = Path(__file__).resolve().parent
    samples_dir = here / "samples"
    samples_dir.mkdir(exist_ok=True)
    for name, data in SAMPLES.items():
        (samples_dir / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes")


if __name__ == "__main__":
    main()
