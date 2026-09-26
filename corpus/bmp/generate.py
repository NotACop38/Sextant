#!/usr/bin/env python3
"""Generate the Sextant BMP corpus.

This script is the authoritative, reproducible source for the BMP samples in
this directory. Re-running it regenerates byte-identical files. Each sample is a
genuine, viewable Windows bitmap: a 14-byte BITMAPFILEHEADER, a 40-byte
BITMAPINFOHEADER, and bottom-up 24-bit BI_RGB pixel rows padded to four bytes,
as documented in ../README.md and ground_truth.json.

All multi-byte integers are little-endian. The images are small gradients; the
pixel content is irrelevant to the structure under test.
"""

import struct
from pathlib import Path

FILE_HEADER_SIZE = 14
INFO_HEADER_SIZE = 40
PIXELS_PER_METER = 2835  # 72 DPI


def pixel_rows(width: int, height: int, seed: int) -> bytes:
    """Bottom-up BGR rows, each padded with zeros to a multiple of four bytes."""
    stride = (width * 3 + 3) & ~3
    out = bytearray()
    for row in range(height):
        line = bytearray()
        for col in range(width):
            line += bytes(
                [
                    (seed * 37 + col * 29) & 0xFF,
                    (seed * 11 + row * 53) & 0xFF,
                    (seed * 7 + (row + col) * 17) & 0xFF,
                ]
            )
        line += bytes(stride - len(line))
        out += line
    return bytes(out)


def bmp(width: int, height: int, seed: int) -> bytes:
    """Build a 24-bit uncompressed bitmap."""
    pixels = pixel_rows(width, height, seed)
    offset = FILE_HEADER_SIZE + INFO_HEADER_SIZE
    file_header = struct.pack("<2sIHHI", b"BM", offset + len(pixels), 0, 0, offset)
    info_header = struct.pack(
        "<IiiHHIIiiII",
        INFO_HEADER_SIZE,
        width,
        height,
        1,  # planes
        24,  # bits per pixel
        0,  # BI_RGB, no compression
        len(pixels),
        PIXELS_PER_METER,
        PIXELS_PER_METER,
        0,  # colors used
        0,  # important colors
    )
    return file_header + info_header + pixels


SAMPLES = {
    "sample_01.bmp": bmp(1, 1, 1),
    "sample_02.bmp": bmp(2, 2, 2),
    "sample_03.bmp": bmp(3, 2, 3),
    "sample_04.bmp": bmp(4, 3, 4),
    "sample_05.bmp": bmp(5, 1, 5),
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
