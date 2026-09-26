#!/usr/bin/env python3
"""Generate the Sextant Windows icon (ICO) corpus.

This script is the authoritative, reproducible source for the ICO samples in
this directory. Re-running it regenerates byte-identical files. Each sample is a
genuine single-image icon file: a 6-byte ICONDIR header, one 16-byte
ICONDIRENTRY, and the image itself stored as a PNG (as Windows Vista and later
allow), as documented in ../README.md and ground_truth.json.

The icon directory is little-endian; the embedded PNG keeps its own big-endian
chunk layout (signature, IHDR, IDAT, IEND, each chunk CRC-32 checked). The
script reads each directory back and checks that it locates exactly the
embedded image. When the corpus was built, every embedded PNG was also decoded
by an independent reader (Java ImageIO), and `file` identified each sample as a
Windows icon resource with PNG image data.
"""

import struct
import zlib
from pathlib import Path

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def png_rgba(size: int, seed: int) -> bytes:
    """A small RGBA image: a colored disc on a transparent square."""
    rows = []
    center = (size - 1) / 2
    for y in range(size):
        row = bytearray([0])  # filter type None
        for x in range(size):
            inside = (x - center) ** 2 + (y - center) ** 2 <= (size / 2) ** 2
            r = (seed * 37 + x * 11) % 256
            g = (seed * 71 + y * 13) % 256
            b = (seed * 19 + (x ^ y) * 7) % 256
            row += bytes([r, g, b, 255 if inside else 0])
        rows.append(bytes(row))
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    idat = zlib.compress(b"".join(rows), 9)
    return PNG_SIGNATURE + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def icon(size: int, seed: int) -> tuple[bytes, bytes]:
    image = png_rgba(size, seed)
    header = struct.pack("<HHH", 0, 1, 1)  # reserved, type 1 (icon), one image
    entry = struct.pack(
        "<BBBBHHII",
        size,  # width
        size,  # height
        0,  # no palette
        0,  # reserved
        1,  # color planes
        32,  # bits per pixel
        len(image),  # bytes in the image
        6 + 16,  # offset of the image from the start of the file
    )
    return header + entry + image, image


SPECS = {
    "sample_01.ico": (8, 1),
    "sample_02.ico": (10, 2),
    "sample_03.ico": (12, 3),
    "sample_04.ico": (14, 4),
    "sample_05.ico": (16, 5),
}


def main():
    here = Path(__file__).resolve().parent
    samples_dir = here / "samples"
    samples_dir.mkdir(exist_ok=True)
    for name, (size, seed) in SPECS.items():
        data, image = icon(size, seed)
        # Read the directory back and check it locates exactly the image.
        reserved, kind, count = struct.unpack_from("<HHH", data, 0)
        width, height, _, _, planes, bits, length, offset = struct.unpack_from("<BBBBHHII", data, 6)
        assert (reserved, kind, count, planes, bits) == (0, 1, 1, 1, 32)
        assert (width, height) == (size, size)
        assert data[offset : offset + length] == image and offset + length == len(data)
        (samples_dir / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes, {size}x{size} PNG icon")


if __name__ == "__main__":
    main()
