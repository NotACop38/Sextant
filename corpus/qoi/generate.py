#!/usr/bin/env python3
"""Generate the Sextant QOI image corpus.

This script is the authoritative, reproducible source for the QOI samples in
this directory. Re-running it regenerates byte-identical files. Each sample is a
genuine image in the Quite OK Image format (specification 1.0): a 14-byte
big-endian header, the encoded pixel stream, and the fixed 8-byte end marker,
as documented in ../README.md and ground_truth.json.

The encoder below follows the specification's operations (RGB, RGBA, INDEX,
DIFF, LUMA, and RUN). Every file is decoded by the independent decoder below
and must reproduce the source pixels exactly.
"""

import struct
from pathlib import Path

END_MARKER = b"\x00" * 7 + b"\x01"


def index_hash(pixel):
    r, g, b, a = pixel
    return (r * 3 + g * 5 + b * 7 + a * 11) % 64


def encode(width, height, channels, colorspace, pixels) -> bytes:
    """Encode RGBA `pixels` (row-major tuples) as a QOI file."""
    out = bytearray(b"qoif" + struct.pack(">IIBB", width, height, channels, colorspace))
    index = [(0, 0, 0, 0)] * 64
    previous = (0, 0, 0, 255)
    run = 0
    for position, pixel in enumerate(pixels):
        if pixel == previous:
            run += 1
            if run == 62 or position == len(pixels) - 1:
                out.append(0xC0 | (run - 1))
                run = 0
            continue
        if run:
            out.append(0xC0 | (run - 1))
            run = 0
        slot = index_hash(pixel)
        if index[slot] == pixel:
            out.append(slot)
        else:
            index[slot] = pixel
            if pixel[3] == previous[3]:
                dr = (pixel[0] - previous[0] + 128) % 256 - 128
                dg = (pixel[1] - previous[1] + 128) % 256 - 128
                db = (pixel[2] - previous[2] + 128) % 256 - 128
                dr_dg, db_dg = dr - dg, db - dg
                if -2 <= dr <= 1 and -2 <= dg <= 1 and -2 <= db <= 1:
                    out.append(0x40 | (dr + 2) << 4 | (dg + 2) << 2 | (db + 2))
                elif -32 <= dg <= 31 and -8 <= dr_dg <= 7 and -8 <= db_dg <= 7:
                    out.append(0x80 | (dg + 32))
                    out.append((dr_dg + 8) << 4 | (db_dg + 8))
                else:
                    out += bytes([0xFE, pixel[0], pixel[1], pixel[2]])
            else:
                out += bytes([0xFF, *pixel])
        previous = pixel
    return bytes(out) + END_MARKER


def decode(data: bytes):
    """Decode a QOI file into (width, height, channels, colorspace, pixels)."""
    assert data[:4] == b"qoif" and data[-8:] == END_MARKER
    width, height, channels, colorspace = struct.unpack(">IIBB", data[4:14])
    index = [(0, 0, 0, 0)] * 64
    pixel = (0, 0, 0, 255)
    pixels = []
    pos, end = 14, len(data) - 8
    while len(pixels) < width * height:
        op = data[pos]
        pos += 1
        if op == 0xFE:
            pixel = (data[pos], data[pos + 1], data[pos + 2], pixel[3])
            pos += 3
        elif op == 0xFF:
            pixel = tuple(data[pos : pos + 4])
            pos += 4
        elif op >> 6 == 0:
            pixel = index[op]
        elif op >> 6 == 1:
            pixel = (
                (pixel[0] + ((op >> 4) & 3) - 2) % 256,
                (pixel[1] + ((op >> 2) & 3) - 2) % 256,
                (pixel[2] + (op & 3) - 2) % 256,
                pixel[3],
            )
        elif op >> 6 == 2:
            dg = (op & 0x3F) - 32
            second = data[pos]
            pos += 1
            pixel = (
                (pixel[0] + dg + (second >> 4) - 8) % 256,
                (pixel[1] + dg) % 256,
                (pixel[2] + dg + (second & 0x0F) - 8) % 256,
                pixel[3],
            )
        else:
            run = (op & 0x3F) + 1
            pixels.extend([pixel] * (run - 1))
        index[index_hash(pixel)] = pixel
        pixels.append(pixel)
    assert pos == end, "the pixel stream must end right before the end marker"
    return width, height, channels, colorspace, pixels


def image(width, height, alpha, pattern):
    pixels = []
    for y in range(height):
        for x in range(width):
            r, g, b = pattern(x, y)
            a = (255 - 16 * ((x + y) % 4)) if alpha else 255
            pixels.append((r % 256, g % 256, b % 256, a))
    return pixels


SPECS = [
    ("sample_01.qoi", 4, 3, 3, 0, lambda x, y: (40 * x, 60 * y, 200)),
    ("sample_02.qoi", 8, 2, 4, 0, lambda x, y: (x * 31, 128, 255 - y * 50)),
    ("sample_03.qoi", 5, 5, 3, 1, lambda x, y: ((x ^ y) * 50, x * 20, y * 20)),
    ("sample_04.qoi", 16, 1, 3, 0, lambda x, y: (0, 0, 0) if x < 12 else (250, 10, 10)),
    ("sample_05.qoi", 6, 4, 4, 1, lambda x, y: (x * 40 + y, 255 - x * 30, (x * y * 17))),
]


def main():
    here = Path(__file__).resolve().parent
    samples_dir = here / "samples"
    samples_dir.mkdir(exist_ok=True)
    for name, width, height, channels, colorspace, pattern in SPECS:
        pixels = image(width, height, channels == 4, pattern)
        data = encode(width, height, channels, colorspace, pixels)
        assert decode(data) == (width, height, channels, colorspace, pixels)
        (samples_dir / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes, {width}x{height}, {channels} channels")


if __name__ == "__main__":
    main()
