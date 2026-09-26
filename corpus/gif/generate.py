#!/usr/bin/env python3
"""Generate the Sextant GIF corpus.

This script is the authoritative, reproducible source for the GIF samples in
this directory. Re-running it regenerates byte-identical files. Each sample is a
genuine, viewable GIF89a image: a header, a logical screen descriptor, a
four-color global color table, one image descriptor, LZW-compressed image data
split into length-prefixed sub-blocks, a zero-length block terminator, and the
trailer, as documented in ../README.md and ground_truth.json.

The LZW encoder below follows the GIF89a specification (variable code width
starting at min_code_size + 1, least-significant-bit-first packing, a clear
code first and an end-of-information code last). `decode` re-expands every
sample and the script refuses to write output that does not round-trip.
"""

import struct
from pathlib import Path

MIN_CODE_SIZE = 2  # four colors
PALETTE = bytes([0, 0, 0, 255, 255, 255, 220, 40, 40, 30, 90, 200])


def lzw_encode(indices: bytes, min_code_size: int) -> bytes:
    clear = 1 << min_code_size
    end = clear + 1
    out = bytearray()
    bit_buffer = 0
    bit_count = 0

    def emit(code: int, width: int) -> None:
        nonlocal bit_buffer, bit_count
        bit_buffer |= code << bit_count
        bit_count += width
        while bit_count >= 8:
            out.append(bit_buffer & 0xFF)
            bit_buffer >>= 8
            bit_count -= 8

    def reset():
        return {bytes([i]): i for i in range(clear)}, end + 1, min_code_size + 1

    table, next_code, width = reset()
    emit(clear, width)
    prefix = b""
    for value in indices:
        candidate = prefix + bytes([value])
        if candidate in table:
            prefix = candidate
            continue
        emit(table[prefix], width)
        if next_code < 4096:
            table[candidate] = next_code
            next_code += 1
            if next_code > (1 << width) and width < 12:
                width += 1
        else:
            emit(clear, width)
            table, next_code, width = reset()
        prefix = bytes([value])
    if prefix:
        emit(table[prefix], width)
    emit(end, width)
    if bit_count:
        out.append(bit_buffer & 0xFF)
    return bytes(out)


def decode(data: bytes, min_code_size: int) -> bytes:
    """Reference GIF LZW decoder, used only to prove the encoder round-trips."""
    clear = 1 << min_code_size
    end = clear + 1
    position = 0
    bit_buffer = 0
    bit_count = 0

    def read(width: int):
        nonlocal position, bit_buffer, bit_count
        while bit_count < width:
            if position >= len(data):
                return None
            bit_buffer |= data[position] << bit_count
            position += 1
            bit_count += 8
        code = bit_buffer & ((1 << width) - 1)
        bit_buffer >>= width
        bit_count -= width
        return code

    out = bytearray()
    table = []
    width = min_code_size + 1
    previous = None
    while True:
        code = read(width)
        if code is None or code == end:
            break
        if code == clear:
            table = [bytes([i]) for i in range(clear)] + [b"", b""]
            width = min_code_size + 1
            previous = None
            continue
        if code < len(table):
            entry = table[code]
            if previous is not None:
                table.append(previous + entry[:1])
        elif previous is not None and code == len(table):
            entry = previous + previous[:1]
            table.append(entry)
        else:
            raise ValueError("corrupt LZW stream")
        out += entry
        previous = entry
        if len(table) == (1 << width) and width < 12:
            width += 1
    return bytes(out)


def sub_blocks(data: bytes) -> bytes:
    out = bytearray()
    for start in range(0, len(data), 255):
        block = data[start : start + 255]
        out.append(len(block))
        out += block
    out.append(0)  # block terminator
    return bytes(out)


def pattern(width: int, height: int, seed: int) -> bytes:
    """A deterministic pseudo-random four-color index image."""
    state = seed * 2654435761 & 0xFFFFFFFF
    pixels = bytearray()
    for _ in range(width * height):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        pixels.append((state >> 16) & 0x03)
    return bytes(pixels)


def gif(width: int, height: int, seed: int) -> bytes:
    indices = pattern(width, height, seed)
    data = lzw_encode(indices, MIN_CODE_SIZE)
    if decode(data, MIN_CODE_SIZE) != indices:
        raise ValueError("LZW round trip failed")
    # Global color table present, 8-bit color resolution, 2^(1+1) entries.
    screen_flags = 0x80 | (0x07 << 4) | 0x01
    header = b"GIF89a" + struct.pack("<HHBBB", width, height, screen_flags, 0, 0)
    image = b"\x2c" + struct.pack("<HHHHB", 0, 0, width, height, 0)
    return header + PALETTE + image + bytes([MIN_CODE_SIZE]) + sub_blocks(data) + b"\x3b"


SAMPLES = {
    "sample_01.gif": gif(8, 8, 1),
    "sample_02.gif": gif(16, 12, 2),
    "sample_03.gif": gif(40, 32, 3),
    "sample_04.gif": gif(48, 40, 4),
    "sample_05.gif": gif(12, 5, 5),
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
