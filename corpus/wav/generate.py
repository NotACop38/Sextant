#!/usr/bin/env python3
"""Generate the Sextant WAV corpus.

This script is the authoritative, reproducible source for the WAV samples in
this directory. Re-running it regenerates byte-identical files. Each sample is a
genuine, playable RIFF WAVE file in the canonical PCM layout: a RIFF header, a
16-byte `fmt ` chunk, and a `data` chunk, as documented in ../README.md and
ground_truth.json.

The header is written explicitly rather than with the `wave` module so the
layout is pinned by this script. All multi-byte integers are little-endian.
Every data chunk has an even length, so no RIFF pad byte is needed.
"""

import math
import struct
from pathlib import Path

PCM = 1


def samples_pcm(frames: int, channels: int, bits: int, rate: int, tone: float) -> bytes:
    """A short sine tone, quantized to unsigned 8-bit or signed 16-bit PCM."""
    out = bytearray()
    for index in range(frames):
        value = math.sin(2.0 * math.pi * tone * index / rate)
        for channel in range(channels):
            scaled = value * (0.5 if channel else 0.8)
            if bits == 8:
                out.append(int(round(128 + 127 * scaled)) & 0xFF)
            else:
                out += struct.pack("<h", int(round(32767 * scaled)))
    return bytes(out)


def wav(frames: int, channels: int, bits: int, rate: int, tone: float) -> bytes:
    """Build a canonical PCM WAVE file."""
    data = samples_pcm(frames, channels, bits, rate, tone)
    if len(data) % 2:
        raise ValueError("data chunk must have an even length")
    block_align = channels * bits // 8
    fmt = struct.pack(
        "<HHIIHH", PCM, channels, rate, rate * block_align, block_align, bits
    )
    body = (
        b"WAVE"
        + b"fmt "
        + struct.pack("<I", len(fmt))
        + fmt
        + b"data"
        + struct.pack("<I", len(data))
        + data
    )
    return b"RIFF" + struct.pack("<I", len(body)) + body


SAMPLES = {
    "sample_01.wav": wav(24, 1, 16, 8000, 440.0),
    "sample_02.wav": wav(16, 2, 16, 16000, 880.0),
    "sample_03.wav": wav(40, 1, 8, 11025, 330.0),
    "sample_04.wav": wav(12, 2, 8, 22050, 1000.0),
    "sample_05.wav": wav(30, 1, 16, 44100, 523.25),
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
