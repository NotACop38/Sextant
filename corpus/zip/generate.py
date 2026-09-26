#!/usr/bin/env python3
"""Generate the Sextant ZIP corpus.

This script is the authoritative, reproducible source for the ZIP samples in
this directory. Re-running it regenerates byte-identical files. Each sample is a
genuine archive holding one stored (uncompressed) file: a local file header,
the file name, the file data, one central directory header, and the end of
central directory record, as documented in ../README.md and ground_truth.json.

The records are written explicitly rather than with `zipfile`, so every field,
including the timestamp and host system, is pinned by this script. The output
is checked by `zipfile`, which must list and extract the single entry with a
matching CRC-32. All multi-byte integers are little-endian.
"""

import io
import struct
import zipfile
import zlib
from pathlib import Path

VERSION_NEEDED = 20  # 2.0
VERSION_MADE_BY = (3 << 8) | 20  # Unix, 2.0
DOS_TIME = (14 << 11) | (30 << 5) | (0 // 2)  # 14:30:00
DOS_DATE = ((2026 - 1980) << 9) | (9 << 5) | 1  # 2026-09-01
EXTERNAL_ATTR = 0o100644 << 16  # regular file, rw-r--r--


def archive(name: str, content: bytes) -> bytes:
    raw_name = name.encode("ascii")
    crc = zlib.crc32(content) & 0xFFFFFFFF
    local = (
        struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04",
            VERSION_NEEDED,
            0,  # flags
            0,  # stored
            DOS_TIME,
            DOS_DATE,
            crc,
            len(content),
            len(content),
            len(raw_name),
            0,  # extra length
        )
        + raw_name
        + content
    )
    central = (
        struct.pack(
            "<4sHHHHHHIIIHHHHHII",
            b"PK\x01\x02",
            VERSION_MADE_BY,
            VERSION_NEEDED,
            0,
            0,
            DOS_TIME,
            DOS_DATE,
            crc,
            len(content),
            len(content),
            len(raw_name),
            0,  # extra length
            0,  # comment length
            0,  # disk number start
            0,  # internal attributes
            EXTERNAL_ATTR,
            0,  # local header offset
        )
        + raw_name
    )
    end = struct.pack(
        "<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0
    )
    data = local + central + end
    with zipfile.ZipFile(io.BytesIO(data)) as check:
        if check.namelist() != [name] or check.read(name) != content:
            raise ValueError("zipfile did not read back the entry")
    return data


SAMPLES = {
    "sample_01.zip": archive("a.txt", b"hello\n"),
    "sample_02.zip": archive("notes.md", b"# Notes\n\nStored, not deflated.\n"),
    "sample_03.zip": archive("data.bin", bytes(range(0, 40, 3))),
    "sample_04.zip": archive("readme", b"Sextant ZIP sample four.\n"),
    "sample_05.zip": archive("dir_a/file.cfg", b"key=value\nother=1\n"),
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
