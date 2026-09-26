#!/usr/bin/env python3
"""Generate the Sextant TAR corpus.

This script is the authoritative, reproducible source for the TAR samples in
this directory. Re-running it regenerates byte-identical files. Each sample is a
POSIX ustar archive holding one regular file smaller than one block: a 512-byte
header of fixed-width ASCII fields, one 512-byte data block padded with zeros,
and the two zero blocks that end an archive, as documented in ../README.md and
ground_truth.json.

Headers are built with `tarfile.TarInfo.tobuf` using pinned metadata. The
archive is not padded to the default 10240-byte record size, which readers
accept; `tarfile` must read back the entry for the script to write it.
"""

import io
import tarfile
from pathlib import Path

BLOCK = 512
MTIME = 1_788_000_000  # 2026-08-29


def archive(name: str, content: bytes, mode: int, owner: str) -> bytes:
    if len(content) > BLOCK:
        raise ValueError("each sample holds a file of at most one block")
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mtime = MTIME
    info.mode = mode
    info.uid = 1000
    info.gid = 1000
    info.uname = owner
    info.gname = owner
    header = info.tobuf(format=tarfile.USTAR_FORMAT, encoding="ascii", errors="strict")
    data = content + bytes(BLOCK - len(content))
    result = header + data + bytes(2 * BLOCK)
    with tarfile.open(fileobj=io.BytesIO(result)) as check:
        member = check.getmember(name)
        if check.extractfile(member).read() != content:
            raise ValueError("tarfile did not read back the entry")
    return result


SAMPLES = {
    "sample_01.tar": archive("a.txt", b"alpha\n", 0o644, "user"),
    "sample_02.tar": archive("notes/todo.md", b"- write tests\n- ship\n", 0o644, "user"),
    "sample_03.tar": archive("run.sh", b"#!/bin/sh\necho ok\n", 0o755, "build"),
    "sample_04.tar": archive("data.csv", b"id,value\n1,10\n2,20\n3,30\n", 0o600, "user"),
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
