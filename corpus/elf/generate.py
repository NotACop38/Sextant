#!/usr/bin/env python3
"""Generate the Sextant ELF64 corpus.

This script is the authoritative, reproducible source for the ELF samples in
this directory. Re-running it regenerates byte-identical files. Each sample is a
minimal, statically linked x86-64 Linux executable: a 64-byte ELF header, one or
two 56-byte program headers, and a short code segment that exits with a fixed
status, as documented in ../README.md and ground_truth.json.

The code performs only the `exit` system call. All multi-byte integers are
little-endian (ELFDATA2LSB).
"""

import struct
from pathlib import Path

BASE = 0x400000
EHDR_SIZE = 64
PHDR_SIZE = 56
PT_LOAD = 1
PT_GNU_STACK = 0x6474E551
PF_X, PF_W, PF_R = 1, 2, 4


def exit_code(status: int, filler: int) -> bytes:
    """`mov edi, status; mov eax, 60; syscall`, preceded by `filler` NOPs."""
    return bytes([0x90] * filler) + (
        b"\xbf" + struct.pack("<I", status) + b"\xb8\x3c\x00\x00\x00\x0f\x05"
    )


def elf(status: int, filler: int, stack_header: bool) -> bytes:
    phnum = 2 if stack_header else 1
    code_offset = EHDR_SIZE + PHDR_SIZE * phnum
    code = exit_code(status, filler)
    size = code_offset + len(code)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + bytes(7)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # ET_EXEC
        0x3E,  # EM_X86_64
        1,  # EV_CURRENT
        BASE + code_offset,  # entry point
        EHDR_SIZE,  # program header table offset
        0,  # no section header table
        0,  # flags
        EHDR_SIZE,
        PHDR_SIZE,
        phnum,
        64,  # section header entry size
        0,  # section header count
        0,  # section name string table index
    )
    load = struct.pack(
        "<IIQQQQQQ", PT_LOAD, PF_R | PF_X, 0, BASE, BASE, size, size, 0x1000
    )
    phdrs = load
    if stack_header:
        phdrs += struct.pack("<IIQQQQQQ", PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 0, 16)
    return header + phdrs + code


SAMPLES = {
    "sample_01.elf": elf(0, 0, False),
    "sample_02.elf": elf(7, 3, True),
    "sample_03.elf": elf(42, 1, False),
    "sample_04.elf": elf(3, 6, True),
    "sample_05.elf": elf(255, 2, False),
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
