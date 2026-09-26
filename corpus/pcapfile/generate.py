#!/usr/bin/env python3
"""Generate the Sextant pcap file-format corpus.

This script is the authoritative, reproducible source for the capture files in
this directory. Re-running it regenerates byte-identical files. Each sample is a
classic little-endian, microsecond-resolution libpcap file with an Ethernet
link type: a 24-byte global header followed by records, each a 16-byte record
header and the captured frame, as documented in ../README.md and
ground_truth.json.

This entry evaluates the pcap container itself as a file format (PRD
Section 15, "a self-referential meta test"). The frames are synthetic
Ethernet/IPv4/UDP datagrams between documentation addresses (RFC 5737).
"""

import struct
from pathlib import Path

LINKTYPE_ETHERNET = 1
SNAPLEN = 65535


def ipv4_checksum(header: bytes) -> int:
    total = sum(struct.unpack(f">{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def frame(payload: bytes, sport: int, dport: int, ident: int) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        ident,
        0,
        64,
        17,
        0,
        bytes([192, 0, 2, 10]),
        bytes([198, 51, 100, 20]),
    )
    ip = ip[:10] + struct.pack(">H", ipv4_checksum(ip)) + ip[12:]
    ether = bytes.fromhex("020000000001") + bytes.fromhex("020000000002") + b"\x08\x00"
    return ether + ip + udp


def capture(packets) -> bytes:
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET))
    for seconds, micros, data in packets:
        out += struct.pack("<IIII", seconds, micros, len(data), len(data)) + data
    return bytes(out)


def session(start: int, sizes, port: int):
    packets = []
    for index, size in enumerate(sizes):
        payload = bytes((index * 31 + k * 7) & 0xFF for k in range(size))
        packets.append((start + index, 1000 * index + 17, frame(payload, 40000 + index, port, index + 1)))
    return capture(packets)


SAMPLES = {
    "sample_01.pcap": session(1_788_000_000, [4, 12], 9999),
    "sample_02.pcap": session(1_788_000_100, [1, 30, 8], 5353),
    "sample_03.pcap": session(1_788_000_200, [20], 123),
    "sample_04.pcap": session(1_788_000_300, [6, 6, 16, 2], 9999),
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
