#!/usr/bin/env python3
"""Generate the Sextant toy protocol capture corpus.

This script is the authoritative, reproducible source for the toy protocol
captures in this directory. Re-running it regenerates byte-identical files.

The toy protocol ("TOYP") is a small controlled binary request/response protocol
authored for the Sextant protocol inference tests (Step 11). It exercises the
three protocol-oriented field semantics: a message type, a sequence number, and
a length, with a length-governed payload.

Wire format (all multi-byte integers little-endian):
  msg_type  u8   one of PING (1), DATA (2), BYE (3)
  sequence  u16  increments once per client request; the server echoes it
  length    u16  the number of payload bytes that follow
  payload   length bytes

The messages are framed in Ethernet + IPv4 + TCP and written to a classic
little-endian pcap file. The client is 10.0.0.10 and the server 10.0.0.20 on TCP
port 9000. The client sends a request and the server replies, echoing the type
and sequence with its own payload, so requests carry a strictly increasing
sequence and the two directions share a flow.
"""

import struct
from pathlib import Path

CLIENT_IP = "10.0.0.10"
SERVER_IP = "10.0.0.20"
CLIENT_PORT = 51000
SERVER_PORT = 9000

PING, DATA, BYE = 1, 2, 3


def toyp(msg_type, sequence, payload):
    """Encode one toy protocol message."""
    return struct.pack("<BHH", msg_type, sequence, len(payload)) + payload


def ip_bytes(addr):
    return bytes(int(part) for part in addr.split("."))


def ethernet(src_mac, dst_mac, payload):
    return dst_mac + src_mac + struct.pack(">H", 0x0800) + payload


def ipv4(src, dst, payload):
    total = 20 + len(payload)
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,            # version 4, IHL 5
        0x00,            # DSCP/ECN
        total,           # total length
        0x0000,          # identification
        0x4000,          # flags (DF), fragment offset 0
        64,              # TTL
        6,               # protocol TCP
        0x0000,          # header checksum (left zero; not validated by Sextant)
        ip_bytes(src),
        ip_bytes(dst),
    )
    return header + payload


def tcp(src_port, dst_port, seq, payload):
    header = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        seq,             # sequence number
        0,               # acknowledgement number
        0x50,            # data offset 5 words
        0x18,            # flags PSH, ACK
        65535,           # window
        0x0000,          # checksum (left zero)
        0x0000,          # urgent pointer
    )
    return header + payload


def frame(to_server, payload):
    client_mac = bytes.fromhex("020000000010")
    server_mac = bytes.fromhex("020000000020")
    if to_server:
        ip = ipv4(CLIENT_IP, SERVER_IP, tcp(CLIENT_PORT, SERVER_PORT, 0, payload))
        return ethernet(client_mac, server_mac, ip)
    ip = ipv4(SERVER_IP, CLIENT_IP, tcp(SERVER_PORT, CLIENT_PORT, 0, payload))
    return ethernet(server_mac, client_mac, ip)


def pcap(records):
    """Build a classic little-endian Ethernet pcap from (to_server, msg) pairs."""
    out = bytearray()
    # Global header: magic, version 2.4, zone, sigfigs, snaplen, linktype 1.
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, (to_server, message) in enumerate(records):
        data = frame(to_server, message)
        out += struct.pack("<IIII", index, 0, len(data), len(data))
        out += data
    return bytes(out)


def session():
    """A client/server session covering all three message types."""
    payloads = {
        PING: [b"", b"ping"],
        DATA: [b"the-quick-brown-fox", b"lorem-ipsum-dolor-sit-amet", b"x"],
        BYE: [b"bye", b"goodbye-now"],
    }
    plan = [
        (PING, b""),
        (DATA, b"the-quick-brown-fox"),
        (PING, b"ping"),
        (DATA, b"lorem-ipsum-dolor-sit-amet"),
        (DATA, b"x"),
        (BYE, b"bye"),
        (PING, b""),
        (DATA, b"another-data-message"),
        (BYE, b"goodbye-now"),
    ]
    _ = payloads
    records = []
    sequence = 0
    for msg_type, request_payload in plan:
        records.append((True, toyp(msg_type, sequence, request_payload)))
        # The server echoes the type and sequence with an acknowledgement body.
        reply = b"ack-" + bytes([msg_type])
        records.append((False, toyp(msg_type, sequence, reply)))
        sequence += 1
    return records


SAMPLES = {
    "session_01.pcap": session(),
}


def main():
    here = Path(__file__).resolve().parent
    samples_dir = here / "samples"
    samples_dir.mkdir(exist_ok=True)
    for name, records in SAMPLES.items():
        data = pcap(records)
        (samples_dir / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes, {len(records)} messages")


if __name__ == "__main__":
    main()
