#!/usr/bin/env python3
"""Generate the Sextant Modbus/TCP capture corpus.

This script is the authoritative, reproducible source for the Modbus/TCP capture
in this directory. Re-running it regenerates a byte-identical file. Modbus/TCP is
the protocol showcase (PRD Section 15): a real, widely deployed industrial
protocol with a public, documented specification, so the inferred structure is
checkable against a known ground truth.

Modbus/TCP wire format (the MBAP header, all integers big-endian, then the PDU):
  transaction_id  u16  request id the response echoes (a transaction/sequence id)
  protocol_id     u16  always 0x0000 for Modbus
  length          u16  number of following bytes (unit id + function code + data)
  unit_id         u8   server unit/slave address
  function_code   u8   the operation (the message type)
  data            ...  function-specific payload

The capture exercises three function codes: read holding registers (0x03), read
coils (0x01), and write single register (0x06). The client (10.0.0.10) issues a
sequence of requests to the server (10.0.0.20) on TCP port 502, each with an
incrementing transaction id, and the server replies, echoing the transaction id,
unit id, and function code. The samples are synthetic but spec-faithful and
carry no third-party data.
"""

import struct
from pathlib import Path

CLIENT_IP = "10.0.0.10"
SERVER_IP = "10.0.0.20"
CLIENT_PORT = 50200
SERVER_PORT = 502
UNIT_ID = 0x01


def mbap(transaction_id, pdu):
    """Wrap a PDU in the MBAP header. The length counts the unit id plus PDU."""
    length = 1 + len(pdu)
    return struct.pack(">HHHB", transaction_id, 0x0000, length, UNIT_ID) + pdu


def read_holding_request(start, quantity):
    return struct.pack(">BHH", 0x03, start, quantity)


def read_holding_response(values):
    body = b"".join(struct.pack(">H", value) for value in values)
    return struct.pack(">BB", 0x03, len(body)) + body


def read_coils_request(start, quantity):
    return struct.pack(">BHH", 0x01, start, quantity)


def read_coils_response(coil_bytes):
    return struct.pack(">BB", 0x01, len(coil_bytes)) + coil_bytes


def write_register_request(address, value):
    return struct.pack(">BHH", 0x06, address, value)


def write_register_response(address, value):
    # The write-single-register response echoes the request.
    return struct.pack(">BHH", 0x06, address, value)


def ip_bytes(addr):
    return bytes(int(part) for part in addr.split("."))


def ethernet(src_mac, dst_mac, payload):
    return dst_mac + src_mac + struct.pack(">H", 0x0800) + payload


def ipv4(src, dst, payload):
    total = 20 + len(payload)
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0x00, total, 0x0000, 0x4000, 64, 6, 0x0000,
        ip_bytes(src), ip_bytes(dst),
    )
    return header + payload


def tcp(src_port, dst_port, payload):
    header = struct.pack(
        ">HHIIBBHHH",
        src_port, dst_port, 0, 0, 0x50, 0x18, 65535, 0x0000, 0x0000,
    )
    return header + payload


def frame(to_server, payload):
    client_mac = bytes.fromhex("020000000010")
    server_mac = bytes.fromhex("020000000020")
    if to_server:
        ip = ipv4(CLIENT_IP, SERVER_IP, tcp(CLIENT_PORT, SERVER_PORT, payload))
        return ethernet(client_mac, server_mac, ip)
    ip = ipv4(SERVER_IP, CLIENT_IP, tcp(SERVER_PORT, CLIENT_PORT, payload))
    return ethernet(server_mac, client_mac, ip)


def pcap(records):
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, (to_server, message) in enumerate(records):
        data = frame(to_server, message)
        out += struct.pack("<IIII", index, 0, len(data), len(data))
        out += data
    return bytes(out)


def session():
    """A sequence of Modbus transactions over the three function codes."""
    transactions = [
        (read_holding_request(0x0000, 2), read_holding_response([0x1234, 0x5678])),
        (read_coils_request(0x0010, 8), read_coils_response(bytes([0b10110011]))),
        (write_register_request(0x0001, 0x00FF), write_register_response(0x0001, 0x00FF)),
        (read_holding_request(0x0002, 4),
         read_holding_response([0x0001, 0x0002, 0x0003, 0x0004])),
        (read_coils_request(0x0000, 16), read_coils_response(bytes([0xFF, 0x0F]))),
        (write_register_request(0x0005, 0x1234), write_register_response(0x0005, 0x1234)),
        (read_holding_request(0x0100, 1), read_holding_response([0xABCD])),
        (read_coils_request(0x0020, 4), read_coils_response(bytes([0b00001010]))),
        (write_register_request(0x000A, 0x4321), write_register_response(0x000A, 0x4321)),
        (read_holding_request(0x0008, 3), read_holding_response([0x1111, 0x2222, 0x3333])),
        (read_coils_request(0x0040, 24), read_coils_response(bytes([0x01, 0x02, 0x03]))),
        (write_register_request(0x0011, 0x9999), write_register_response(0x0011, 0x9999)),
    ]
    records = []
    transaction_id = 1
    for request, response in transactions:
        records.append((True, mbap(transaction_id, request)))
        records.append((False, mbap(transaction_id, response)))
        transaction_id += 1
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
