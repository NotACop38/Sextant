#!/usr/bin/env python3
"""Generate the Sextant Standard MIDI File corpus.

This script is the authoritative, reproducible source for the MIDI samples in
this directory. Re-running it regenerates byte-identical files. Each sample is a
genuine Standard MIDI File: an MThd header chunk (length 6, format, track
count, division) followed by that many MTrk chunks, each a big-endian length
and the track's delta-timed events ending in the End of Track meta event, as
documented in ../README.md and ground_truth.json.

Every file is parsed back by an independent reader below, which walks the
chunks, decodes every variable-length delta time and event, and requires each
track to end exactly with End of Track.
"""

import struct
from pathlib import Path


def vlq(value: int) -> bytes:
    """Encode a MIDI variable-length quantity."""
    out = [value & 0x7F]
    value >>= 7
    while value:
        out.append(0x80 | (value & 0x7F))
        value >>= 7
    return bytes(reversed(out))


def track(events) -> bytes:
    """A track chunk from (delta, event bytes) pairs, closed by End of Track."""
    body = b"".join(vlq(delta) + event for delta, event in events)
    body += vlq(0) + b"\xff\x2f\x00"
    return b"MTrk" + struct.pack(">I", len(body)) + body


def tempo(microseconds_per_quarter: int):
    return (0, b"\xff\x51\x03" + microseconds_per_quarter.to_bytes(3, "big"))


def melody(channel: int, notes, length: int, velocity: int):
    """Note-on and note-off pairs for each note in turn."""
    events = []
    for note in notes:
        events.append((0, bytes([0x90 | channel, note, velocity])))
        events.append((length, bytes([0x80 | channel, note, 0x40])))
    return events


def smf(fmt: int, division: int, tracks) -> bytes:
    header = b"MThd" + struct.pack(">IHHH", 6, fmt, len(tracks), division)
    return header + b"".join(tracks)


def read_back(data: bytes) -> int:
    """Walk a Standard MIDI File and return its track count."""
    assert data[:4] == b"MThd"
    length, fmt, ntrks, _division = struct.unpack(">IHHH", data[4:14])
    assert length == 6 and fmt in (0, 1) and (fmt == 1 or ntrks == 1)
    pos = 14
    for _ in range(ntrks):
        assert data[pos : pos + 4] == b"MTrk"
        size = struct.unpack(">I", data[pos + 4 : pos + 8])[0]
        body = data[pos + 8 : pos + 8 + size]
        assert len(body) == size
        i = 0
        ended = False
        while i < len(body):
            while body[i] & 0x80:
                i += 1
            i += 1
            status = body[i]
            if status == 0xFF:
                kind, meta_len = body[i + 1], body[i + 2]
                i += 3 + meta_len
                ended = kind == 0x2F
            elif status & 0xF0 in (0x80, 0x90):
                i += 3
            else:
                raise AssertionError(f"unexpected status {status:#x}")
        assert ended and i == len(body)
        pos += 8 + size
    assert pos == len(data)
    return ntrks


SAMPLES = {
    "sample_01.mid": smf(0, 96, [track([tempo(500_000)] + melody(0, [60, 62, 64], 48, 100))]),
    "sample_02.mid": smf(
        1,
        480,
        [
            track([tempo(600_000)]),
            track(melody(0, [67, 69, 71, 72], 240, 90)),
        ],
    ),
    "sample_03.mid": smf(
        1,
        960,
        [
            track([tempo(428_571)]),
            track(melody(1, [48, 55], 960, 80)),
            track(melody(2, [72, 76, 79, 84, 79], 480, 110)),
        ],
    ),
    "sample_04.mid": smf(0, 192, [track([tempo(750_000)] + melody(3, [57], 384, 64))]),
    "sample_05.mid": smf(
        1,
        240,
        [
            track([tempo(500_000)] + melody(0, [60, 64, 67], 120, 96)),
            track(melody(9, [36, 38, 36, 38, 42, 42], 60, 127)),
        ],
    ),
}


def main():
    here = Path(__file__).resolve().parent
    samples_dir = here / "samples"
    samples_dir.mkdir(exist_ok=True)
    for name, data in SAMPLES.items():
        tracks = read_back(data)
        (samples_dir / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes, {tracks} track(s)")


if __name__ == "__main__":
    main()
