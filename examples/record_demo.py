#!/usr/bin/env python3
"""Record the Sextant demo as an asciinema v2 cast.

This runs the real ``sextant`` commands against the bundled TLV corpus and
captures their output into ``docs/demo.cast``, an asciicast v2 file. The result
plays with ``asciinema play docs/demo.cast`` and can be uploaded to
asciinema.org or rendered to a GIF or SVG.

The cast is generated from genuine command output, not hand-written, so it stays
honest as the tool changes. Regenerate it whenever the demo flow changes:

    cargo build --release
    python3 examples/record_demo.py

The story is the project's one-line pitch: an unknown blob goes in, a field map
and a working parser come out, fully offline.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SEXTANT = os.environ.get("SEXTANT", str(REPO_ROOT / "target" / "release" / "sextant"))
CAST_PATH = REPO_ROOT / "docs" / "demo.cast"

WIDTH = 100
HEIGHT = 34

# Pacing, in seconds, for a readable playback.
PROMPT_PAUSE = 0.6
TYPE_DELAY = 0.03
POST_OUTPUT_PAUSE = 1.2


class CastWriter:
    """Accumulate asciicast v2 output events with a running clock."""

    def __init__(self) -> None:
        self.events: list[list] = []
        self.clock = 0.0

    def wait(self, seconds: float) -> None:
        self.clock += seconds

    def emit(self, text: str) -> None:
        self.events.append([round(self.clock, 3), "o", text])

    def prompt(self) -> None:
        self.wait(PROMPT_PAUSE)
        self.emit("$ ")

    def type_command(self, command: str) -> None:
        for char in command:
            self.wait(TYPE_DELAY)
            self.emit(char)
        self.wait(0.2)
        self.emit("\r\n")

    def output(self, text: str) -> None:
        # Normalize newlines for terminal playback.
        self.emit(text.replace("\n", "\r\n"))
        self.wait(POST_OUTPUT_PAUSE)


def run(args: list[str]) -> str:
    """Run a sextant command and return its combined output."""
    result = subprocess.run(
        [SEXTANT, *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout + result.stderr


def main() -> int:
    if not Path(SEXTANT).exists():
        print(
            f"error: {SEXTANT} not found. Build it first: cargo build --release",
            file=sys.stderr,
        )
        return 1

    samples = "corpus/tlv/samples"
    sample_one = "corpus/tlv/samples/sample_01.tlv"

    with tempfile.TemporaryDirectory() as work:
        report = str(Path(work) / "report.json")

        cast = CastWriter()
        banner = (
            "# Sextant demo: an unknown binary blob in, "
            "a field map and a working parser out.\r\n"
        )
        cast.emit(banner)
        cast.wait(1.0)

        steps = [
            (
                f"sextant infer {samples} --no-llm --out report.json",
                ["infer", samples, "--no-llm", "--out", report],
            ),
            (
                f"sextant inspect report.json --sample {sample_one}",
                ["inspect", report, "--sample", sample_one],
            ),
            (
                "sextant export report.json --format kaitai",
                ["export", report, "--format", "kaitai"],
            ),
        ]

        for display, args in steps:
            cast.prompt()
            cast.type_command(display)
            cast.output(run(args))

        cast.prompt()
        cast.wait(1.0)

        header = {
            "version": 2,
            "width": WIDTH,
            "height": HEIGHT,
            "timestamp": int(time.time()),
            "title": "Sextant demo",
            "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
        }

        CAST_PATH.parent.mkdir(parents=True, exist_ok=True)
        with CAST_PATH.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(header) + "\n")
            for event in cast.events:
                handle.write(json.dumps(event) + "\n")

    print(f"Wrote {CAST_PATH}")
    print("Play it with: asciinema play docs/demo.cast")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
