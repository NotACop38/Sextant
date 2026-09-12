# Draft project introduction: executable hypotheses for binary data

This is an unpublished draft, not a release announcement. Refresh validation and
distribution status before sharing it.

Sextant combines statistical inference, a native Rust executor, and editable
parser exports. It proposes boundaries, lengths, and repetition from binary
samples, executes each hypothesis, and reports fit and per-field evidence.
The public CLI operates offline; an optional engine API allows model proposals.

Refinements must preserve aggregate fit and previously successful samples.
Semantic names remain suggestions, even when the bytes fit. A perfect fit score
can describe an opaque payload without recovering its internal structure.

Kaitai, ImHex, Wireshark Lua, and 010 Editor exporters support checked subsets of
the IR. Native execution and target runtime validation are separate forms of
evidence. The benchmark currently uses 21 development samples in five formats;
held-out accuracy, full PRD corpus coverage, and competitor comparisons remain open.

Build from source using the [installation guide](installation.md). See the
[README](../README.md), [verification explanation](how-it-works.md), and
[review record](REVIEW_2026-09-12.md) for current capabilities and limitations.
