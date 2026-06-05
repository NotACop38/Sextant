# Examples

Runnable examples that exercise Sextant against the bundled ground-truth corpus.
All of them are fully offline and statistics-only.

Build the binary first:

```bash
cargo build --release
```

## `quickstart.sh`: the infer, inspect, export flow

A shell script that runs the whole quick start against a corpus format: infer a
report, inspect a sample through it, and export a Kaitai Struct parser.

```bash
./examples/quickstart.sh          # uses the TLV corpus
./examples/quickstart.sh png      # or any directory under corpus/
```

It writes its report and parser to a temporary directory and cleans up after
itself. Set `SEXTANT=/path/to/sextant` to point at a different binary.

## `infer_corpus` (Rust): embedding the library

A Rust example that drives the same pipeline through the library API instead of
the CLI, so it shows how to embed Sextant. It ingests a corpus format, infers a
structure, and prints the fit score and field map.

```bash
cargo run -p sextant-engine --example infer_corpus           # TLV
cargo run -p sextant-engine --example infer_corpus -- png    # another format
```

This example is compiled by `cargo build --all-targets` and is exercised in the
test suite, so it stays working as the engine evolves.

## `record_demo.py`: regenerate the demo cast

Generates [`docs/demo.cast`](../docs/demo.cast), the asciinema recording linked
from the README, from genuine command output. Regenerate it whenever the demo
flow changes.

```bash
python3 examples/record_demo.py
```

Play the result with `asciinema play docs/demo.cast`, or upload it to
asciinema.org.

## See also

- [Quick start](../docs/quickstart.md): the same flow, explained step by step.
- [Workflows](../docs/workflows.md): every command and option.
