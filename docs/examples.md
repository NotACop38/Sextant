# Examples and demo

Sextant ships runnable examples that work against the bundled ground-truth corpus
on a fresh checkout. They are all fully offline. The sources live in
[`examples/`](../examples/), with a short index in
[`examples/README.md`](../examples/README.md).

Build the binary first:

```bash
cargo build --release
```

## The recorded demo

The demo shows the project's one-line pitch: an unknown binary blob goes in, and
a field map plus a working parser come out, fully offline.

It is recorded as an asciinema cast at [`docs/demo.cast`](demo.cast). Play it
locally:

```bash
asciinema play docs/demo.cast
```

The cast is generated from genuine command output by
[`examples/record_demo.py`](../examples/record_demo.py), not hand-written, so it
stays honest as the tool changes. Regenerate it with:

```bash
python3 examples/record_demo.py
```

## Run the flow yourself

The [`quickstart.sh`](../examples/quickstart.sh) script runs the same infer,
inspect, export flow against any corpus format:

```bash
./examples/quickstart.sh          # the TLV corpus
./examples/quickstart.sh png      # any directory under corpus/
```

## Embed the library

The [`infer_corpus`](../sextant-engine/examples/infer_corpus.rs) Rust example
drives the pipeline through the library API, which is useful if you want to embed
Sextant rather than shell out to the binary:

```bash
cargo run -p sextant-engine --example infer_corpus
cargo run -p sextant-engine --example infer_corpus -- png
```

## See also

- [Quick start](quickstart.md): the flow explained step by step.
- [Workflows](workflows.md): the full command reference.
- [How it works](how-it-works.md): why the output is verified, not guessed.
