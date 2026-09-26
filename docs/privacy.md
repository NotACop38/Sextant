# Privacy and offline analysis

Sextant runs fully offline by default. Ingestion, statistical inference, the
executor, the scorer, refinement, `inspect`, `export`, and `bench` all run
locally and open no network connection.

The only component that can send data off the machine is the optional model
pass, and it runs only when you ask for it with `--provider`:

```bash
# Offline: no --provider, so nothing is sent.
sextant infer ./samples --out report.json

# Offline, stated explicitly: --no-llm also rejects any --provider.
sextant infer ./samples --no-llm --out report.json

# Model-assisted: sends a bounded request to the configured provider.
sextant infer ./samples --provider anthropic --out report.json
```

A credential present in the environment never enables the model pass on its
own, so an API key exported for another tool cannot cause egress.

## Three levels of assurance

1. **A build without the `llm` feature** contains no network code at all. The
   default `cargo build -p sextant-re` produces such a binary, and a test
   checks that the default build links no network crate.
2. **`--no-llm`** runs statistics-only in any build and refuses to combine with
   `--provider`.
3. **Omitting `--provider`** runs statistics-only in any build.

Release binaries include the model providers, so they rely on the second or
third level.

## When you enable the model pass

The request holds the candidate field layout and at most 256 bytes from each
of the first four samples, never file paths or environment contents. Retries
can send the same request more than once. API keys come from the environment
or the config file, never from a command-line flag. Responses are cached on
disk only when you set `SEXTANT_MODEL_CACHE_DIR`. Every model proposal must
preserve the native fit before it is kept, but its names and roles are
suggestions: verifying byte ranges does not establish what the bytes mean.
[Model data handling](model-data-handling.md) documents every setting, limit,
and caveat.

## Optional external tools

`export --cross-validate` launches the local Kaitai compiler and a Python
runtime. They are optional and outside the native offline guarantee. Sextant
runs them in a private temporary directory, with Python in isolated mode,
deadlines, and output caps, but it cannot control the network behavior of a
replaced or compromised executable. Configure trusted tools, and isolate the
process where that matters.

## What to keep private

Reports and generated parsers can contain sample constants, such as
signatures, and inferred metadata. Keep them, the samples, and any model cache
as private as the samples themselves. Analyze potentially malicious samples in
an isolated environment regardless of model settings; see
[SECURITY.md](../SECURITY.md) and the [threat model](threat-model.md).
