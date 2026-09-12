# Privacy and offline analysis

The v0.1.0 CLI runs the native statistical engine, executor, scorer, refinement,
inspection, and ordinary export locally. It does not call a model or open network
connections. `--no-llm` documents that choice explicitly:

```bash
sextant infer ./samples --no-llm --out report.json
```

The engine library also offers `infer_with_llm` for callers that explicitly
configure a provider. It sends candidate metadata and bounded byte previews.
Candidate constants can contain sample-derived data beyond the preview, and
retries can transmit a request again. Caching is opt-in. Ollama keeps data local
only when its configured endpoint is local. See [model data handling](model-data-handling.md)
for the actual limits and cost-accounting behavior.

API keys come from environment variables or configuration, never CLI flags.
Model proposals must preserve native fit, but semantic labels are suggestions;
verification of byte ranges does not establish what those bytes mean.

## Optional external tools

`export --cross-validate` launches the local Kaitai compiler and Python runtime.
They are optional and not part of the native offline guarantee. Sextant bounds
their runtime and output and uses a private temporary directory, but cannot
control network behavior of a replaced or compromised external executable.
Configure trusted tools and use process/network isolation where required.

Reports and generated code can contain sensitive sample constants and inferred
metadata. Keep them private along with samples and optional model caches. For
hostile samples, use an isolated environment regardless of model settings.
