# Privacy and the `--no-llm` story

Sextant is designed so that the powerful default is also the private one. The
statistical engine, the executor, and the scorer are native Rust and run
entirely on your machine. The v0.1.0 CLI always uses that statistics-only path.
The engine also contains an optional language-model semantic path for library
use and tests; this page explains what is and is not transmitted when that path
is enabled by an integrator.

## The two modes

| | Statistics-only CLI (`--no-llm`) | Engine model path |
|---|---|---|
| Network egress | None. Zero bytes leave the machine. | Only the prompt described below, sent to your chosen provider. |
| What runs | Ingestion, statistical inference, the native executor and scorer, refinement, export. | All of that, plus a semantic pass and model-proposed refinements. |
| Where the result comes from | Verified entirely by the native executor. | Still verified entirely by the native executor. The model only proposes; it never decides. |
| Requirements | None beyond the binary. | An API key in the environment or config and a caller that uses `infer_with_llm`. |

The verification property does not change between modes. In both, a hypothesis
is accepted only because it parsed your samples. The model can speed up the
search and add semantic names and roles, but a model proposal is applied only
when the native scorer confirms it does not lower the verified fit (FR-26,
FR-31). See [How it works](how-it-works.md).

## `--no-llm`: fully offline

Pass `--no-llm` to `infer` and Sextant transmits nothing. This is a hard
guarantee, not a best effort (NFR-4):

```bash
sextant infer ./samples --no-llm --out report.json
```

`inspect`, `export`, and `bench` never contact the network at all, regardless of
flags. They operate purely on the local report and samples.

If you need to prove the offline property in a locked-down environment, run
Sextant with no network route available (for example in a container with
networking disabled). The `--no-llm` path completes normally, because it never
opens a socket.

> Note on the current build: the public CLI does not expose provider selection
> flags yet. `sextant infer` already behaves as a statistics-only, offline run,
> and `--no-llm` documents that intent explicitly.

## What the engine model path transmits, when enabled

When a caller opts in to `infer_with_llm`, Sextant sends a single bounded request
per model call, to the provider configured by that caller (Anthropic or OpenAI as
first-class options, Ollama optionally and locally). The request contains:

- a compact description of the candidate structure (field boundaries, sizes, and
  tentative roles), and
- a bounded byte view of the samples, capped by the caller's semantic options.

It does not send your whole corpus, your file names, your environment, or any
secret. The byte view is limited by the per-sample cap so you control exactly
how much sample data can leave the machine. Responses are cached on disk keyed by
a hash of the exact request, so re-runs are reproducible and do not repeat calls.

For the precise contents, controls, and provider behavior, see
[Model data handling](model-data-handling.md).

## Secrets

API keys are read only from the environment or a configuration file, never from
a command-line flag (FR-40). This keeps keys out of your shell history and out of
process listings. If no key is present, an LLM-enabled caller cannot authenticate
to a remote provider and should fall back to the verified statistics-only result.

## Recommended posture for sensitive samples

- For confidential or regulated data, use `--no-llm`. Nothing leaves the
  machine.
- When you do enable the engine model path, use the smallest byte cap that still
  lets inference work, to minimize what is sent.
- Analyze potentially malicious samples in an isolated environment regardless of
  mode. See [SECURITY.md](../SECURITY.md).
