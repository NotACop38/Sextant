# Model data handling

This note documents what the optional engine language-model path does with your
data when an integrator enables it: what is transmitted, what is not, how it is
bounded, and how to turn it off entirely. It is the detailed companion to
[Privacy and the `--no-llm` story](privacy.md), and it satisfies the
"model data handling" requirement in PRD Section 16.

The one-line summary: the model accelerates the search and proposes semantics,
but it never sees more than a bounded, capped view of your samples, and it never
decides the result. Verification stays native and local.

## The default CLI is offline

The v0.1.0 CLI always runs the statistics-only path and transmits nothing
(NFR-4). The native statistical engine, executor, and scorer produce a complete,
verified result on their own. The model path is available through the engine API
for callers that explicitly invoke `infer_with_llm`.

## When the engine model path is enabled

When an integrator enables the model path, Sextant makes one or more bounded
requests to the provider configured by that caller. Anthropic and OpenAI are
first-class provider implementations; Ollama is an optional local provider that
keeps even the model step on your own machine. The public CLI does not expose
`--provider`, `--model`, or model-call budget flags in v0.1.0.

### What is transmitted

Each model request contains only:

- **A compact description of the candidate structure.** Field boundaries, sizes,
  endianness and width hypotheses, and the tentative roles the statistical pass
  has already inferred. This is structural metadata, not your raw data wholesale.
- **A bounded byte view of the samples.** A limited slice of sample bytes so the
  model can reason about values, strictly capped by the caller's semantic
  options. This cap is the upper bound on how much sample data can ever leave
  the machine.
- **A fixed instruction and a JSON schema.** The model is asked to return
  structured JSON (field annotations and refinement operations expressed against
  the IR). Free-form text output is not accepted.

### What is not transmitted

- Your entire corpus. Only the capped byte view is included, not every byte of
  every sample.
- File names, paths, directory structure, or other filesystem metadata.
- Environment variables, configuration, or secrets. API keys are read from the
  environment or a config file and used only to authenticate the request; they
  are never echoed into prompts.
- Anything at all when `--no-llm` is set.

## How the data is bounded and controlled

- **Per-sample byte cap.** The inference byte cap limits both what is read and
  what can be sent. Set it as low as inference allows for sensitive data.
- **Call cap and budget.** A maximum number of model calls per run, and an
  optional spend budget, bound cost and exposure (NFR-9). If a limit is hit, the
  run degrades gracefully to the best verified statistics-only result.
- **On-disk caching.** Responses are cached keyed by a hash of the exact
  request, so identical requests are served from disk with no new network call
  (NFR-6). This makes runs reproducible and avoids repeated transmission.
- **Low temperature.** The model is queried deterministically for reproducible
  proposals.

## The verification guarantee

This is the property that makes the model pass safe to use. Every model proposal
flows through the same native executor and scorer that the offline pipeline uses.
A proposal is applied only if the verified fit does not regress on the full
sample set (FR-26, FR-31). The model proposes; the executor disposes. Enabling
the model can only add verified improvements and semantic labels on top of the
statistics-only baseline; it can never lower the verified parse score, and it
can never substitute an unchecked guess for a tested result.

## Turning it off

- Use the v0.1.0 CLI, which runs statistics-only.
- Or set `no_llm` when calling the engine API.

Either way, Sextant runs fully offline and still produces a verified field map
and a runnable parser.
