# Model data handling

The public CLI runs statistics-only. The optional engine `infer_with_llm` API
sends requests only when an integrator enables it. Native execution and scoring
remain local in both modes.

## Request contents

Requests include a candidate structure, instructions, a response schema, and a
sample byte view bounded by the semantic options. The candidate itself may
contain sample-derived constants or labels, so the byte-view cap is not a cap
on every piece of sample-derived information in the request. These contents can
be sensitive. File paths and environment variables are not automatically added
to prompts; API keys authenticate the request rather than becoming prompt text.

Anthropic, OpenAI, and Ollama adapters use the caller's configured endpoint.
Ollama is local only when that endpoint is local. A remote Ollama endpoint sends
the request off the machine. The caller must choose and trust its endpoint.

## Limits, retries, and storage

- Semantic options bound sample selection and byte previews per request.
- The client limits logical calls. Retrying a failed call can make up to four
  HTTP attempts, so logical-call counts are not transmission counts.
- The optional spend check uses configured token prices and previously recorded
  usage. Default prices are zero, and an in-flight call may exceed a remaining
  budget. This is accounting support, not a strict provider spending cap.
- Disk caching is opt-in through client configuration. Without a configured
  cache directory, repeated requests can be transmitted again. Cache contents
  include model responses and should be stored in a private trusted directory.
- Provider responses can contain prose or fences around JSON; Sextant extracts
  a JSON proposal and validates its supported operations before applying it.

## What verification establishes

Every proposed structural change is executed against the full retained sample
set. Acceptance requires a finite nondecreasing aggregate score and preserves
previously successful and fully verified samples. Names and roles can change
without affecting that score. Their semantic correctness is not verified by
byte coverage and must be assessed by the analyst.

Native fit does not validate a provider, its retention policy, exported parser
runtime behavior, or results on unseen inputs. Low-temperature requests and
optional caches do not guarantee reproducible provider responses.

## Keeping analysis local

Use the statistics-only CLI or set `no_llm` in engine options. Optional external
Kaitai cross-validation executes tools chosen through the local environment;
it is outside the native core's no-network boundary. Analyze hostile samples in
an isolated environment. See [privacy](privacy.md) and [SECURITY.md](../SECURITY.md).
