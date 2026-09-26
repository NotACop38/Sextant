# Model data handling

The model pass is optional and off by default. It runs only when you pass
`--provider` to `sextant infer`, in a binary built with the `llm` feature.
Without `--provider`, or with `--no-llm`, nothing leaves the machine, and a
build without the feature contains no network code at all. Execution and
scoring stay local in every mode.

## What a request contains

A model-assisted run makes one logical request. It contains:

- fixed instructions and the JSON Schema the answer must follow;
- the candidate's name and, for each field, its index, name, role, type, and
  size rule, for example `6: length role=length kind=u16 little-endian size=2
  bytes`; and
- for each of the first four samples, its total length and at most its first
  256 bytes, in hex.

It does not contain file paths, constants beyond what appears in those bytes,
or anything from your environment. The API key authenticates the request and
is never part of the prompt. The byte preview is the main sample-derived
content, but the field layout is derived from the samples too, so treat the
whole request as sensitive.

## Providers and settings

Settings come from the process environment first, then from the Sextant config
file. Secrets are never read from a command-line flag.

| Setting | Meaning |
|---|---|
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` | The API key for that provider. Required for it. |
| `OLLAMA_HOST` | The Ollama server, for example `http://127.0.0.1:11434`. |
| `SEXTANT_ANTHROPIC_MODEL`, `SEXTANT_OPENAI_MODEL`, `SEXTANT_OLLAMA_MODEL` | The model to use when `--model` is not given. Anthropic defaults to `claude-opus-5` and OpenAI to `gpt-6-luna`; Ollama has no default. |
| `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` | Send requests to another endpoint, such as a gateway. |
| `SEXTANT_ANTHROPIC_EFFORT` | The Anthropic effort level: `low`, `medium`, `high`, `xhigh`, or `max`. Unset (or `off`) leaves it to the model's default. |
| `SEXTANT_ANTHROPIC_FALLBACKS` | `on` (the default) lets Anthropic re-run a request its model declines on another Anthropic model within the same call; `off` disables it. |
| `SEXTANT_MODEL_CACHE_DIR` | Cache responses in this directory (see below). Unset by default. |
| `SEXTANT_CONFIG` | The config file to read instead of the default location. |

The config file holds `KEY=VALUE` lines. Its default location is
`~/.config/sextant/config` on Unix and `%APPDATA%\sextant\config` on Windows.
On Unix, Sextant refuses a config file that its group or other users can
access, because it holds API keys; restrict it with `chmod 600`.

Each provider sends requests only to its configured endpoint. A remote Ollama
server takes the request off the machine like any other provider, so choose an
endpoint you trust. Providers that send an API key refuse a plain `http`
endpoint unless it is loopback, and loopback traffic never goes through a
proxy.

## Limits, retries, and accounting

- `--max-llm-calls` caps the logical calls in a run (default 8). A run needs
  one.
- A transient failure (a connection error, a timeout, or a retryable HTTP
  status such as 429 or 5xx) is retried up to three times with backoff that
  honors the provider's `retry-after`, so one logical call can mean up to four
  transmissions. When an endpoint rejects the Anthropic fallback option, the
  request is sent once more without it.
- Each HTTP request has an overall deadline of five minutes and a ten-second
  connection timeout, and response bodies are size-capped.
- The report's `metadata.model` records the calls made and the tokens the
  provider reported, including for responses that were then rejected, such as
  a refusal, a truncated answer, or unparseable JSON.
- Proposals are checked locally too: at most 256 entries of an answer are
  considered, and re-scoring stops at a fixed work budget.

## The response cache

When `SEXTANT_MODEL_CACHE_DIR` is set, each successful response is stored
there, keyed by a hash of the provider, model, endpoint, settings, and the
exact request. Repeating a run then replays the answer without a provider
call, and the report counts zero calls. The directory is checked before any
request, so a misconfigured cache fails before a billed call.

A cache entry holds the response, which can echo sample bytes, so the cache is
off by default. On Unix the directory is restricted to mode 0700 and each
entry to 0600, and a failure to set either is an error; on other platforms,
put the cache in a private directory. Entries are written atomically, and a
symlink, special file, oversized entry, or corrupt entry is treated as a miss.

## What verification establishes

Every proposed change is executed against the full retained sample set. A
change is kept only when the aggregate fit does not drop, every sample that
parsed or fully verified still does, and no sample loses a constraint check it
passed before. A rename must not change which field any reference binds to.
When the call fails or its result is unusable, the run keeps the
statistics-only result, and the report records why.

Names, roles, and the format-family guess can change without affecting the
fit. Their meaning is not verified by byte coverage, so review them as
suggestions. Native fit also says nothing about a provider's retention policy,
an exported parser's runtime behavior, or samples you did not supply. Sampling
parameters such as temperature are not sent, and a provider may answer the
same request differently, so only the cache makes a run exactly repeatable.

## Keeping analysis local

Omit `--provider`, or pass `--no-llm` to make the intent explicit and to have
any `--provider` rejected. For a guarantee enforced at build time, build
without the `llm` feature. Optional Kaitai cross-validation runs local tools
and is outside the native core's no-network boundary. Analyze hostile samples
in an isolated environment. See [Privacy](privacy.md) and
[SECURITY.md](../SECURITY.md).
