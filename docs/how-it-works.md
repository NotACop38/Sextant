# How it works

The defining property of Sextant is verification. Every structural hypothesis is
executed natively against your bytes and scored, and nothing is reported as fact
unless it parsed the samples. This page explains the two pieces that make that
work: the Format Hypothesis IR and the verification loop.

## The pipeline at a glance

```
  samples  ->  ingest  ->  statistical inference  ->  candidate IRs
                                                          |
                                                          v
                                        +----------------------------------+
                                        |  execute each IR against bytes   |
                                        |  score the fit (0 to 1)          |
                                        +----------------------------------+
                                                          |
                          best score                      v
   exporters  <-  chosen IR  <-  refine: nudge, swap, and (optionally) ask
                                  the model, keeping only verified gains
```

Ingestion normalizes inputs into an ordered sample set. Statistical inference
proposes candidate structures. The executor and scorer test them. Refinement
improves the best one without ever lowering its verified score. Exporters emit a
parser from the final, verified structure.

## The Format Hypothesis IR

The IR is a structured, executable description of what Sextant thinks a format
is. It is the single source of truth that everything else is built around:
inference writes it, the executor runs it, the report serializes it, and the
exporters read it. Keeping one IR in the middle is what lets Sextant verify a
hypothesis and then emit a Kaitai spec, an ImHex pattern, a Wireshark dissector,
and a 010 template from the same checked structure.

An IR is a `Format` containing one or more `Structure` definitions, each a list
of `Field`s. A field has:

- a **kind**: a fixed-size integer or bytes, a string, an array, a nested
  struct, an opaque payload, and so on;
- a **size rule**: a fixed size, a size derived from another field (a
  length-prefix relationship), or "to the end";
- a **count rule** for arrays: a fixed count, or a count driven by another
  field;
- a **role**: the semantic label, such as `magic`, `version`, `length`, `count`,
  `offset`, `checksum`, `timestamp`, `flags`, `enum`, `payload`, or `unknown`;
- **constraints**: for example, that a magic field equals a constant, that a
  value lies in a range, or that a checksum verifies over a covered byte range;
  and
- **evidence and confidence**: why the field was hypothesized this way, and how
  sure Sextant is.

Relationships such as length, count, offset, and checksum point at the field they
depend on by name. Validation resolves every reference and rejects dangling ones,
so an IR that reaches the executor is always well-formed. The IR serializes to
and from JSON, which is what the report stores.

The key idea is that the IR is not prose or a diagram. It is executable. That is
what makes a hypothesis falsifiable.

## The verification loop

This is the heart of the tool, and the property to protect above all.

### Execute

The executor runs an IR against one sample and produces concrete field instances
with byte ranges and decoded values, or a localized failure with the offset and
the reason. It is native Rust with no JVM, no Kaitai compiler, and no network
dependency, so it runs under `--no-llm` and fully offline. It enforces hard
resource limits (recursion depth, maximum array length, and a wall-clock cap) so
no input can cause a panic, a hang, or unbounded allocation.

### Score

The scorer turns a run into a fit score from 0 to 1, broken into three
dimensions:

- **Coverage**: how much of each sample the structure accounts for, with no
  unexplained leftover bytes.
- **Consistency**: whether internal relationships hold. Does a length field
  match the bytes it governs? Does a count match the number of records? Does a
  checksum (CRC32, CRC16, additive, or XOR over its covered range) verify?
- **Generality**: whether one structure fits across all samples, not just one.

A correct hypothesis scores near 1.0. A wrong one scores low, and the breakdown
points at the dimension that failed, which is what makes the failure useful.

### Refine

Sextant starts from the candidates that statistical inference proposed, executes
and scores each, and keeps the best. It then tries to improve it: nudging field
boundaries and swapping endianness and width hypotheses. The engine also has an
optional model semantic path for callers that invoke it directly; the v0.1.0 CLI
does not expose provider flags and runs statistics-only. Every candidate change
is run through the same executor and scorer, and a change is kept only if the
verified score does not regress on the full sample set. The loop always
terminates, by convergence, a target score, or a maximum iteration count.

### The non-negotiable invariant

The model proposes; the executor disposes. A model or heuristic change is never
accepted if it lowers the verified parse score on the full sample set (FR-26,
FR-31). The engine model path can suggest better names, roles, and refinements
and can speed up the search, but it never decides the result and it can never
substitute an unchecked guess for a tested one. This is why enabling that path
can only improve on the statistics-only baseline, never fall below it.

## Why this matters

A model that simply emits a guess can sound confident and be wrong, and you have
no way to tell. Sextant makes every hypothesis falsifiable and tests it, so the
parser it hands you is one that actually parsed your samples, and the confidence
report tells you honestly which parts were verified and which were inferred. The
real parsers (Kaitai, ImHex, Wireshark, 010) are exporters off that verified IR
at the very end.

See [Privacy and the `--no-llm` story](privacy.md) for how the optional model
pass fits into this without weakening the guarantee, and
[Model data handling](model-data-handling.md) for exactly what it transmits.
