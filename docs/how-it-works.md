# How it works

The defining property of Sextant is verification. Every structural hypothesis
is executed natively against your samples and scored, and nothing is kept
unless it parses them. This page explains the pieces that make that work: the
Format Hypothesis IR, statistical inference, and the verification loop.

## The pipeline at a glance

```
  samples  ->  ingest  ->  statistical inference  ->  candidate IRs
                                                          |
                                                          v
                                        +----------------------------------+
                                        |  execute each IR against bytes   |
                                        |  score the fit and the structure |
                                        +----------------------------------+
                                                          |
                          best candidate                  v
   exporters  <-  chosen IR  <-  refine: nudge, swap, and (optionally) ask
                                  the model, keeping only verified gains
```

Ingestion normalizes inputs into an ordered sample set. Statistical inference
proposes candidate structures. The executor and scorer test them. Refinement
improves the best one without ever lowering its verified score. Exporters
translate the final structure into parser specs.

## The Format Hypothesis IR

The IR is a structured, executable description of what Sextant thinks a format
is. Inference writes it, the executor runs it, the report stores it, and the
exporters read it. Keeping one IR in the middle is what lets Sextant verify a
hypothesis once and then emit a Kaitai spec, a Wireshark dissector, an ImHex
pattern, and a 010 template from the same checked structure.

An IR is a `Format`: a name, a default byte order, named enums, and a root
`Structure`, which is an ordered list of `Field`s. A field has:

- a **kind**: an integer (width, signedness, byte order), raw bytes, a string,
  an enum, a nested struct, an array, or an opaque payload;
- a **size rule**: a fixed size, a size taken from a length field, a
  terminator, or "to the end" of the sample or enclosing region;
- a **count rule** for arrays: a fixed count, a count field, a length field
  that bounds the array's total bytes, or "to the end";
- an optional **offset**: an absolute position, or one taken from an offset
  field;
- a **role**: `magic`, `version`, `length`, `count`, `offset`, `checksum`,
  `timestamp`, `flags`, `enum`, `reserved`, `payload`, or `unknown`;
- **constraints**: an expected constant, an integer range, or a checksum
  (CRC-32, CRC-16/ARC, additive sum, or XOR) over a byte range anchored to
  fields; and
- **evidence and confidence**: which detector proposed the field, how many
  samples support it, and why.

A struct may carry a size rule. It is then a bounded region: its fields are
read inside the region and may not run past it, and parsing continues after
the region even when its fields leave some bytes unread. This is how Sextant
types a length-governed body, such as a RIFF chunk or a container payload,
whose layout is only partly known.

References between fields (a length, a count, an offset, a checksum anchor)
name the field they depend on. Validation resolves every reference, rejects
dangling, forward, and ambiguous ones, bounds nesting depth and sizes, and
reports each problem with its location. Every report and export path
validates the IR before using it, and the IR round-trips losslessly through
JSON.

The IR is not prose or a diagram. It is executable, which is what makes a
hypothesis falsifiable.

## Statistical inference

Inference looks for evidence that holds in every sample: invariant bytes (a
signature), integers whose value equals the sample length, the length of a
region, or a number of records, integers that point at an invariant marker,
and checksums that verify. It segments the header region with a two-part
minimum description length code, which types a byte run as a constant, an
integer, text, or raw bytes only when that shortens the description of the
samples.

From that evidence it builds candidates from several families: a fixed
layout; a size field that governs the rest of the sample, with the body typed
as a nested sized struct when that verifies; counted records; variable
regions in sequence, confirmed by what follows them; length-prefixed chunk
streams with per-chunk checksums; an offset to an invariant marker; a typed
prefix before an opaque payload; and magic-only and opaque fallbacks, so there
is always a candidate that parses.

## The verification loop

This is the heart of the tool and the property to protect above all.

### Execute

The executor runs an IR against one sample and produces concrete field
instances with byte ranges and decoded values, or a localized failure with the
offset and the reason. It is native Rust with no JVM, no Kaitai compiler, and
no network dependency, so it runs fully offline. It enforces limits on
recursion depth, array length, field count, owned output bytes, total work,
and wall-clock time. Fuzzing and malformed-input tests exercise these limits;
they show robustness on what was tried, not a proof for every input.

### Score

The scorer turns the executions over all samples into a fit score from 0 to 1
with three dimensions:

- **Coverage**: the fraction of each sample's bytes the fields explain, with
  no overruns and no double counting. Gaps and trailing bytes lower it.
- **Consistency**: the fraction of the hypothesis's own constraints that hold:
  constants, integer ranges, and checksums.
- **Generality**: the fraction of samples that parse to a clean end.

Coverage and consistency are averaged with a penalty for the worst sample, so
a hypothesis that fits one sample and fails another cannot hide behind the
mean.

Fit answers "does this parse every sample without contradiction?" An opaque
field that swallows each sample fits perfectly, so fit alone cannot tell a
recovered format from no recovery at all. The **structure** measure answers
the second question. It estimates, as a two-part description length, how many
bits the hypothesis still needs to reproduce the samples, relative to storing
them raw:

- bytes pinned by a passing constant or a verifying checksum cost nothing per
  sample;
- an integer costs the logarithm of the range of values it takes;
- printable text costs `log2(95)` bits per character;
- raw bytes, opaque payloads, failed constants, and unexplained bytes cost
  eight bits each; and
- every field definition costs a fixed charge, so splitting bytes into many
  fields cannot buy credit.

Structure is one minus that ratio: zero for an opaque hypothesis, higher as
constants, checksums, and typed fields explain more. Payload bytes are
unpredictable by nature, so payload-heavy formats have a low ceiling. It
compares hypotheses over the same samples; it is not a probability or a
semantic judgment.

### Choose

Candidates are ranked by whether they fully verify every sample, then fit,
then how many checksum checks pass, then how many field relationships they
encode, then structure, with the name as a final tie-break, so the result is
deterministic. A passing checksum ranks first among the evidence because it
almost never verifies by chance.

### Refine

Refinement starts from the best candidate and tries local changes: nudging
field boundaries and swapping byte order and integer widths. Every change runs
through the same executor and scorer. A heuristic change is kept only if it
strictly improves the fit over the full sample set and no sample that parsed,
or fully verified, loses that status. Because every accepted change raises a
score bounded by one, the loop converges; a hard cap on passes backs that up.
The report records each accepted step with the score before and after.

### The model pass

With `sextant infer --provider`, in a build with the `llm` feature, a language
model is asked for names, roles, types, enum meanings, size rules, and a
format-family guess, as structured output. The request holds the candidate's
field layout and at most 256 bytes from each of the first four samples. Each
proposal is applied only through the executor and scorer, under the same gate
as refinement plus one more rule: no sample may lose a constraint check it
passed before. A rename must not change what any reference binds to. See
[Model data handling](model-data-handling.md).

### The non-negotiable invariant

The model proposes; the executor disposes. A model or heuristic change is
never accepted if it lowers the verified parse score on the full sample set
(FR-26, FR-31). The model can suggest better names, roles, and refinements and
speed up the search, but it never decides the result and cannot substitute an
unchecked guess for a tested one. Enabling it can therefore only match or
improve the statistics-only fit, never fall below it.

## What verification does and does not establish

Verification establishes that the chosen IR parses the retained samples as
scored. It does not establish that field meanings are right, that the
structure holds for samples you did not supply, or that an exported parser
behaves identically in its own runtime. Confidence values summarize evidence
from the samples; they are not calibrated probabilities.

Exporters translate the IR into another language and refuse layouts the
target cannot express faithfully. That translation is checked separately:
optional Kaitai cross-validation compiles the spec and requires it to consume
every sample; runtime tests run generated Kaitai (through the Python runtime)
and Wireshark Lua and compare their field ranges with the native executor's.
ImHex and 010 Editor output has no runtime qualification yet.

See [Privacy and the `--no-llm` story](privacy.md) for how the optional model
pass fits in without weakening the guarantee.
