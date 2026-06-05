//! The language-model semantic pass and its verified refinement loop (FR-29 to
//! FR-32, FR-25, FR-26, FR-31).
//!
//! The model proposes; the native executor disposes. [`semantic_pass`] sends the
//! current candidate structure and a byte-capped view of the samples to a model,
//! receives a *structured* proposal (never free-form text, FR-30), and then runs
//! every proposed change through the very same scorer the heuristic refinement
//! loop uses. A change is applied only when the verified fit score over the full
//! sample set does not regress (FR-26, FR-31): the model accelerates the search
//! for names, roles, types, enum meanings, and a format-family guess, but it can
//! never lower the verified score or overrule the executor.
//!
//! # What is sent off the machine
//!
//! Only the candidate's field summary and at most
//! [`SemanticOptions::max_prompt_bytes_per_sample`] bytes from each of at most
//! [`SemanticOptions::max_samples_in_prompt`] samples are placed in the prompt.
//! That byte cap is the privacy guardrail (NFR-4). Cost is bounded by the
//! [`LlmClient`]'s call cap and budget (NFR-9); a run that trips a limit returns
//! an error, and callers (see [`crate::orchestrate::infer_with_llm`]) degrade
//! gracefully to the best verified statistics-only result.

use std::fmt::Write as _;

use serde::Deserialize;
use sextant_ir::{EnumDef, EnumVariant, Format, Kind, Role, SizeRule};
use sextant_llm::{JsonRequest, LlmClient, LlmError, LlmProvider};

use crate::limits::Limits;
use crate::refine::{RefineOutcome, RefineStep, Seg, field_paths, navigate};
use crate::report::{kind_label, role_label, size_label};
use crate::scorer::{Score, ScoreWeights, score_with};

/// The largest score regression tolerated when accepting a proposal. It is
/// floating-point noise only: a real drop is rejected, while a pure annotation
/// (a name or a role, which do not change the parse) scores identically and is
/// accepted (FR-26).
const REGRESSION_EPSILON: f64 = 1e-9;

/// The default per-sample byte cap placed in a prompt (NFR-4).
pub const DEFAULT_MAX_PROMPT_BYTES_PER_SAMPLE: usize = 256;

/// The default number of samples summarized in a prompt.
pub const DEFAULT_MAX_SAMPLES_IN_PROMPT: usize = 4;

/// The system instruction framing the semantic task for the model.
const SYSTEM_PROMPT: &str = "\
You are a binary-format reverse-engineering assistant. You are given a candidate \
field layout and a bounded hex view of sample bytes. Propose semantic \
annotations and concrete, testable refinements expressed against the given \
fields. Reference each field by its integer index. Do not invent fields you \
cannot see. Respond with a single JSON object and nothing else.";

/// A human-readable description of the JSON the model must return, folded into
/// the structured request (FR-30).
const SCHEMA_HINT: &str = "\
{\"format_family\": \"<string, optional>\", \"fields\": [{\"index\": <int>, \
\"name\": \"<string, optional>\", \"role\": \"<one of: magic, version, length, \
count, offset, checksum, timestamp, flags, enum, reserved, payload, unknown>\", \
\"type\": {\"type\": \"integer\", \"width\": <1|2|4|8>, \"signed\": \
\"unsigned|signed\", \"endianness\": \"little|big\"}, \"size\": {\"rule\": \
\"fixed|derived|to_end\", \"bytes\": <int>, \"length_field\": \"<name>\"}, \
\"enum\": [{\"value\": <int>, \"name\": \"<string>\"}], \"rationale\": \
\"<string, optional>\"}]}";

/// Options controlling the semantic pass.
#[derive(Debug, Clone)]
pub struct SemanticOptions {
    /// The maximum number of bytes from any single sample placed in the prompt.
    /// This is the hard privacy cap on what leaves the machine (NFR-4).
    pub max_prompt_bytes_per_sample: usize,
    /// The maximum number of samples summarized in the prompt.
    pub max_samples_in_prompt: usize,
}

impl Default for SemanticOptions {
    fn default() -> Self {
        Self {
            max_prompt_bytes_per_sample: DEFAULT_MAX_PROMPT_BYTES_PER_SAMPLE,
            max_samples_in_prompt: DEFAULT_MAX_SAMPLES_IN_PROMPT,
        }
    }
}

/// The structured proposal a model returns from the semantic pass (FR-29,
/// FR-30). Free-form prose is not accepted: the response is parsed into this
/// shape, and anything that does not deserialize is an
/// [`LlmError::InvalidResponse`].
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ModelProposal {
    /// The model's guess at the format family (for example `png` or `riff`).
    #[serde(default)]
    pub format_family: Option<String>,
    /// Per-field annotations and refinement operations, keyed by field index.
    #[serde(default)]
    pub fields: Vec<FieldProposal>,
}

/// One field's proposed annotations and refinements (FR-29, FR-30).
///
/// Every member except [`Self::index`] is optional; a proposal may set only a
/// name, only a role, a concrete type, a size rule, enum meanings, or any
/// combination. Each non-empty proposal is applied as one atomic candidate and
/// gated by the scorer (FR-26).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FieldProposal {
    /// The index of the field this proposal targets, in the same pre-order as
    /// the report's flattened field map.
    pub index: usize,
    /// A proposed field name.
    #[serde(default)]
    pub name: Option<String>,
    /// A proposed semantic role.
    #[serde(default)]
    pub role: Option<Role>,
    /// A proposed concrete type (an IR [`Kind`]). Structural kinds (`struct` and
    /// `array`) are not accepted from the model, so the field tree shape, and
    /// therefore field indices, stay stable across the pass.
    #[serde(rename = "type", default)]
    pub kind: Option<Kind>,
    /// A proposed size rule (for example a length dependency on another field).
    #[serde(default)]
    pub size: Option<SizeRule>,
    /// Proposed enum value meanings. When present the field is converted to an
    /// enum that references a generated definition (FR-29).
    #[serde(rename = "enum", default)]
    pub enum_variants: Option<Vec<EnumVariant>>,
    /// The model's rationale, recorded in the field's evidence for
    /// explainability (FR-28, NFR-7).
    #[serde(default)]
    pub rationale: Option<String>,
}

impl FieldProposal {
    /// Whether this proposal changes anything at all.
    fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.role.is_none()
            && self.kind.is_none()
            && self.size.is_none()
            && self.enum_variants.is_none()
            && self.rationale.is_none()
    }

    /// A short human-readable summary of what the proposal changes.
    fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(name) = &self.name {
            parts.push(format!("name={name}"));
        }
        if let Some(role) = self.role {
            parts.push(format!("role={}", role_label(Some(role))));
        }
        if let Some(kind) = &self.kind {
            parts.push(format!("type={}", kind_label(kind)));
        }
        if self.size.is_some() {
            parts.push("size".to_owned());
        }
        if self.enum_variants.is_some() {
            parts.push("enum".to_owned());
        }
        let summary = if parts.is_empty() {
            "no change".to_owned()
        } else {
            parts.join(", ")
        };
        format!("model: field {} ({summary})", self.index)
    }
}

/// The result of a semantic pass.
#[derive(Debug, Clone)]
pub struct SemanticOutcome {
    /// The annotated and refined IR, never worse than the input by verified
    /// score (FR-26).
    pub format: Format,
    /// The verified score of [`Self::format`] over the sample set.
    pub score: Score,
    /// The verified score of the input IR, the baseline the pass may not regress
    /// below (FR-26, FR-31).
    pub baseline_score: Score,
    /// Every proposal the pass considered, accepted or rejected, in order
    /// (FR-28).
    pub history: Vec<RefineStep>,
    /// The model's format-family guess, if it offered one.
    pub format_family: Option<String>,
}

/// Run the semantic pass over `format` against `samples` using `client`.
///
/// The pass makes one structured model call, parses the response into a
/// [`ModelProposal`], and applies each field proposal through the scorer's
/// non-regression gate. The returned [`SemanticOutcome::format`] is guaranteed
/// to score no lower than the input over the full sample set (FR-26, FR-31).
///
/// # Errors
///
/// Returns [`LlmError`] if the model call fails (transport, cache, a tripped
/// call cap or budget, NFR-9) or if the response is not a structured proposal
/// (FR-30). It never panics and never mutates the input format.
pub fn semantic_pass<P: LlmProvider>(
    format: &Format,
    samples: &[&[u8]],
    client: &LlmClient<P>,
    limits: &Limits,
    options: &SemanticOptions,
) -> Result<SemanticOutcome, LlmError> {
    let weights = ScoreWeights::default();
    let baseline_score = score_with(format, samples, limits, weights);

    let paths = field_paths(format);
    let prompt = build_prompt(format, &paths, samples, options);
    let request = JsonRequest::new(prompt, SCHEMA_HINT).with_system(SYSTEM_PROMPT);
    let response = client.complete_json(&request)?;

    // Free-form output is not accepted: the response must deserialize into the
    // structured proposal shape (FR-30).
    let proposal: ModelProposal = serde_json::from_value(response.value).map_err(|error| {
        LlmError::InvalidResponse(format!("model proposal did not match the schema: {error}"))
    })?;

    let mut best = format.clone();
    let mut best_score = baseline_score.clone();
    let mut history = Vec::new();

    // The format-family guess is pure metadata; it cannot change a parse, so it
    // is recorded directly rather than gated.
    if let Some(family) = proposal.format_family.as_ref().filter(|f| !f.is_empty()) {
        best.metadata
            .extra
            .insert("format_family".to_owned(), family.clone());
    }

    for field_proposal in &proposal.fields {
        if field_proposal.is_empty() {
            continue;
        }
        let description = field_proposal.describe();
        let Some(path) = paths.get(field_proposal.index) else {
            history.push(rejected(
                format!(
                    "{description}: field index {} is out of range",
                    field_proposal.index
                ),
                best_score.overall,
            ));
            continue;
        };

        let candidate = match apply_field_proposal(&best, path, field_proposal) {
            Some(candidate) if candidate.validate().is_ok() => candidate,
            _ => {
                history.push(rejected(
                    format!("{description}: proposal could not be applied as valid IR"),
                    best_score.overall,
                ));
                continue;
            }
        };

        let score = score_with(&candidate, samples, limits, weights);
        if score.overall + REGRESSION_EPSILON >= best_score.overall {
            // The verified score did not regress, so the model proposal is
            // accepted (FR-26).
            history.push(RefineStep {
                description,
                outcome: RefineOutcome::Accepted,
                score_before: best_score.overall,
                score_after: score.overall,
            });
            best = candidate;
            best_score = score;
        } else {
            // The model proposal would lower the verified score, so the
            // executor rejects it. The model never has final authority (FR-31).
            history.push(RefineStep {
                description,
                outcome: RefineOutcome::Rejected,
                score_before: best_score.overall,
                score_after: score.overall,
            });
        }
    }

    Ok(SemanticOutcome {
        format: best,
        score: best_score,
        baseline_score,
        history,
        format_family: proposal.format_family,
    })
}

/// Build a rejected-with-no-change history step.
fn rejected(description: String, score: f64) -> RefineStep {
    RefineStep {
        description,
        outcome: RefineOutcome::Rejected,
        score_before: score,
        score_after: score,
    }
}

/// Clone `format` and apply `proposal` to the field at `path`, returning the new
/// format, or `None` if the path does not resolve or the proposal does not fit.
fn apply_field_proposal(format: &Format, path: &[Seg], proposal: &FieldProposal) -> Option<Format> {
    let mut clone = format.clone();
    {
        let field = navigate(&mut clone.root, path)?;
        if let Some(name) = &proposal.name {
            field.name = Some(name.clone());
        }
        if let Some(role) = proposal.role {
            field.role = Some(role);
        }
        if let Some(kind) = &proposal.kind {
            // Reject struct and array kinds so the field tree shape, and the
            // field indices the model referenced, stay stable across the pass.
            if matches!(kind, Kind::Struct { .. } | Kind::Array { .. }) {
                return None;
            }
            field.kind = kind.clone();
            // Integers and enums take their size from their width, so any stale
            // explicit size rule is cleared.
            if matches!(field.kind, Kind::Integer { .. } | Kind::Enum { .. }) {
                field.size = None;
            }
        }
        if let Some(size) = &proposal.size {
            field.size = Some(size.clone());
        }
        if let Some(rationale) = &proposal.rationale {
            field.evidence.model_rationale = Some(rationale.clone());
        }
        field
            .evidence
            .detector
            .get_or_insert_with(|| "llm-semantic".to_owned());
    }

    if let Some(variants) = &proposal.enum_variants {
        apply_enum(&mut clone, path, variants)?;
    }

    Some(clone)
}

/// Convert the field at `path` into an enum that references a generated
/// definition carrying `variants`. The width and endianness come from the
/// field's current integer or enum kind, defaulting to a single byte.
fn apply_enum(format: &mut Format, path: &[Seg], variants: &[EnumVariant]) -> Option<()> {
    let (width, endianness, enum_name) = {
        let field = navigate(&mut format.root, path)?;
        let (width, endianness) = match &field.kind {
            Kind::Integer {
                width, endianness, ..
            }
            | Kind::Enum {
                width, endianness, ..
            } => (*width, *endianness),
            _ => (1u8, None),
        };
        let base = field.name.clone().unwrap_or_else(|| "field".to_owned());
        (width, endianness, format!("{base}_values"))
    };

    format.enums.insert(
        enum_name.clone(),
        EnumDef {
            width: Some(width),
            variants: variants.to_vec(),
        },
    );

    let field = navigate(&mut format.root, path)?;
    field.kind = Kind::Enum {
        enum_ref: enum_name,
        width,
        endianness,
    };
    field.size = None;
    field.role.get_or_insert(Role::Enum);
    Some(())
}

/// Build the prompt: a numbered field summary plus a byte-capped hex view of the
/// samples. No more than `max_prompt_bytes_per_sample` bytes of any sample ever
/// reach the prompt (NFR-4).
fn build_prompt(
    format: &Format,
    paths: &[Vec<Seg>],
    samples: &[&[u8]],
    options: &SemanticOptions,
) -> String {
    let mut prompt = String::new();
    let _ = writeln!(prompt, "Candidate format: {}", format.name);
    let _ = writeln!(prompt, "Fields (index: summary):");
    for (index, path) in paths.iter().enumerate() {
        if let Some(field) = field_at(format, path) {
            let name = field.name.clone().unwrap_or_else(|| "(unnamed)".to_owned());
            let _ = writeln!(
                prompt,
                "  {index}: {name} role={} kind={} size={}",
                role_label(field.role),
                kind_label(&field.kind),
                size_label(field),
            );
        }
    }

    let _ = writeln!(prompt, "\nSamples (byte-capped hex):");
    let cap = options.max_prompt_bytes_per_sample;
    for (index, sample) in samples
        .iter()
        .take(options.max_samples_in_prompt)
        .enumerate()
    {
        let shown = &sample[..sample.len().min(cap)];
        let _ = writeln!(
            prompt,
            "  sample {index} ({} bytes total, showing {}): {}",
            sample.len(),
            shown.len(),
            hex(shown),
        );
    }

    prompt
}

/// Resolve a path to a shared field reference by cloning and navigating, used
/// only to read field metadata when building the prompt.
fn field_at<'a>(format: &'a Format, path: &[Seg]) -> Option<&'a sextant_ir::Field> {
    let (first, rest) = path.split_first()?;
    let Seg::Field(index) = first else {
        return None;
    };
    let mut field = format.root.fields.get(*index)?;
    for seg in rest {
        field = match seg {
            Seg::Field(index) => match &field.kind {
                Kind::Struct { structure } => structure.fields.get(*index)?,
                _ => return None,
            },
            Seg::Element => match &field.kind {
                Kind::Array { element, .. } => element.as_ref(),
                _ => return None,
            },
        };
    }
    Some(field)
}

/// Render bytes as lowercase space-separated hex.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{byte:02x}");
    }
    out
}
