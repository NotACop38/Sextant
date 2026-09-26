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
//! # What a proposal may change
//!
//! The response must be a JSON object. Each entry of its `fields` array is read
//! on its own, so a malformed entry (an unknown role, a wrong type, a negative
//! index) is skipped and recorded in the history rather than discarding the
//! whole response. Every applied proposal marks the edited field's evidence
//! detector (for example `statistics+model`), so the report shows the model was
//! involved even when it gave no rationale.
//!
//! - Field and enum variant names must be identifiers of ASCII letters, digits,
//!   and underscores of bounded length, so no control, bidirectional, or
//!   invisible character can enter the IR through a name. Rationale, enum
//!   variant descriptions, and the format-family guess have such characters
//!   removed and are bounded in length.
//! - A rename is an annotation, so it must not change what the format means.
//!   Every by-name reference (sizes, counts, offsets, and checksum anchors,
//!   including those held by array elements and by arrays of arrays) is
//!   resolved to the field definition it binds to, before and after the rename,
//!   under the lexical rules of both the IR validator and the executor. Exactly
//!   the references bound to the renamed field are rewritten, and the rename is
//!   refused if any other reference would bind to a different field or become
//!   unresolved. The scorer alone cannot catch such a change, because the
//!   retained samples may happen to agree on both targets.
//! - On top of the shared gate ([`Score::preserves_verified_fit`]), no sample
//!   may lose a constraint check it passed before, so an equal-score trade
//!   cannot swap which samples verify.
//!
//! # What is sent off the machine
//!
//! Only the candidate's field summary and at most
//! [`SemanticOptions::max_prompt_bytes_per_sample`] bytes from each of at most
//! [`SemanticOptions::max_samples_in_prompt`] samples are placed in the prompt.
//! That byte cap is the privacy guardrail (NFR-4). Cost is bounded by the
//! [`LlmClient`]'s call cap and budget (NFR-9); a run that trips a limit returns
//! an error, and callers (see [`crate::orchestrate::infer_with_llm`]) degrade
//! gracefully to the best verified statistics-only result. The local work a
//! response can cause is bounded as well: at most
//! [`SemanticOptions::max_proposals`] entries are considered, and candidate
//! re-scoring stops once [`SemanticOptions::max_rescore_work`] is spent.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Deserialize;
use serde_json::Value;
use sextant_ir::{
    Constraint, CountRule, EnumDef, EnumVariant, Evidence, Field, FieldOffset, FieldRef, Format,
    Kind, MAX_NESTING_DEPTH, RangeAnchor, Role, SizeRule, Structure, ValidationReport,
};
use sextant_llm::{JsonRequest, LlmClient, LlmError, LlmProvider};

use crate::limits::Limits;
use crate::refine::{RefineOutcome, RefineStep, Seg, field_paths, navigate};
use crate::report::{kind_label, role_label, size_label};
use crate::scorer::{Score, ScoreWeights, score_with};

/// The default per-sample byte cap placed in a prompt (NFR-4).
pub const DEFAULT_MAX_PROMPT_BYTES_PER_SAMPLE: usize = 256;

/// The default number of samples summarized in a prompt.
pub const DEFAULT_MAX_SAMPLES_IN_PROMPT: usize = 4;

/// The default number of `fields` entries the pass considers from one model
/// response (see [`SemanticOptions::max_proposals`]).
pub const DEFAULT_MAX_PROPOSALS: usize = 256;

/// The default re-scoring budget for one pass, in the work units of
/// [`SemanticOptions::max_rescore_work`]: about four gibibytes of re-executed
/// sample bytes.
pub const DEFAULT_MAX_RESCORE_WORK: u64 = 1 << 32;

/// The longest field or enum variant name accepted from a model, in bytes.
pub const MAX_MODEL_NAME_BYTES: usize = 64;

/// The longest model rationale or enum variant description kept in the IR, in
/// bytes, after control and invisible characters are removed.
pub const MAX_MODEL_RATIONALE_BYTES: usize = 512;

/// The longest format-family guess kept in the format metadata, in bytes.
pub const MAX_MODEL_FORMAT_FAMILY_BYTES: usize = 64;

/// The most enum variants a single model proposal may carry.
pub const MAX_MODEL_ENUM_VARIANTS: usize = 256;

/// The evidence detector recorded on a model-edited field that had none. A
/// field that already names a detector gets `+model` appended instead, for
/// example `statistics+model`.
pub const MODEL_DETECTOR: &str = "model";

/// The suffix appended to an existing evidence detector when the model edits
/// the field.
const MODEL_DETECTOR_SUFFIX: &str = "+model";

/// The most bytes of untrusted text (a proposed name, a parse error, or an IR
/// label) echoed into one history description.
const MAX_DESCRIPTION_TEXT_BYTES: usize = 160;

/// Why a proposal is refused when its field path no longer resolves.
const UNRESOLVED_PATH: &str = "the field path does not resolve in the current format";

/// Why a rename is refused when the format nests deeper than validation allows.
const TOO_DEEP_TO_RESOLVE: &str =
    "the format nests too deeply to check which fields its references bind to";

/// The system instruction framing the semantic task for the model.
const SYSTEM_PROMPT: &str = "\
You are a binary-format reverse-engineering assistant. You are given a candidate \
field layout and a bounded hex view of sample bytes. Propose semantic \
annotations and concrete, testable refinements expressed against the given \
fields. Reference each field by its integer index. Write every name as an \
identifier made of ASCII letters, digits, and underscores. Do not invent fields \
you cannot see. Respond with a single JSON object and nothing else.";

/// A human-readable description of the JSON the model must return, folded into
/// the structured request (FR-30).
const SCHEMA_HINT: &str = "\
{\"format_family\": \"<string, optional>\", \"fields\": [{\"index\": <int>, \
\"name\": \"<identifier, optional>\", \"role\": \"<one of: magic, version, \
length, count, offset, message_type, sequence, checksum, timestamp, flags, enum, \
reserved, payload, unknown>\", \"type\": {\"type\": \"integer\", \"width\": <1|2|4|8>, \"signed\": \
\"unsigned|signed\", \"endianness\": \"little|big\"}, \"size\": {\"rule\": \
\"fixed|derived|to_end\", \"bytes\": <int>, \"length_field\": \"<name>\"}, \
\"enum\": [{\"value\": <int>, \"name\": \"<identifier>\"}], \"rationale\": \
\"<string, optional>\"}]}";

/// Every semantic role a proposal may name, as the IR serializes it.
const ROLE_NAMES: [&str; 14] = [
    "magic",
    "version",
    "length",
    "count",
    "offset",
    "message_type",
    "sequence",
    "checksum",
    "timestamp",
    "flags",
    "enum",
    "reserved",
    "payload",
    "unknown",
];

/// The JSON Schema of a [`ModelProposal`], sent with the request so a provider
/// that supports structured output returns a well-formed object (FR-30). It
/// uses only the subset structured output accepts: every object is closed, and
/// there are no numeric or length constraints. The pass still checks every
/// entry itself, so a provider that ignores the schema is handled the same way.
fn proposal_schema() -> serde_json::Value {
    use serde_json::json;
    let closed = |properties: serde_json::Value, required: &[&str]| {
        json!({
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false,
        })
    };
    let kind = json!({
        "anyOf": [
            closed(
                json!({
                    "type": {"const": "integer"},
                    "width": {"enum": [1, 2, 4, 8]},
                    "signed": {"enum": ["unsigned", "signed"]},
                    "endianness": {"enum": ["little", "big"]},
                }),
                &["type", "width", "signed"],
            ),
            closed(json!({"type": {"const": "bytes"}}), &["type"]),
            closed(
                json!({
                    "type": {"const": "string"},
                    "encoding": {"enum": ["ascii", "utf8", "utf16_le", "utf16_be", "latin1"]},
                }),
                &["type", "encoding"],
            ),
            closed(json!({"type": {"const": "opaque"}}), &["type"]),
        ]
    });
    let size = json!({
        "anyOf": [
            closed(
                json!({"rule": {"const": "fixed"}, "bytes": {"type": "integer"}}),
                &["rule", "bytes"],
            ),
            closed(
                json!({"rule": {"const": "derived"}, "length_field": {"type": "string"}}),
                &["rule", "length_field"],
            ),
            closed(json!({"rule": {"const": "to_end"}}), &["rule"]),
        ]
    });
    let variant = closed(
        json!({"value": {"type": "integer"}, "name": {"type": "string"}}),
        &["value", "name"],
    );
    let field = closed(
        json!({
            "index": {"type": "integer"},
            "name": {"type": "string"},
            "role": {"enum": ROLE_NAMES},
            "type": kind,
            "size": size,
            "enum": {"type": "array", "items": variant},
            "rationale": {"type": "string"},
        }),
        &["index"],
    );
    closed(
        json!({
            "format_family": {"type": "string"},
            "fields": {"type": "array", "items": field},
        }),
        &["fields"],
    )
}

/// Options controlling the semantic pass.
#[derive(Debug, Clone)]
pub struct SemanticOptions {
    /// The maximum number of bytes from any single sample placed in the prompt.
    /// This is the hard privacy cap on what leaves the machine (NFR-4).
    pub max_prompt_bytes_per_sample: usize,
    /// The maximum number of samples summarized in the prompt.
    pub max_samples_in_prompt: usize,
    /// The maximum number of entries of a response's `fields` array the pass
    /// considers. Later entries are not read, and the skip is recorded in the
    /// history.
    pub max_proposals: usize,
    /// The total work the pass may spend re-scoring candidates. Each candidate
    /// evaluation re-executes the full sample set and costs one unit per sample
    /// plus one unit per sample byte. Once another evaluation would exceed the
    /// budget, the remaining entries are not evaluated and the skip is recorded
    /// in the history. An entry rejected before scoring costs nothing.
    pub max_rescore_work: u64,
}

impl Default for SemanticOptions {
    fn default() -> Self {
        Self {
            max_prompt_bytes_per_sample: DEFAULT_MAX_PROMPT_BYTES_PER_SAMPLE,
            max_samples_in_prompt: DEFAULT_MAX_SAMPLES_IN_PROMPT,
            max_proposals: DEFAULT_MAX_PROPOSALS,
            max_rescore_work: DEFAULT_MAX_RESCORE_WORK,
        }
    }
}

/// The structured proposal a model returns from the semantic pass (FR-29,
/// FR-30).
///
/// Free-form prose is not accepted: a response that is not a JSON object, or
/// whose `fields` member is present but not an array, is an
/// [`LlmError::InvalidResponse`]. Within that shape, [`semantic_pass`] reads
/// each `fields` entry on its own as a [`FieldProposal`]: an entry that does not
/// match is skipped and recorded in the history, and a `format_family` that is
/// not a string is ignored and recorded, rather than discarding the response.
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
    /// A proposed field name. It is accepted only as an identifier of at most
    /// [`MAX_MODEL_NAME_BYTES`] bytes of ASCII letters, digits, and underscores
    /// that does not start with a digit, and only when renaming the field
    /// leaves every reference in the format bound to the same field.
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
    /// enum that references a generated definition (FR-29). Variant names follow
    /// the same identifier rule as field names, and at most
    /// [`MAX_MODEL_ENUM_VARIANTS`] variants are accepted.
    #[serde(rename = "enum", default)]
    pub enum_variants: Option<Vec<EnumVariant>>,
    /// The model's rationale, recorded in the field's evidence for
    /// explainability (FR-28, NFR-7) after control and invisible characters are
    /// removed and the text is bounded to [`MAX_MODEL_RATIONALE_BYTES`].
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

    /// A short human-readable summary of what the proposal changes. Model text
    /// is escaped so it cannot inject control or invisible characters.
    fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(name) = &self.name {
            parts.push(format!(
                "name={}",
                display_text(name, MAX_DESCRIPTION_TEXT_BYTES)
            ));
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
    /// (FR-28). Entries skipped as malformed, an ignored format-family guess,
    /// and entries left unconsidered by [`SemanticOptions::max_proposals`] or
    /// [`SemanticOptions::max_rescore_work`] are recorded as rejected steps with
    /// the reason in the description.
    pub history: Vec<RefineStep>,
    /// The model's format-family guess, if it offered a usable one, with
    /// control and invisible characters removed.
    pub format_family: Option<String>,
}

/// Run the semantic pass over `format` against `samples` using `client`.
///
/// The pass makes one structured model call, reads each entry of the response
/// as a [`FieldProposal`], and applies each through the scorer's
/// non-regression gate. The returned [`SemanticOutcome::format`] is guaranteed
/// to score no lower than the input over the full sample set (FR-26, FR-31).
///
/// # Errors
///
/// Returns [`LlmError`] if the model call fails (transport, cache, a tripped
/// call cap or budget, NFR-9) or if the response is not a structured proposal
/// object (FR-30). A malformed entry inside an otherwise well-formed response
/// is skipped and recorded, not an error. It never panics and never mutates the
/// input format.
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
    let request = JsonRequest::new(prompt, SCHEMA_HINT)
        .with_system(SYSTEM_PROMPT)
        .with_json_schema(proposal_schema());
    let response = client.complete_json(&request)?;
    // Free-form output is not accepted: the response must be a proposal object
    // (FR-30). Its entries are read one at a time below.
    let response = ResponseParts::split(&response.value)?;

    let mut best = format.clone();
    let mut best_score = baseline_score.clone();
    let mut history = Vec::new();

    // The format-family guess is pure metadata; it cannot change a parse, so it
    // is recorded directly rather than gated.
    let format_family = match read_format_family(response.format_family) {
        Ok(family) => family,
        Err(reason) => {
            history.push(rejected(reason, best_score.overall));
            None
        }
    };
    if let Some(family) = &format_family {
        best.metadata
            .extra
            .insert("format_family".to_owned(), family.clone());
    }

    let cost = rescore_cost(samples);
    let mut work_spent: u64 = 0;
    let considered = response.entries.len().min(options.max_proposals);

    for (position, entry) in response.entries[..considered].iter().enumerate() {
        let proposal = match parse_entry(entry) {
            Ok(proposal) => proposal,
            Err(reason) => {
                history.push(rejected(
                    format!("model: entry {position} skipped: {reason}"),
                    best_score.overall,
                ));
                continue;
            }
        };
        if proposal.is_empty() {
            continue;
        }
        let description = proposal.describe();
        let Some(path) = paths.get(proposal.index) else {
            history.push(rejected(
                format!(
                    "{description}: field index {} is out of range",
                    proposal.index
                ),
                best_score.overall,
            ));
            continue;
        };

        let candidate = match apply_field_proposal(&best, path, &proposal) {
            Ok(candidate) => candidate,
            Err(reason) => {
                history.push(rejected(
                    format!("{description}: {reason}"),
                    best_score.overall,
                ));
                continue;
            }
        };
        if let Err(report) = candidate.validate() {
            history.push(rejected(
                format!(
                    "{description}: proposal could not be applied as valid IR ({})",
                    first_problem(&report)
                ),
                best_score.overall,
            ));
            continue;
        }

        // Every evaluation re-executes the full sample set, so the total
        // re-scoring work one response can cause is budgeted.
        let Some(spent) = work_spent
            .checked_add(cost)
            .filter(|spent| *spent <= options.max_rescore_work)
        else {
            history.push(rejected(
                format!(
                    "model: re-scoring budget of {} work units exhausted; {} remaining entries \
                     were not evaluated",
                    options.max_rescore_work,
                    considered - position
                ),
                best_score.overall,
            ));
            break;
        };
        work_spent = spent;

        let score = score_with(&candidate, samples, limits, weights);
        match gate_rejection(&score, &best_score) {
            None => {
                // The verified fit did not regress and no sample lost a passing
                // check, so the model proposal is accepted (FR-26).
                history.push(RefineStep {
                    description,
                    outcome: RefineOutcome::Accepted,
                    score_before: best_score.overall,
                    score_after: score.overall,
                });
                best = candidate;
                best_score = score;
            }
            Some(reason) => {
                // The executor rejects the proposal. The model never has final
                // authority (FR-31).
                history.push(RefineStep {
                    description: format!("{description}: {reason}"),
                    outcome: RefineOutcome::Rejected,
                    score_before: best_score.overall,
                    score_after: score.overall,
                });
            }
        }
    }

    if response.entries.len() > considered {
        history.push(rejected(
            format!(
                "model: {} entries beyond the per-response cap of {} were not considered",
                response.entries.len() - considered,
                options.max_proposals
            ),
            best_score.overall,
        ));
    }

    Ok(SemanticOutcome {
        format: best,
        score: best_score,
        baseline_score,
        history,
        format_family,
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

/// The semantic pass's acceptance gate. It applies the common verified-fit gate
/// (FR-26, FR-31) and additionally requires that no sample lose a constraint
/// check it passed before, so a change that keeps the aggregate score by
/// trading which samples pass their checks is not accepted. Returns why the
/// candidate is rejected, or `None` when it may be applied.
fn gate_rejection(candidate: &Score, baseline: &Score) -> Option<String> {
    if !candidate.preserves_verified_fit(baseline) {
        return Some("rejected, the verified fit would regress".to_owned());
    }
    candidate
        .samples
        .iter()
        .zip(&baseline.samples)
        .find(|(after, before)| after.constraints_passed < before.constraints_passed)
        .map(|(after, before)| {
            format!(
                "rejected, sample {} would lose a passing constraint check ({} passing before, \
                 {} after)",
                before.index, before.constraints_passed, after.constraints_passed
            )
        })
}

/// The work units one candidate evaluation costs: one per sample plus one per
/// sample byte, since each evaluation re-executes every sample.
fn rescore_cost(samples: &[&[u8]]) -> u64 {
    samples.iter().fold(0u64, |total, sample| {
        let bytes = u64::try_from(sample.len()).unwrap_or(u64::MAX);
        total.saturating_add(bytes).saturating_add(1)
    })
}

/// The first validation problem of a rejected candidate, escaped and bounded
/// for a history description.
fn first_problem(report: &ValidationReport) -> String {
    report.errors.first().map_or_else(
        || "validation stopped early".to_owned(),
        |error| display_text(&error.to_string(), MAX_DESCRIPTION_TEXT_BYTES),
    )
}

/// A model response split into its parts, with the top-level shape checked.
/// The entries are parsed later, one at a time.
struct ResponseParts<'a> {
    /// The `format_family` member, when present and not null.
    format_family: Option<&'a Value>,
    /// The entries of the `fields` array, empty when it is absent or null.
    entries: &'a [Value],
}

impl<'a> ResponseParts<'a> {
    /// Split a response. A value that is not a JSON object, or whose `fields`
    /// member is present but not an array, is not a structured proposal
    /// (FR-30).
    fn split(value: &'a Value) -> Result<Self, LlmError> {
        let object = value.as_object().ok_or_else(|| {
            LlmError::InvalidResponse("model proposal is not a JSON object".to_owned())
        })?;
        let entries: &[Value] = match object.get("fields") {
            None | Some(Value::Null) => &[],
            Some(Value::Array(entries)) => entries.as_slice(),
            Some(_) => {
                return Err(LlmError::InvalidResponse(
                    "model proposal member `fields` is not an array".to_owned(),
                ));
            }
        };
        let format_family = object.get("format_family").filter(|value| !value.is_null());
        Ok(Self {
            format_family,
            entries,
        })
    }
}

/// Read and clean the model's format-family guess, or say why it is ignored.
fn read_format_family(value: Option<&Value>) -> Result<Option<String>, String> {
    match value {
        None => Ok(None),
        Some(Value::String(text)) => {
            let family = sanitize_text(text, MAX_MODEL_FORMAT_FAMILY_BYTES);
            Ok((!family.is_empty()).then_some(family))
        }
        Some(_) => Err("model: format_family ignored: not a string".to_owned()),
    }
}

/// Parse one `fields` entry into a [`FieldProposal`], or say why it is skipped.
/// The enum variant count is checked on the raw value first, so an oversized
/// list is never copied into typed variants.
fn parse_entry(entry: &Value) -> Result<FieldProposal, String> {
    let variant_count = entry
        .get("enum")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if variant_count > MAX_MODEL_ENUM_VARIANTS {
        return Err(format!(
            "it proposes {variant_count} enum variants, above the cap of {MAX_MODEL_ENUM_VARIANTS}"
        ));
    }
    FieldProposal::deserialize(entry).map_err(|error| {
        format!(
            "malformed field proposal ({})",
            display_text(&error.to_string(), MAX_DESCRIPTION_TEXT_BYTES)
        )
    })
}

/// Clone `format` and apply `proposal` to the field at `path`, returning the new
/// format, or why the proposal cannot be applied.
fn apply_field_proposal(
    format: &Format,
    path: &[Seg],
    proposal: &FieldProposal,
) -> Result<Format, String> {
    // Screen the model's text before anything touches the IR.
    if proposal
        .name
        .as_deref()
        .is_some_and(|name| !is_safe_identifier(name))
    {
        return Err(unsafe_name_reason("the proposed name"));
    }
    let variants = proposal
        .enum_variants
        .as_deref()
        .map(screen_enum_variants)
        .transpose()?;
    let rationale = proposal
        .rationale
        .as_deref()
        .map(|text| sanitize_text(text, MAX_MODEL_RATIONALE_BYTES))
        .filter(|text| !text.is_empty());

    let mut clone = format.clone();
    if let Some(name) = &proposal.name {
        // A rename is an annotation: it rewrites exactly the references bound to
        // the field and is refused if any other reference would change target.
        rename_field(&mut clone.root, path, name)?;
    }
    {
        let field = navigate(&mut clone.root, path).ok_or_else(|| UNRESOLVED_PATH.to_owned())?;
        if let Some(role) = proposal.role {
            // An explicit `unknown` role only fills a missing role; it never
            // erases a concrete role the statistical pipeline already assigned,
            // which would make the report less informative at no score cost.
            if role != Role::Unknown || field.role.is_none() {
                field.role = Some(role);
            }
        }
        if let Some(kind) = &proposal.kind {
            // Reject struct and array kinds, and reject collapsing a field that
            // is already a struct or array into a primitive: either changes the
            // field tree shape and makes the field indices the model referenced,
            // and later proposals reference, stale.
            if matches!(kind, Kind::Struct { .. } | Kind::Array { .. })
                || matches!(field.kind, Kind::Struct { .. } | Kind::Array { .. })
            {
                return Err(
                    "a proposed type may not add or replace a struct or array, which would \
                     change the field indices"
                        .to_owned(),
                );
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
        if let Some(rationale) = rationale {
            field.evidence.model_rationale = Some(rationale);
        }
        mark_model_involvement(&mut field.evidence);
    }

    if let Some(variants) = variants {
        apply_enum(&mut clone, path, variants)?;
    }

    Ok(clone)
}

/// Record on a field's evidence that the model edited it: `model` when no
/// detector was recorded, otherwise the existing detector with `+model`
/// appended (for example `statistics+model`). Marking twice changes nothing.
fn mark_model_involvement(evidence: &mut Evidence) {
    let marked = match evidence.detector.as_deref() {
        None | Some("") => MODEL_DETECTOR.to_owned(),
        Some(detector)
            if detector == MODEL_DETECTOR || detector.ends_with(MODEL_DETECTOR_SUFFIX) =>
        {
            return;
        }
        Some(detector) => format!("{detector}{MODEL_DETECTOR_SUFFIX}"),
    };
    evidence.detector = Some(marked);
}

/// Check proposed enum variants: bounded in number, with safe identifier names
/// and cleaned descriptions. Returns the variants to store, or why the proposal
/// is refused.
fn screen_enum_variants(variants: &[EnumVariant]) -> Result<Vec<EnumVariant>, String> {
    if variants.len() > MAX_MODEL_ENUM_VARIANTS {
        return Err(format!(
            "it proposes {} enum variants, above the cap of {MAX_MODEL_ENUM_VARIANTS}",
            variants.len()
        ));
    }
    variants
        .iter()
        .map(|variant| {
            if !is_safe_identifier(&variant.name) {
                return Err(unsafe_name_reason("an enum variant name"));
            }
            Ok(EnumVariant {
                value: variant.value,
                name: variant.name.clone(),
                description: variant
                    .description
                    .as_deref()
                    .map(|text| sanitize_text(text, MAX_MODEL_RATIONALE_BYTES))
                    .filter(|text| !text.is_empty()),
            })
        })
        .collect()
}

/// Convert the field at `path` into an enum that references a generated
/// definition carrying `variants`. The width and endianness come from the
/// field's current integer or enum kind, defaulting to a single byte. A struct
/// or array field is refused, since collapsing it would change the field tree.
fn apply_enum(format: &mut Format, path: &[Seg], variants: Vec<EnumVariant>) -> Result<(), String> {
    let (width, endianness, enum_name) = {
        let field = navigate(&mut format.root, path).ok_or_else(|| UNRESOLVED_PATH.to_owned())?;
        let (width, endianness) = match &field.kind {
            Kind::Integer {
                width, endianness, ..
            }
            | Kind::Enum {
                width, endianness, ..
            } => (*width, *endianness),
            Kind::Struct { .. } | Kind::Array { .. } => {
                return Err(
                    "enum meanings cannot replace a struct or array field, which would change \
                     the field indices"
                        .to_owned(),
                );
            }
            Kind::Bytes | Kind::String { .. } | Kind::Opaque => (1u8, None),
        };
        let base = field.name.clone().unwrap_or_else(|| "field".to_owned());
        // Two fields that share a name in different scopes, or two unnamed
        // fields, would otherwise collide on the same key and silently overwrite
        // each other's variants. Uniquify so every field gets its own definition.
        (width, endianness, unique_enum_name(format, &base))
    };

    format.enums.insert(
        enum_name.clone(),
        EnumDef {
            width: Some(width),
            variants,
        },
    );

    let field = navigate(&mut format.root, path).ok_or_else(|| UNRESOLVED_PATH.to_owned())?;
    field.kind = Kind::Enum {
        enum_ref: enum_name,
        width,
        endianness,
    };
    field.size = None;
    field.role.get_or_insert(Role::Enum);
    Ok(())
}

/// Build an enum definition name from `base` that does not collide with an
/// existing definition, appending a numeric suffix when needed.
fn unique_enum_name(format: &Format, base: &str) -> String {
    let candidate = format!("{base}_values");
    if !format.enums.contains_key(&candidate) {
        return candidate;
    }
    let mut suffix = 2usize;
    loop {
        let candidate = format!("{base}_values_{suffix}");
        if !format.enums.contains_key(&candidate) {
            return candidate;
        }
        suffix += 1;
    }
}

/// Rename the field at `path` to `name` without changing what the format
/// means (FR-26, FR-31).
///
/// Every by-name reference is resolved to the field it binds to before the
/// rename. The field is renamed, exactly the references that were bound to it
/// are rewritten to the new name, and every reference is resolved again. The
/// rename is refused when any reference would now bind to a different field or
/// become unresolved: for example when the new name would capture a reference
/// that bound to a same-named field in an enclosing scope, or when naming an
/// unnamed field would capture a reference to an outer field of that name.
fn rename_field(root: &mut Structure, path: &[Seg], name: &str) -> Result<(), String> {
    let current = navigate(root, path).ok_or_else(|| UNRESOLVED_PATH.to_owned())?;
    if current.name.as_deref() == Some(name) {
        return Ok(());
    }

    let before = reference_bindings(root).ok_or_else(|| TOO_DEEP_TO_RESOLVE.to_owned())?;
    navigate(root, path)
        .ok_or_else(|| UNRESOLVED_PATH.to_owned())?
        .name = Some(name.to_owned());
    for binding in before.iter().filter(|binding| binding.binds_to(path)) {
        rewrite_reference(root, binding, name)
            .ok_or_else(|| "a reference to the renamed field could not be rewritten".to_owned())?;
    }

    let after = reference_bindings(root).ok_or_else(|| TOO_DEEP_TO_RESOLVE.to_owned())?;
    if before.len() != after.len() {
        return Err("the rename would change the set of field references".to_owned());
    }
    match before.iter().zip(&after).find(|(old, new)| old != new) {
        Some((old, _)) => Err(format!(
            "the rename would change which field the {} reference of {} binds to",
            old.slot.label(),
            describe_path(root, &old.owner)
        )),
        None => Ok(()),
    }
}

/// Rewrite the by-name reference `binding` describes so it names `name`.
/// Returns `None` when the reference is no longer where the binding says.
fn rewrite_reference(root: &mut Structure, binding: &ReferenceBinding, name: &str) -> Option<()> {
    let field = navigate(root, &binding.owner)?;
    let reference = match binding.slot {
        RefSlot::Offset => match &mut field.offset {
            Some(FieldOffset::Derived { offset_field }) => offset_field,
            _ => return None,
        },
        RefSlot::Size => match &mut field.size {
            Some(SizeRule::Derived { length_field }) => length_field,
            _ => return None,
        },
        RefSlot::Count => match &mut field.kind {
            Kind::Array {
                count:
                    CountRule::FromField {
                        count_field: reference,
                    }
                    | CountRule::BoundedBy {
                        length_field: reference,
                    },
                ..
            } => reference,
            _ => return None,
        },
        RefSlot::ChecksumFrom(position) => match field.constraints.get_mut(position)? {
            Constraint::Checksum { spec } => anchor_field_mut(&mut spec.covered.from),
            _ => return None,
        },
        RefSlot::ChecksumTo(position) => match field.constraints.get_mut(position)? {
            Constraint::Checksum { spec } => anchor_field_mut(&mut spec.covered.to),
            _ => return None,
        },
    };
    *reference = FieldRef::new(name);
    Some(())
}

/// The field reference inside a checksum range anchor.
fn anchor_field_mut(anchor: &mut RangeAnchor) -> &mut FieldRef {
    match anchor {
        RangeAnchor::FieldStart { field } | RangeAnchor::FieldEnd { field } => field,
    }
}

/// Which by-name reference of a field a [`ReferenceBinding`] describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefSlot {
    /// A derived offset.
    Offset,
    /// A derived size.
    Size,
    /// An array's count field or byte-length bound.
    Count,
    /// The start anchor of the checksum constraint at this position in the
    /// field's constraint list.
    ChecksumFrom(usize),
    /// The end anchor of the checksum constraint at this position.
    ChecksumTo(usize),
}

impl RefSlot {
    /// A short label for history descriptions.
    fn label(self) -> &'static str {
        match self {
            RefSlot::Offset => "offset",
            RefSlot::Size => "size",
            RefSlot::Count => "count",
            RefSlot::ChecksumFrom(_) => "checksum range start",
            RefSlot::ChecksumTo(_) => "checksum range end",
        }
    }
}

/// One by-name reference in a format and the field definition it binds to.
///
/// The binding is resolved under two rule sets. The IR validator and the
/// executor agree on valid IR, but differ at two edges: a scope that declares a
/// name twice (the validator binds the first declaration, the executor the
/// latest one parsed) and a checksum anchor on an array element that names the
/// element itself (the validator sees the element, while the executor never
/// binds array elements). A rename must preserve both, so neither the checks
/// run on candidates nor the parse can observe a different target.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReferenceBinding {
    /// The path of the field that holds the reference.
    owner: Vec<Seg>,
    /// Which of the owner's references this is.
    slot: RefSlot,
    /// The field the reference binds to under the validator's rules.
    validator: Option<Vec<Seg>>,
    /// The field the reference binds to under the executor's rules.
    executor: Option<Vec<Seg>>,
}

impl ReferenceBinding {
    /// Whether the reference binds to the field at `target` under either rule
    /// set.
    fn binds_to(&self, target: &[Seg]) -> bool {
        self.validator.as_deref() == Some(target) || self.executor.as_deref() == Some(target)
    }
}

/// Resolve every by-name reference in `root` to the field definition it binds
/// to, in a deterministic walk order. Returns `None` when the format nests
/// deeper than validation allows, so the walk stays bounded.
fn reference_bindings(root: &Structure) -> Option<Vec<ReferenceBinding>> {
    let mut walker = BindingWalker {
        frames: Vec::new(),
        bindings: Vec::new(),
    };
    walker.walk_structure(root, &[])?;
    Some(walker.bindings)
}

/// One lexical scope on the resolution chain while walking a format: the
/// fields of a structure, or the single element of an array.
struct ScopeFrame<'a> {
    /// The path of the field that owns this scope, empty for the root.
    owner: Vec<Seg>,
    /// Whether this is an array element's single-field scope.
    element: bool,
    /// Where each name is declared in this scope, in field order.
    declarations: BTreeMap<&'a str, Vec<usize>>,
    /// How many leading fields are visible to the child being walked, the
    /// position of the field the walk descended through.
    visible: usize,
}

impl ScopeFrame<'_> {
    /// The path of the field declared at `index` in this scope.
    fn path_of(&self, index: usize) -> Vec<Seg> {
        let mut path = self.owner.clone();
        path.push(if self.element {
            Seg::Element
        } else {
            Seg::Field(index)
        });
        path
    }

    /// The validator's rule: the first declaration of `name` in the scope,
    /// visible only when it lies before `bound`.
    fn validator_lookup(&self, name: &str, bound: usize) -> Option<Vec<Seg>> {
        let first = *self.declarations.get(name)?.first()?;
        (first < bound).then(|| self.path_of(first))
    }

    /// The executor's rule: the latest declaration of `name` before `bound`,
    /// which is the most recent binding of that name when the reference is
    /// evaluated. Array elements are never bound while parsing.
    fn executor_lookup(&self, name: &str, bound: usize) -> Option<Vec<Seg>> {
        if self.element {
            return None;
        }
        let positions = self.declarations.get(name)?;
        let earlier = positions.partition_point(|&position| position < bound);
        let last = *positions.get(earlier.checked_sub(1)?)?;
        Some(self.path_of(last))
    }
}

/// Walks a format in parse order, resolving each by-name reference against the
/// chain of enclosing scopes, as `sextant_ir::validate` and the executor do.
struct BindingWalker<'a> {
    /// The scope chain, outermost first.
    frames: Vec<ScopeFrame<'a>>,
    /// Every reference resolved so far, in walk order.
    bindings: Vec<ReferenceBinding>,
}

impl<'a> BindingWalker<'a> {
    /// Resolve `name` from the innermost scope outward. Only the first `bound`
    /// fields of the innermost scope are visible; each enclosing scope exposes
    /// the fields before the child the walk descended through.
    fn resolve(&self, name: &str, bound: usize) -> (Option<Vec<Seg>>, Option<Vec<Seg>>) {
        let Some((innermost, enclosing)) = self.frames.split_last() else {
            return (None, None);
        };
        let chain = || {
            std::iter::once((innermost, bound))
                .chain(enclosing.iter().rev().map(|frame| (frame, frame.visible)))
        };
        let validator = chain().find_map(|(frame, bound)| frame.validator_lookup(name, bound));
        let executor = chain().find_map(|(frame, bound)| frame.executor_lookup(name, bound));
        (validator, executor)
    }

    /// Resolve and record one reference held by the field at `owner`.
    fn record(&mut self, owner: &[Seg], slot: RefSlot, name: &str, bound: usize) {
        let (validator, executor) = self.resolve(name, bound);
        self.bindings.push(ReferenceBinding {
            owner: owner.to_vec(),
            slot,
            validator,
            executor,
        });
    }

    /// Enter a scope. A validated format nests at most [`MAX_NESTING_DEPTH`]
    /// levels below the root, so anything deeper is refused rather than walked
    /// without bound.
    fn push_frame(&mut self, frame: ScopeFrame<'a>) -> Option<()> {
        if self.frames.len() > MAX_NESTING_DEPTH {
            return None;
        }
        self.frames.push(frame);
        Some(())
    }

    /// Walk the fields of `structure`, which is owned by the field at `owner`
    /// (the root structure when `owner` is empty).
    fn walk_structure(&mut self, structure: &'a Structure, owner: &[Seg]) -> Option<()> {
        let mut declarations: BTreeMap<&'a str, Vec<usize>> = BTreeMap::new();
        for (index, field) in structure.fields.iter().enumerate() {
            if let Some(name) = field.name.as_deref() {
                declarations.entry(name).or_default().push(index);
            }
        }
        self.push_frame(ScopeFrame {
            owner: owner.to_vec(),
            element: false,
            declarations,
            visible: 0,
        })?;
        let mut path = owner.to_vec();
        for (index, field) in structure.fields.iter().enumerate() {
            path.push(Seg::Field(index));
            self.walk_field(field, &path, index, structure.fields.len())?;
            path.pop();
        }
        self.frames.pop();
        Some(())
    }

    /// Record the references `field` holds and walk its children. The field
    /// sits at `index` in the innermost scope, which has `scope_len` fields.
    fn walk_field(
        &mut self,
        field: &'a Field,
        path: &[Seg],
        index: usize,
        scope_len: usize,
    ) -> Option<()> {
        // Offsets, sizes, and counts see only the fields parsed before this one.
        if let Some(FieldOffset::Derived { offset_field }) = &field.offset {
            self.record(path, RefSlot::Offset, offset_field.as_str(), index);
        }
        if let Some(SizeRule::Derived { length_field }) = &field.size {
            self.record(path, RefSlot::Size, length_field.as_str(), index);
        }
        if let Kind::Array {
            count:
                CountRule::FromField {
                    count_field: reference,
                }
                | CountRule::BoundedBy {
                    length_field: reference,
                },
            ..
        } = &field.kind
        {
            self.record(path, RefSlot::Count, reference.as_str(), index);
        }
        // Checksum anchors may name any field of the innermost scope, because
        // they are evaluated once that scope has been parsed.
        for (position, constraint) in field.constraints.iter().enumerate() {
            if let Constraint::Checksum { spec } = constraint {
                self.record(
                    path,
                    RefSlot::ChecksumFrom(position),
                    spec.covered.from.field().as_str(),
                    scope_len,
                );
                self.record(
                    path,
                    RefSlot::ChecksumTo(position),
                    spec.covered.to.field().as_str(),
                    scope_len,
                );
            }
        }

        match &field.kind {
            Kind::Struct { structure } => {
                self.frames.last_mut()?.visible = index;
                self.walk_structure(structure, path)?;
            }
            Kind::Array { element, .. } => {
                // The element is walked in a scope of its own, as the validator
                // does. Its own references see only the enclosing scopes.
                self.frames.last_mut()?.visible = index;
                let mut declarations = BTreeMap::new();
                if let Some(name) = element.name.as_deref() {
                    declarations.insert(name, vec![0]);
                }
                self.push_frame(ScopeFrame {
                    owner: path.to_vec(),
                    element: true,
                    declarations,
                    visible: 0,
                })?;
                let mut element_path = path.to_vec();
                element_path.push(Seg::Element);
                self.walk_field(element, &element_path, 0, 1)?;
                self.frames.pop();
            }
            _ => {}
        }
        Some(())
    }
}

/// Whether `name` is a safe identifier: one to [`MAX_MODEL_NAME_BYTES`] bytes of
/// ASCII letters, digits, and underscores, not starting with a digit. This
/// excludes every control, bidirectional, and invisible character.
fn is_safe_identifier(name: &str) -> bool {
    name.len() <= MAX_MODEL_NAME_BYTES
        && name
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Why a model-supplied name is refused.
fn unsafe_name_reason(what: &str) -> String {
    format!(
        "{what} is not a safe identifier (ASCII letters, digits, and underscores, not starting \
         with a digit, at most {MAX_MODEL_NAME_BYTES} bytes)"
    )
}

/// Clean free text from a model before it is stored in the IR. Tabs and line
/// breaks become spaces; control, bidirectional, and other invisible formatting
/// characters are removed; surrounding whitespace is trimmed; and text longer
/// than `max_bytes` is cut on a character boundary and marked with `...`.
fn sanitize_text(text: &str, max_bytes: usize) -> String {
    const ELLIPSIS: &str = "...";
    let mut out = String::new();
    for c in text.chars() {
        let c = if matches!(c, '\t' | '\n' | '\r') {
            ' '
        } else {
            c
        };
        if crate::text::is_unsafe_to_display(c) {
            continue;
        }
        if out.len() + c.len_utf8() > max_bytes {
            let mut end = max_bytes.saturating_sub(ELLIPSIS.len()).min(out.len());
            while !out.is_char_boundary(end) {
                end -= 1;
            }
            out.truncate(end);
            out.push_str(ELLIPSIS);
            break;
        }
        out.push(c);
    }
    out.trim().to_owned()
}

/// Render untrusted text for a history description: printable ASCII passes
/// through, every other character is shown as a `\u{...}` escape, and the
/// result is cut after about `max_bytes` bytes and marked with `...`.
fn display_text(text: &str, max_bytes: usize) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if out.len() >= max_bytes {
            out.push_str("...");
            break;
        }
        if c == ' ' || c.is_ascii_graphic() {
            out.push(c);
        } else {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        }
    }
    out
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
        if let Some(field) = field_at(&format.root, path) {
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

/// Take one step along a field path: select a root field when `current` is
/// `None`, otherwise a field of the current struct or the current array's
/// element.
fn step<'a>(root: &'a Structure, current: Option<&'a Field>, seg: Seg) -> Option<&'a Field> {
    match (seg, current) {
        (Seg::Field(index), None) => root.fields.get(index),
        (Seg::Field(index), Some(field)) => match &field.kind {
            Kind::Struct { structure } => structure.fields.get(index),
            _ => None,
        },
        (Seg::Element, Some(field)) => match &field.kind {
            Kind::Array { element, .. } => Some(element.as_ref()),
            _ => None,
        },
        (Seg::Element, None) => None,
    }
}

/// Resolve a path to a shared field reference, used to read field metadata
/// when building the prompt.
fn field_at<'a>(root: &'a Structure, path: &[Seg]) -> Option<&'a Field> {
    let mut current = None;
    for &seg in path {
        current = Some(step(root, current, seg)?);
    }
    current
}

/// A readable label for the field at `path`: the names along the path joined
/// with dots, escaped and bounded for a history description.
fn describe_path(root: &Structure, path: &[Seg]) -> String {
    let mut names = Vec::new();
    let mut current = None;
    for &seg in path {
        let Some(field) = step(root, current, seg) else {
            break;
        };
        names.push(field.name.as_deref().unwrap_or("(unnamed)"));
        current = Some(field);
    }
    display_text(&names.join("."), MAX_DESCRIPTION_TEXT_BYTES)
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

#[cfg(test)]
mod tests {
    use super::*;
    use sextant_ir::{ChecksumAlgorithm, ChecksumSpec, Confidence, CoveredRange, Signedness};

    /// Visit every schema node in `schema`, depth first.
    fn visit(schema: &Value, check: &mut impl FnMut(&serde_json::Map<String, Value>)) {
        match schema {
            Value::Object(map) => {
                check(map);
                map.values().for_each(|child| visit(child, check));
            }
            Value::Array(items) => items.iter().for_each(|child| visit(child, check)),
            _ => {}
        }
    }

    #[test]
    fn the_proposal_schema_uses_only_what_structured_output_accepts() {
        let schema = proposal_schema();
        let mut objects = 0;
        visit(&schema, &mut |node| {
            if node.contains_key("properties") {
                objects += 1;
                assert_eq!(
                    node.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "an object schema is open: {node:?}"
                );
            }
            for unsupported in [
                "minimum",
                "maximum",
                "multipleOf",
                "minLength",
                "maxLength",
                "pattern",
            ] {
                assert!(
                    !node.contains_key(unsupported),
                    "unsupported keyword {unsupported}"
                );
            }
        });
        assert!(objects >= 8, "expected every nested object: {objects}");
    }

    #[test]
    fn every_role_and_encoding_in_the_schema_is_a_real_ir_value() {
        for name in ROLE_NAMES {
            let role: Role = serde_json::from_value(Value::from(name)).expect("a role name");
            assert_eq!(serde_json::to_value(role).expect("serialize"), name);
        }
        for encoding in ["ascii", "utf8", "utf16_le", "utf16_be", "latin1"] {
            let kind: Kind =
                serde_json::from_value(serde_json::json!({"type": "string", "encoding": encoding}))
                    .expect("a string encoding");
            assert!(matches!(kind, Kind::String { .. }));
        }
    }

    #[test]
    fn a_proposal_that_follows_the_schema_is_read_in_full() {
        let entry = serde_json::json!({
            "index": 2,
            "name": "chunk_length",
            "role": "length",
            "type": {"type": "integer", "width": 4, "signed": "unsigned", "endianness": "big"},
            "size": {"rule": "fixed", "bytes": 4},
            "enum": [{"value": 1, "name": "one"}],
            "rationale": "governs the data length"
        });
        let proposal = parse_entry(&entry).expect("a well-formed entry");
        assert_eq!(proposal.index, 2);
        assert_eq!(proposal.role, Some(Role::Length));
        assert!(matches!(
            proposal.kind,
            Some(Kind::Integer { width: 4, .. })
        ));
        assert!(matches!(proposal.size, Some(SizeRule::Fixed { bytes: 4 })));
        assert_eq!(
            proposal.enum_variants.map(|variants| variants.len()),
            Some(1)
        );
    }

    fn u8_named(name: &str) -> Field {
        Field::new(
            Kind::Integer {
                width: 1,
                signed: Signedness::Unsigned,
                endianness: None,
            },
            Confidence::CERTAIN,
        )
        .with_name(name)
    }

    /// A root structure whose single leaf sits `depth` structs deep.
    fn nested(depth: usize) -> Structure {
        let mut structure = Structure::new(vec![u8_named("leaf")]);
        for _ in 0..depth {
            structure = Structure::new(vec![
                Field::new(Kind::Struct { structure }, Confidence::CERTAIN).with_name("s"),
            ]);
        }
        structure
    }

    fn as_format(root: Structure) -> Format {
        Format {
            name: "nested".to_owned(),
            endianness: sextant_ir::Endianness::Little,
            root,
            enums: Default::default(),
            metadata: Default::default(),
        }
    }

    #[test]
    fn binding_resolution_is_bounded_by_the_validator_nesting_limit() {
        // The deepest format validation accepts is still resolved.
        assert!(as_format(nested(MAX_NESTING_DEPTH)).validate().is_ok());
        assert!(reference_bindings(&nested(MAX_NESTING_DEPTH)).is_some());
        // One level deeper is refused by both, so the walk stays bounded.
        assert!(as_format(nested(MAX_NESTING_DEPTH + 1)).validate().is_err());
        assert!(reference_bindings(&nested(MAX_NESTING_DEPTH + 1)).is_none());
        let mut deep = nested(MAX_NESTING_DEPTH + 1);
        assert_eq!(
            rename_field(&mut deep, &[Seg::Field(0)], "t"),
            Err(TOO_DEEP_TO_RESOLVE.to_owned())
        );
    }

    #[test]
    fn a_rename_is_refused_where_validator_and_executor_bindings_differ() {
        // The element `x` anchors its checksum to `x`. The validator binds the
        // element itself; the executor never binds array elements and binds
        // the outer `x`. Renaming the outer field would keep one binding and
        // break the other, so it is refused.
        let mut element = u8_named("x");
        element.constraints.push(Constraint::Checksum {
            spec: ChecksumSpec {
                algorithm: ChecksumAlgorithm::Additive,
                covered: CoveredRange {
                    from: RangeAnchor::FieldStart { field: "x".into() },
                    to: RangeAnchor::FieldEnd { field: "x".into() },
                },
            },
        });
        let items = Field::new(
            Kind::Array {
                element: Box::new(element),
                count: CountRule::Fixed { count: 1 },
            },
            Confidence::CERTAIN,
        )
        .with_name("items");
        let root = Structure::new(vec![u8_named("x"), items]);
        assert!(as_format(root.clone()).validate().is_ok());

        let bindings = reference_bindings(&root).expect("a shallow format resolves");
        assert_eq!(bindings.len(), 2);
        for binding in &bindings {
            assert_eq!(
                binding.validator.as_deref(),
                Some(&[Seg::Field(1), Seg::Element][..])
            );
            assert_eq!(binding.executor.as_deref(), Some(&[Seg::Field(0)][..]));
        }

        let mut renamed = root.clone();
        let refusal = rename_field(&mut renamed, &[Seg::Field(0)], "w")
            .expect_err("the divergent binding makes the rename unsafe");
        assert!(refusal.contains("binds to"), "{refusal}");

        // A field no reference binds to can still be renamed.
        let mut renamed = root;
        rename_field(&mut renamed, &[Seg::Field(1)], "values")
            .expect("an unreferenced field can be renamed");
        assert_eq!(renamed.fields[1].name.as_deref(), Some("values"));
    }

    #[test]
    fn safe_identifiers_are_ascii_words_of_bounded_length() {
        for name in ["length", "_tail", "crc32", "A_b_9"] {
            assert!(is_safe_identifier(name), "{name:?} should be accepted");
        }
        let long = "n".repeat(MAX_MODEL_NAME_BYTES + 1);
        for name in [
            "",
            "9lives",
            "has space",
            "a-b",
            "pay\u{202E}load",
            "len\u{0007}",
            "l\u{00E4}ngd",
            long.as_str(),
        ] {
            assert!(!is_safe_identifier(name), "{name:?} should be refused");
        }
        assert!(is_safe_identifier(&"n".repeat(MAX_MODEL_NAME_BYTES)));
    }

    #[test]
    fn sanitized_text_drops_hidden_characters_and_is_bounded() {
        assert_eq!(
            sanitize_text(" a\u{0007}b\u{202E}c\u{200B}\nd\u{E0041}\t", 64),
            "abc d"
        );
        let long = "\u{00E9}".repeat(400);
        let cut = sanitize_text(&long, 101);
        assert!(cut.len() <= 101, "{} bytes", cut.len());
        assert!(cut.ends_with("..."));
        assert!(sanitize_text("\u{0000}\u{202E}", 16).is_empty());
    }

    #[test]
    fn displayed_text_escapes_everything_but_printable_ascii() {
        assert_eq!(display_text("ok \u{202E}x\n", 64), "ok \\u{202e}x\\u{a}");
        let shown = display_text(&"x".repeat(1000), 16);
        assert!(shown.len() <= 16 + 3 && shown.ends_with("..."));
    }

    #[test]
    fn model_involvement_is_marked_once() {
        let mut evidence = Evidence::default();
        mark_model_involvement(&mut evidence);
        assert_eq!(evidence.detector.as_deref(), Some("model"));
        let mut evidence = Evidence {
            detector: Some("statistics".to_owned()),
            ..Evidence::default()
        };
        mark_model_involvement(&mut evidence);
        mark_model_involvement(&mut evidence);
        assert_eq!(evidence.detector.as_deref(), Some("statistics+model"));
    }
}
