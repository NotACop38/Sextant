//! Tests for the language-model semantic pass and its verified refinement loop
//! (Step 9, FR-26, FR-29 to FR-32).
//!
//! Every test uses the in-process mock provider, so no network is touched. The
//! central guarantee under test is the non-regression invariant: the model
//! proposes, but a proposal is applied only when the native scorer confirms the
//! verified fit does not drop, and enabling the model never lowers the verified
//! score below the statistics-only baseline (FR-26, FR-31).

use std::cell::RefCell;
use std::rc::Rc;

use sextant_engine::{
    InferenceOptions, IngestOptions, Limits, SemanticOptions, infer, infer_with_llm, ingest, score,
    semantic_pass,
};
use sextant_ir::{
    Confidence, Endianness, Field, Format, Kind, Role, Signedness, SizeRule, Structure,
};
use sextant_llm::{
    CompletionRequest, CompletionResponse, JsonRequest, JsonResponse, LlmClient, LlmError,
    LlmProvider, MockProvider, ProviderKind, Usage,
};

/// Build SDLP-like samples: magic(4) length(u16 le) payload trailer(4 bytes).
/// No checksum constraint is verified, so the trailer bytes are arbitrary; this
/// keeps the baseline score at the top so any regression is unambiguous.
fn samples() -> Vec<Vec<u8>> {
    let make = |payload: &[u8]| {
        let mut data = b"SDLP".to_vec();
        data.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        data.extend_from_slice(payload);
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        data
    };
    vec![make(&[1, 2, 3]), make(&[9; 8]), make(&[4, 5])]
}

/// A field with no name, role, or constraints, carrying the given kind and size.
fn field(name: &str, kind: Kind, size: Option<SizeRule>) -> Field {
    Field {
        name: Some(name.to_owned()),
        kind,
        size,
        offset: None,
        role: None,
        constraints: Vec::new(),
        confidence: Confidence::clamped(0.5),
        evidence: Default::default(),
    }
}

/// A statistics-style baseline IR for the samples: it parses every sample to a
/// clean end and scores at the top, but its fields are unnamed in role and the
/// magic and trailer are still plain bytes. This stands in for the output of the
/// statistics-only pipeline that the semantic pass refines.
fn baseline_format() -> Format {
    let magic = field("f0", Kind::Bytes, Some(SizeRule::Fixed { bytes: 4 }));
    let length = field(
        "length",
        Kind::Integer {
            width: 2,
            signed: Signedness::Unsigned,
            endianness: Some(Endianness::Little),
        },
        None,
    );
    let payload = field(
        "f2",
        Kind::Bytes,
        Some(SizeRule::Derived {
            length_field: "length".into(),
        }),
    );
    let trailer = field("f3", Kind::Bytes, Some(SizeRule::Fixed { bytes: 4 }));
    Format {
        name: "sdlp-baseline".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(vec![magic, length, payload, trailer]),
        enums: Default::default(),
        metadata: Default::default(),
    }
}

fn slices(samples: &[Vec<u8>]) -> Vec<&[u8]> {
    samples.iter().map(Vec::as_slice).collect()
}

/// Wrap a mock provider that returns a canned JSON proposal in a client.
fn client_with_proposal(value: serde_json::Value) -> LlmClient<MockProvider> {
    LlmClient::new(MockProvider::new("mock").with_json(value))
}

#[test]
fn a_good_proposal_improves_roles_and_types_without_regressing() {
    let samples = samples();
    let slices = slices(&samples);
    let format = baseline_format();
    let baseline = score(&format, &slices);

    // The model names the magic and length, assigns their roles, and gives the
    // trailer a concrete integer type and a checksum role. None of these lower
    // the verified fit, so all should be accepted (FR-26).
    let proposal = serde_json::json!({
        "format_family": "sdlp",
        "fields": [
            {"index": 0, "name": "magic", "role": "magic", "rationale": "constant prefix"},
            {"index": 1, "name": "length", "role": "length", "rationale": "equals payload size"},
            {"index": 3, "name": "crc", "role": "checksum",
             "type": {"type": "integer", "width": 4, "signed": "unsigned", "endianness": "little"},
             "rationale": "trailing 32-bit value"}
        ]
    });
    let client = client_with_proposal(proposal);
    let outcome = semantic_pass(
        &format,
        &slices,
        &client,
        &Limits::default(),
        &SemanticOptions::default(),
    )
    .expect("the semantic pass completes");

    // The verified score did not drop (the non-regression invariant, FR-26).
    assert!(
        outcome.score.overall + 1e-9 >= baseline.overall,
        "score regressed: {} to {}",
        baseline.overall,
        outcome.score.overall
    );

    let fields = &outcome.format.root.fields;
    // Role annotations improved: previously unknown, now assigned.
    assert_eq!(fields[0].role, Some(Role::Magic));
    assert_eq!(fields[0].name.as_deref(), Some("magic"));
    assert_eq!(fields[1].role, Some(Role::Length));
    assert_eq!(fields[3].role, Some(Role::Checksum));
    // Type annotation improved: the trailer is now a concrete integer.
    assert!(matches!(fields[3].kind, Kind::Integer { width: 4, .. }));
    // The model rationale is recorded for explainability (FR-28).
    assert_eq!(
        fields[1].evidence.model_rationale.as_deref(),
        Some("equals payload size")
    );
    // The format-family guess is captured.
    assert_eq!(
        outcome
            .format
            .metadata
            .extra
            .get("format_family")
            .map(String::as_str),
        Some("sdlp")
    );
    // Every applied step was accepted and recorded (FR-28).
    assert!(!outcome.history.is_empty());
    assert!(
        outcome
            .history
            .iter()
            .all(|step| step.outcome == sextant_engine::RefineOutcome::Accepted)
    );
}

#[test]
fn a_bad_proposal_is_rejected_and_the_score_does_not_drop() {
    let samples = samples();
    let slices = slices(&samples);
    let format = baseline_format();
    let baseline = score(&format, &slices);

    // Misreading the 16-bit length as a single byte shifts every later field and
    // leaves a trailing unexplained byte, so the verified fit drops. The executor
    // must reject it (FR-26, FR-31): the model never has final authority.
    let proposal = serde_json::json!({
        "fields": [
            {"index": 1, "role": "length",
             "type": {"type": "integer", "width": 1, "signed": "unsigned", "endianness": "little"}}
        ]
    });
    let client = client_with_proposal(proposal);
    let outcome = semantic_pass(
        &format,
        &slices,
        &client,
        &Limits::default(),
        &SemanticOptions::default(),
    )
    .expect("the semantic pass completes");

    // The non-regression invariant holds: the score is unchanged.
    assert!((outcome.score.overall - baseline.overall).abs() < 1e-9);
    // The bad proposal was recorded as rejected (FR-28).
    assert!(
        outcome.history.iter().any(
            |step| step.outcome == sextant_engine::RefineOutcome::Rejected
                && step.score_after < step.score_before
        ),
        "a regressing proposal must be recorded as rejected"
    );
    // The length field kept its verified width; the model did not overrule it.
    assert!(matches!(
        outcome.format.root.fields[1].kind,
        Kind::Integer { width: 2, .. }
    ));
}

#[test]
fn an_out_of_range_index_is_rejected_and_the_pass_terminates() {
    let samples = samples();
    let slices = slices(&samples);
    let format = baseline_format();

    // A proposal that references a field that does not exist must not panic and
    // must be recorded as rejected; the pass still terminates.
    let proposal = serde_json::json!({
        "fields": [
            {"index": 99, "role": "length"},
            {"index": 0, "name": "magic", "role": "magic"}
        ]
    });
    let client = client_with_proposal(proposal);
    let outcome = semantic_pass(
        &format,
        &slices,
        &client,
        &Limits::default(),
        &SemanticOptions::default(),
    )
    .expect("the semantic pass completes");

    assert!(
        outcome
            .history
            .iter()
            .any(|step| step.outcome == sextant_engine::RefineOutcome::Rejected)
    );
    // The valid second proposal was still applied.
    assert_eq!(outcome.format.root.fields[0].role, Some(Role::Magic));
}

#[test]
fn enum_meanings_are_applied_when_they_do_not_regress() {
    let samples = samples();
    let slices = slices(&samples);
    let format = baseline_format();
    let baseline = score(&format, &slices);

    // Attaching enum meanings to the length integer turns it into an enum that
    // parses identically (same width), so the fit does not regress and the model
    // proposal is accepted (FR-29).
    let proposal = serde_json::json!({
        "fields": [
            {"index": 1, "enum": [{"value": 3, "name": "small"}, {"value": 8, "name": "large"}]}
        ]
    });
    let client = client_with_proposal(proposal);
    let outcome = semantic_pass(
        &format,
        &slices,
        &client,
        &Limits::default(),
        &SemanticOptions::default(),
    )
    .expect("the semantic pass completes");

    assert!(outcome.score.overall + 1e-9 >= baseline.overall);
    assert!(matches!(
        outcome.format.root.fields[1].kind,
        Kind::Enum { width: 2, .. }
    ));
    assert!(!outcome.format.enums.is_empty(), "an enum was registered");
}

#[test]
fn renaming_a_referenced_field_rewrites_its_dependents() {
    let samples = samples();
    let slices = slices(&samples);
    let format = baseline_format();
    let baseline = score(&format, &slices);

    // The payload's size is derived from the field named "length". Renaming that
    // field must rewrite the dependent reference so the IR stays consistent and
    // the parse does not regress; otherwise the rename would dangle and be
    // rejected. The rename does not change the parse, so it must be accepted.
    let proposal = serde_json::json!({
        "fields": [
            {"index": 1, "name": "len", "role": "length"}
        ]
    });
    let client = client_with_proposal(proposal);
    let outcome = semantic_pass(
        &format,
        &slices,
        &client,
        &Limits::default(),
        &SemanticOptions::default(),
    )
    .expect("the semantic pass completes");

    // The rename was accepted and the score held (the dependency was rewritten).
    assert!(outcome.score.overall + 1e-9 >= baseline.overall);
    assert_eq!(outcome.format.root.fields[1].name.as_deref(), Some("len"));
    // The payload's length reference now points at the new name, and the IR is
    // still valid (no dangling reference).
    assert!(matches!(
        &outcome.format.root.fields[2].size,
        Some(SizeRule::Derived { length_field }) if length_field.as_str() == "len"
    ));
    outcome
        .format
        .validate()
        .expect("the renamed IR has no dangling references");
}

#[test]
fn an_unknown_role_does_not_erase_a_concrete_role() {
    let samples = samples();
    let slices = slices(&samples);
    let format = baseline_format();

    // The first proposal assigns a concrete role; a later proposal returning
    // `unknown` for the same field must not erase it, since that would make the
    // report less informative at no score cost.
    let proposal = serde_json::json!({
        "fields": [
            {"index": 0, "role": "magic"},
            {"index": 0, "role": "unknown"}
        ]
    });
    let client = client_with_proposal(proposal);
    let outcome = semantic_pass(
        &format,
        &slices,
        &client,
        &Limits::default(),
        &SemanticOptions::default(),
    )
    .expect("the semantic pass completes");

    assert_eq!(
        outcome.format.root.fields[0].role,
        Some(Role::Magic),
        "an unknown role must not overwrite a concrete one"
    );
}

#[test]
fn free_form_text_is_rejected_as_an_invalid_response() {
    let samples = samples();
    let slices = slices(&samples);
    let format = baseline_format();

    // A provider whose text is not JSON cannot satisfy the structured contract
    // (FR-30); the pass returns an error rather than guessing.
    let client = LlmClient::new(MockProvider::new("mock").with_text("the first field is a magic"));
    let error = semantic_pass(
        &format,
        &slices,
        &client,
        &Limits::default(),
        &SemanticOptions::default(),
    )
    .expect_err("free-form text is not a structured proposal");
    assert!(matches!(error, LlmError::InvalidResponse(_)));
}

/// A provider that records the prompt it was handed, so a test can prove the
/// byte cap (NFR-4) by inspecting exactly what would be sent off the machine.
///
/// The recorded prompt is shared through an `Rc<RefCell<String>>` handle that
/// the test keeps a clone of, so the prompt can be read back without the client
/// exposing its wrapped provider. Going through a shared handle, rather than a
/// `provider_ref` accessor, keeps the client's cache, call cap, and budget the
/// only path to the provider.
struct RecordingProvider {
    last_prompt: Rc<RefCell<String>>,
    response: serde_json::Value,
}

impl RecordingProvider {
    /// Build a provider and return it alongside a handle the test reads the
    /// recorded prompt from.
    fn new(response: serde_json::Value) -> (Self, Rc<RefCell<String>>) {
        let last_prompt = Rc::new(RefCell::new(String::new()));
        let provider = Self {
            last_prompt: Rc::clone(&last_prompt),
            response,
        };
        (provider, last_prompt)
    }
}

impl LlmProvider for RecordingProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Mock
    }

    fn model(&self) -> &str {
        "recording"
    }

    fn complete(&self, _request: &CompletionRequest) -> Result<CompletionResponse, LlmError> {
        Ok(CompletionResponse {
            text: String::new(),
            usage: Usage::default(),
        })
    }

    fn complete_json(&self, request: &JsonRequest) -> Result<JsonResponse, LlmError> {
        if let Some(message) = request.messages.first() {
            *self.last_prompt.borrow_mut() = message.content.clone();
        }
        Ok(JsonResponse {
            value: self.response.clone(),
            usage: Usage::default(),
        })
    }
}

#[test]
fn the_prompt_byte_cap_bounds_what_is_sent() {
    // A sample whose first four bytes are 0x11 and whose tail contains a marker
    // byte 0x99 that lies beyond the cap. With a cap of four bytes, the marker
    // must never appear in the prompt (NFR-4).
    let sample = vec![0x11, 0x11, 0x11, 0x11, 0x99, 0x99, 0x99, 0x99];
    let slices: Vec<&[u8]> = vec![sample.as_slice()];
    let format = baseline_format();

    let (provider, recorded_prompt) = RecordingProvider::new(serde_json::json!({"fields": []}));
    let client = LlmClient::new(provider);
    let options = SemanticOptions {
        max_prompt_bytes_per_sample: 4,
        max_samples_in_prompt: 4,
    };
    let _ = semantic_pass(&format, &slices, &client, &Limits::default(), &options)
        .expect("the semantic pass completes");

    let prompt = recorded_prompt.borrow().clone();
    assert!(
        prompt.contains("11"),
        "the capped prefix bytes are present: {prompt}"
    );
    assert!(
        !prompt.contains("99"),
        "no byte beyond the cap leaks into the prompt: {prompt}"
    );
}

#[test]
fn enabling_the_model_never_drops_below_the_statistics_baseline_on_the_corpus() {
    // The statistics-only baseline over a corpus format.
    let dir = corpus_dir("sdlp");
    let set = ingest(
        &[dir.to_string_lossy().into_owned()],
        &IngestOptions::default(),
    )
    .expect("ingest the sdlp corpus");
    let baseline = infer(&set, &InferenceOptions::default());

    // A mix of a regressing proposal and an out-of-range index. Every proposal is
    // either rejected or harmless, so the model run must not score below the
    // statistics-only baseline (FR-26, FR-31).
    let proposal = serde_json::json!({
        "format_family": "sdlp",
        "fields": [
            {"index": 0, "size": {"rule": "fixed", "bytes": 1}},
            {"index": 250, "role": "length"}
        ]
    });
    let client = client_with_proposal(proposal);
    let report = infer_with_llm(&set, &llm_enabled(), &client, &SemanticOptions::default());

    assert!(
        report.score.overall + 1e-9 >= baseline.score.overall,
        "the model run dropped below the statistics baseline: {} < {}",
        report.score.overall,
        baseline.score.overall
    );
    // The report records that the model pass ran.
    assert!(!report.metadata.no_llm);
}

#[test]
fn a_failing_model_call_degrades_to_the_statistics_result() {
    let dir = corpus_dir("sdlp");
    let set = ingest(
        &[dir.to_string_lossy().into_owned()],
        &IngestOptions::default(),
    )
    .expect("ingest the sdlp corpus");
    let baseline = infer(&set, &InferenceOptions::default());

    // The provider returns text that is not JSON, so the structured call fails.
    // The run must fall back to the verified statistics-only result rather than
    // erroring (PRD Section 12, graceful degradation).
    let client = LlmClient::new(MockProvider::new("mock").with_text("sorry, no structure"));
    let report = infer_with_llm(&set, &llm_enabled(), &client, &SemanticOptions::default());

    assert!((report.score.overall - baseline.score.overall).abs() < 1e-9);
}

#[test]
fn no_llm_skips_the_provider_entirely() {
    let dir = corpus_dir("sdlp");
    let set = ingest(
        &[dir.to_string_lossy().into_owned()],
        &IngestOptions::default(),
    )
    .expect("ingest the sdlp corpus");

    // With `no_llm` set, `infer_with_llm` must not consult the provider at all,
    // so no call is made and the report is the statistics-only result with the
    // offline flag preserved (FR-32, NFR-4).
    let client = client_with_proposal(serde_json::json!({
        "format_family": "sdlp",
        "fields": [{"index": 0, "name": "magic", "role": "magic"}]
    }));
    let options = InferenceOptions {
        no_llm: true,
        ..InferenceOptions::default()
    };
    let report = infer_with_llm(&set, &options, &client, &SemanticOptions::default());

    assert_eq!(client.calls_made(), 0, "the provider must not be called");
    assert!(report.metadata.no_llm);
    // The model's format-family guess never reached the report, since the model
    // was never consulted.
    assert!(
        !report.format.metadata.extra.contains_key("format_family"),
        "no model metadata leaks into a no_llm run"
    );
}

/// Inference options with the language model enabled, for the corpus tests that
/// exercise `infer_with_llm`'s model path. The default disables the model.
fn llm_enabled() -> InferenceOptions {
    InferenceOptions {
        no_llm: false,
        ..InferenceOptions::default()
    }
}

fn corpus_dir(format: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("engine crate has a parent")
        .join("corpus")
        .join(format)
        .join("samples")
}
