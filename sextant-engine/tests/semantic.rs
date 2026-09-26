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

use sextant_engine::semantic::{
    DEFAULT_MAX_PROPOSALS, MAX_MODEL_ENUM_VARIANTS, MAX_MODEL_NAME_BYTES, MAX_MODEL_RATIONALE_BYTES,
};
use sextant_engine::{
    InferenceOptions, IngestOptions, Limits, RefineOutcome, Report, RunMetadata, SemanticOptions,
    SemanticOutcome, execute, infer, infer_with_llm, ingest, score, semantic_pass,
};
use sextant_ir::{
    ChecksumAlgorithm, ChecksumSpec, Confidence, Constraint, CountRule, CoveredRange, Endianness,
    Field, Format, Kind, RangeAnchor, Role, Signedness, SizeRule, Structure,
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

/// Run the semantic pass with a canned proposal and the default options.
fn run(format: &Format, samples: &[&[u8]], proposal: serde_json::Value) -> SemanticOutcome {
    semantic_pass(
        format,
        samples,
        &client_with_proposal(proposal),
        &Limits::default(),
        &SemanticOptions::default(),
    )
    .expect("the semantic pass completes")
}

/// A little-endian format with the given root fields.
fn format_of(fields: Vec<Field>) -> Format {
    Format {
        name: "nested".to_owned(),
        endianness: Endianness::Little,
        root: Structure::new(fields),
        enums: Default::default(),
        metadata: Default::default(),
    }
}

/// An unsigned one-byte integer field.
fn u8_field(name: &str) -> Field {
    field(
        name,
        Kind::Integer {
            width: 1,
            signed: Signedness::Unsigned,
            endianness: None,
        },
        None,
    )
}

/// A bytes field whose size is taken from the named length field.
fn derived_bytes(name: &str, length_field: &str) -> Field {
    field(
        name,
        Kind::Bytes,
        Some(SizeRule::Derived {
            length_field: length_field.into(),
        }),
    )
}

/// A struct field holding `fields`.
fn struct_field(name: &str, fields: Vec<Field>) -> Field {
    field(
        name,
        Kind::Struct {
            structure: Structure::new(fields),
        },
        None,
    )
}

/// An array field of `element`, counted by `count`.
fn array_field(name: &str, element: Field, count: CountRule) -> Field {
    field(
        name,
        Kind::Array {
            element: Box::new(element),
            count,
        },
        None,
    )
}

/// The structure inside a struct field.
fn inner(field: &Field) -> &Structure {
    match &field.kind {
        Kind::Struct { structure } => structure,
        other => panic!("expected a struct field, found {other:?}"),
    }
}

/// The element of an array field.
fn element(field: &Field) -> &Field {
    match &field.kind {
        Kind::Array { element, .. } => element,
        other => panic!("expected an array field, found {other:?}"),
    }
}

/// The name a field's derived size refers to, if it has one.
fn size_ref(field: &Field) -> Option<&str> {
    match &field.size {
        Some(SizeRule::Derived { length_field }) => Some(length_field.as_str()),
        _ => None,
    }
}

/// The name an array field's count refers to, if it has one.
fn count_ref(field: &Field) -> Option<&str> {
    match &field.kind {
        Kind::Array {
            count: CountRule::FromField { count_field },
            ..
        } => Some(count_field.as_str()),
        _ => None,
    }
}

/// The field names of the report's flattened field map for `format`, in order.
fn report_names(format: &Format, samples: &[&[u8]]) -> Vec<String> {
    let metadata = RunMetadata {
        tool_version: "test".to_owned(),
        sample_count: samples.len(),
        total_bytes: samples.iter().map(|sample| sample.len()).sum(),
        no_llm: false,
    };
    Report::build(format.clone(), score(format, samples), Vec::new(), metadata)
        .field_map
        .into_iter()
        .map(|entry| entry.name)
        .collect()
}

/// The `(index, name)` pairs of the numbered field summary in a prompt.
fn prompt_fields(prompt: &str) -> Vec<(usize, String)> {
    prompt
        .lines()
        .skip_while(|line| !line.starts_with("Fields (index: summary):"))
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .map(|line| {
            let (index, summary) = line
                .trim()
                .split_once(": ")
                .expect("an `index: summary` line");
            let name = summary.split_whitespace().next().expect("a field name");
            (index.parse().expect("a numeric index"), name.to_owned())
        })
        .collect()
}

/// Whether text holds only printable ASCII, so no control, bidirectional, or
/// invisible character supplied by the model reached it.
fn is_printable_ascii(text: &str) -> bool {
    text.chars().all(|c| c == ' ' || c.is_ascii_graphic())
}

#[test]
fn a_higher_aggregate_score_cannot_sacrifice_a_previously_parsed_sample() {
    let mut format = baseline_format();
    format.root = Structure::new(vec![field(
        "data",
        Kind::Bytes,
        Some(SizeRule::Fixed { bytes: 1 }),
    )]);
    let mut samples = vec![vec![0; 100]; 100];
    samples.push(vec![0]);
    let slices = slices(&samples);
    let baseline = score(&format, &slices);
    let mut regressed = format.clone();
    regressed.root.fields[0].size = Some(SizeRule::Fixed { bytes: 100 });
    let proposed = score(&regressed, &slices);
    assert!(proposed.overall > baseline.overall);
    assert!(proposed.generality < baseline.generality);

    let client = client_with_proposal(serde_json::json!({
        "fields": [{"index": 0, "size": {"rule": "fixed", "bytes": 100}}]
    }));
    let outcome = semantic_pass(
        &format,
        &slices,
        &client,
        &Limits::default(),
        &SemanticOptions::default(),
    )
    .unwrap();
    assert_eq!(outcome.format, format);
    assert_eq!(outcome.score.generality, 1.0);
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
        ..SemanticOptions::default()
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

// Field numbering: the semantic pass and the report's field map agree.

/// A format that nests structs inside arrays of arrays inside structs, with a
/// unique name on every field, and the length of a sample it parses exactly.
fn deeply_nested_format() -> (Format, usize) {
    let pair = array_field(
        "pair",
        array_field("pv", u8_field("leaf"), CountRule::Fixed { count: 1 }),
        CountRule::Fixed { count: 1 },
    );
    let cell = struct_field("cell", vec![u8_field("x"), pair, u8_field("y")]);
    let grid = array_field(
        "grid",
        array_field("row", cell, CountRule::Fixed { count: 2 }),
        CountRule::Fixed { count: 2 },
    );
    let outer = struct_field(
        "outer",
        vec![
            u8_field("count"),
            grid,
            struct_field("inner", vec![struct_field("deep", vec![u8_field("a")])]),
        ],
    );
    let magic = field("magic", Kind::Bytes, Some(SizeRule::Fixed { bytes: 2 }));
    let len = 2 + 1 + 2 * 2 * 3 + 1 + 1;
    (format_of(vec![magic, outer, u8_field("tail")]), len)
}

#[test]
fn field_indices_match_the_report_field_map_at_any_depth() {
    let (format, len) = deeply_nested_format();
    format.validate().expect("the nested format is valid IR");
    let sample = vec![7u8; len];
    let slices: Vec<&[u8]> = vec![sample.as_slice()];
    assert!(score(&format, &slices).fully_verified());

    let expected = [
        "magic", "outer", "count", "grid", "row", "cell", "x", "pair", "pv", "leaf", "y", "inner",
        "deep", "a", "tail",
    ];
    let map = report_names(&format, &slices);
    assert_eq!(map, expected);

    // The prompt numbers the fields exactly as the report's field map does.
    let (provider, recorded_prompt) = RecordingProvider::new(serde_json::json!({"fields": []}));
    let client = LlmClient::new(provider);
    semantic_pass(
        &format,
        &slices,
        &client,
        &Limits::default(),
        &SemanticOptions::default(),
    )
    .expect("the semantic pass completes");
    let listed = prompt_fields(&recorded_prompt.borrow());
    assert!(
        listed
            .iter()
            .enumerate()
            .all(|(position, (index, _))| position == *index)
    );
    let listed_names: Vec<String> = listed.into_iter().map(|(_, name)| name).collect();
    assert_eq!(listed_names, map);

    // A proposal addressed by a field-map index edits exactly that field, even
    // inside an array of arrays.
    let outcome = run(
        &format,
        &slices,
        serde_json::json!({"fields": [
            {"index": 6, "name": "col_x"},
            {"index": 9, "name": "leaf_value"},
            {"index": 14, "name": "trailer"}
        ]}),
    );
    let mut renamed: Vec<String> = expected.iter().map(|name| (*name).to_owned()).collect();
    renamed[6] = "col_x".to_owned();
    renamed[9] = "leaf_value".to_owned();
    renamed[14] = "trailer".to_owned();
    assert_eq!(report_names(&outcome.format, &slices), renamed);
    assert!(
        outcome
            .history
            .iter()
            .all(|step| step.outcome == RefineOutcome::Accepted)
    );
}

#[test]
fn indices_inside_an_array_of_arrays_follow_the_report_field_map() {
    // grid is an array of row arrays of cell structs {x, y}, followed by z. The
    // report's field map is [grid, row, cell, x, y, z]. Index 3 used to be out
    // of range for the semantic pass, and index 2 used to rename z.
    let cell = struct_field("cell", vec![u8_field("x"), u8_field("y")]);
    let row = array_field("row", cell, CountRule::Fixed { count: 2 });
    let format = format_of(vec![
        array_field("grid", row, CountRule::Fixed { count: 2 }),
        u8_field("z"),
    ]);
    let sample = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
    let slices: Vec<&[u8]> = vec![&sample[..]];
    assert_eq!(
        report_names(&format, &slices),
        ["grid", "row", "cell", "x", "y", "z"]
    );

    let outcome = run(
        &format,
        &slices,
        serde_json::json!({"fields": [
            {"index": 3, "name": "col", "role": "payload"},
            {"index": 2, "name": "point"},
            {"index": 5, "name": "tail"}
        ]}),
    );
    assert_eq!(
        report_names(&outcome.format, &slices),
        ["grid", "row", "point", "col", "y", "tail"]
    );
    let x = &inner(element(element(&outcome.format.root.fields[0]))).fields[0];
    assert_eq!(x.role, Some(Role::Payload));
    assert!(
        outcome
            .history
            .iter()
            .all(|step| step.outcome == RefineOutcome::Accepted)
    );
}

// Renames preserve every reference binding.

#[test]
fn a_rename_that_would_capture_an_outer_reference_is_rejected() {
    // data's size binds to the root `length`. Renaming s.k to `length` makes
    // the inner field shadow it and silently rebinds data's size to s.k.
    let format = format_of(vec![
        u8_field("length"),
        struct_field("s", vec![u8_field("k"), derived_bytes("data", "length")]),
    ]);
    format.validate().expect("valid IR");
    // On the retained samples the two fields agree, so the score cannot tell.
    let samples = [vec![2u8, 2, 0xAA, 0xBB], vec![1, 1, 0xCC]];
    let slices = slices(&samples);
    let unseen = [2u8, 3, 0xAA, 0xBB, 0xCC];
    assert_eq!(execute(&format, &unseen, &Limits::default()).consumed, 4);

    let outcome = run(
        &format,
        &slices,
        serde_json::json!({"fields": [{"index": 2, "name": "length"}]}),
    );
    assert_eq!(
        outcome.format, format,
        "the capturing rename is not applied"
    );
    let step = &outcome.history[0];
    assert_eq!(step.outcome, RefineOutcome::Rejected);
    assert!(
        step.description.contains("binds to"),
        "{}",
        step.description
    );
    // The meaning is unchanged on an unseen sample where the fields differ.
    assert_eq!(
        execute(&outcome.format, &unseen, &Limits::default()).consumed,
        4
    );

    // Naming a previously unnamed field must not capture the reference either.
    let mut unnamed = format.clone();
    if let Kind::Struct { structure } = &mut unnamed.root.fields[1].kind {
        structure.fields[0].name = None;
    }
    unnamed.validate().expect("valid IR");
    let outcome = run(
        &unnamed,
        &slices,
        serde_json::json!({"fields": [{"index": 2, "name": "length"}]}),
    );
    assert_eq!(outcome.format, unnamed);
    assert_eq!(outcome.history[0].outcome, RefineOutcome::Rejected);
}

#[test]
fn a_rename_rewrites_only_the_references_bound_to_the_renamed_field() {
    // s.data binds to the shadowing s.length, and tail binds to the root
    // length. Renaming the root field must leave s.data alone.
    let format = format_of(vec![
        u8_field("length"),
        struct_field(
            "s",
            vec![u8_field("length"), derived_bytes("data", "length")],
        ),
        derived_bytes("tail", "length"),
    ]);
    format.validate().expect("valid IR");
    let samples = [vec![2u8, 2, 1, 2, 3, 4], vec![1, 1, 5, 6]];
    let slices = slices(&samples);
    let unseen = [1u8, 3, 1, 2, 3, 4];
    let before = execute(&format, &unseen, &Limits::default());
    assert_eq!(before.consumed, 6);

    let outcome = run(
        &format,
        &slices,
        serde_json::json!({"fields": [{"index": 0, "name": "n"}]}),
    );
    let fields = &outcome.format.root.fields;
    assert_eq!(fields[0].name.as_deref(), Some("n"));
    assert_eq!(size_ref(&fields[2]), Some("n"), "tail follows the rename");
    assert_eq!(
        size_ref(&inner(&fields[1]).fields[1]),
        Some("length"),
        "s.data keeps its binding to s.length"
    );
    outcome.format.validate().expect("the renamed IR is valid");
    let after = execute(&outcome.format, &unseen, &Limits::default());
    assert_eq!(after.consumed, before.consumed);
    assert_eq!(after.leaf_ranges, before.leaf_ranges);
}

#[test]
fn a_rename_rewrites_references_held_by_array_elements() {
    // Every reference to `len` is held by an array element: the element's own
    // size, and the checksum anchors of another array's element. (An element
    // cannot be positioned, so it holds no offset reference.)
    let item = derived_bytes("item", "len");
    let mut sum = u8_field("sum");
    sum.constraints.push(Constraint::Checksum {
        spec: ChecksumSpec {
            algorithm: ChecksumAlgorithm::Additive,
            covered: CoveredRange {
                from: RangeAnchor::FieldStart {
                    field: "len".into(),
                },
                to: RangeAnchor::FieldEnd {
                    field: "len".into(),
                },
            },
        },
    });
    let format = format_of(vec![
        u8_field("len"),
        array_field(
            "items",
            item,
            CountRule::FromField {
                count_field: "len".into(),
            },
        ),
        array_field("sums", sum, CountRule::Fixed { count: 1 }),
    ]);
    format.validate().expect("valid IR");
    let samples = [vec![1u8, 0x10, 1], vec![2, 0x20, 0x21, 0x22, 0x23, 2]];
    let slices = slices(&samples);
    assert!(score(&format, &slices).fully_verified());

    let outcome = run(
        &format,
        &slices,
        serde_json::json!({"fields": [{"index": 0, "name": "n"}]}),
    );
    let step = &outcome.history[0];
    assert_eq!(
        step.outcome,
        RefineOutcome::Accepted,
        "{}",
        step.description
    );
    outcome
        .format
        .validate()
        .expect("every element reference was rewritten");
    assert!(outcome.score.fully_verified());
    let fields = &outcome.format.root.fields;
    assert_eq!(fields[0].name.as_deref(), Some("n"));
    assert_eq!(count_ref(&fields[1]), Some("n"));
    let item = element(&fields[1]);
    assert_eq!(size_ref(item), Some("n"));
    let Constraint::Checksum { spec } = &element(&fields[2]).constraints[0] else {
        panic!("the checksum constraint is kept");
    };
    assert_eq!(spec.covered.from.field().as_str(), "n");
    assert_eq!(spec.covered.to.field().as_str(), "n");
}

#[test]
fn a_rename_rewrites_references_inside_arrays_of_arrays() {
    // grid holds `len` rows of `len` cells of `len` bytes each.
    let row = array_field(
        "row",
        derived_bytes("cell", "len"),
        CountRule::FromField {
            count_field: "len".into(),
        },
    );
    let format = format_of(vec![
        u8_field("len"),
        array_field(
            "grid",
            row,
            CountRule::FromField {
                count_field: "len".into(),
            },
        ),
    ]);
    format.validate().expect("valid IR");
    let samples = [vec![1u8, 0xAA], vec![2, 1, 2, 3, 4, 5, 6, 7, 8]];
    let slices = slices(&samples);
    assert!(score(&format, &slices).fully_verified());

    let outcome = run(
        &format,
        &slices,
        serde_json::json!({"fields": [{"index": 0, "name": "n"}]}),
    );
    let step = &outcome.history[0];
    assert_eq!(
        step.outcome,
        RefineOutcome::Accepted,
        "{}",
        step.description
    );
    outcome
        .format
        .validate()
        .expect("every nested reference was rewritten");
    let grid = &outcome.format.root.fields[1];
    assert_eq!(count_ref(grid), Some("n"));
    assert_eq!(count_ref(element(grid)), Some("n"));
    assert_eq!(size_ref(element(element(grid))), Some("n"));
}

// The gate refuses equal-score trades between samples.

#[test]
fn an_equal_score_trade_that_swaps_which_sample_passes_a_check_is_rejected() {
    let mut value = field(
        "value",
        Kind::Integer {
            width: 2,
            signed: Signedness::Unsigned,
            endianness: Some(Endianness::Little),
        },
        None,
    );
    value
        .constraints
        .push(Constraint::IntRange { min: 0, max: 255 });
    let format = format_of(vec![value]);
    // Read little-endian, the first sample is in range and the second is not;
    // read big-endian, the reverse. A trailing byte keeps both samples short of
    // full verification, so the shared gate alone cannot tell the trade apart.
    let samples = [vec![0x01u8, 0x00, 0xFF], vec![0x00, 0x01, 0xFF]];
    let slices = slices(&samples);
    let baseline = score(&format, &slices);
    let mut flipped = format.clone();
    flipped.root.fields[0].kind = Kind::Integer {
        width: 2,
        signed: Signedness::Unsigned,
        endianness: Some(Endianness::Big),
    };
    let traded = score(&flipped, &slices);
    assert_eq!(traded.overall, baseline.overall);
    assert!(traded.preserves_verified_fit(&baseline));
    assert_eq!(baseline.samples[0].constraints_passed, 1);
    assert_eq!(traded.samples[0].constraints_passed, 0);

    let outcome = run(
        &format,
        &slices,
        serde_json::json!({"fields": [
            {"index": 0, "type": {"type": "integer", "width": 2, "signed": "unsigned",
                                  "endianness": "big"}},
            {"index": 0, "name": "value_le"}
        ]}),
    );
    assert!(matches!(
        outcome.format.root.fields[0].kind,
        Kind::Integer {
            endianness: Some(Endianness::Little),
            ..
        }
    ));
    let trade = &outcome.history[0];
    assert_eq!(trade.outcome, RefineOutcome::Rejected);
    assert!(
        trade
            .description
            .contains("would lose a passing constraint check"),
        "{}",
        trade.description
    );
    // An equal-score change that keeps every passing check is still accepted.
    assert_eq!(outcome.history[1].outcome, RefineOutcome::Accepted);
    assert_eq!(
        outcome.format.root.fields[0].name.as_deref(),
        Some("value_le")
    );
}

// Model output handling.

#[test]
fn malformed_entries_are_skipped_without_discarding_the_response() {
    let samples = samples();
    let slices = slices(&samples);
    let format = baseline_format();
    let proposal = serde_json::json!({
        "format_family": 42,
        "fields": [
            {"index": 0, "role": "definitely-not-a-role"},
            "not an object",
            {"index": -3, "name": "magic"},
            {"index": 1, "name": "len", "role": "length"}
        ]
    });
    let outcome = run(&format, &slices, proposal);

    // The valid entry is applied even though its neighbors are malformed.
    let fields = &outcome.format.root.fields;
    assert_eq!(fields[1].name.as_deref(), Some("len"));
    assert_eq!(fields[1].role, Some(Role::Length));
    assert_eq!(fields[0].role, None, "the malformed role was not applied");
    // Each malformed entry, and the unusable format family, is recorded.
    let malformed = outcome
        .history
        .iter()
        .filter(|step| {
            step.outcome == RefineOutcome::Rejected && step.description.contains("malformed")
        })
        .count();
    assert_eq!(malformed, 3);
    assert!(
        outcome
            .history
            .iter()
            .any(|step| step.description.contains("format_family"))
    );
    assert!(outcome.format_family.is_none());
    assert!(
        outcome
            .history
            .iter()
            .all(|step| is_printable_ascii(&step.description))
    );
}

#[test]
fn a_response_that_is_not_a_proposal_object_is_an_invalid_response() {
    let samples = samples();
    let slices = slices(&samples);
    let format = baseline_format();
    for value in [
        serde_json::json!(["not", "an", "object"]),
        serde_json::json!("the first field is a magic"),
        serde_json::json!({"fields": {"index": 0, "role": "magic"}}),
        serde_json::json!({"fields": "magic at zero"}),
    ] {
        let error = semantic_pass(
            &format,
            &slices,
            &client_with_proposal(value.clone()),
            &Limits::default(),
            &SemanticOptions::default(),
        )
        .expect_err("not a structured proposal");
        assert!(
            matches!(error, LlmError::InvalidResponse(_)),
            "{value}: {error:?}"
        );
    }
}

#[test]
fn entries_beyond_the_per_response_cap_are_not_considered() {
    assert_eq!(DEFAULT_MAX_PROPOSALS, 256);
    let samples = samples();
    let slices = slices(&samples);
    let entries: Vec<serde_json::Value> = (0..DEFAULT_MAX_PROPOSALS + 44)
        .map(|_| serde_json::json!({"index": 0, "role": "magic"}))
        .collect();
    let outcome = run(
        &baseline_format(),
        &slices,
        serde_json::json!({ "fields": entries }),
    );

    // One step per considered entry, then one summary of the skipped entries.
    assert_eq!(outcome.history.len(), DEFAULT_MAX_PROPOSALS + 1);
    let summary = outcome.history.last().expect("a summary step");
    assert_eq!(summary.outcome, RefineOutcome::Rejected);
    assert!(
        summary
            .description
            .contains("44 entries beyond the per-response cap of 256"),
        "{}",
        summary.description
    );
}

#[test]
fn the_rescoring_budget_bounds_candidate_evaluations() {
    let samples = samples();
    let slices = slices(&samples);
    let format = baseline_format();
    // Each evaluation costs one unit per sample plus one per sample byte, so
    // this budget pays for exactly two evaluations.
    let per_evaluation: u64 = slices.iter().map(|sample| 1 + sample.len() as u64).sum();
    let options = SemanticOptions {
        max_rescore_work: 2 * per_evaluation,
        ..SemanticOptions::default()
    };
    let proposal = serde_json::json!({"fields": [
        {"index": 0, "role": "magic"},
        {"index": 99, "role": "length"},
        {"index": 1, "role": "length"},
        {"index": 2, "role": "payload"},
        {"index": 3, "role": "checksum"}
    ]});
    let outcome = semantic_pass(
        &format,
        &slices,
        &client_with_proposal(proposal),
        &Limits::default(),
        &options,
    )
    .expect("the semantic pass completes");

    // The out-of-range entry was rejected before scoring and cost nothing.
    let fields = &outcome.format.root.fields;
    assert_eq!(fields[0].role, Some(Role::Magic));
    assert_eq!(fields[1].role, Some(Role::Length));
    assert_eq!(fields[2].role, None);
    assert_eq!(fields[3].role, None);
    let accepted = outcome
        .history
        .iter()
        .filter(|step| step.outcome == RefineOutcome::Accepted)
        .count();
    assert_eq!(accepted, 2);
    let summary = outcome.history.last().expect("a budget step");
    assert!(
        summary.description.contains("budget")
            && summary.description.contains("2 remaining entries"),
        "{}",
        summary.description
    );
}

#[test]
fn model_edits_mark_the_field_evidence_detector() {
    let samples = samples();
    let slices = slices(&samples);
    let mut format = baseline_format();
    format.root.fields[0].evidence.detector = Some("statistics".to_owned());
    // No proposal carries a rationale; the detector must show the model anyway.
    let outcome = run(
        &format,
        &slices,
        serde_json::json!({"fields": [
            {"index": 0, "role": "magic"},
            {"index": 0, "name": "magic"},
            {"index": 1, "role": "length"}
        ]}),
    );
    let fields = &outcome.format.root.fields;
    assert_eq!(
        fields[0].evidence.detector.as_deref(),
        Some("statistics+model")
    );
    assert!(fields[0].evidence.model_rationale.is_none());
    assert_eq!(fields[1].evidence.detector.as_deref(), Some("model"));
    // A field the model did not edit keeps its evidence.
    assert_eq!(fields[3].evidence.detector, None);
}

#[test]
fn unsafe_model_names_are_rejected() {
    let samples = samples();
    let slices = slices(&samples);
    let long = "n".repeat(MAX_MODEL_NAME_BYTES + 1);
    let unsafe_names = [
        "pay\u{202E}load",
        "len\u{0007}",
        "l\u{00E4}ngd",
        "has space",
        "",
        "9lives",
        "a-b",
        long.as_str(),
    ];
    let mut entries: Vec<serde_json::Value> = unsafe_names
        .iter()
        .map(|name| serde_json::json!({"index": 2, "name": name}))
        .collect();
    entries.push(serde_json::json!({"index": 2, "name": "payload_2"}));
    let outcome = run(
        &baseline_format(),
        &slices,
        serde_json::json!({ "fields": entries }),
    );

    assert_eq!(
        outcome.format.root.fields[2].name.as_deref(),
        Some("payload_2")
    );
    let rejected: Vec<_> = outcome
        .history
        .iter()
        .filter(|step| step.outcome == RefineOutcome::Rejected)
        .collect();
    assert_eq!(rejected.len(), unsafe_names.len());
    assert!(
        rejected
            .iter()
            .all(|step| step.description.contains("not a safe identifier"))
    );
    // No model-supplied control or bidirectional character reaches the history.
    assert!(
        outcome
            .history
            .iter()
            .all(|step| is_printable_ascii(&step.description))
    );
}

#[test]
fn enum_variants_need_safe_names_and_a_bounded_count() {
    let samples = samples();
    let slices = slices(&samples);
    let too_many: Vec<serde_json::Value> = (0..=MAX_MODEL_ENUM_VARIANTS)
        .map(|value| serde_json::json!({"value": value, "name": format!("v{value}")}))
        .collect();
    let proposal = serde_json::json!({"fields": [
        {"index": 1, "enum": [{"value": 3, "name": "small\u{202E}"}]},
        {"index": 1, "enum": too_many},
        {"index": 1, "enum": [{"value": 3, "name": "small",
                               "description": "three\u{0000} bytes\u{202E}\nlong"}]}
    ]});
    let outcome = run(&baseline_format(), &slices, proposal);

    assert_eq!(outcome.history[0].outcome, RefineOutcome::Rejected);
    assert_eq!(outcome.history[1].outcome, RefineOutcome::Rejected);
    assert!(
        outcome.history[1].description.contains("enum variants"),
        "{}",
        outcome.history[1].description
    );
    assert_eq!(outcome.history[2].outcome, RefineOutcome::Accepted);
    assert!(matches!(
        outcome.format.root.fields[1].kind,
        Kind::Enum { width: 2, .. }
    ));
    let definition = outcome.format.enums.values().next().expect("an enum");
    assert_eq!(definition.variants.len(), 1);
    assert_eq!(
        definition.variants[0].description.as_deref(),
        Some("three bytes long")
    );
}

#[test]
fn an_enum_proposal_cannot_collapse_a_struct() {
    // Collapsing the struct into a one-byte enum would parse the sample the
    // same way but change the field tree, making later indices stale.
    let format = format_of(vec![struct_field("s", vec![u8_field("a")])]);
    let sample = [5u8];
    let slices: Vec<&[u8]> = vec![&sample[..]];
    let outcome = run(
        &format,
        &slices,
        serde_json::json!({"fields": [
            {"index": 0, "enum": [{"value": 5, "name": "five"}]},
            {"index": 1, "name": "value"}
        ]}),
    );
    assert_eq!(outcome.history[0].outcome, RefineOutcome::Rejected);
    assert!(outcome.format.enums.is_empty());
    assert_eq!(
        inner(&outcome.format.root.fields[0]).fields[0]
            .name
            .as_deref(),
        Some("value")
    );
}

#[test]
fn model_rationale_and_format_family_are_cleaned_and_bounded() {
    let samples = samples();
    let slices = slices(&samples);
    let rationale = format!(
        "constant\u{0007} prefix\u{202E}\nseen in every sample {}",
        "x".repeat(10_000)
    );
    let proposal = serde_json::json!({
        "format_family": "sd\u{202E}lp\u{0007}",
        "fields": [{"index": 0, "role": "magic", "rationale": rationale}]
    });
    let outcome = run(&baseline_format(), &slices, proposal);

    let stored = outcome.format.root.fields[0]
        .evidence
        .model_rationale
        .as_deref()
        .expect("the rationale is recorded");
    assert!(
        stored.len() <= MAX_MODEL_RATIONALE_BYTES,
        "{}",
        stored.len()
    );
    assert!(stored.starts_with("constant prefix seen in every sample"));
    assert!(!stored.chars().any(|c| c.is_control() || c == '\u{202E}'));
    assert_eq!(outcome.format_family.as_deref(), Some("sdlp"));
    assert_eq!(
        outcome
            .format
            .metadata
            .extra
            .get("format_family")
            .map(String::as_str),
        Some("sdlp")
    );
}
