//! The provider-agnostic model interface (PRD Section 12, FR-33).
//!
//! A single trait, [`LlmProvider`], exposes two calls: a plain-text completion
//! and a structured call that returns JSON. Every concrete provider (Anthropic,
//! OpenAI, Ollama, and the test-only mock) implements this trait, and the rest
//! of Sextant only ever talks to the trait, never to a specific provider.

use serde::{Deserialize, Serialize};

use crate::config::ProviderKind;
use crate::error::LlmError;

/// The default cap on generated tokens for a request.
///
/// Current Claude models think before answering by default, and `max_tokens`
/// bounds the thinking and the answer together, so a tight cap truncates the
/// answer. This value leaves room for both while keeping a non-streaming
/// response well inside the request timeout.
pub const DEFAULT_MAX_TOKENS: u32 = 16_000;

/// The role of a message in a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// A system instruction that frames the task.
    System,
    /// A message from the user (the prompt).
    User,
    /// A message previously produced by the assistant.
    Assistant,
}

/// A single message in a completion request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// Who authored the message.
    pub role: Role,
    /// The message text.
    pub content: String,
}

impl Message {
    /// Construct a message with the given role and content.
    pub fn new(role: Role, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
        }
    }

    /// Construct a user message.
    pub fn user(content: impl Into<String>) -> Self {
        Self::new(Role::User, content)
    }

    /// Construct an assistant message.
    pub fn assistant(content: impl Into<String>) -> Self {
        Self::new(Role::Assistant, content)
    }
}

/// A plain-text completion request.
///
/// The struct is `Serialize` so the client can hash it into a stable cache key
/// (NFR-6). The fields are deliberately provider-neutral; each provider maps
/// them onto its own wire format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompletionRequest {
    /// An optional system instruction.
    pub system: Option<String>,
    /// The conversation so far. Most requests are a single user message.
    pub messages: Vec<Message>,
    /// The maximum number of tokens to generate, including any thinking the
    /// model does first. Defaults to [`DEFAULT_MAX_TOKENS`].
    pub max_tokens: u32,
    /// An explicit sampling temperature, sent only when set.
    ///
    /// `None`, the default, leaves sampling to the provider and omits the
    /// field from the request: current Anthropic models reject a
    /// `temperature` with HTTP 400, and reasoning models elsewhere ignore or
    /// reject it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
}

impl CompletionRequest {
    /// A request with a single user message, the default token cap, and no
    /// explicit temperature.
    pub fn user(prompt: impl Into<String>) -> Self {
        Self {
            system: None,
            messages: vec![Message::user(prompt)],
            max_tokens: DEFAULT_MAX_TOKENS,
            temperature: None,
        }
    }

    /// Set the system instruction.
    #[must_use]
    pub fn with_system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }

    /// Set the maximum number of tokens to generate.
    #[must_use]
    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }

    /// Request an explicit sampling temperature. Only set this for a model
    /// that accepts one; current Anthropic models reject it.
    #[must_use]
    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }
}

/// A structured request that asks the model to return JSON (FR-30).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRequest {
    /// An optional system instruction.
    pub system: Option<String>,
    /// The conversation so far.
    pub messages: Vec<Message>,
    /// A human-readable description of the JSON shape the model should return.
    /// This is folded into the prompt so providers without a native structured
    /// mode still produce parseable output.
    pub schema_hint: String,
    /// The maximum number of tokens to generate, including any thinking.
    /// Defaults to [`DEFAULT_MAX_TOKENS`].
    pub max_tokens: u32,
    /// An explicit sampling temperature, sent only when set. See
    /// [`CompletionRequest::temperature`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// An optional machine-readable JSON Schema for the response.
    ///
    /// Providers with a native structured-output mode use it to constrain the
    /// answer: the Anthropic provider sends it as `output_config.format` after
    /// closing every object schema with `additionalProperties: false`, and
    /// falls back to the prose hint when the schema is not an object schema or
    /// explicitly allows extra properties. Other providers rely on the hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<serde_json::Value>,
}

impl JsonRequest {
    /// A structured request with a single user message, a schema hint, the
    /// default token cap, and no explicit temperature.
    pub fn new(prompt: impl Into<String>, schema_hint: impl Into<String>) -> Self {
        Self {
            system: None,
            messages: vec![Message::user(prompt)],
            schema_hint: schema_hint.into(),
            max_tokens: DEFAULT_MAX_TOKENS,
            temperature: None,
            json_schema: None,
        }
    }

    /// Set the system instruction.
    #[must_use]
    pub fn with_system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }

    /// Set the maximum number of tokens to generate.
    #[must_use]
    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }

    /// Request an explicit sampling temperature. Only set this for a model
    /// that accepts one; current Anthropic models reject it.
    #[must_use]
    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    /// Attach a machine-readable JSON Schema for the response. See
    /// [`Self::json_schema`].
    #[must_use]
    pub fn with_json_schema(mut self, schema: serde_json::Value) -> Self {
        self.json_schema = Some(schema);
        self
    }
}

/// Token usage reported by a provider, used for budget accounting (NFR-9).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// Tokens consumed by the prompt.
    pub input_tokens: u32,
    /// Tokens produced in the completion, including any thinking.
    pub output_tokens: u32,
}

/// The result of a completion call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionResponse {
    /// The generated text.
    pub text: String,
    /// Token usage for this call.
    pub usage: Usage,
}

/// The result of a structured call: the parsed JSON plus token usage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonResponse {
    /// The parsed JSON value the model returned.
    pub value: serde_json::Value,
    /// Token usage for this call.
    pub usage: Usage,
}

/// The provider-agnostic model interface.
///
/// Implementations must be deterministic about their identity ([`Self::kind`],
/// [`Self::model`], and [`Self::cache_scope`]) because those values feed the
/// cache key. They should not perform retry, caching, or budget accounting
/// themselves; that is the job of [`crate::LlmClient`], which wraps any
/// provider. A call that fails after the provider reported token usage should
/// attach it with [`LlmError::with_usage`] so the spend is still counted.
pub trait LlmProvider {
    /// Which provider this is.
    fn kind(&self) -> ProviderKind;

    /// The model identifier this provider was constructed for.
    fn model(&self) -> &str;

    /// Everything besides the kind, the model, and the request itself that
    /// decides what the provider returns: the endpoint URL and any
    /// provider-level request options.
    ///
    /// [`crate::LlmClient`] folds this into the cache key so that responses
    /// from different endpoints or settings never alias (NFR-6). In-process
    /// providers have nothing to add and keep the default, `Value::Null`.
    fn cache_scope(&self) -> serde_json::Value {
        serde_json::Value::Null
    }

    /// Perform a plain-text completion call.
    fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, LlmError>;

    /// Perform a structured call that returns JSON (FR-30).
    ///
    /// The default implementation folds the schema hint into the prompt, asks
    /// the model for JSON only, runs an ordinary completion, and extracts the
    /// JSON object from the response. If extraction fails, the error carries
    /// the call's usage. Providers with a native structured mode may override
    /// this.
    fn complete_json(&self, request: &JsonRequest) -> Result<JsonResponse, LlmError> {
        let response = self.complete(&json_completion_request(request))?;
        json_response(response)
    }
}

/// Forward the trait through a boxed provider so a dynamically resolved
/// [`Box<dyn LlmProvider>`] (for example from [`crate::build_provider`]) can be
/// wrapped in an [`crate::LlmClient`], which is generic over `P: LlmProvider`.
impl LlmProvider for Box<dyn LlmProvider> {
    fn kind(&self) -> ProviderKind {
        (**self).kind()
    }

    fn model(&self) -> &str {
        (**self).model()
    }

    fn cache_scope(&self) -> serde_json::Value {
        (**self).cache_scope()
    }

    fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, LlmError> {
        (**self).complete(request)
    }

    fn complete_json(&self, request: &JsonRequest) -> Result<JsonResponse, LlmError> {
        (**self).complete_json(request)
    }
}

/// Build the plain completion behind a structured call: the schema hint is
/// folded into the system instruction together with a JSON-only instruction.
pub(crate) fn json_completion_request(request: &JsonRequest) -> CompletionRequest {
    let instruction = format!(
        "Respond with a single JSON value and nothing else. The JSON must match this shape: {}",
        request.schema_hint
    );
    let system = match &request.system {
        Some(existing) => format!("{existing}\n\n{instruction}"),
        None => instruction,
    };
    CompletionRequest {
        system: Some(system),
        messages: request.messages.clone(),
        max_tokens: request.max_tokens,
        temperature: request.temperature,
    }
}

/// Turn a completion into a structured response by extracting its JSON. A
/// failure keeps the completion's usage attached so the spend is counted
/// (NFR-9).
pub(crate) fn json_response(response: CompletionResponse) -> Result<JsonResponse, LlmError> {
    match extract_json(&response.text) {
        Ok(value) => Ok(JsonResponse {
            value,
            usage: response.usage,
        }),
        Err(error) => Err(error.with_usage(response.usage)),
    }
}

/// Extract a single JSON value from model output that may wrap it in prose or a
/// fenced code block.
///
/// The model is asked for JSON only, but real models sometimes add a sentence
/// or a Markdown fence, so this is forgiving, within limits:
///
/// - The whole trimmed text is tried first.
/// - Otherwise every `{` or `[` is a candidate start, scanned left to right,
///   and parsed with a streaming deserializer so trailing prose is ignored.
///   The first complete object wins. A complete array is kept only as a
///   fallback, and the scan skips past every complete value so that an object
///   nested inside it is never returned on its own.
/// - A candidate that is valid JSON up to the end of the text but never closes
///   is a truncated document. Every later candidate lies inside it, so the
///   scan stops there and never returns an inner fragment.
/// - A candidate that is not JSON (for example `{index}` in prose) is skipped
///   as a whole bracket-balanced region, so a complete object nested inside a
///   malformed document is not mistaken for the answer either. A region that
///   never balances ends the scan for the same reason as truncation.
pub(crate) fn extract_json(text: &str) -> Result<serde_json::Value, LlmError> {
    let trimmed = text.trim();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        return Ok(value);
    }

    let mut fallback: Option<serde_json::Value> = None;
    let mut first_error: Option<String> = None;
    let mut cursor = 0;
    while let Some(offset) = trimmed[cursor..].find(['{', '[']) {
        let start = cursor + offset;
        let candidate = &trimmed[start..];
        let mut stream =
            serde_json::Deserializer::from_str(candidate).into_iter::<serde_json::Value>();
        match stream.next() {
            Some(Ok(value)) => {
                if value.is_object() {
                    return Ok(value);
                }
                fallback.get_or_insert(value);
                // Skip the value's interior: anything nested in it is part of
                // this value, not a separate answer.
                cursor = start + stream.byte_offset().max(1);
            }
            Some(Err(error)) if error.is_eof() => {
                // A document starts here and runs off the end of the text.
                return fallback.ok_or_else(|| {
                    LlmError::InvalidResponse(
                        "response JSON is truncated: the document never closes".to_owned(),
                    )
                });
            }
            Some(Err(error)) => {
                first_error.get_or_insert_with(|| error.to_string());
                match balanced_extent(candidate) {
                    Some(length) => cursor = start + length,
                    // The region never balances, so later candidates would be
                    // fragments of it.
                    None => break,
                }
            }
            None => break,
        }
    }

    fallback.ok_or_else(|| match first_error {
        Some(error) => LlmError::InvalidResponse(format!("response was not valid JSON: {error}")),
        None => LlmError::InvalidResponse("response contained no JSON value".to_owned()),
    })
}

/// The byte length of the bracket-balanced region that starts at the opening
/// bracket at the beginning of `text`, skipping brackets inside JSON strings,
/// or `None` when the region never closes.
///
/// The scan is byte-wise, which is safe for UTF-8 because the ASCII bytes it
/// looks for never occur inside a multi-byte sequence.
fn balanced_extent(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in text.bytes().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_plain_json_object() {
        let value = extract_json(r#"{"a": 1}"#).expect("plain object parses");
        assert_eq!(value["a"], serde_json::json!(1));
    }

    #[test]
    fn extract_json_from_prose_and_fences() {
        let text = "Here is the answer:\n```json\n{\"name\": \"len\"}\n```\nThanks!";
        let value = extract_json(text).expect("object inside prose parses");
        assert_eq!(value["name"], serde_json::json!("len"));
    }

    #[test]
    fn extract_json_array() {
        let value = extract_json("prefix [1, 2, 3] suffix").expect("array parses");
        assert_eq!(value, serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn extract_rejects_non_json() {
        let error = extract_json("there is no json here").expect_err("must fail");
        assert!(matches!(error, LlmError::InvalidResponse(_)));
    }

    #[test]
    fn a_truncated_document_never_yields_an_inner_fragment() {
        // The outer proposal is cut off mid-array. The first field object is
        // complete on its own, but returning it would silently drop the rest of
        // the answer, so extraction must fail instead.
        let text = r#"Answer: {"fields": [{"index": 0, "name": "magic"}, {"index": 1, "name""#;
        let error = extract_json(text).expect_err("truncated JSON is refused");
        assert!(
            matches!(&error, LlmError::InvalidResponse(message) if message.contains("truncated")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_malformed_document_never_yields_an_inner_fragment() {
        // A trailing comma makes the outer object invalid; the nested object is
        // complete but is not the answer.
        let text = r#"{"fields": [1, 2,], "extra": {"index": 0}}"#;
        let error = extract_json(text).expect_err("malformed JSON is refused");
        assert!(matches!(error, LlmError::InvalidResponse(_)));
    }

    #[test]
    fn prose_braces_before_the_answer_are_skipped() {
        let text = r#"Fields use {index} and [name] keys. {"format_family": "png"}"#;
        let value = extract_json(text).expect("the object after the prose parses");
        assert_eq!(value["format_family"], serde_json::json!("png"));
    }

    #[test]
    fn a_complete_object_is_preferred_over_an_earlier_array() {
        let text = r#"Indices [0, 1] map to {"fields": []} here."#;
        let value = extract_json(text).expect("an object is present");
        assert_eq!(value, serde_json::json!({"fields": []}));
    }

    #[test]
    fn the_first_complete_object_wins_and_trailing_prose_is_ignored() {
        let text = r#"{"a": 1} and then {"b": 2} and a stray {"#;
        let value = extract_json(text).expect("first object parses");
        assert_eq!(value, serde_json::json!({"a": 1}));
    }

    #[test]
    fn objects_nested_in_an_array_are_not_returned_alone() {
        let text = r#"Here: [{"index": 0}] done"#;
        let value = extract_json(text).expect("the array is the only value");
        assert_eq!(value, serde_json::json!([{"index": 0}]));
    }

    #[test]
    fn brackets_inside_strings_do_not_confuse_the_region_scan() {
        let text = r#"{"note": "a } inside", oops} {"a": 1}"#;
        let value = extract_json(text).expect("the object after the bad one parses");
        assert_eq!(value, serde_json::json!({"a": 1}));
    }

    #[test]
    fn pathological_nesting_fails_cleanly() {
        let deep = "[".repeat(10_000);
        assert!(extract_json(&deep).is_err());
        let braces = "{".repeat(10_000);
        assert!(extract_json(&braces).is_err());
    }

    #[test]
    fn default_requests_leave_temperature_unset_and_allow_thinking_room() {
        let completion = CompletionRequest::user("hi");
        assert_eq!(completion.temperature, None);
        assert_eq!(completion.max_tokens, DEFAULT_MAX_TOKENS);
        let json = JsonRequest::new("hi", "an object");
        assert_eq!(json.temperature, None);
        assert_eq!(json.max_tokens, DEFAULT_MAX_TOKENS);
        // An unset temperature is omitted from the serialized request, which is
        // also what the cache key hashes.
        let value = serde_json::to_value(&completion).expect("serialize");
        assert!(value.get("temperature").is_none());
        let set = serde_json::to_value(CompletionRequest::user("hi").with_temperature(0.5))
            .expect("serialize");
        assert_eq!(set["temperature"], serde_json::json!(0.5));
    }

    struct TextProvider(&'static str);

    impl LlmProvider for TextProvider {
        fn kind(&self) -> ProviderKind {
            ProviderKind::Mock
        }

        fn model(&self) -> &str {
            "text"
        }

        fn complete(&self, _request: &CompletionRequest) -> Result<CompletionResponse, LlmError> {
            Ok(CompletionResponse {
                text: self.0.to_owned(),
                usage: Usage {
                    input_tokens: 7,
                    output_tokens: 3,
                },
            })
        }
    }

    #[test]
    fn a_default_structured_call_that_fails_to_parse_keeps_its_usage() {
        let error = TextProvider("no json at all")
            .complete_json(&JsonRequest::new("hi", "an object"))
            .expect_err("not JSON");
        let (inner, usage) = error.into_parts();
        assert!(matches!(inner, LlmError::InvalidResponse(_)));
        assert_eq!(
            usage,
            Some(Usage {
                input_tokens: 7,
                output_tokens: 3
            })
        );
    }
}
