//! The provider-agnostic model interface (PRD Section 12, FR-33).
//!
//! A single trait, [`LlmProvider`], exposes two calls: a plain-text completion
//! and a structured call that returns JSON. Every concrete provider (Anthropic,
//! OpenAI, Ollama, and the test-only mock) implements this trait, and the rest
//! of Sextant only ever talks to the trait, never to a specific provider.

use serde::{Deserialize, Serialize};

use crate::config::ProviderKind;
use crate::error::LlmError;

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
    /// The maximum number of tokens to generate.
    pub max_tokens: u32,
    /// The sampling temperature. Sextant defaults to a low value for
    /// reproducibility (PRD Section 12).
    pub temperature: f32,
}

impl CompletionRequest {
    /// A request with a single user message and Sextant's low-temperature
    /// defaults.
    pub fn user(prompt: impl Into<String>) -> Self {
        Self {
            system: None,
            messages: vec![Message::user(prompt)],
            max_tokens: 1024,
            temperature: 0.0,
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
    /// The maximum number of tokens to generate.
    pub max_tokens: u32,
    /// The sampling temperature.
    pub temperature: f32,
}

impl JsonRequest {
    /// A structured request with a single user message and a schema hint.
    pub fn new(prompt: impl Into<String>, schema_hint: impl Into<String>) -> Self {
        Self {
            system: None,
            messages: vec![Message::user(prompt)],
            schema_hint: schema_hint.into(),
            max_tokens: 1024,
            temperature: 0.0,
        }
    }

    /// Set the system instruction.
    #[must_use]
    pub fn with_system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }
}

/// Token usage reported by a provider, used for budget accounting (NFR-9).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// Tokens consumed by the prompt.
    pub input_tokens: u32,
    /// Tokens produced in the completion.
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
/// Implementations must be deterministic about their identity ([`Self::kind`]
/// and [`Self::model`]) because those values feed the cache key. They should
/// not perform retry, caching, or budget accounting themselves; that is the job
/// of [`crate::LlmClient`], which wraps any provider.
pub trait LlmProvider {
    /// Which provider this is.
    fn kind(&self) -> ProviderKind;

    /// The model identifier this provider was constructed for.
    fn model(&self) -> &str;

    /// Perform a plain-text completion call.
    fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, LlmError>;

    /// Perform a structured call that returns JSON (FR-30).
    ///
    /// The default implementation folds the schema hint into the prompt, asks
    /// the model for JSON only, runs an ordinary completion, and extracts the
    /// JSON object from the response. Providers with a native structured mode
    /// may override this.
    fn complete_json(&self, request: &JsonRequest) -> Result<JsonResponse, LlmError> {
        let instruction = format!(
            "Respond with a single JSON value and nothing else. The JSON must match this shape: {}",
            request.schema_hint
        );
        let system = match &request.system {
            Some(existing) => format!("{existing}\n\n{instruction}"),
            None => instruction,
        };
        let completion = CompletionRequest {
            system: Some(system),
            messages: request.messages.clone(),
            max_tokens: request.max_tokens,
            temperature: request.temperature,
        };
        let response = self.complete(&completion)?;
        let value = extract_json(&response.text)?;
        Ok(JsonResponse {
            value,
            usage: response.usage,
        })
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

    fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, LlmError> {
        (**self).complete(request)
    }

    fn complete_json(&self, request: &JsonRequest) -> Result<JsonResponse, LlmError> {
        (**self).complete_json(request)
    }
}

/// Extract a single JSON value from model output that may wrap it in prose or a
/// fenced code block.
///
/// The model is asked for JSON only, but real models sometimes add a sentence
/// or a Markdown fence, so this is forgiving: it parses the whole string first
/// and, failing that, the substring between the first opening and last closing
/// brace or bracket.
fn extract_json(text: &str) -> Result<serde_json::Value, LlmError> {
    let trimmed = text.trim();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        return Ok(value);
    }

    let object = slice_between(trimmed, '{', '}');
    let array = slice_between(trimmed, '[', ']');
    // Prefer whichever delimited region starts first in the text.
    let candidate = match (object, array) {
        (Some(o), Some(a)) => {
            if o.as_ptr() <= a.as_ptr() {
                Some(o)
            } else {
                Some(a)
            }
        }
        (Some(o), None) => Some(o),
        (None, Some(a)) => Some(a),
        (None, None) => None,
    };

    match candidate {
        Some(slice) => serde_json::from_str(slice).map_err(|error| {
            LlmError::InvalidResponse(format!("response was not valid JSON: {error}"))
        }),
        None => Err(LlmError::InvalidResponse(
            "response contained no JSON value".to_string(),
        )),
    }
}

/// Return the substring from the first `open` to the matching last `close`,
/// inclusive, or `None` if either is absent.
fn slice_between(text: &str, open: char, close: char) -> Option<&str> {
    let start = text.find(open)?;
    let end = text.rfind(close)?;
    if end > start {
        Some(&text[start..=end])
    } else {
        None
    }
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
}
