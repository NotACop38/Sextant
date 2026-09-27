//! The Anthropic Messages API provider (FR-33, PRD Section 12).
//!
//! Compiled only with the `anthropic` feature. The API key is supplied by the
//! caller, which reads it from the environment or configuration, never from a
//! flag (FR-40).
//!
//! # Request shape
//!
//! Current Claude models think before answering by default, reject sampling
//! parameters such as `temperature` with HTTP 400, and count thinking against
//! `max_tokens`. Requests therefore never send a `thinking` field, send
//! `temperature` only when the caller set one explicitly, and use a default
//! token cap with room for thinking plus the answer
//! ([`crate::DEFAULT_MAX_TOKENS`]).
//!
//! By default the provider leaves the effort level (`output_config.effort`)
//! to the model, since not every model accepts one; [`Effort`] sets it
//! explicitly. It opts into server-side refusal fallbacks (`fallbacks:
//! "default"` with the `server-side-fallback-2026-07-01` beta), so a request
//! the first model declines can be re-run on another Anthropic model within
//! the same call. A model or platform that rejects the fallbacks parameter
//! with HTTP 400 gets the same request once more without it, so the default
//! works everywhere. Both are configurable. A structured call whose
//! [`JsonRequest`] carries a JSON Schema is sent as structured output
//! (`output_config.format`), which enforces the shape, so the prose JSON-only
//! instruction and schema hint are folded into the system prompt only when no
//! schema can be sent.
//!
//! # Responses
//!
//! Only `text` content blocks carry the answer; thinking and fallback blocks
//! are ignored. A response is accepted only when it ended with `end_turn` or
//! `stop_sequence`. Hitting the token limit, a refusal, a paused turn, a tool
//! call, an unknown or missing stop reason, or a response without text becomes
//! a typed error that carries the call's token usage and is never cached.

use std::str::FromStr;
use std::time::Duration;

use reqwest::header::{CONTENT_TYPE, HeaderValue};
use serde::{Deserialize, Serialize};

use crate::config::ProviderKind;
use crate::error::LlmError;
use crate::provider::{
    self, CompletionRequest, CompletionResponse, JsonRequest, JsonResponse, LlmProvider, Usage,
};
use crate::providers::http;
use crate::sanitize;

/// The default Anthropic Messages API endpoint.
const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
/// The Messages API version header value.
const API_VERSION: &str = "2023-06-01";
/// The beta flag that enables `fallbacks: "default"`.
const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";
/// The deepest schema nesting that is rewritten for structured output.
const MAX_SCHEMA_DEPTH: usize = 64;

/// How much effort the model spends on thinking and answering, sent as
/// `output_config.effort`. Lower effort is faster and cheaper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effort {
    /// The least thinking; suited to small, well-specified tasks.
    Low,
    /// A balance of depth and cost.
    Medium,
    /// Deep thinking.
    High,
    /// Deeper than `high`.
    XHigh,
    /// The most thinking the model will do.
    Max,
}

impl Effort {
    /// The wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Effort::Low => "low",
            Effort::Medium => "medium",
            Effort::High => "high",
            Effort::XHigh => "xhigh",
            Effort::Max => "max",
        }
    }

    /// Parse the [`crate::ANTHROPIC_EFFORT_ENV`] setting: an effort level, or
    /// `off` (also `none`) to leave effort out of the request.
    ///
    /// # Errors
    ///
    /// Returns [`LlmError::Config`] for any other value.
    pub fn parse_setting(value: &str) -> Result<Option<Self>, LlmError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "none" => Ok(None),
            other => other.parse().map(Some),
        }
    }
}

impl FromStr for Effort {
    type Err = LlmError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" => Ok(Effort::Low),
            "medium" => Ok(Effort::Medium),
            "high" => Ok(Effort::High),
            "xhigh" => Ok(Effort::XHigh),
            "max" => Ok(Effort::Max),
            _ => Err(LlmError::Config(format!(
                "{} must be one of low, medium, high, xhigh, max, or off (got `{}`)",
                crate::config::ANTHROPIC_EFFORT_ENV,
                sanitize::for_display(value)
            ))),
        }
    }
}

/// A provider that talks to the Anthropic Messages API.
pub struct AnthropicProvider {
    http: reqwest::blocking::Client,
    api_key: String,
    api_key_header: HeaderValue,
    model: String,
    base_url: String,
    effort: Option<Effort>,
    fallbacks: bool,
    timeout: Duration,
}

// A manual Debug that never prints the API key. Deriving Debug would format the
// secret in full, so any accidental `{:?}` of a provider (a log line, an error
// chain) would leak the credential (FR-40, PRD Section 16).
impl std::fmt::Debug for AnthropicProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnthropicProvider")
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .field("effort", &self.effort)
            .field("fallbacks", &self.fallbacks)
            .field("timeout", &self.timeout)
            .field("api_key", &"[redacted]")
            .finish()
    }
}

impl AnthropicProvider {
    /// Build a provider for the given model with the default endpoint, the
    /// model's own default effort, refusal fallbacks on, and the default
    /// request timeout. The API key comes from the caller's configuration, not
    /// from a flag (FR-40).
    ///
    /// # Errors
    ///
    /// Returns [`LlmError::Config`] when the key is empty or contains
    /// characters that cannot appear in an HTTP header, and
    /// [`LlmError::Provider`] when the HTTP client cannot be built.
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self, LlmError> {
        let api_key = api_key.into().trim().to_owned();
        let mut api_key_header = HeaderValue::from_str(&api_key)
            .ok()
            .filter(|_| !api_key.is_empty())
            .ok_or_else(|| {
                LlmError::Config(
                    "the Anthropic API key is empty or is not a valid HTTP header value".to_owned(),
                )
            })?;
        // Keeps the key out of any header debug output.
        api_key_header.set_sensitive(true);
        Ok(Self {
            http: http::build_client(ProviderKind::Anthropic, DEFAULT_BASE_URL)?,
            api_key,
            api_key_header,
            model: model.into(),
            base_url: DEFAULT_BASE_URL.to_owned(),
            effort: None,
            fallbacks: true,
            timeout: http::DEFAULT_REQUEST_TIMEOUT,
        })
    }

    /// Override the base URL (used by integration setups that proxy the API).
    ///
    /// # Errors
    ///
    /// Returns [`LlmError::Config`] when the URL is not `http` or `https`, has
    /// a query or fragment, or would send the API key over plain `http` to a
    /// host that is not loopback.
    pub fn with_base_url(mut self, base_url: impl AsRef<str>) -> Result<Self, LlmError> {
        let base_url = http::validate_base_url(
            ProviderKind::Anthropic,
            base_url.as_ref(),
            http::Credentials::Sent,
        )?;
        self.http = http::build_client(ProviderKind::Anthropic, &base_url)?;
        self.base_url = base_url;
        Ok(self)
    }

    /// Set the effort level, or `None` to leave `output_config.effort` out
    /// (for a model that does not support effort).
    #[must_use]
    pub fn with_effort(mut self, effort: Option<Effort>) -> Self {
        self.effort = effort;
        self
    }

    /// Turn server-side refusal fallbacks on or off.
    #[must_use]
    pub fn with_fallbacks(mut self, enabled: bool) -> Self {
        self.fallbacks = enabled;
        self
    }

    /// Set the overall deadline for one HTTP attempt, from connecting until
    /// the whole response has been read. The default is five minutes.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send one Messages API request, optionally constrained to a JSON Schema.
    fn send(
        &self,
        request: &CompletionRequest,
        schema: Option<serde_json::Value>,
    ) -> Result<CompletionResponse, LlmError> {
        let response = match self.post(request, schema.clone(), self.fallbacks) {
            // A model or platform without server-side fallbacks rejects the
            // parameter before generating anything, so nothing was billed:
            // send the same request once more without it.
            Err(LlmError::HttpStatus {
                status: 400,
                message,
                ..
            }) if self.fallbacks && message.to_ascii_lowercase().contains("fallback") => {
                self.post(request, schema, false)?
            }
            other => other?,
        };

        let usage = response.usage.total();
        match response.into_text() {
            Ok(text) => Ok(CompletionResponse { text, usage }),
            // The call was billed even though its answer is unusable.
            Err(error) => Err(error.with_usage(usage)),
        }
    }

    /// Post one Messages API request body, with or without refusal fallbacks.
    fn post(
        &self,
        request: &CompletionRequest,
        schema: Option<serde_json::Value>,
        fallbacks: bool,
    ) -> Result<WireResponse, LlmError> {
        let (system, messages) = http::split_system(&request.system, &request.messages);
        let output_config = (self.effort.is_some() || schema.is_some()).then(|| WireOutputConfig {
            effort: self.effort.map(Effort::as_str),
            format: schema.map(|schema| WireFormat {
                kind: "json_schema",
                schema,
            }),
        });
        let body = WireRequest {
            model: &self.model,
            max_tokens: request.max_tokens,
            temperature: request.temperature,
            system,
            messages: messages
                .into_iter()
                .map(|message| WireMessage {
                    role: http::role_str(message.role),
                    content: message.content,
                })
                .collect(),
            output_config,
            fallbacks: fallbacks.then_some("default"),
        };
        let bytes = serde_json::to_vec(&body)
            .map_err(|error| LlmError::Serialization(error.to_string()))?;

        let mut builder = self
            .http
            .post(format!("{}/v1/messages", self.base_url))
            .header("x-api-key", self.api_key_header.clone())
            .header("anthropic-version", API_VERSION)
            .header(CONTENT_TYPE, "application/json");
        if fallbacks {
            builder = builder.header("anthropic-beta", FALLBACK_BETA);
        }
        http::send_json(
            builder.body(bytes),
            ProviderKind::Anthropic,
            Some(&self.api_key),
            self.timeout,
        )
    }
}

/// Prepare a caller's JSON Schema for structured output: every object schema
/// must forbid unknown properties, so `additionalProperties: false` is added
/// where it is missing. Returns `None`, which falls back to the prose hint,
/// when the root is not an object schema, some object explicitly allows extra
/// properties, or the schema is nested too deeply.
fn closed_schema(schema: &serde_json::Value) -> Option<serde_json::Value> {
    let is_object_root = schema.get("type").and_then(serde_json::Value::as_str) == Some("object");
    if !is_object_root {
        return None;
    }
    let mut copy = schema.clone();
    close_objects(&mut copy, 0).then_some(copy)
}

/// Recursively close every object schema under `node`. Returns `false` when
/// the schema cannot be closed without changing its meaning.
fn close_objects(node: &mut serde_json::Value, depth: usize) -> bool {
    use serde_json::Value;
    if depth > MAX_SCHEMA_DEPTH {
        return false;
    }
    let Some(map) = node.as_object_mut() else {
        // A boolean schema has nothing to close.
        return true;
    };
    let is_object_schema = match map.get("type") {
        Some(Value::String(kind)) => kind == "object",
        Some(Value::Array(kinds)) => kinds.iter().any(|kind| kind.as_str() == Some("object")),
        _ => map.contains_key("properties"),
    };
    if is_object_schema {
        match map.get("additionalProperties") {
            None => {
                map.insert("additionalProperties".to_owned(), Value::Bool(false));
            }
            Some(Value::Bool(false)) => {}
            Some(_) => return false,
        }
    }
    for key in ["properties", "patternProperties", "$defs", "definitions"] {
        if let Some(Value::Object(children)) = map.get_mut(key) {
            if !children
                .values_mut()
                .all(|child| close_objects(child, depth + 1))
            {
                return false;
            }
        }
    }
    for key in ["items", "not", "if", "then", "else", "contains"] {
        match map.get_mut(key) {
            Some(Value::Array(children)) => {
                if !children
                    .iter_mut()
                    .all(|child| close_objects(child, depth + 1))
                {
                    return false;
                }
            }
            Some(child) => {
                if !close_objects(child, depth + 1) {
                    return false;
                }
            }
            None => {}
        }
    }
    for key in ["anyOf", "allOf", "oneOf", "prefixItems"] {
        if let Some(Value::Array(children)) = map.get_mut(key) {
            if !children
                .iter_mut()
                .all(|child| close_objects(child, depth + 1))
            {
                return false;
            }
        }
    }
    true
}

#[derive(Serialize)]
struct WireMessage {
    role: &'static str,
    content: String,
}

#[derive(Serialize)]
struct WireRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    messages: Vec<WireMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_config: Option<WireOutputConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fallbacks: Option<&'static str>,
}

#[derive(Serialize)]
struct WireOutputConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    effort: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<WireFormat>,
}

#[derive(Serialize)]
struct WireFormat {
    #[serde(rename = "type")]
    kind: &'static str,
    schema: serde_json::Value,
}

#[derive(Deserialize)]
struct WireResponse {
    #[serde(default)]
    content: Vec<WireContentBlock>,
    #[serde(default)]
    stop_reason: Option<String>,
    #[serde(default)]
    stop_details: Option<serde_json::Value>,
    #[serde(default)]
    usage: WireUsage,
}

#[derive(Deserialize)]
struct WireContentBlock {
    #[serde(rename = "type", default)]
    kind: String,
    // Kept loosely typed so an unfamiliar block type cannot fail the parse.
    #[serde(default)]
    text: Option<serde_json::Value>,
}

#[derive(Deserialize, Default)]
struct WireUsage {
    #[serde(default)]
    input_tokens: Option<u64>,
    #[serde(default)]
    output_tokens: Option<u64>,
    /// Per-attempt usage. With refusal fallbacks, the top-level counts cover
    /// only the attempt that produced the returned message, while these cover
    /// every attempt, including a declined one.
    #[serde(default)]
    iterations: Option<Vec<WireIteration>>,
}

#[derive(Deserialize)]
struct WireIteration {
    #[serde(default)]
    input_tokens: Option<u64>,
    #[serde(default)]
    output_tokens: Option<u64>,
}

impl WireUsage {
    /// The usage to account: the larger of the top-level counts and the sum
    /// over every attempt, so a fallback never hides the declined attempt's
    /// spend.
    fn total(&self) -> Usage {
        let mut input = 0u64;
        let mut output = 0u64;
        for iteration in self.iterations.iter().flatten() {
            input = input.saturating_add(iteration.input_tokens.unwrap_or(0));
            output = output.saturating_add(iteration.output_tokens.unwrap_or(0));
        }
        http::usage(
            Some(input.max(self.input_tokens.unwrap_or(0))),
            Some(output.max(self.output_tokens.unwrap_or(0))),
        )
    }
}

impl WireResponse {
    /// The answer text, or a typed error when the response is not a complete,
    /// accepted answer.
    fn into_text(self) -> Result<String, LlmError> {
        let provider = ProviderKind::Anthropic;
        match self.stop_reason.as_deref() {
            Some("end_turn" | "stop_sequence") => {}
            Some("max_tokens" | "model_context_window_exceeded") => {
                return Err(LlmError::Truncated { provider });
            }
            Some("refusal") => {
                let detail = |key: &str| {
                    self.stop_details
                        .as_ref()
                        .and_then(|details| details.get(key))
                        .and_then(serde_json::Value::as_str)
                        .map(sanitize::for_display)
                        .filter(|text| !text.is_empty())
                };
                return Err(LlmError::Refused {
                    provider,
                    category: detail("category"),
                    explanation: detail("explanation"),
                });
            }
            Some(other) => {
                return Err(LlmError::UnexpectedStop {
                    provider,
                    reason: sanitize::for_display(other),
                });
            }
            None => {
                return Err(LlmError::UnexpectedStop {
                    provider,
                    reason: "no stop reason".to_owned(),
                });
            }
        }
        let text: String = self
            .content
            .iter()
            .filter(|block| block.kind == "text")
            .filter_map(|block| block.text.as_ref().and_then(serde_json::Value::as_str))
            .collect();
        if text.trim().is_empty() {
            return Err(LlmError::EmptyResponse { provider });
        }
        Ok(text)
    }
}

impl LlmProvider for AnthropicProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Anthropic
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn cache_scope(&self) -> serde_json::Value {
        serde_json::json!({
            "endpoint": self.base_url,
            "api_version": API_VERSION,
            "effort": self.effort.map(Effort::as_str),
            "fallbacks": self.fallbacks,
        })
    }

    fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, LlmError> {
        self.send(request, None)
    }

    fn complete_json(&self, request: &JsonRequest) -> Result<JsonResponse, LlmError> {
        let schema = request.json_schema.as_ref().and_then(closed_schema);
        // Structured output enforces the schema, so the prose JSON-only
        // instruction and hint are sent only when there is no schema.
        let completion = if schema.is_some() {
            CompletionRequest {
                system: request.system.clone(),
                messages: request.messages.clone(),
                max_tokens: request.max_tokens,
                temperature: request.temperature,
            }
        } else {
            provider::json_completion_request(request)
        };
        let response = self.send(&completion, schema)?;
        provider::json_response(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::ResponseCache;
    use crate::client::{Backoff, LlmClient, Pricing};
    use crate::providers::fake_server::{FakeServer, Reply};

    const KEY: &str = "sk-ant-test-key-0123456789";

    fn provider(server: &FakeServer) -> AnthropicProvider {
        AnthropicProvider::new(KEY, "claude-opus-5")
            .expect("build")
            .with_base_url(&server.base_url)
            .expect("loopback base URL")
            .with_timeout(Duration::from_secs(10))
    }

    fn message(stop_reason: &str, content: serde_json::Value) -> Reply {
        Reply::json(
            200,
            &serde_json::json!({
                "id": "msg_test",
                "type": "message",
                "role": "assistant",
                "model": "claude-opus-5",
                "content": content,
                "stop_reason": stop_reason,
                "stop_details": null,
                "usage": {"input_tokens": 12, "output_tokens": 34},
            })
            .to_string(),
        )
    }

    fn answer(text: &str) -> Reply {
        message(
            "end_turn",
            serde_json::json!([
                {"type": "thinking", "thinking": "", "signature": "sig"},
                {"type": "text", "text": text},
            ]),
        )
    }

    #[test]
    fn debug_never_reveals_the_api_key() {
        let provider =
            AnthropicProvider::new("sk-ant-super-secret", "claude-opus-5").expect("build");
        let shown = format!("{provider:?}");
        assert!(
            !shown.contains("sk-ant-super-secret"),
            "key leaked: {shown}"
        );
        assert!(shown.contains("[redacted]"), "no redaction marker: {shown}");
    }

    #[test]
    fn the_request_omits_sampling_thinking_and_effort_and_opts_into_fallbacks() {
        let server = FakeServer::start(vec![answer("hello")]);
        let response = provider(&server)
            .complete(&CompletionRequest::user("hi").with_system("be brief"))
            .expect("completes");
        // Only the text block is the answer; the thinking block is ignored.
        assert_eq!(response.text, "hello");
        assert_eq!(
            response.usage,
            Usage {
                input_tokens: 12,
                output_tokens: 34
            }
        );

        let request = server.next_request();
        assert_eq!(request.path, "/v1/messages");
        assert_eq!(request.header("x-api-key"), Some(KEY));
        assert_eq!(request.header("anthropic-version"), Some("2023-06-01"));
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(
            request.header("anthropic-beta"),
            Some("server-side-fallback-2026-07-01")
        );
        let body = request.json();
        assert_eq!(body["model"], serde_json::json!("claude-opus-5"));
        assert_eq!(body["max_tokens"], serde_json::json!(16_000));
        assert_eq!(body["system"], serde_json::json!("be brief"));
        assert_eq!(body["fallbacks"], serde_json::json!("default"));
        // Effort is left to the model, since not every model accepts it.
        for absent in ["temperature", "top_p", "top_k", "thinking", "output_config"] {
            assert!(body.get(absent).is_none(), "{absent} was sent: {body}");
        }
    }

    #[test]
    fn an_explicit_temperature_is_sent_and_options_can_be_turned_off() {
        let server = FakeServer::start(vec![answer("ok")]);
        provider(&server)
            .with_effort(None)
            .with_fallbacks(false)
            .complete(&CompletionRequest::user("hi").with_temperature(0.25))
            .expect("completes");
        let request = server.next_request();
        assert_eq!(request.header("anthropic-beta"), None);
        let body = request.json();
        assert_eq!(body["temperature"], serde_json::json!(0.25));
        assert!(body.get("output_config").is_none(), "{body}");
        assert!(body.get("fallbacks").is_none(), "{body}");
    }

    #[test]
    fn an_explicit_effort_is_sent() {
        let server = FakeServer::start(vec![answer("ok")]);
        provider(&server)
            .with_effort(Some(Effort::Medium))
            .complete(&CompletionRequest::user("hi"))
            .expect("completes");
        let body = server.next_request().json();
        assert_eq!(
            body["output_config"],
            serde_json::json!({"effort": "medium"})
        );
    }

    #[test]
    fn rejected_fallbacks_are_dropped_and_the_request_is_sent_once_more() {
        let rejection = Reply::json(
            400,
            &serde_json::json!({
                "type": "error",
                "error": {
                    "type": "invalid_request_error",
                    "message": "fallbacks: this model does not support server-side fallbacks"
                }
            })
            .to_string(),
        );
        let server = FakeServer::start(vec![rejection, answer("ok")]);
        let response = provider(&server)
            .complete(&CompletionRequest::user("hi"))
            .expect("the retry without fallbacks answers");
        assert_eq!(response.text, "ok");

        let first = server.next_request();
        assert_eq!(first.json()["fallbacks"], serde_json::json!("default"));
        let second = server.next_request();
        assert_eq!(second.header("anthropic-beta"), None);
        assert!(second.json().get("fallbacks").is_none());
    }

    #[test]
    fn an_unrelated_bad_request_is_not_retried() {
        let rejection = Reply::json(
            400,
            &serde_json::json!({
                "type": "error",
                "error": {"type": "invalid_request_error", "message": "max_tokens: too large"}
            })
            .to_string(),
        );
        let server = FakeServer::start(vec![rejection]);
        let error = provider(&server)
            .complete(&CompletionRequest::user("hi"))
            .expect_err("a bad request fails");
        assert!(
            matches!(error, LlmError::HttpStatus { status: 400, .. }),
            "{error:?}"
        );
    }

    #[test]
    fn a_json_schema_is_sent_as_structured_output_with_closed_objects() {
        let server = FakeServer::start(vec![answer(r#"{"fields": [{"index": 0}]}"#)]);
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "fields": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"index": {"type": "integer"}},
                        "required": ["index"]
                    }
                }
            },
            "required": ["fields"]
        });
        let response = provider(&server)
            .complete_json(&JsonRequest::new("annotate", "a proposal").with_json_schema(schema))
            .expect("structured call");
        assert_eq!(response.value["fields"][0]["index"], serde_json::json!(0));

        let body = server.next_request().json();
        let config = &body["output_config"];
        assert!(config.get("effort").is_none(), "{config}");
        assert_eq!(config["format"]["type"], serde_json::json!("json_schema"));
        let sent = &config["format"]["schema"];
        assert_eq!(sent["additionalProperties"], serde_json::json!(false));
        assert_eq!(
            sent["properties"]["fields"]["items"]["additionalProperties"],
            serde_json::json!(false)
        );
        // The schema is enforced, so neither the prose hint nor the JSON-only
        // instruction reaches the prompt.
        assert!(body.get("system").is_none(), "{body}");
    }

    #[test]
    fn a_structured_call_keeps_the_callers_system_prompt() {
        let server = FakeServer::start(vec![answer(r#"{"fields": []}"#)]);
        let schema = serde_json::json!({
            "type": "object",
            "properties": {"fields": {"type": "array"}},
            "required": ["fields"]
        });
        provider(&server)
            .complete_json(
                &JsonRequest::new("annotate", "a proposal")
                    .with_system("be precise")
                    .with_json_schema(schema),
            )
            .expect("structured call");
        let body = server.next_request().json();
        assert_eq!(body["system"], serde_json::json!("be precise"));
    }

    #[test]
    fn a_schema_that_allows_extra_properties_falls_back_to_the_hint() {
        let server = FakeServer::start(vec![answer(r#"{"a": 1}"#)]);
        let open = serde_json::json!({
            "type": "object",
            "properties": {"a": {"type": "integer"}},
            "additionalProperties": true
        });
        provider(&server)
            .complete_json(&JsonRequest::new("x", "an object").with_json_schema(open))
            .expect("structured call");
        let body = server.next_request().json();
        assert!(body["output_config"].get("format").is_none(), "{body}");
        // Without an enforced schema, the prose hint carries the shape.
        assert!(
            body["system"]
                .as_str()
                .is_some_and(|system| system.contains("an object")),
            "{body}"
        );
        assert!(closed_schema(&serde_json::json!({"type": "array"})).is_none());
    }

    #[test]
    fn truncation_refusal_and_other_stops_are_typed_errors_with_usage() {
        let server = FakeServer::start(vec![
            message(
                "max_tokens",
                serde_json::json!([{"type": "text", "text": "{\"fields\": ["}]),
            ),
            Reply::json(
                200,
                &serde_json::json!({
                    "content": [],
                    "stop_reason": "refusal",
                    "stop_details": {"type": "refusal", "category": "cyber", "explanation": "declined\u{1b}[0m"},
                    "usage": {"input_tokens": 5, "output_tokens": 0},
                })
                .to_string(),
            ),
            message("pause_turn", serde_json::json!([{"type": "text", "text": "x"}])),
            message("tool_use", serde_json::json!([{"type": "tool_use", "id": "t", "name": "n", "input": {}}])),
            message("something_new", serde_json::json!([{"type": "text", "text": "x"}])),
            message("end_turn", serde_json::json!([{"type": "thinking", "thinking": ""}])),
        ]);
        let provider = provider(&server);
        let request = CompletionRequest::user("hi");

        let (error, usage) = provider
            .complete(&request)
            .expect_err("truncated")
            .into_parts();
        assert!(matches!(error, LlmError::Truncated { .. }), "{error}");
        assert_eq!(
            usage,
            Some(Usage {
                input_tokens: 12,
                output_tokens: 34
            })
        );

        let (error, usage) = provider
            .complete(&request)
            .expect_err("refused")
            .into_parts();
        match &error {
            LlmError::Refused {
                category,
                explanation,
                ..
            } => {
                assert_eq!(category.as_deref(), Some("cyber"));
                assert_eq!(explanation.as_deref(), Some("declined [0m"));
            }
            other => panic!("expected a refusal, got {other}"),
        }
        assert_eq!(usage.map(|usage| usage.input_tokens), Some(5));

        for expected in ["pause_turn", "tool_use", "something_new"] {
            let (error, _) = provider
                .complete(&request)
                .expect_err(expected)
                .into_parts();
            assert!(
                matches!(&error, LlmError::UnexpectedStop { reason, .. } if reason == expected),
                "{expected}: {error}"
            );
        }

        let (error, _) = provider
            .complete(&request)
            .expect_err("no text")
            .into_parts();
        assert!(matches!(error, LlmError::EmptyResponse { .. }), "{error}");
    }

    #[test]
    fn a_rejected_response_is_accounted_and_never_cached() {
        let dir = std::env::temp_dir().join(format!(
            "sextant-llm-anthropic-cache-{}",
            std::process::id()
        ));
        let server = FakeServer::start(vec![
            message(
                "max_tokens",
                serde_json::json!([{"type": "text", "text": "{"}]),
            ),
            answer(r#"{"ok": true}"#),
        ]);
        let client = LlmClient::new(provider(&server))
            .with_cache(ResponseCache::new(&dir))
            .with_backoff(Backoff::none())
            .with_pricing(Pricing {
                input_per_1k: 1.0,
                output_per_1k: 1.0,
            });
        let request = JsonRequest::new("hi", "an object");
        let error = client.complete_json(&request).expect_err("truncated");
        assert!(matches!(error, LlmError::Truncated { .. }), "{error}");
        assert!(client.spent() > 0.0, "the truncated call's spend was lost");
        // The identical request is sent again rather than served a cached
        // truncation, and the good answer is then cached.
        let response = client.complete_json(&request).expect("second attempt");
        assert_eq!(response.value, serde_json::json!({"ok": true}));
        assert_eq!(client.calls_made(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fallback_usage_counts_every_attempt() {
        let server = FakeServer::start(vec![Reply::json(
            200,
            &serde_json::json!({
                "model": "claude-opus-4-8",
                "content": [
                    {"type": "fallback", "from": {"model": "claude-opus-5"}, "to": {"model": "claude-opus-4-8"}},
                    {"type": "text", "text": "answer"}
                ],
                "stop_reason": "end_turn",
                "usage": {
                    "input_tokens": 100,
                    "output_tokens": 20,
                    "iterations": [
                        {"type": "message", "input_tokens": 100, "output_tokens": 7},
                        {"type": "fallback_message", "input_tokens": 100, "output_tokens": 20}
                    ]
                },
            })
            .to_string(),
        )]);
        let response = provider(&server)
            .complete(&CompletionRequest::user("hi"))
            .expect("the fallback answered");
        assert_eq!(response.text, "answer");
        assert_eq!(
            response.usage,
            Usage {
                input_tokens: 200,
                output_tokens: 27
            }
        );
    }

    #[test]
    fn an_error_body_is_summarized_without_the_key() {
        let server = FakeServer::start(vec![Reply::Json {
            status: 401,
            headers: vec![("x-should-retry", "false".to_owned())],
            body: format!(
                r#"{{"type":"error","error":{{"type":"authentication_error","message":"invalid x-api-key {KEY}"}}}}"#
            ),
        }]);
        // Through a client that would retry a transient failure: the provider
        // said not to, so exactly one request is made.
        let client = LlmClient::new(provider(&server)).with_backoff(Backoff {
            max_retries: 3,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            max_total_delay: Duration::from_secs(5),
        });
        let error = client
            .complete(&CompletionRequest::user("hi"))
            .expect_err("unauthorized");
        let shown = error.to_string();
        assert!(!shown.contains(KEY), "the key leaked: {shown}");
        assert!(shown.contains("authentication_error"), "{shown}");
        assert!(!error.is_retryable());
        server.next_request();
        assert_eq!(server.count_more(Duration::from_millis(200)), 0);
    }

    #[test]
    fn overloaded_responses_are_retried_after_the_requested_delay() {
        let server = FakeServer::start(vec![
            Reply::Json {
                status: 529,
                headers: vec![("retry-after-ms", "30".to_owned())],
                body:
                    r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#
                        .to_owned(),
            },
            answer("recovered"),
        ]);
        let client = LlmClient::new(provider(&server)).with_backoff(Backoff {
            max_retries: 2,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            max_total_delay: Duration::from_secs(5),
        });
        let response = client
            .complete(&CompletionRequest::user("hi"))
            .expect("retried");
        assert_eq!(response.text, "recovered");
        server.next_request();
        server.next_request();
    }

    #[test]
    fn plain_http_to_a_remote_host_is_refused() {
        let error = AnthropicProvider::new(KEY, "claude-opus-5")
            .expect("build")
            .with_base_url("http://anthropic-proxy.example.com")
            .expect_err("refused");
        assert!(matches!(error, LlmError::Config(_)));
        assert!(!error.to_string().contains(KEY));
    }

    #[test]
    fn an_unusable_key_is_refused_at_construction() {
        for bad in ["", "   ", "sk-ant\nInjected: header"] {
            assert!(
                matches!(
                    AnthropicProvider::new(bad, "claude-opus-5"),
                    Err(LlmError::Config(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn effort_settings_parse() {
        assert_eq!(
            Effort::parse_setting("LOW").expect("low"),
            Some(Effort::Low)
        );
        assert_eq!(
            Effort::parse_setting("xhigh").expect("xhigh"),
            Some(Effort::XHigh)
        );
        assert_eq!(Effort::parse_setting("off").expect("off"), None);
        assert!(Effort::parse_setting("turbo").is_err());
    }

    #[test]
    fn deeply_nested_schemas_fall_back_to_the_hint() {
        let mut schema = serde_json::json!({"type": "object"});
        for _ in 0..(MAX_SCHEMA_DEPTH + 2) {
            schema = serde_json::json!({"type": "object", "properties": {"inner": schema}});
        }
        assert!(closed_schema(&schema).is_none());
    }
}
