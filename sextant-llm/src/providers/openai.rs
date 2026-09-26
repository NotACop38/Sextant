//! The OpenAI Chat Completions provider (FR-33, PRD Section 12).
//!
//! Compiled only with the `openai` feature. The API key comes from the caller's
//! configuration, never from a flag (FR-40).
//!
//! Requests go to `/v1/chat/completions` and bound the output with
//! `max_completion_tokens`, which also covers a reasoning model's reasoning
//! tokens. `temperature` is sent only when the caller set one, since reasoning
//! models reject it. A response is accepted only when its `finish_reason` is
//! `stop`: a `refusal`, a content filter, the token limit, a tool call, an
//! unknown or missing reason, or an empty message becomes a typed error that
//! carries the call's usage and is never cached. [`crate::JsonRequest`] JSON
//! Schemas are not sent; structured calls rely on the prose hint.

use std::time::Duration;

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use serde::{Deserialize, Serialize};

use crate::config::ProviderKind;
use crate::error::LlmError;
use crate::provider::{CompletionRequest, CompletionResponse, LlmProvider, Message, Role};
use crate::providers::http;
use crate::sanitize;

/// The default OpenAI API endpoint.
const DEFAULT_BASE_URL: &str = "https://api.openai.com";

/// A provider that talks to the OpenAI Chat Completions API.
pub struct OpenAiProvider {
    http: reqwest::blocking::Client,
    api_key: String,
    authorization: HeaderValue,
    model: String,
    base_url: String,
    timeout: Duration,
}

// A manual Debug that never prints the API key. Deriving Debug would format the
// secret in full, so any accidental `{:?}` of a provider (a log line, an error
// chain) would leak the credential (FR-40, PRD Section 16).
impl std::fmt::Debug for OpenAiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAiProvider")
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .field("timeout", &self.timeout)
            .field("api_key", &"[redacted]")
            .finish()
    }
}

impl OpenAiProvider {
    /// Build a provider for the given model with the default endpoint and
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
        let mut authorization = HeaderValue::from_str(&format!("Bearer {api_key}"))
            .ok()
            .filter(|_| !api_key.is_empty())
            .ok_or_else(|| {
                LlmError::Config(
                    "the OpenAI API key is empty or is not a valid HTTP header value".to_owned(),
                )
            })?;
        // Keeps the key out of any header debug output.
        authorization.set_sensitive(true);
        Ok(Self {
            http: http::build_client(ProviderKind::OpenAi, DEFAULT_BASE_URL)?,
            api_key,
            authorization,
            model: model.into(),
            base_url: DEFAULT_BASE_URL.to_owned(),
            timeout: http::DEFAULT_REQUEST_TIMEOUT,
        })
    }

    /// Override the base URL.
    ///
    /// # Errors
    ///
    /// Returns [`LlmError::Config`] when the URL is not `http` or `https`, has
    /// a query or fragment, or would send the API key over plain `http` to a
    /// host that is not loopback.
    pub fn with_base_url(mut self, base_url: impl AsRef<str>) -> Result<Self, LlmError> {
        let base_url = http::validate_base_url(
            ProviderKind::OpenAi,
            base_url.as_ref(),
            http::Credentials::Sent,
        )?;
        self.http = http::build_client(ProviderKind::OpenAi, &base_url)?;
        self.base_url = base_url;
        Ok(self)
    }

    /// Set the overall deadline for one HTTP attempt, from connecting until
    /// the whole response has been read. The default is five minutes.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[derive(Serialize)]
struct WireMessage {
    role: &'static str,
    content: String,
}

#[derive(Serialize)]
struct WireRequest<'a> {
    model: &'a str,
    messages: Vec<WireMessage>,
    max_completion_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

#[derive(Deserialize)]
struct WireResponse {
    #[serde(default)]
    choices: Vec<WireChoice>,
    #[serde(default)]
    usage: Option<WireUsage>,
}

#[derive(Deserialize)]
struct WireChoice {
    #[serde(default)]
    message: Option<WireChoiceMessage>,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize, Default)]
struct WireChoiceMessage {
    /// `null` when the model refused or answered with tool calls only.
    #[serde(default)]
    content: Option<String>,
    /// The model's refusal text, when it declined.
    #[serde(default)]
    refusal: Option<String>,
}

#[derive(Deserialize)]
struct WireUsage {
    #[serde(default)]
    prompt_tokens: Option<u64>,
    #[serde(default)]
    completion_tokens: Option<u64>,
}

impl WireResponse {
    /// The answer text, or a typed error when the response is not a complete,
    /// accepted answer.
    fn into_text(self) -> Result<String, LlmError> {
        let provider = ProviderKind::OpenAi;
        let Some(choice) = self.choices.into_iter().next() else {
            return Err(LlmError::EmptyResponse { provider });
        };
        let message = choice.message.unwrap_or_default();
        if let Some(refusal) = message.refusal.filter(|text| !text.trim().is_empty()) {
            return Err(LlmError::Refused {
                provider,
                category: None,
                explanation: Some(sanitize::for_display(&refusal)),
            });
        }
        match choice.finish_reason.as_deref() {
            Some("stop") => {}
            Some("length") => return Err(LlmError::Truncated { provider }),
            Some("content_filter") => {
                return Err(LlmError::Refused {
                    provider,
                    category: Some("content_filter".to_owned()),
                    explanation: None,
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
                    reason: "no finish reason".to_owned(),
                });
            }
        }
        match message.content {
            Some(text) if !text.trim().is_empty() => Ok(text),
            _ => Err(LlmError::EmptyResponse { provider }),
        }
    }
}

impl LlmProvider for OpenAiProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::OpenAi
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn cache_scope(&self) -> serde_json::Value {
        serde_json::json!({"endpoint": self.base_url})
    }

    fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, LlmError> {
        // OpenAI carries the system instruction as the first message.
        let (system, rest) = http::split_system(&request.system, &request.messages);
        let mut messages = Vec::new();
        if let Some(system) = system {
            messages.push(WireMessage {
                role: http::role_str(Role::System),
                content: system,
            });
        }
        for Message { role, content } in rest {
            messages.push(WireMessage {
                role: http::role_str(role),
                content,
            });
        }

        let body = WireRequest {
            model: &self.model,
            messages,
            max_completion_tokens: request.max_tokens,
            temperature: request.temperature,
        };
        let bytes = serde_json::to_vec(&body)
            .map_err(|error| LlmError::Serialization(error.to_string()))?;

        let builder = self
            .http
            .post(format!("{}/v1/chat/completions", self.base_url))
            .header(AUTHORIZATION, self.authorization.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(bytes);
        let response: WireResponse = http::send_json(
            builder,
            ProviderKind::OpenAi,
            Some(&self.api_key),
            self.timeout,
        )?;

        let usage = response
            .usage
            .as_ref()
            .map(|usage| http::usage(usage.prompt_tokens, usage.completion_tokens))
            .unwrap_or_default();
        match response.into_text() {
            Ok(text) => Ok(CompletionResponse { text, usage }),
            // The call was billed even though its answer is unusable.
            Err(error) => Err(error.with_usage(usage)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Usage;
    use crate::providers::fake_server::{FakeServer, Reply};

    const KEY: &str = "sk-openai-test-key-0123456789";

    fn provider(server: &FakeServer) -> OpenAiProvider {
        OpenAiProvider::new(KEY, "gpt-6-luna")
            .expect("build")
            .with_base_url(&server.base_url)
            .expect("loopback base URL")
            .with_timeout(Duration::from_secs(10))
    }

    fn completion(message: serde_json::Value, finish_reason: serde_json::Value) -> Reply {
        Reply::json(
            200,
            &serde_json::json!({
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
                "usage": {"prompt_tokens": 9, "completion_tokens": 4},
            })
            .to_string(),
        )
    }

    #[test]
    fn debug_never_reveals_the_api_key() {
        let provider = OpenAiProvider::new("sk-openai-super-secret", "gpt-6-luna").expect("build");
        let shown = format!("{provider:?}");
        assert!(
            !shown.contains("sk-openai-super-secret"),
            "key leaked: {shown}"
        );
        assert!(shown.contains("[redacted]"), "no redaction marker: {shown}");
    }

    #[test]
    fn the_request_uses_max_completion_tokens_and_omits_temperature() {
        let server = FakeServer::start(vec![
            completion(
                serde_json::json!({"role": "assistant", "content": "hello", "refusal": null}),
                serde_json::json!("stop"),
            ),
            completion(
                serde_json::json!({"role": "assistant", "content": "again"}),
                serde_json::json!("stop"),
            ),
        ]);
        let provider = provider(&server);
        let response = provider
            .complete(&CompletionRequest::user("hi").with_system("be brief"))
            .expect("completes");
        assert_eq!(response.text, "hello");
        assert_eq!(
            response.usage,
            Usage {
                input_tokens: 9,
                output_tokens: 4
            }
        );
        let request = server.next_request();
        assert_eq!(request.path, "/v1/chat/completions");
        assert_eq!(
            request.header("authorization"),
            Some(format!("Bearer {KEY}").as_str())
        );
        assert_eq!(request.header("content-type"), Some("application/json"));
        let body = request.json();
        assert_eq!(body["max_completion_tokens"], serde_json::json!(16_000));
        assert!(body.get("max_tokens").is_none(), "{body}");
        assert!(body.get("temperature").is_none(), "{body}");
        assert_eq!(body["messages"][0]["role"], serde_json::json!("system"));

        provider
            .complete(&CompletionRequest::user("hi").with_temperature(0.5))
            .expect("completes");
        assert_eq!(
            server.next_request().json()["temperature"],
            serde_json::json!(0.5)
        );
    }

    #[test]
    fn a_refusal_with_null_content_is_a_typed_error() {
        let server = FakeServer::start(vec![completion(
            serde_json::json!({"role": "assistant", "content": null, "refusal": "I can't help with that."}),
            serde_json::json!("stop"),
        )]);
        let (error, usage) = provider(&server)
            .complete(&CompletionRequest::user("hi"))
            .expect_err("refused")
            .into_parts();
        assert!(
            matches!(&error, LlmError::Refused { explanation: Some(text), .. } if text.contains("can't help")),
            "{error}"
        );
        assert_eq!(usage.map(|usage| usage.output_tokens), Some(4));
    }

    #[test]
    fn finish_reasons_other_than_stop_are_typed_errors() {
        let server = FakeServer::start(vec![
            completion(
                serde_json::json!({"content": "{\"fields\": ["}),
                serde_json::json!("length"),
            ),
            completion(
                serde_json::json!({"content": null}),
                serde_json::json!("content_filter"),
            ),
            completion(
                serde_json::json!({"content": null, "tool_calls": []}),
                serde_json::json!("tool_calls"),
            ),
            completion(serde_json::json!({"content": "x"}), serde_json::Value::Null),
            completion(
                serde_json::json!({"content": null}),
                serde_json::json!("stop"),
            ),
            Reply::json(200, r#"{"choices": [], "usage": {"prompt_tokens": 1}}"#),
        ]);
        let provider = provider(&server);
        let request = CompletionRequest::user("hi");
        let next = || {
            provider
                .complete(&request)
                .expect_err("rejected")
                .into_parts()
                .0
        };
        assert!(matches!(next(), LlmError::Truncated { .. }));
        assert!(matches!(
            next(),
            LlmError::Refused { category: Some(category), .. } if category == "content_filter"
        ));
        assert!(
            matches!(next(), LlmError::UnexpectedStop { reason, .. } if reason == "tool_calls")
        );
        assert!(matches!(next(), LlmError::UnexpectedStop { .. }));
        assert!(matches!(next(), LlmError::EmptyResponse { .. }));
        assert!(matches!(next(), LlmError::EmptyResponse { .. }));
    }

    #[test]
    fn an_error_body_is_summarized_without_the_key() {
        let server = FakeServer::start(vec![Reply::json(
            401,
            &format!(
                r#"{{"error":{{"message":"Incorrect API key provided: {KEY}.","type":"invalid_request_error","code":"invalid_api_key"}}}}"#
            ),
        )]);
        let error = provider(&server)
            .complete(&CompletionRequest::user("hi"))
            .expect_err("unauthorized");
        let shown = error.to_string();
        assert!(!shown.contains(KEY), "the key leaked: {shown}");
        assert!(
            shown.contains("Incorrect API key provided: [redacted]"),
            "{shown}"
        );
        assert!(!error.is_retryable());
    }

    #[test]
    fn plain_http_to_a_remote_host_is_refused() {
        let error = OpenAiProvider::new(KEY, "gpt-6-luna")
            .expect("build")
            .with_base_url("http://openai-proxy.example.com")
            .expect_err("refused");
        assert!(matches!(error, LlmError::Config(_)));
    }
}
