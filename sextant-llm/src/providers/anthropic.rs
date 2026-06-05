//! The Anthropic Messages API provider (FR-33, PRD Section 12).
//!
//! Compiled only with the `anthropic` feature. The API key is supplied by the
//! caller, which reads it from the environment or configuration, never from a
//! flag (FR-40).

use serde::{Deserialize, Serialize};

use crate::config::ProviderKind;
use crate::error::LlmError;
use crate::provider::{CompletionRequest, CompletionResponse, LlmProvider, Usage};
use crate::providers::http;

/// The default Anthropic Messages API endpoint.
const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
/// The Messages API version header value.
const API_VERSION: &str = "2023-06-01";

/// A provider that talks to the Anthropic Messages API.
#[derive(Debug)]
pub struct AnthropicProvider {
    http: reqwest::blocking::Client,
    api_key: String,
    model: String,
    base_url: String,
}

impl AnthropicProvider {
    /// Build a provider for the given model. The API key comes from the caller's
    /// configuration, not from a flag (FR-40).
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self, LlmError> {
        Ok(Self {
            http: http::build_client(ProviderKind::Anthropic)?,
            api_key: api_key.into(),
            model: model.into(),
            base_url: DEFAULT_BASE_URL.to_string(),
        })
    }

    /// Override the base URL (used by integration setups that proxy the API).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }
}

#[derive(Serialize)]
struct WireMessage {
    role: &'static str,
    content: String,
}

#[derive(Serialize)]
struct WireRequest {
    model: String,
    max_tokens: u32,
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    messages: Vec<WireMessage>,
}

#[derive(Deserialize)]
struct WireResponse {
    #[serde(default)]
    content: Vec<WireContentBlock>,
    #[serde(default)]
    usage: WireUsage,
}

#[derive(Deserialize)]
struct WireContentBlock {
    #[serde(default)]
    text: String,
}

#[derive(Deserialize, Default)]
struct WireUsage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
}

impl LlmProvider for AnthropicProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Anthropic
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, LlmError> {
        let (system, messages) = http::split_system(&request.system, &request.messages);
        let body = WireRequest {
            model: self.model.clone(),
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
        };

        let url = format!("{}/v1/messages", self.base_url);
        let builder = self
            .http
            .post(url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", API_VERSION)
            .json(&body);
        let response: WireResponse = http::send(builder, ProviderKind::Anthropic)?;

        let text = response
            .content
            .into_iter()
            .map(|block| block.text)
            .collect::<Vec<_>>()
            .join("");
        Ok(CompletionResponse {
            text,
            usage: Usage {
                input_tokens: response.usage.input_tokens,
                output_tokens: response.usage.output_tokens,
            },
        })
    }
}
