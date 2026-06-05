//! The OpenAI chat-completions provider (FR-33, PRD Section 12).
//!
//! Compiled only with the `openai` feature. The API key comes from the caller's
//! configuration, never from a flag (FR-40).

use serde::{Deserialize, Serialize};

use crate::config::ProviderKind;
use crate::error::LlmError;
use crate::provider::{CompletionRequest, CompletionResponse, LlmProvider, Message, Role, Usage};
use crate::providers::http;

/// The default OpenAI API endpoint.
const DEFAULT_BASE_URL: &str = "https://api.openai.com";

/// A provider that talks to the OpenAI chat-completions API.
pub struct OpenAiProvider {
    http: reqwest::blocking::Client,
    api_key: String,
    model: String,
    base_url: String,
}

// A manual Debug that never prints the API key. Deriving Debug would format the
// secret in full, so any accidental `{:?}` of a provider (a log line, an error
// chain) would leak the credential (FR-40, PRD Section 16).
impl std::fmt::Debug for OpenAiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAiProvider")
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .field("api_key", &"[redacted]")
            .finish()
    }
}

impl OpenAiProvider {
    /// Build a provider for the given model. The API key comes from the caller's
    /// configuration, not from a flag (FR-40).
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self, LlmError> {
        Ok(Self {
            http: http::build_client(ProviderKind::OpenAi)?,
            api_key: api_key.into(),
            model: model.into(),
            base_url: DEFAULT_BASE_URL.to_string(),
        })
    }

    /// Override the base URL.
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
    messages: Vec<WireMessage>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Deserialize)]
struct WireResponse {
    #[serde(default)]
    choices: Vec<WireChoice>,
    #[serde(default)]
    usage: WireUsage,
}

#[derive(Deserialize)]
struct WireChoice {
    #[serde(default)]
    message: WireChoiceMessage,
}

#[derive(Deserialize, Default)]
struct WireChoiceMessage {
    #[serde(default)]
    content: String,
}

#[derive(Deserialize, Default)]
struct WireUsage {
    #[serde(default)]
    prompt_tokens: u32,
    #[serde(default)]
    completion_tokens: u32,
}

impl LlmProvider for OpenAiProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::OpenAi
    }

    fn model(&self) -> &str {
        &self.model
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
            model: self.model.clone(),
            messages,
            max_tokens: request.max_tokens,
            temperature: request.temperature,
        };

        let url = format!("{}/v1/chat/completions", self.base_url);
        let builder = self.http.post(url).bearer_auth(&self.api_key).json(&body);
        let response: WireResponse = http::send(builder, ProviderKind::OpenAi)?;

        let text = response
            .choices
            .into_iter()
            .next()
            .map(|choice| choice.message.content)
            .unwrap_or_default();
        Ok(CompletionResponse {
            text,
            usage: Usage {
                input_tokens: response.usage.prompt_tokens,
                output_tokens: response.usage.completion_tokens,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_reveals_the_api_key() {
        let provider = OpenAiProvider::new("sk-openai-super-secret", "gpt-4o-mini").expect("build");
        let shown = format!("{provider:?}");
        assert!(
            !shown.contains("sk-openai-super-secret"),
            "key leaked: {shown}"
        );
        assert!(shown.contains("[redacted]"), "no redaction marker: {shown}");
    }
}
