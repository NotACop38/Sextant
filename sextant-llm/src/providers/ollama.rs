//! The optional local Ollama provider (PRD Section 12).
//!
//! Compiled only with the `ollama` feature. Ollama needs no API key; the server
//! host is read from configuration (the `OLLAMA_HOST` variable), never from a
//! flag (FR-40). Only `http` and `https` URLs are accepted; the default when
//! the variable is unset at the factory layer is a localhost URL.

use serde::{Deserialize, Serialize};

use crate::config::ProviderKind;
use crate::error::LlmError;
use crate::provider::{CompletionRequest, CompletionResponse, LlmProvider, Message, Role, Usage};
use crate::providers::http;

/// Default Ollama base URL when configuration supplies a bare intent without a
/// full URL. Prefers loopback so a misconfigured environment does not quietly
/// send prompts to a remote host.
pub const DEFAULT_OLLAMA_HOST: &str = "http://127.0.0.1:11434";

/// A provider that talks to a local or remote Ollama server.
#[derive(Debug)]
pub struct OllamaProvider {
    http: reqwest::blocking::Client,
    model: String,
    base_url: String,
}

impl OllamaProvider {
    /// Build a provider for the given model against the Ollama server at
    /// `host`. The host comes from configuration, not from a flag (FR-40).
    ///
    /// # Errors
    ///
    /// Returns [`LlmError::Provider`] when `host` is not an `http` or `https`
    /// URL (after normalizing a host-only value to `http://...`).
    pub fn new(host: impl Into<String>, model: impl Into<String>) -> Result<Self, LlmError> {
        let base_url = normalize_ollama_host(&host.into())?;
        Ok(Self {
            http: http::build_client(ProviderKind::Ollama)?,
            model: model.into(),
            base_url,
        })
    }
}

/// Accept only http/https Ollama endpoints. A bare `host:port` is treated as
/// `http://host:port`. Other schemes (file, gopher, etc.) are rejected.
fn normalize_ollama_host(host: &str) -> Result<String, LlmError> {
    let trimmed = host.trim().trim_end_matches('/');
    let candidate = if trimmed.contains("://") {
        trimmed.to_owned()
    } else if trimmed.is_empty() {
        DEFAULT_OLLAMA_HOST.to_owned()
    } else {
        format!("http://{trimmed}")
    };
    let ok = candidate.starts_with("http://") || candidate.starts_with("https://");
    if !ok {
        return Err(LlmError::Provider {
            provider: ProviderKind::Ollama,
            message: format!(
                "OLLAMA_HOST must be an http or https URL (got `{trimmed}`); \
                 default is {DEFAULT_OLLAMA_HOST}"
            ),
        });
    }
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_http_schemes() {
        let error = normalize_ollama_host("file:///tmp/ollama").expect_err("scheme");
        assert!(matches!(error, LlmError::Provider { .. }));
    }

    #[test]
    fn accepts_https_and_bare_host() {
        assert_eq!(
            normalize_ollama_host("https://ollama.example:11434/").expect("https"),
            "https://ollama.example:11434"
        );
        assert_eq!(
            normalize_ollama_host("127.0.0.1:11434").expect("bare"),
            "http://127.0.0.1:11434"
        );
    }
}

#[derive(Serialize)]
struct WireMessage {
    role: &'static str,
    content: String,
}

#[derive(Serialize)]
struct WireOptions {
    temperature: f32,
    num_predict: u32,
}

#[derive(Serialize)]
struct WireRequest {
    model: String,
    messages: Vec<WireMessage>,
    stream: bool,
    options: WireOptions,
}

#[derive(Deserialize)]
struct WireResponse {
    #[serde(default)]
    message: WireResponseMessage,
    #[serde(default)]
    prompt_eval_count: u32,
    #[serde(default)]
    eval_count: u32,
}

#[derive(Deserialize, Default)]
struct WireResponseMessage {
    #[serde(default)]
    content: String,
}

impl LlmProvider for OllamaProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Ollama
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, LlmError> {
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
            stream: false,
            options: WireOptions {
                temperature: request.temperature,
                num_predict: request.max_tokens,
            },
        };

        let url = format!("{}/api/chat", self.base_url);
        let builder = self.http.post(url).json(&body);
        let response: WireResponse = http::send(builder, ProviderKind::Ollama)?;

        Ok(CompletionResponse {
            text: response.message.content,
            usage: Usage {
                input_tokens: response.prompt_eval_count,
                output_tokens: response.eval_count,
            },
        })
    }
}
