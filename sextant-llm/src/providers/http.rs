//! Shared HTTP plumbing for the network providers.
//!
//! Compiled only with the `http` feature. Keeps the per-provider modules focused
//! on their wire format by centralizing client construction, error
//! classification, and response decoding.

use std::time::Duration;

use serde::de::DeserializeOwned;

use crate::config::ProviderKind;
use crate::error::LlmError;
use crate::provider::{Message, Role};

/// Build a blocking HTTP client with a conservative timeout.
pub(crate) fn build_client(provider: ProviderKind) -> Result<reqwest::blocking::Client, LlmError> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|error| LlmError::Provider {
            provider,
            message: format!("could not build HTTP client: {error}"),
        })
}

/// Map a transport-layer error onto an [`LlmError`], marking timeouts and
/// connection failures as retryable transport errors and everything else as a
/// provider error.
pub(crate) fn classify(error: reqwest::Error, provider: ProviderKind) -> LlmError {
    if error.is_timeout() || error.is_connect() {
        LlmError::Transport(format!("{provider}: {error}"))
    } else {
        LlmError::Provider {
            provider,
            message: error.to_string(),
        }
    }
}

/// Send a prepared request, check the status, and decode the JSON body.
pub(crate) fn send<R: DeserializeOwned>(
    builder: reqwest::blocking::RequestBuilder,
    provider: ProviderKind,
) -> Result<R, LlmError> {
    let response = builder.send().map_err(|error| classify(error, provider))?;
    let status = response.status();
    if !status.is_success() {
        // A 429 or 5xx is transient and worth retrying; other statuses are not.
        let body = response.text().unwrap_or_default();
        let message = format!("HTTP {status}: {body}");
        if status.as_u16() == 429 || status.is_server_error() {
            return Err(LlmError::Transport(format!("{provider}: {message}")));
        }
        return Err(LlmError::Provider { provider, message });
    }
    response.json::<R>().map_err(|error| LlmError::Provider {
        provider,
        message: format!("could not parse response: {error}"),
    })
}

/// Map a [`Role`] onto its wire string.
pub(crate) fn role_str(role: Role) -> &'static str {
    match role {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
    }
}

/// Split a request into an optional combined system instruction and the
/// remaining user and assistant messages. Providers that carry the system
/// instruction out of band (Anthropic) use both halves; providers that accept a
/// system message inline (OpenAI, Ollama) prepend the system half as a message.
pub(crate) fn split_system(
    system: &Option<String>,
    messages: &[Message],
) -> (Option<String>, Vec<Message>) {
    let mut system_parts = Vec::new();
    if let Some(existing) = system {
        system_parts.push(existing.clone());
    }
    let mut rest = Vec::new();
    for message in messages {
        match message.role {
            Role::System => system_parts.push(message.content.clone()),
            _ => rest.push(message.clone()),
        }
    }
    let combined = if system_parts.is_empty() {
        None
    } else {
        Some(system_parts.join("\n\n"))
    };
    (combined, rest)
}
