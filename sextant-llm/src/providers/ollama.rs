//! The optional local Ollama provider (PRD Section 12).
//!
//! Compiled only with the `ollama` feature. Ollama needs no API key; the server
//! host is read from configuration (the `OLLAMA_HOST` variable), never from a
//! flag (FR-40). Only `http` and `https` URLs are accepted. When the variable
//! is unset or blank the host is [`DEFAULT_OLLAMA_HOST`], a bare host without a
//! port gets Ollama's port 11434, and the bind-all addresses `0.0.0.0` and `::`
//! (which configure a server to listen everywhere, not a place to connect to)
//! are reached over loopback. A loopback host is contacted directly, never
//! through a proxy.
//!
//! Ollama has no default model, since a local server only serves the models
//! its owner pulled; see [`crate::ProviderKind::model_env_var`].

use std::net::Ipv6Addr;
use std::time::Duration;

use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};

use crate::config::ProviderKind;
use crate::error::LlmError;
use crate::provider::{CompletionRequest, CompletionResponse, LlmProvider, Message, Role};
use crate::providers::http;
use crate::sanitize;

/// The Ollama base URL used when `OLLAMA_HOST` is unset or blank. Loopback, so a
/// misconfigured environment does not quietly send prompts to a remote host.
pub const DEFAULT_OLLAMA_HOST: &str = "http://127.0.0.1:11434";

/// The port Ollama listens on by default, applied to a bare host.
const DEFAULT_OLLAMA_PORT: u16 = 11434;

/// A provider that talks to a local or remote Ollama server.
#[derive(Debug)]
pub struct OllamaProvider {
    http: reqwest::blocking::Client,
    model: String,
    base_url: String,
    timeout: Duration,
}

impl OllamaProvider {
    /// Build a provider for the given model against the Ollama server at
    /// `host`. The host comes from configuration, not from a flag (FR-40). An
    /// empty `host` means [`DEFAULT_OLLAMA_HOST`].
    ///
    /// # Errors
    ///
    /// Returns [`LlmError::Config`] when `host` is not an `http` or `https`
    /// URL or a `host[:port]` value, and [`LlmError::Provider`] when the HTTP
    /// client cannot be built.
    pub fn new(host: impl Into<String>, model: impl Into<String>) -> Result<Self, LlmError> {
        let base_url = normalize_ollama_host(&host.into())?;
        Ok(Self {
            http: http::build_client(ProviderKind::Ollama, &base_url)?,
            model: model.into(),
            base_url,
            timeout: http::DEFAULT_REQUEST_TIMEOUT,
        })
    }

    /// Set the overall deadline for one HTTP attempt, from connecting until
    /// the whole response has been read. The default is five minutes; a large
    /// local model may need longer.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Normalize an `OLLAMA_HOST` value into a base URL without a trailing slash.
///
/// An empty value is [`DEFAULT_OLLAMA_HOST`]. A value without a scheme is
/// `http`, and gets port 11434 when it names none (`:1234` alone means
/// loopback on that port). A full URL keeps its own port, or the scheme's
/// default when it names none. `0.0.0.0` and `::` become their loopback
/// counterparts.
fn normalize_ollama_host(raw: &str) -> Result<String, LlmError> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Ok(DEFAULT_OLLAMA_HOST.to_owned());
    }
    let candidate = if trimmed.contains("://") {
        trimmed.to_owned()
    } else {
        with_default_port(trimmed)?
    };
    let mut url = reqwest::Url::parse(&candidate).map_err(|error| invalid_host(trimmed, &error))?;
    let loopback = match url.host_str() {
        Some("0.0.0.0") => Some("127.0.0.1"),
        Some("[::]") => Some("[::1]"),
        _ => None,
    };
    if let Some(loopback) = loopback {
        url.set_host(Some(loopback))
            .map_err(|error| invalid_host(trimmed, &error))?;
    }
    http::validate_base_url(
        ProviderKind::Ollama,
        url.as_str(),
        http::Credentials::NotSent,
    )
}

/// Turn a scheme-less `host[:port][/path]` into an `http` URL with Ollama's
/// default port when none is given.
fn with_default_port(value: &str) -> Result<String, LlmError> {
    let (authority, path) = value.split_at(value.find('/').unwrap_or(value.len()));
    let (host, port) =
        split_host_port(authority).ok_or_else(|| invalid_host(value, &"bad host or port"))?;
    let host = if host.is_empty() {
        "127.0.0.1".to_owned()
    } else {
        host
    };
    Ok(format!(
        "http://{host}:{}{path}",
        port.unwrap_or(DEFAULT_OLLAMA_PORT)
    ))
}

/// Split `host[:port]`, accepting bracketed and bare IPv6 addresses. Returns
/// `None` for a malformed value or a port outside 1 to 65535.
fn split_host_port(authority: &str) -> Option<(String, Option<u16>)> {
    let port = |text: &str| text.parse::<u16>().ok().filter(|port| *port != 0);
    if let Some(rest) = authority.strip_prefix('[') {
        let (address, after) = rest.split_once(']')?;
        let host = format!("[{address}]");
        return match after.strip_prefix(':') {
            Some(text) => Some((host, Some(port(text)?))),
            None if after.is_empty() => Some((host, None)),
            None => None,
        };
    }
    match authority.matches(':').count() {
        0 => Some((authority.to_owned(), None)),
        1 => {
            let (host, text) = authority.split_once(':')?;
            Some((host.to_owned(), Some(port(text)?)))
        }
        // More than one colon without brackets can only be a bare IPv6 address.
        _ => authority
            .parse::<Ipv6Addr>()
            .ok()
            .map(|_| (format!("[{authority}]"), None)),
    }
}

fn invalid_host(value: &str, error: &dyn std::fmt::Display) -> LlmError {
    LlmError::Config(format!(
        "OLLAMA_HOST must be an http or https URL or a host[:port] (got `{}`: {error}); the \
         default is {DEFAULT_OLLAMA_HOST}",
        sanitize::for_display(value)
    ))
}

#[derive(Serialize)]
struct WireMessage {
    role: &'static str,
    content: String,
}

#[derive(Serialize)]
struct WireOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    num_predict: u32,
}

#[derive(Serialize)]
struct WireRequest<'a> {
    model: &'a str,
    messages: Vec<WireMessage>,
    stream: bool,
    options: WireOptions,
}

#[derive(Deserialize)]
struct WireResponse {
    #[serde(default)]
    message: Option<WireResponseMessage>,
    /// Why generation ended (`stop`, or `length` at the token limit). Older
    /// servers omit it.
    #[serde(default)]
    done_reason: Option<String>,
    #[serde(default)]
    prompt_eval_count: Option<u64>,
    #[serde(default)]
    eval_count: Option<u64>,
}

#[derive(Deserialize, Default)]
struct WireResponseMessage {
    #[serde(default)]
    content: Option<String>,
}

impl WireResponse {
    /// The answer text, or a typed error for a cut-off or empty response.
    fn into_text(self) -> Result<String, LlmError> {
        let provider = ProviderKind::Ollama;
        if self.done_reason.as_deref() == Some("length") {
            return Err(LlmError::Truncated { provider });
        }
        match self.message.and_then(|message| message.content) {
            Some(text) if !text.trim().is_empty() => Ok(text),
            _ => Err(LlmError::EmptyResponse { provider }),
        }
    }
}

impl LlmProvider for OllamaProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Ollama
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn cache_scope(&self) -> serde_json::Value {
        serde_json::json!({"endpoint": self.base_url})
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
            model: &self.model,
            messages,
            stream: false,
            options: WireOptions {
                temperature: request.temperature,
                num_predict: request.max_tokens,
            },
        };
        let bytes = serde_json::to_vec(&body)
            .map_err(|error| LlmError::Serialization(error.to_string()))?;

        let builder = self
            .http
            .post(format!("{}/api/chat", self.base_url))
            .header(CONTENT_TYPE, "application/json")
            .body(bytes);
        let response: WireResponse =
            http::send_json(builder, ProviderKind::Ollama, None, self.timeout)?;

        let usage = http::usage(response.prompt_eval_count, response.eval_count);
        match response.into_text() {
            Ok(text) => Ok(CompletionResponse { text, usage }),
            Err(error) => Err(error.with_usage(usage)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::fake_server::{FakeServer, Reply};

    #[test]
    fn rejects_non_http_schemes() {
        let error = normalize_ollama_host("file:///tmp/ollama").expect_err("scheme");
        assert!(matches!(error, LlmError::Config(_)));
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

    #[test]
    fn bare_hosts_get_the_default_port_and_bind_all_means_loopback() {
        for (raw, expected) in [
            ("", DEFAULT_OLLAMA_HOST),
            ("   ", DEFAULT_OLLAMA_HOST),
            ("0.0.0.0", "http://127.0.0.1:11434"),
            ("0.0.0.0:9999", "http://127.0.0.1:9999"),
            ("http://0.0.0.0:11434", "http://127.0.0.1:11434"),
            ("localhost", "http://localhost:11434"),
            ("gpu.example.com", "http://gpu.example.com:11434"),
            ("gpu.example.com:8080", "http://gpu.example.com:8080"),
            (":5555", "http://127.0.0.1:5555"),
            ("[::1]", "http://[::1]:11434"),
            ("::1", "http://[::1]:11434"),
            ("[::]", "http://[::1]:11434"),
            ("[::1]:8000", "http://[::1]:8000"),
            // A full URL keeps the scheme's own default port, as Ollama does.
            ("http://gpu.example.com", "http://gpu.example.com"),
            (
                "gpu.example.com/ollama/",
                "http://gpu.example.com:11434/ollama",
            ),
        ] {
            assert_eq!(
                normalize_ollama_host(raw).expect(raw),
                expected,
                "OLLAMA_HOST={raw:?}"
            );
        }
    }

    #[test]
    fn malformed_hosts_are_refused() {
        for raw in [
            "gpu.example.com:notaport",
            "gpu.example.com:0",
            "gpu.example.com:99999",
            "[::1",
            "[::1]x",
            "a:b:c",
            "http://",
            "gpu.example.com?x=1",
        ] {
            assert!(
                matches!(normalize_ollama_host(raw), Err(LlmError::Config(_))),
                "OLLAMA_HOST={raw:?} was accepted"
            );
        }
    }

    fn chat(content: &str, done_reason: Option<&str>) -> Reply {
        Reply::json(
            200,
            &serde_json::json!({
                "model": "qwen3",
                "message": {"role": "assistant", "content": content},
                "done": true,
                "done_reason": done_reason,
                "prompt_eval_count": 8,
                "eval_count": 3,
            })
            .to_string(),
        )
    }

    fn provider(server: &FakeServer) -> OllamaProvider {
        OllamaProvider::new(server.base_url.as_str(), "qwen3")
            .expect("build")
            .with_timeout(Duration::from_secs(10))
    }

    #[test]
    fn the_request_omits_an_unset_temperature() {
        let server = FakeServer::start(vec![chat("hello", Some("stop"))]);
        let response = provider(&server)
            .complete(&CompletionRequest::user("hi"))
            .expect("completes");
        assert_eq!(response.text, "hello");
        let request = server.next_request();
        assert_eq!(request.path, "/api/chat");
        let body = request.json();
        assert_eq!(body["stream"], serde_json::json!(false));
        assert_eq!(body["options"]["num_predict"], serde_json::json!(16_000));
        assert!(body["options"].get("temperature").is_none(), "{body}");
    }

    #[test]
    fn a_length_stop_or_empty_answer_is_a_typed_error() {
        let server =
            FakeServer::start(vec![chat("{\"fields\": [", Some("length")), chat("", None)]);
        let provider = provider(&server);
        let (error, usage) = provider
            .complete(&CompletionRequest::user("hi"))
            .expect_err("cut off")
            .into_parts();
        assert!(matches!(error, LlmError::Truncated { .. }), "{error}");
        assert_eq!(usage.map(|usage| usage.output_tokens), Some(3));
        let (error, _) = provider
            .complete(&CompletionRequest::user("hi"))
            .expect_err("empty")
            .into_parts();
        assert!(matches!(error, LlmError::EmptyResponse { .. }), "{error}");
    }

    #[test]
    fn an_error_body_yields_the_server_message() {
        let server = FakeServer::start(vec![Reply::json(
            404,
            r#"{"error":"model 'qwen3' not found, try pulling it first"}"#,
        )]);
        let error = provider(&server)
            .complete(&CompletionRequest::user("hi"))
            .expect_err("missing model");
        assert!(
            matches!(&error, LlmError::HttpStatus { status: 404, message, .. } if message.contains("try pulling")),
            "{error}"
        );
        assert!(!error.is_retryable());
    }
}
