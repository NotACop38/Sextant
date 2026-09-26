//! Shared HTTP plumbing for the network providers.
//!
//! Compiled only with the `http` feature. Keeps the per-provider modules focused
//! on their wire format by centralizing endpoint validation, client
//! construction, deadlines, error classification, and response decoding.

use std::io::Read as _;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::HeaderMap;
use serde::de::DeserializeOwned;

use crate::client::MAX_RETRY_AFTER;
use crate::config::ProviderKind;
use crate::error::LlmError;
use crate::provider::{Message, Role, Usage};
use crate::sanitize;

/// Cap on a single provider response body so a hostile or misconfigured server
/// cannot force an unbounded allocation into the process (FR-24).
pub(crate) const MAX_RESPONSE_BODY_BYTES: usize = 4 << 20;

/// Cap on how much of an error response body is read to extract its message.
const MAX_ERROR_BODY_BYTES: usize = 64 << 10;

/// The default overall deadline for one HTTP attempt, from connecting until the
/// whole response body has been read. Current models think before answering,
/// so a generous bound avoids cutting off a long but healthy answer.
pub(crate) const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// The deadline for establishing a connection. The overall deadline still
/// applies on top of it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether a provider authenticates every request with a secret, which decides
/// whether a plain `http` endpoint is acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Credentials {
    /// Requests carry an API key, so plain `http` is refused unless the host
    /// is loopback. Unused in a build with only the Ollama provider.
    #[cfg_attr(not(any(feature = "anthropic", feature = "openai")), allow(dead_code))]
    Sent,
    /// Requests carry no secret (Ollama).
    NotSent,
}

/// Validate and normalize a provider base URL.
///
/// The URL must be `http` or `https`, name a host, and carry no query or
/// fragment (the API path is appended to it). A provider that sends an API key
/// may use plain `http` only for a loopback host, so a key is never sent in
/// the clear over a network. The result has no trailing slash.
pub(crate) fn validate_base_url(
    provider: ProviderKind,
    raw: &str,
    credentials: Credentials,
) -> Result<String, LlmError> {
    // The raw value is never echoed: a mistyped URL can hold credentials.
    let url = reqwest::Url::parse(raw.trim()).map_err(|error| {
        LlmError::Config(format!(
            "the {provider} base URL is not a valid URL: {error}"
        ))
    })?;
    let host = url.host_str().unwrap_or_default();
    if host.is_empty() {
        return Err(LlmError::Config(format!(
            "the {provider} base URL has no host"
        )));
    }
    match url.scheme() {
        "https" => {}
        "http" if credentials == Credentials::NotSent || is_loopback(&url) => {}
        "http" => {
            return Err(LlmError::Config(format!(
                "refusing to send the {provider} API key over plain http to {}; use an https URL \
                 or a loopback address",
                sanitize::for_display(host)
            )));
        }
        other => {
            return Err(LlmError::Config(format!(
                "the {provider} base URL must use http or https, not `{}`",
                sanitize::for_display(other)
            )));
        }
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(LlmError::Config(format!(
            "the {provider} base URL must not contain a query or fragment"
        )));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

/// Whether `url` points at this machine: `localhost`, an IPv4 loopback address
/// (`127.0.0.0/8`), or the IPv6 loopback address in plain or IPv4-mapped form.
pub(crate) fn is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let bare = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    if bare.eq_ignore_ascii_case("localhost") || bare.eq_ignore_ascii_case("localhost.") {
        return true;
    }
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        Err(_) => false,
    }
}

/// Build a blocking HTTP client for `base_url` with a connect timeout and no
/// redirects.
///
/// Redirects are disabled so a compromised or unexpected endpoint cannot bounce
/// credentials onto a different host. Proxies are disabled entirely for a
/// loopback endpoint, so a local server (typically Ollama) is reached directly
/// instead of being sent through `HTTP_PROXY` to another machine. Other
/// endpoints honor the usual proxy environment variables.
pub(crate) fn build_client(provider: ProviderKind, base_url: &str) -> Result<Client, LlmError> {
    let direct = reqwest::Url::parse(base_url).is_ok_and(|url| is_loopback(&url));
    let mut builder = Client::builder()
        .timeout(DEFAULT_REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if direct {
        builder = builder.no_proxy();
    }
    builder.build().map_err(|error| LlmError::Provider {
        provider,
        message: format!("could not build HTTP client: {error}"),
    })
}

/// Map a transport-layer error onto an [`LlmError`].
///
/// Connection failures, timeouts, and failures while sending or receiving are
/// retryable [`LlmError::Transport`] errors. A request that could not be built
/// is a non-retryable [`LlmError::Provider`] error. The URL is left out of the
/// message and the text is sanitized, with `secret` redacted.
pub(crate) fn classify(
    error: reqwest::Error,
    provider: ProviderKind,
    secret: Option<&str>,
) -> LlmError {
    let what = if error.is_timeout() {
        "the request timed out"
    } else if error.is_connect() {
        "could not connect"
    } else {
        "the request failed"
    };
    let final_error = error.is_builder() || error.is_redirect() || error.is_status();
    let detail = sanitize::message(&describe_chain(&error.without_url()), secret);
    if final_error {
        LlmError::Provider {
            provider,
            message: format!("{what}: {detail}"),
        }
    } else {
        LlmError::Transport(format!("{provider}: {what}: {detail}"))
    }
}

/// An error and its sources joined into one line, a few levels deep.
fn describe_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    for _ in 0..4 {
        let Some(inner) = source else { break };
        let part = inner.to_string();
        if !text.contains(&part) {
            text.push_str(": ");
            text.push_str(&part);
        }
        source = inner.source();
    }
    text
}

/// Send a prepared request under one overall deadline, check the status, and
/// decode the JSON body.
///
/// `timeout` bounds the whole attempt, connecting and reading the full body
/// included, rather than each read separately, so a server that trickles
/// bytes cannot hold a call open indefinitely. A non-success status becomes
/// [`LlmError::HttpStatus`] carrying the provider's sanitized error message,
/// whether a retry may help, and any requested retry delay. `secret` is
/// redacted from every message.
pub(crate) fn send_json<R: DeserializeOwned>(
    builder: RequestBuilder,
    provider: ProviderKind,
    secret: Option<&str>,
    timeout: Duration,
) -> Result<R, LlmError> {
    let deadline = Instant::now().checked_add(timeout);
    // A per-request timeout in reqwest is a total deadline that also covers
    // the body; the read loop below enforces it once more.
    let response = builder
        .timeout(timeout)
        .send()
        .map_err(|error| classify(error, provider, secret))?;
    let status = response.status();
    if !status.is_success() {
        let retryable = should_retry(status.as_u16(), response.headers());
        let retry_after = retry_after(response.headers());
        let (body, _) = read_limited(response, MAX_ERROR_BODY_BYTES, deadline);
        return Err(LlmError::HttpStatus {
            provider,
            status: status.as_u16(),
            message: error_message(&body, secret),
            retryable,
            retry_after,
        });
    }
    let (body, end) = read_limited(response, MAX_RESPONSE_BODY_BYTES, deadline);
    match end {
        ReadEnd::Complete => {}
        ReadEnd::OverLimit => {
            return Err(LlmError::Provider {
                provider,
                message: format!("response body exceeds the {MAX_RESPONSE_BODY_BYTES}-byte cap"),
            });
        }
        ReadEnd::TimedOut => {
            return Err(LlmError::Transport(format!(
                "{provider}: the response was not complete within {} seconds",
                timeout.as_secs_f64()
            )));
        }
        ReadEnd::Failed(error) => {
            return Err(LlmError::Transport(format!(
                "{provider}: reading the response failed: {}",
                sanitize::message(&describe_chain(&error), secret)
            )));
        }
    }
    serde_json::from_slice(&body).map_err(|error| LlmError::Provider {
        provider,
        message: format!("could not parse response: {error}"),
    })
}

/// How reading a body ended.
enum ReadEnd {
    /// The whole body was read.
    Complete,
    /// The body is longer than the limit; only the limit was kept.
    OverLimit,
    /// The overall deadline passed first.
    TimedOut,
    /// The connection failed mid-body.
    Failed(std::io::Error),
}

/// Read at most `limit` bytes of the body, stopping at the deadline.
fn read_limited(
    mut response: Response,
    limit: usize,
    deadline: Option<Instant>,
) -> (Vec<u8>, ReadEnd) {
    let past_deadline = || deadline.is_some_and(|deadline| Instant::now() >= deadline);
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if past_deadline() {
            return (bytes, ReadEnd::TimedOut);
        }
        match response.read(&mut chunk) {
            Ok(0) => return (bytes, ReadEnd::Complete),
            Ok(read) => {
                let room = limit - bytes.len();
                if read > room {
                    bytes.extend_from_slice(&chunk[..room]);
                    return (bytes, ReadEnd::OverLimit);
                }
                bytes.extend_from_slice(&chunk[..read]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) if past_deadline() => return (bytes, ReadEnd::TimedOut),
            Err(error) => return (bytes, ReadEnd::Failed(error)),
        }
    }
}

/// Whether a failed status is worth retrying. The provider's `x-should-retry`
/// header wins when it is `true` or `false`; otherwise 408, 409, 429, and 5xx
/// (which includes 529, overloaded) are retryable.
fn should_retry(status: u16, headers: &HeaderMap) -> bool {
    let hint = headers
        .get("x-should-retry")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    match hint {
        Some(value) if value.eq_ignore_ascii_case("true") => true,
        Some(value) if value.eq_ignore_ascii_case("false") => false,
        _ => matches!(status, 408 | 409 | 429 | 500..=599),
    }
}

/// The delay a provider requested in `retry-after-ms` (milliseconds) or
/// `retry-after` (seconds), capped at [`MAX_RETRY_AFTER`]. A date-valued,
/// zero, negative, or unparseable header yields `None`, which leaves the
/// client's own backoff in charge.
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let number = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<f64>().ok())
    };
    number("retry-after-ms")
        .and_then(|millis| positive_seconds(millis / 1000.0))
        .or_else(|| number("retry-after").and_then(positive_seconds))
}

/// A strictly positive, finite number of seconds as a capped duration.
fn positive_seconds(seconds: f64) -> Option<Duration> {
    if !seconds.is_finite() || seconds <= 0.0 {
        return None;
    }
    Duration::try_from_secs_f64(seconds.min(MAX_RETRY_AFTER.as_secs_f64())).ok()
}

/// A short, safe message for an error response body.
///
/// Provider JSON errors (`{"error": {"type": ..., "message": ...}}` from
/// Anthropic and OpenAI, `{"error": "..."}` from Ollama) yield their message
/// rather than the raw body. The result is sanitized, truncated, and has
/// `secret` redacted, so an echoed key or a terminal escape sequence never
/// reaches the user's screen.
fn error_message(body: &[u8], secret: Option<&str>) -> String {
    let text = String::from_utf8_lossy(body);
    let extracted = serde_json::from_str::<serde_json::Value>(text.trim())
        .ok()
        .and_then(|value| provider_error_message(&value));
    let raw = match extracted {
        Some(message) => message,
        None if text.trim().is_empty() => "(empty response body)".to_owned(),
        None => text.into_owned(),
    };
    sanitize::message(&raw, secret)
}

/// The message inside a provider's JSON error body, if it has the usual shape.
fn provider_error_message(value: &serde_json::Value) -> Option<String> {
    match value.get("error")? {
        serde_json::Value::Object(error) => {
            let message = error.get("message").and_then(serde_json::Value::as_str)?;
            match error.get("type").and_then(serde_json::Value::as_str) {
                Some(kind) if !kind.is_empty() => Some(format!("{kind}: {message}")),
                _ => Some(message.to_owned()),
            }
        }
        serde_json::Value::String(message) => Some(message.clone()),
        _ => None,
    }
}

/// Convert a wire token count to the crate's `u32` counts, saturating.
pub(crate) fn tokens(count: u64) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// Build a [`Usage`] from wire token counts, treating absent counts as zero.
pub(crate) fn usage(input: Option<u64>, output: Option<u64>) -> Usage {
    Usage {
        input_tokens: tokens(input.unwrap_or(0)),
        output_tokens: tokens(output.unwrap_or(0)),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::fake_server::{FakeServer, Reply};
    use reqwest::header::HeaderValue;

    fn url(text: &str) -> reqwest::Url {
        reqwest::Url::parse(text).expect("valid URL")
    }

    #[test]
    fn loopback_detection_covers_names_and_addresses() {
        for loopback in [
            "http://localhost:11434",
            "http://LOCALHOST",
            "http://127.0.0.1:8080",
            "http://127.3.4.5",
            "http://[::1]:11434",
            "http://[::ffff:127.0.0.1]",
        ] {
            assert!(is_loopback(&url(loopback)), "{loopback}");
        }
        for remote in [
            "http://example.com",
            "http://10.0.0.1",
            "http://[2001:db8::1]",
            "http://localhost.example.com",
            "http://0.0.0.0",
        ] {
            assert!(!is_loopback(&url(remote)), "{remote}");
        }
    }

    #[test]
    fn a_keyed_provider_refuses_plain_http_to_a_remote_host() {
        let error = validate_base_url(
            ProviderKind::Anthropic,
            "http://api.example.com",
            Credentials::Sent,
        )
        .expect_err("plain http with a key");
        assert!(matches!(error, LlmError::Config(message) if message.contains("plain http")));
        assert_eq!(
            validate_base_url(
                ProviderKind::Anthropic,
                "http://127.0.0.1:9/",
                Credentials::Sent
            )
            .expect("loopback http is fine"),
            "http://127.0.0.1:9"
        );
        assert_eq!(
            validate_base_url(
                ProviderKind::Anthropic,
                "https://proxy.example.com/anthropic/",
                Credentials::Sent
            )
            .expect("https is fine"),
            "https://proxy.example.com/anthropic"
        );
        // A provider without a key may use plain http anywhere.
        assert!(
            validate_base_url(
                ProviderKind::Ollama,
                "http://gpu.example.com:11434",
                Credentials::NotSent
            )
            .is_ok()
        );
    }

    #[test]
    fn unusable_base_urls_are_refused_without_echoing_them() {
        for bad in [
            "ftp://example.com",
            "file:///etc/passwd",
            "https://example.com/?key=sk-secret",
            "https://example.com/#frag",
            "not a url sk-secret",
        ] {
            let error =
                validate_base_url(ProviderKind::OpenAi, bad, Credentials::Sent).expect_err(bad);
            let shown = error.to_string();
            assert!(matches!(error, LlmError::Config(_)), "{bad}: {shown}");
            assert!(!shown.contains("sk-secret"), "{bad}: {shown}");
        }
    }

    #[test]
    fn retry_hints_follow_the_header_then_the_status() {
        let mut headers = HeaderMap::new();
        for (status, expected) in [
            (408, true),
            (409, true),
            (429, true),
            (500, true),
            (529, true),
            (599, true),
            (400, false),
            (401, false),
            (404, false),
            (413, false),
        ] {
            assert_eq!(should_retry(status, &headers), expected, "{status}");
        }
        headers.insert("x-should-retry", HeaderValue::from_static("false"));
        assert!(!should_retry(503, &headers));
        headers.insert("x-should-retry", HeaderValue::from_static("true"));
        assert!(should_retry(400, &headers));
    }

    #[test]
    fn retry_after_prefers_milliseconds_and_is_capped() {
        let mut headers = HeaderMap::new();
        assert_eq!(retry_after(&headers), None);
        headers.insert("retry-after", HeaderValue::from_static("3"));
        assert_eq!(retry_after(&headers), Some(Duration::from_secs(3)));
        headers.insert("retry-after-ms", HeaderValue::from_static("250"));
        assert_eq!(retry_after(&headers), Some(Duration::from_millis(250)));
        let mut long = HeaderMap::new();
        long.insert("retry-after", HeaderValue::from_static("86400"));
        assert_eq!(retry_after(&long), Some(MAX_RETRY_AFTER));
        for junk in ["-5", "0", "NaN", "inf", "Wed, 21 Oct 2015 07:28:00 GMT"] {
            let mut odd = HeaderMap::new();
            odd.insert("retry-after", HeaderValue::from_str(junk).expect("header"));
            assert_eq!(retry_after(&odd), None, "{junk}");
        }
    }

    #[test]
    fn error_bodies_are_reduced_to_a_safe_message() {
        let key = "sk-ant-api03-leaky";
        let body = format!(
            r#"{{"type":"error","error":{{"type":"authentication_error","message":"bad key {key}\u001b[2J\u001b]0;pwned\u0007"}}}}"#
        );
        let shown = error_message(body.as_bytes(), Some(key));
        assert!(
            shown.starts_with("authentication_error: bad key [redacted]"),
            "{shown}"
        );
        assert!(!shown.contains(key));
        assert!(!shown.chars().any(char::is_control), "{shown:?}");

        // Ollama's flat error shape.
        assert_eq!(
            error_message(br#"{"error":"model 'x' not found"}"#, None),
            "model 'x' not found"
        );

        // A non-JSON body (for example an HTML page from a proxy) is truncated.
        let html = format!("<html>{}</html>", "x".repeat(10_000));
        let shown = error_message(html.as_bytes(), None);
        assert!(shown.len() <= sanitize::MAX_MESSAGE_BYTES + 3);
        assert_eq!(error_message(b"", None), "(empty response body)");
    }

    #[test]
    fn the_overall_deadline_covers_a_trickling_body() {
        // The server sends headers promptly and then one body byte at a time.
        // Each read succeeds quickly, so only an overall deadline stops it.
        let server = FakeServer::start(vec![Reply::Drip {
            interval: Duration::from_millis(50),
            total: Duration::from_secs(8),
        }]);
        let client = build_client(ProviderKind::Mock, &server.base_url).expect("client");
        let started = Instant::now();
        let result: Result<serde_json::Value, LlmError> = send_json(
            client.post(format!("{}/drip", server.base_url)).body("{}"),
            ProviderKind::Mock,
            None,
            Duration::from_millis(400),
        );
        let elapsed = started.elapsed();
        let error = result.expect_err("the deadline fires");
        assert!(error.is_retryable(), "a timeout is transient: {error}");
        assert!(
            elapsed < Duration::from_secs(4),
            "the call ran for {elapsed:?} despite a 400 ms deadline"
        );
    }

    #[test]
    fn the_overall_deadline_covers_a_silent_server() {
        let server = FakeServer::start(vec![Reply::Silent {
            hold: Duration::from_secs(8),
        }]);
        let client = build_client(ProviderKind::Mock, &server.base_url).expect("client");
        let started = Instant::now();
        let result: Result<serde_json::Value, LlmError> = send_json(
            client
                .post(format!("{}/silent", server.base_url))
                .body("{}"),
            ProviderKind::Mock,
            None,
            Duration::from_millis(300),
        );
        let error = result.expect_err("the deadline fires");
        assert!(matches!(error, LlmError::Transport(_)), "{error}");
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn an_oversized_body_is_refused() {
        let body = format!("\"{}\"", "a".repeat(MAX_RESPONSE_BODY_BYTES + 10));
        let server = FakeServer::start(vec![Reply::json(200, &body)]);
        let client = build_client(ProviderKind::Mock, &server.base_url).expect("client");
        let result: Result<serde_json::Value, LlmError> = send_json(
            client.post(format!("{}/big", server.base_url)).body("{}"),
            ProviderKind::Mock,
            None,
            Duration::from_secs(20),
        );
        assert!(
            matches!(&result, Err(LlmError::Provider { message, .. }) if message.contains("cap")),
            "{result:?}"
        );
    }

    #[test]
    fn statuses_become_typed_errors_with_retry_hints() {
        let server = FakeServer::start(vec![Reply::Json {
            status: 529,
            headers: vec![("retry-after", "2".to_owned())],
            body: r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#
                .to_owned(),
        }]);
        let client = build_client(ProviderKind::Mock, &server.base_url).expect("client");
        let result: Result<serde_json::Value, LlmError> = send_json(
            client.post(format!("{}/busy", server.base_url)).body("{}"),
            ProviderKind::Mock,
            None,
            Duration::from_secs(10),
        );
        match result {
            Err(LlmError::HttpStatus {
                status,
                message,
                retryable,
                retry_after,
                ..
            }) => {
                assert_eq!(status, 529);
                assert_eq!(message, "overloaded_error: Overloaded");
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(2)));
            }
            other => panic!("expected an HTTP status error, got {other:?}"),
        }
    }

    /// The child half of [`loopback_requests_bypass_proxies`]: run in a
    /// subprocess whose environment points every proxy variable at a fake
    /// proxy. It does nothing unless that subprocess set the probe variable.
    #[test]
    #[ignore = "run by loopback_requests_bypass_proxies in a subprocess"]
    fn loopback_proxy_probe() {
        if std::env::var_os(PROBE_ENV).is_none() {
            return;
        }
        let server = FakeServer::start(vec![Reply::json(200, r#"{"ok":true}"#)]);
        let client = build_client(ProviderKind::Ollama, &server.base_url).expect("client");
        let value: serde_json::Value = send_json(
            client
                .post(format!("{}/api/chat", server.base_url))
                .body("{}"),
            ProviderKind::Ollama,
            None,
            Duration::from_secs(3),
        )
        .expect("the loopback server answered directly");
        assert_eq!(value["ok"], serde_json::json!(true));
        server.next_request();
    }

    const PROBE_ENV: &str = "SEXTANT_LLM_PROXY_PROBE";

    #[test]
    fn loopback_requests_bypass_proxies() {
        // Tests cannot set environment variables in-process (that is unsafe in
        // Rust 2024), so a copy of this test binary runs the probe with every
        // proxy variable aimed at a listener that must never see a connection.
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").expect("bind proxy");
        proxy.set_nonblocking(true).expect("nonblocking");
        let proxy_url = format!("http://{}", proxy.local_addr().expect("address"));
        let exe = std::env::current_exe().expect("test binary");
        let mut command = std::process::Command::new(exe);
        command
            .args([
                "providers::http::tests::loopback_proxy_probe",
                "--exact",
                "--ignored",
                "--test-threads=1",
            ])
            .env(PROBE_ENV, "1")
            .env_remove("NO_PROXY")
            .env_remove("no_proxy");
        for name in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
            command.env(name, &proxy_url);
        }
        let output = command.output().expect("run the probe");
        assert!(
            output.status.success(),
            "the probe failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "the probe did not run: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        match proxy.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("a loopback request was routed through HTTP_PROXY"),
            Err(error) => panic!("unexpected proxy listener error: {error}"),
        }
    }
}
