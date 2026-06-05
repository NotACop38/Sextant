//! An in-process mock provider so tests and CI need no network.
//!
//! The mock returns canned responses, counts how many times it was actually
//! invoked (so a test can prove the cache prevented a second call), and can be
//! told to fail a number of times with a transport error so the retry policy
//! can be exercised deterministically.

use std::cell::Cell;

use crate::config::ProviderKind;
use crate::error::LlmError;
use crate::provider::{
    CompletionRequest, CompletionResponse, JsonRequest, JsonResponse, LlmProvider, Usage,
};

/// A configurable, network-free provider for tests.
#[derive(Debug)]
pub struct MockProvider {
    model: String,
    text: String,
    json: Option<serde_json::Value>,
    usage: Usage,
    /// Number of leading calls that should fail with a transport error.
    transient_failures: Cell<u32>,
    /// Total number of times a call method was invoked, including failures.
    calls: Cell<u32>,
}

impl MockProvider {
    /// A mock for the given model with empty canned output.
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            text: String::new(),
            json: None,
            usage: Usage::default(),
            transient_failures: Cell::new(0),
            calls: Cell::new(0),
        }
    }

    /// Set the canned completion text.
    #[must_use]
    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text = text.into();
        self
    }

    /// Set the canned JSON value returned by structured calls.
    #[must_use]
    pub fn with_json(mut self, value: serde_json::Value) -> Self {
        self.json = Some(value);
        self
    }

    /// Set the token usage reported by every call.
    #[must_use]
    pub fn with_usage(mut self, usage: Usage) -> Self {
        self.usage = usage;
        self
    }

    /// Make the next `count` calls fail with a transport error before
    /// succeeding, to drive the retry policy.
    #[must_use]
    pub fn with_transient_failures(self, count: u32) -> Self {
        self.transient_failures.set(count);
        self
    }

    /// How many times a call method was invoked, including retried failures.
    pub fn calls(&self) -> u32 {
        self.calls.get()
    }

    /// Common bookkeeping: count the call and fail if a transient failure is
    /// still pending.
    fn enter_call(&self) -> Result<(), LlmError> {
        self.calls.set(self.calls.get() + 1);
        let pending = self.transient_failures.get();
        if pending > 0 {
            self.transient_failures.set(pending - 1);
            return Err(LlmError::Transport(format!(
                "mock transient failure ({pending} remaining)"
            )));
        }
        Ok(())
    }
}

impl LlmProvider for MockProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Mock
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn complete(&self, _request: &CompletionRequest) -> Result<CompletionResponse, LlmError> {
        self.enter_call()?;
        Ok(CompletionResponse {
            text: self.text.clone(),
            usage: self.usage,
        })
    }

    fn complete_json(&self, request: &JsonRequest) -> Result<JsonResponse, LlmError> {
        self.enter_call()?;
        let value = match &self.json {
            Some(value) => value.clone(),
            None => serde_json::from_str(&self.text).map_err(|error| {
                LlmError::InvalidResponse(format!(
                    "mock has no canned JSON and its text is not JSON: {error} (schema hint was: {})",
                    request.schema_hint
                ))
            })?,
        };
        Ok(JsonResponse {
            value,
            usage: self.usage,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_canned_text() {
        let mock = MockProvider::new("m").with_text("hello");
        let response = mock
            .complete(&CompletionRequest::user("ignored"))
            .expect("ok");
        assert_eq!(response.text, "hello");
        assert_eq!(mock.calls(), 1);
    }

    #[test]
    fn returns_canned_json() {
        let mock = MockProvider::new("m").with_json(serde_json::json!({"role": "length"}));
        let response = mock
            .complete_json(&JsonRequest::new("ignored", "an object"))
            .expect("ok");
        assert_eq!(response.value["role"], serde_json::json!("length"));
    }
}
