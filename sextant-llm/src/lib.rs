//! Provider-agnostic language-model interface for Sextant (FR-33, PRD Section
//! 12).
//!
//! The language-model pass is always optional. The model proposes; the native
//! executor disposes. This crate provides the interface and the providers; it
//! never has final authority over Sextant's output, and `--no-llm` bypasses it
//! entirely so that no bytes leave the machine (FR-31, FR-32).
//!
//! # What this crate gives you
//!
//! - [`LlmProvider`]: the single trait every provider implements, with a
//!   plain-text [`LlmProvider::complete`] call and a structured
//!   [`LlmProvider::complete_json`] call (FR-30).
//! - [`MockProvider`]: an in-process provider so tests and CI need no network.
//! - First-class [`providers::anthropic`] and [`providers::openai`]
//!   implementations and an optional [`providers::ollama`] one, each behind a
//!   feature flag.
//! - [`LlmClient`]: wraps any provider with on-disk caching, retries with
//!   backoff, a per-run call cap, and an optional spend budget (NFR-6, NFR-9).
//! - [`resolve_provider`] and [`build_provider`]: auto-detect the provider from
//!   credentials present in the environment, disambiguated by an explicit
//!   choice. Secrets come only from the environment or configuration, never
//!   from a flag (FR-40).
//!
//! # Safety and privacy
//!
//! Nothing here runs unless a caller constructs a provider, and a caller in
//! `--no-llm` mode never does. The default build compiles no network code at
//! all; the HTTP providers are pulled in only by their feature flags.

mod cache;
mod client;
mod config;
mod error;
mod factory;
mod mock;
mod provider;
pub mod providers;

pub use cache::{ResponseCache, request_key};
pub use client::{Backoff, CallLimits, LlmClient, Pricing};
pub use config::{EnvSource, ProcessEnv, ProviderKind, detect_available, resolve_provider};
pub use error::LlmError;
pub use factory::build_provider;
pub use mock::MockProvider;
pub use provider::{
    CompletionRequest, CompletionResponse, JsonRequest, JsonResponse, LlmProvider, Message, Role,
    Usage,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A unique temporary directory removed when the guard drops.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "sextant-llm-it-{tag}-{}-{unique}",
                std::process::id()
            ));
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn trait_object_is_usable_through_the_mock() {
        // The whole point of the abstraction: code depends on the trait, not on
        // a concrete provider. No network is touched.
        let provider: Box<dyn LlmProvider> = Box::new(MockProvider::new("m").with_text("hello"));
        let response = provider
            .complete(&CompletionRequest::user("hi"))
            .expect("mock completes");
        assert_eq!(response.text, "hello");
    }

    #[test]
    fn cache_serves_a_repeated_request_without_a_second_provider_call() {
        // This is the NFR-6 acceptance test: an identical request is served from
        // disk, and the underlying provider is never invoked a second time.
        let dir = TempDir::new("cache-hit");
        let provider = MockProvider::new("m").with_text("cached-result");
        let client = LlmClient::new(provider).with_cache(ResponseCache::new(&dir.0));

        let request = CompletionRequest::user("explain this structure");
        let first = client.complete(&request).expect("first call");
        assert_eq!(first.text, "cached-result");
        assert_eq!(client.calls_made(), 1, "first call hits the provider");

        let second = client.complete(&request).expect("second call");
        assert_eq!(second.text, "cached-result");
        assert_eq!(
            client.calls_made(),
            1,
            "the identical request is served from cache, not the provider"
        );
    }

    #[test]
    fn cache_persists_across_client_instances() {
        // A fresh client over a fresh provider still answers from the cache that
        // a previous run wrote, proving the entry is on disk (NFR-6).
        let dir = TempDir::new("cache-persist");
        let request = CompletionRequest::user("same prompt");

        {
            let client = LlmClient::new(MockProvider::new("m").with_text("from-disk"))
                .with_cache(ResponseCache::new(&dir.0));
            client.complete(&request).expect("warm the cache");
        }

        // A brand-new provider that would return different text if it were ever
        // called. The cached value must win.
        let provider = MockProvider::new("m").with_text("would-be-network");
        let client = LlmClient::new(provider).with_cache(ResponseCache::new(&dir.0));
        let response = client.complete(&request).expect("served from disk");
        assert_eq!(response.text, "from-disk");
        assert_eq!(
            client.calls_made(),
            0,
            "no provider call was needed for a cached request"
        );
    }

    #[test]
    fn structured_calls_are_cached_too() {
        let dir = TempDir::new("json-cache");
        let provider = MockProvider::new("m").with_json(serde_json::json!({"role": "length"}));
        let client = LlmClient::new(provider).with_cache(ResponseCache::new(&dir.0));

        let request = JsonRequest::new("annotate", "an object with a role field");
        let first = client.complete_json(&request).expect("first json call");
        assert_eq!(first.value["role"], serde_json::json!("length"));
        let second = client.complete_json(&request).expect("second json call");
        assert_eq!(second.value, first.value);
        assert_eq!(client.calls_made(), 1, "the second json call is cached");
    }
}
