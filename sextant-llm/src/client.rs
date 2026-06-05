//! The client that wraps any [`LlmProvider`] with the cross-cutting concerns:
//! on-disk caching, retries with backoff, a per-run call cap, and an optional
//! spend budget (NFR-6, NFR-9).
//!
//! Providers stay simple and stateless; all of the policy lives here, so it is
//! identical no matter which provider is underneath.

use std::cell::Cell;
use std::time::Duration;

use crate::cache::{ResponseCache, request_key};
use crate::error::LlmError;
use crate::provider::{
    CompletionRequest, CompletionResponse, JsonRequest, JsonResponse, LlmProvider, Usage,
};

/// Cost-control limits for a single run (NFR-9).
#[derive(Debug, Clone, Copy, Default)]
pub struct CallLimits {
    /// The maximum number of model calls. `None` means unlimited.
    pub max_calls: Option<u32>,
    /// The spend budget in the same unit as [`Pricing`]. `None` means no cap.
    pub budget: Option<f64>,
}

/// Per-thousand-token prices used to estimate spend for the budget (NFR-9).
///
/// Defaults are zero, so without explicit pricing the budget never trips; a
/// caller that wants budget enforcement supplies real prices.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pricing {
    /// Price per one thousand input tokens.
    pub input_per_1k: f64,
    /// Price per one thousand output tokens.
    pub output_per_1k: f64,
}

impl Pricing {
    /// Estimate the cost of a single call from its token usage.
    pub fn estimate(&self, usage: &Usage) -> f64 {
        let input = f64::from(usage.input_tokens) / 1000.0 * self.input_per_1k;
        let output = f64::from(usage.output_tokens) / 1000.0 * self.output_per_1k;
        input + output
    }
}

/// Retry policy for transient transport failures.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    /// How many times to retry after the first attempt fails.
    pub max_retries: u32,
    /// The base delay; attempt `n` waits `base * 2^n`. A zero base never sleeps,
    /// which keeps tests fast.
    pub base_delay: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
        }
    }
}

impl Backoff {
    /// A policy that never retries and never sleeps, for tests.
    pub fn none() -> Self {
        Self {
            max_retries: 0,
            base_delay: Duration::ZERO,
        }
    }
}

/// Wraps a provider with caching, retries, a call cap, and a budget.
pub struct LlmClient<P: LlmProvider> {
    provider: P,
    cache: Option<ResponseCache>,
    limits: CallLimits,
    pricing: Pricing,
    backoff: Backoff,
    calls_made: Cell<u32>,
    spent: Cell<f64>,
}

impl<P: LlmProvider> LlmClient<P> {
    /// Build a client around a provider with default policy: no cache, no
    /// limits, zero pricing, and the default backoff.
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            cache: None,
            limits: CallLimits::default(),
            pricing: Pricing::default(),
            backoff: Backoff::default(),
            calls_made: Cell::new(0),
            spent: Cell::new(0.0),
        }
    }

    /// Attach an on-disk response cache.
    #[must_use]
    pub fn with_cache(mut self, cache: ResponseCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Set the call cap and budget.
    #[must_use]
    pub fn with_limits(mut self, limits: CallLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Set the token pricing used for budget estimation.
    #[must_use]
    pub fn with_pricing(mut self, pricing: Pricing) -> Self {
        self.pricing = pricing;
        self
    }

    /// Set the retry policy.
    #[must_use]
    pub fn with_backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// The number of provider calls made so far (cache hits do not count).
    pub fn calls_made(&self) -> u32 {
        self.calls_made.get()
    }

    /// The estimated spend so far.
    pub fn spent(&self) -> f64 {
        self.spent.get()
    }

    /// Borrow the wrapped provider. This is for introspection (for example a
    /// test provider that records the prompt it was handed); the client owns all
    /// policy, so a caller cannot use this to bypass the cache, the call cap, or
    /// the budget.
    pub fn provider_ref(&self) -> &P {
        &self.provider
    }

    /// Run a plain-text completion, consulting the cache first (NFR-6).
    pub fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, LlmError> {
        let key = self.key_for("completion", request)?;
        if let Some(cache) = &self.cache {
            if let Some(hit) = cache.get::<CompletionResponse>(&key)? {
                return Ok(hit);
            }
        }

        self.precheck()?;
        self.calls_made.set(self.calls_made.get() + 1);
        let response = self.with_retry(|| self.provider.complete(request))?;
        self.account(&response.usage);

        if let Some(cache) = &self.cache {
            cache.put(&key, &response)?;
        }
        Ok(response)
    }

    /// Run a structured JSON call, consulting the cache first (NFR-6).
    pub fn complete_json(&self, request: &JsonRequest) -> Result<JsonResponse, LlmError> {
        let key = self.key_for("json", request)?;
        if let Some(cache) = &self.cache {
            if let Some(hit) = cache.get::<JsonResponse>(&key)? {
                return Ok(hit);
            }
        }

        self.precheck()?;
        self.calls_made.set(self.calls_made.get() + 1);
        let response = self.with_retry(|| self.provider.complete_json(request))?;
        self.account(&response.usage);

        if let Some(cache) = &self.cache {
            cache.put(&key, &response)?;
        }
        Ok(response)
    }

    /// Compute the cache key for a serializable request.
    fn key_for<T: serde::Serialize>(
        &self,
        call_kind: &str,
        request: &T,
    ) -> Result<String, LlmError> {
        let value = serde_json::to_value(request)
            .map_err(|error| LlmError::Serialization(error.to_string()))?;
        Ok(request_key(
            self.provider.kind(),
            self.provider.model(),
            call_kind,
            &value,
        ))
    }

    /// Enforce the call cap and the budget before a fresh provider call.
    fn precheck(&self) -> Result<(), LlmError> {
        if let Some(limit) = self.limits.max_calls {
            if self.calls_made.get() >= limit {
                return Err(LlmError::CallLimitReached { limit });
            }
        }
        if let Some(budget) = self.limits.budget {
            if self.spent.get() >= budget {
                return Err(LlmError::BudgetExhausted {
                    budget,
                    spent: self.spent.get(),
                });
            }
        }
        Ok(())
    }

    /// Add the estimated cost of a completed call to the running spend.
    fn account(&self, usage: &Usage) {
        self.spent
            .set(self.spent.get() + self.pricing.estimate(usage));
    }

    /// Call the provider, retrying transient transport failures with
    /// exponential backoff. Non-transport errors are returned immediately.
    fn with_retry<T>(&self, mut call: impl FnMut() -> Result<T, LlmError>) -> Result<T, LlmError> {
        let mut attempt = 0;
        loop {
            match call() {
                Ok(value) => return Ok(value),
                Err(error) => {
                    let retryable = matches!(error, LlmError::Transport(_));
                    if !retryable || attempt >= self.backoff.max_retries {
                        return Err(error);
                    }
                    let delay = self.backoff.base_delay * 2u32.pow(attempt);
                    if !delay.is_zero() {
                        std::thread::sleep(delay);
                    }
                    attempt += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProviderKind;
    use crate::mock::MockProvider;
    use crate::provider::CompletionRequest;

    #[test]
    fn estimate_uses_both_token_counts() {
        let pricing = Pricing {
            input_per_1k: 1.0,
            output_per_1k: 2.0,
        };
        let usage = Usage {
            input_tokens: 1000,
            output_tokens: 500,
        };
        assert!((pricing.estimate(&usage) - 2.0).abs() < 1e-9);
    }

    #[test]
    fn call_cap_blocks_further_calls() {
        let client =
            LlmClient::new(MockProvider::new("mock").with_text("hi")).with_limits(CallLimits {
                max_calls: Some(1),
                budget: None,
            });
        let a = CompletionRequest::user("first");
        let b = CompletionRequest::user("second");
        assert!(client.complete(&a).is_ok());
        let error = client
            .complete(&b)
            .expect_err("second call is over the cap");
        assert!(matches!(error, LlmError::CallLimitReached { limit: 1 }));
        assert_eq!(client.calls_made(), 1);
    }

    #[test]
    fn budget_blocks_once_exhausted() {
        let provider = MockProvider::new("mock").with_text("hi").with_usage(Usage {
            input_tokens: 1000,
            output_tokens: 0,
        });
        let client = LlmClient::new(provider)
            .with_pricing(Pricing {
                input_per_1k: 1.0,
                output_per_1k: 0.0,
            })
            .with_limits(CallLimits {
                max_calls: None,
                budget: Some(0.5),
            });
        // First call: spend was 0, under budget, so it runs and spends 1.0.
        assert!(client.complete(&CompletionRequest::user("a")).is_ok());
        // Second call: spend now exceeds the budget, so it is refused.
        let error = client
            .complete(&CompletionRequest::user("b"))
            .expect_err("budget exhausted");
        assert!(matches!(error, LlmError::BudgetExhausted { .. }));
    }

    #[test]
    fn retries_transient_transport_failures() {
        // Fail twice with a transport error, then succeed.
        let provider = MockProvider::new("mock")
            .with_text("ok")
            .with_transient_failures(2);
        let client = LlmClient::new(provider).with_backoff(Backoff {
            max_retries: 3,
            base_delay: Duration::ZERO,
        });
        let response = client
            .complete(&CompletionRequest::user("hi"))
            .expect("succeeds after retries");
        assert_eq!(response.text, "ok");
        // The whole retried sequence is one logical call against the cap.
        assert_eq!(client.calls_made(), 1);
    }

    #[test]
    fn gives_up_after_max_retries() {
        let provider = MockProvider::new("mock")
            .with_text("never reached")
            .with_transient_failures(5);
        let client = LlmClient::new(provider).with_backoff(Backoff::none());
        let error = client
            .complete(&CompletionRequest::user("hi"))
            .expect_err("exhausts retries");
        assert!(matches!(error, LlmError::Transport(_)));
    }

    #[test]
    fn client_reports_its_provider_kind() {
        let client = LlmClient::new(MockProvider::new("mock"));
        // The mock identifies as the mock provider.
        assert_eq!(client.provider.kind(), ProviderKind::Mock);
    }
}
