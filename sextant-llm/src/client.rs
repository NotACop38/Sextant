//! The client that wraps any [`LlmProvider`] with the cross-cutting concerns:
//! on-disk caching, retries with backoff, a per-run call cap, and an optional
//! spend budget (NFR-6, NFR-9).
//!
//! Providers stay simple and stateless; all of the policy lives here, so it is
//! identical no matter which provider is underneath.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cache::{ResponseCache, request_key};
use crate::error::LlmError;
use crate::provider::{
    CompletionRequest, CompletionResponse, JsonRequest, JsonResponse, LlmProvider, Usage,
};

/// Default per-run model call cap. Finite so a runaway refinement loop cannot
/// issue unbounded provider calls when the caller forgets to set limits (NFR-9).
pub const DEFAULT_MAX_CALLS: u32 = 32;

/// The longest delay honored from a provider's `retry-after` or
/// `retry-after-ms` header. A longer request is shortened to this.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);

/// Cost-control limits for a single run (NFR-9).
#[derive(Debug, Clone, Copy)]
pub struct CallLimits {
    /// The maximum number of model calls. `None` means unlimited (tests only;
    /// production callers should keep the default finite cap).
    pub max_calls: Option<u32>,
    /// The spend budget in the same unit as [`Pricing`]. `None` means no cap.
    pub budget: Option<f64>,
}

impl Default for CallLimits {
    fn default() -> Self {
        Self {
            max_calls: Some(DEFAULT_MAX_CALLS),
            budget: None,
        }
    }
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

/// Retry policy for transient failures: connection errors, timeouts, and the
/// HTTP statuses a provider marks as retryable (408, 409, 429, 5xx, or any
/// status with `x-should-retry: true`).
///
/// A provider's `retry-after` hint replaces the computed delay, up to
/// [`MAX_RETRY_AFTER`]. Otherwise attempt `n` waits `base_delay * 2^n`, capped
/// at `max_delay` and scaled by a random factor between 0.75 and 1.0 so that
/// clients which failed together do not retry in lockstep. A retry whose delay
/// would push the total time slept past `max_total_delay` is not made.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    /// How many times to retry after the first attempt fails.
    pub max_retries: u32,
    /// The base of the exponential delay. A zero base never sleeps unless the
    /// provider asks for a delay, which keeps tests fast.
    pub base_delay: Duration,
    /// The cap on any single computed delay.
    pub max_delay: Duration,
    /// The cap on the total time spent sleeping between the attempts of one
    /// logical call.
    pub max_total_delay: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(8),
            max_total_delay: Duration::from_secs(120),
        }
    }
}

impl Backoff {
    /// A policy that never retries and never sleeps, for tests.
    pub fn none() -> Self {
        Self {
            max_retries: 0,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            max_total_delay: Duration::ZERO,
        }
    }

    /// The delay before retry number `attempt` (zero-based). `retry_after` is
    /// the provider's requested delay, if any; `jitter` is a value in `[0, 1]`
    /// that scales a computed delay down by up to a quarter.
    ///
    /// Every step saturates, so no attempt number or configuration can
    /// overflow or panic.
    fn delay_for(&self, attempt: u32, retry_after: Option<Duration>, jitter: f64) -> Duration {
        if let Some(requested) = retry_after {
            return requested.min(MAX_RETRY_AFTER);
        }
        let factor = 1u32.checked_shl(attempt).unwrap_or(u32::MAX);
        let delay = self.base_delay.saturating_mul(factor).min(self.max_delay);
        let jitter = if jitter.is_finite() {
            jitter.clamp(0.0, 1.0)
        } else {
            0.0
        };
        Duration::try_from_secs_f64(delay.as_secs_f64() * (1.0 - 0.25 * jitter)).unwrap_or(delay)
    }
}

/// A small, fast, non-cryptographic generator for retry jitter (splitmix64),
/// seeded from the clock and a process-wide counter. Jitter only has to spread
/// retries out, so no stronger source is needed.
struct Jitter(u64);

impl Jitter {
    fn from_clock() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos() as u64);
        Self(nanos ^ COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed))
    }

    /// The next value, uniform in `[0, 1)`.
    fn next_unit(&mut self) -> f64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        (z >> 11) as f64 / (1u64 << 53) as f64
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
    /// Build a client around a provider with default policy: no cache, the
    /// finite default call cap, zero pricing, and the default backoff.
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

    /// The estimated spend so far, including calls whose responses were then
    /// rejected (a refusal, a truncated answer, or unparseable JSON).
    pub fn spent(&self) -> f64 {
        self.spent.get()
    }

    /// Run a plain-text completion, consulting the cache first (NFR-6). Only a
    /// successful response is cached.
    pub fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, LlmError> {
        let key = self.key_for("completion", request)?;
        if let Some(cache) = &self.cache {
            if let Some(hit) = cache.get::<CompletionResponse>(&key) {
                return Ok(hit);
            }
        }

        self.precheck()?;
        self.calls_made.set(self.calls_made.get().saturating_add(1));
        let response = self.with_retry(|| self.provider.complete(request))?;
        self.account(&response.usage);

        if let Some(cache) = &self.cache {
            cache.put(&key, &response)?;
        }
        Ok(response)
    }

    /// Run a structured JSON call, consulting the cache first (NFR-6). Only a
    /// successful response is cached.
    pub fn complete_json(&self, request: &JsonRequest) -> Result<JsonResponse, LlmError> {
        let key = self.key_for("json", request)?;
        if let Some(cache) = &self.cache {
            if let Some(hit) = cache.get::<JsonResponse>(&key) {
                return Ok(hit);
            }
        }

        self.precheck()?;
        self.calls_made.set(self.calls_made.get().saturating_add(1));
        let response = self.with_retry(|| self.provider.complete_json(request))?;
        self.account(&response.usage);

        if let Some(cache) = &self.cache {
            cache.put(&key, &response)?;
        }
        Ok(response)
    }

    /// Compute the cache key for a serializable request, scoped to the
    /// provider's endpoint and settings.
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
            &self.provider.cache_scope(),
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

    /// Add the estimated cost of a call to the running spend.
    fn account(&self, usage: &Usage) {
        self.spent
            .set(self.spent.get() + self.pricing.estimate(usage));
    }

    /// Call the provider, retrying transient failures with bounded, jittered
    /// backoff. Usage attached to a failure is accounted before the failure is
    /// examined, so an unusable but billed response still counts against the
    /// budget (NFR-9). Non-retryable errors are returned immediately.
    fn with_retry<T>(&self, mut call: impl FnMut() -> Result<T, LlmError>) -> Result<T, LlmError> {
        let mut attempt: u32 = 0;
        let mut slept = Duration::ZERO;
        let mut jitter = Jitter::from_clock();
        loop {
            let error = match call() {
                Ok(value) => return Ok(value),
                Err(error) => error,
            };
            let (error, usage) = error.into_parts();
            if let Some(usage) = usage {
                self.account(&usage);
            }
            if !error.is_retryable() || attempt >= self.backoff.max_retries {
                return Err(error);
            }
            let delay = self
                .backoff
                .delay_for(attempt, error.retry_after(), jitter.next_unit());
            let total = slept.saturating_add(delay);
            if total > self.backoff.max_total_delay {
                return Err(error);
            }
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            slept = total;
            attempt = attempt.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProviderKind;
    use crate::mock::MockProvider;
    use crate::provider::CompletionRequest;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::time::Instant;

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
            ..Backoff::default()
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

    #[test]
    fn a_high_attempt_count_cannot_overflow_the_delay() {
        // `2u32.pow(32)` used to overflow (a panic in debug builds). Every step
        // now saturates and the delay is capped.
        let backoff = Backoff {
            max_retries: u32::MAX,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(8),
            max_total_delay: Duration::MAX,
        };
        for attempt in [0, 3, 31, 32, 33, 64, u32::MAX] {
            assert!(backoff.delay_for(attempt, None, 0.0) <= Duration::from_secs(8));
        }
        assert_eq!(backoff.delay_for(40, None, 0.0), Duration::from_secs(8));
        // An enormous cap and base still produce a finite delay without
        // panicking.
        let huge = Backoff {
            base_delay: Duration::MAX,
            max_delay: Duration::MAX,
            ..backoff
        };
        let _ = huge.delay_for(u32::MAX, None, 0.5);
    }

    #[test]
    fn many_retries_complete_without_panicking() {
        // Forty transient failures run through attempt numbers past 32, which
        // overflowed the old `2u32.pow(attempt)` computation.
        let provider = MockProvider::new("mock")
            .with_text("ok")
            .with_transient_failures(40);
        let client = LlmClient::new(provider).with_backoff(Backoff {
            max_retries: 40,
            base_delay: Duration::from_nanos(1),
            max_delay: Duration::from_nanos(1),
            max_total_delay: Duration::from_secs(1),
        });
        let response = client
            .complete(&CompletionRequest::user("hi"))
            .expect("succeeds on the last retry");
        assert_eq!(response.text, "ok");
    }

    #[test]
    fn jitter_scales_computed_delays_down_by_at_most_a_quarter() {
        let backoff = Backoff {
            base_delay: Duration::from_millis(400),
            ..Backoff::default()
        };
        assert_eq!(backoff.delay_for(1, None, 0.0), Duration::from_millis(800));
        assert_eq!(backoff.delay_for(1, None, 1.0), Duration::from_millis(600));
        let mut jitter = Jitter::from_clock();
        for _ in 0..1000 {
            let unit = jitter.next_unit();
            assert!((0.0..1.0).contains(&unit), "jitter out of range: {unit}");
            let delay = backoff.delay_for(2, None, unit);
            assert!(delay <= Duration::from_millis(1600));
            assert!(delay >= Duration::from_millis(1200));
        }
    }

    #[test]
    fn a_provider_retry_after_replaces_the_computed_delay_up_to_a_cap() {
        let backoff = Backoff::default();
        assert_eq!(
            backoff.delay_for(0, Some(Duration::from_secs(7)), 0.9),
            Duration::from_secs(7)
        );
        assert_eq!(
            backoff.delay_for(0, Some(Duration::from_secs(3600)), 0.0),
            MAX_RETRY_AFTER
        );
    }

    /// A provider that replays a scripted sequence of outcomes, for driving the
    /// retry and accounting paths deterministically.
    struct Scripted {
        outcomes: RefCell<VecDeque<Result<CompletionResponse, LlmError>>>,
        calls: Cell<u32>,
    }

    impl Scripted {
        fn new(outcomes: Vec<Result<CompletionResponse, LlmError>>) -> Self {
            Self {
                outcomes: RefCell::new(outcomes.into()),
                calls: Cell::new(0),
            }
        }
    }

    impl LlmProvider for Scripted {
        fn kind(&self) -> ProviderKind {
            ProviderKind::Mock
        }

        fn model(&self) -> &str {
            "scripted"
        }

        fn complete(&self, _request: &CompletionRequest) -> Result<CompletionResponse, LlmError> {
            self.calls.set(self.calls.get() + 1);
            self.outcomes
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Err(LlmError::Transport("script exhausted".to_owned())))
        }
    }

    fn status(code: u16, retryable: bool, retry_after: Option<Duration>) -> LlmError {
        LlmError::HttpStatus {
            provider: ProviderKind::Mock,
            status: code,
            message: "scripted".to_owned(),
            retryable,
            retry_after,
        }
    }

    fn ok(text: &str) -> Result<CompletionResponse, LlmError> {
        Ok(CompletionResponse {
            text: text.to_owned(),
            usage: Usage::default(),
        })
    }

    fn fast_backoff() -> Backoff {
        Backoff {
            max_retries: 3,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            max_total_delay: Duration::from_secs(5),
        }
    }

    #[test]
    fn retryable_statuses_are_retried_and_others_are_not() {
        let client = LlmClient::new(Scripted::new(vec![
            Err(status(529, true, None)),
            ok("fine"),
        ]))
        .with_backoff(fast_backoff());
        assert_eq!(
            client
                .complete(&CompletionRequest::user("a"))
                .expect("retried")
                .text,
            "fine"
        );
        assert_eq!(client.provider.calls.get(), 2);

        let client = LlmClient::new(Scripted::new(vec![Err(status(400, false, None)), ok("x")]))
            .with_backoff(fast_backoff());
        let error = client
            .complete(&CompletionRequest::user("a"))
            .expect_err("a 400 is final");
        assert!(matches!(error, LlmError::HttpStatus { status: 400, .. }));
        assert_eq!(client.provider.calls.get(), 1);
    }

    #[test]
    fn a_provider_retry_after_is_honored() {
        let client = LlmClient::new(Scripted::new(vec![
            Err(status(429, true, Some(Duration::from_millis(60)))),
            ok("later"),
        ]))
        .with_backoff(fast_backoff());
        let started = Instant::now();
        client
            .complete(&CompletionRequest::user("a"))
            .expect("succeeds after waiting");
        assert!(
            started.elapsed() >= Duration::from_millis(60),
            "the retry-after delay was not honored"
        );
    }

    #[test]
    fn the_total_retry_delay_is_capped() {
        let outcomes = (0..10)
            .map(|_| Err(status(503, true, Some(Duration::from_millis(40)))))
            .collect();
        let client = LlmClient::new(Scripted::new(outcomes)).with_backoff(Backoff {
            max_retries: 10,
            max_total_delay: Duration::from_millis(100),
            ..fast_backoff()
        });
        let started = Instant::now();
        let error = client
            .complete(&CompletionRequest::user("a"))
            .expect_err("gives up once the total delay budget is spent");
        assert!(matches!(error, LlmError::HttpStatus { status: 503, .. }));
        // Two 40 ms waits fit in the 100 ms budget; a third would not.
        assert_eq!(client.provider.calls.get(), 3);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    fn usage(input: u32, output: u32) -> Usage {
        Usage {
            input_tokens: input,
            output_tokens: output,
        }
    }

    fn priced<P: LlmProvider>(provider: P) -> LlmClient<P> {
        LlmClient::new(provider)
            .with_backoff(fast_backoff())
            .with_pricing(Pricing {
                input_per_1k: 1.0,
                output_per_1k: 1.0,
            })
    }

    #[test]
    fn usage_from_an_unparseable_json_response_is_accounted() {
        // The provider returned (and billed) text that is not JSON. The error
        // surfaces unchanged, but the spend is counted.
        let provider = MockProvider::new("mock")
            .with_text("not json")
            .with_usage(usage(1000, 1000));
        let client = priced(provider);
        let error = client
            .complete_json(&JsonRequest::new("a", "an object"))
            .expect_err("not JSON");
        assert!(matches!(error, LlmError::InvalidResponse(_)));
        assert!(
            (client.spent() - 2.0).abs() < 1e-9,
            "spent {}",
            client.spent()
        );
    }

    #[test]
    fn usage_from_a_refused_response_is_accounted_and_nothing_is_cached() {
        let dir = TempDir::new("refusal");
        let refusal = || {
            Err(LlmError::Refused {
                provider: ProviderKind::Mock,
                category: Some("cyber".to_owned()),
                explanation: None,
            }
            .with_usage(usage(500, 0)))
        };
        let client = priced(Scripted::new(vec![refusal(), refusal()]))
            .with_cache(ResponseCache::new(&dir.0));
        let request = CompletionRequest::user("a");
        for expected_calls in 1..=2 {
            let error = client.complete(&request).expect_err("refused");
            assert!(matches!(error, LlmError::Refused { .. }), "got {error}");
            // A refusal is never cached, so the second identical request goes
            // back to the provider.
            assert_eq!(client.provider.calls.get(), expected_calls);
        }
        assert!(
            (client.spent() - 1.0).abs() < 1e-9,
            "spent {}",
            client.spent()
        );
        let entries = std::fs::read_dir(&dir.0).map_or(0, |entries| entries.count());
        assert_eq!(entries, 0, "a refused response was written to the cache");
    }

    /// A unique temporary directory removed when the guard drops.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "sextant-llm-client-{tag}-{}-{unique}",
                std::process::id()
            )))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
