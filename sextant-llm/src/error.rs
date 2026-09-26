//! Errors raised by the language-model layer.
//!
//! The crate follows the rest of the workspace and hand-writes its error type
//! rather than pulling in a derive macro, so the dependency surface of the
//! optional model layer stays small.

use std::fmt;
use std::time::Duration;

use crate::config::ProviderKind;
use crate::provider::Usage;

/// Every way a model call can fail.
///
/// None of these variants can be produced in `--no-llm` mode, because that mode
/// never constructs a provider or a client in the first place (FR-32).
#[derive(Debug)]
pub enum LlmError {
    /// Auto-detection found no provider credentials in the environment or the
    /// configuration, so there is nothing to talk to.
    NoProviderConfigured,
    /// More than one provider's credentials were present and the caller did not
    /// pass `--provider` to choose between them.
    AmbiguousProvider {
        /// The providers whose credentials were detected, in priority order.
        available: Vec<ProviderKind>,
    },
    /// The requested provider was not compiled into this build (its feature
    /// flag was off).
    ProviderUnavailable(ProviderKind),
    /// The requested provider is compiled in, but its credential was not found
    /// in the environment or configuration.
    MissingCredential {
        /// The provider whose credential is missing.
        provider: ProviderKind,
        /// The environment variable that supplies the credential.
        env_var: &'static str,
    },
    /// The provider has no built-in default model and none was configured.
    MissingModel {
        /// The provider that needs a model identifier.
        provider: ProviderKind,
        /// The environment variable (or config file key) that supplies it.
        env_var: &'static str,
    },
    /// A configuration source or setting is unusable: a config file that
    /// cannot be read or is too permissive, a setting with an unknown value, or
    /// a refused endpoint URL.
    Config(String),
    /// The per-run cap on the number of model calls was reached (NFR-9).
    CallLimitReached {
        /// The configured maximum number of calls.
        limit: u32,
    },
    /// The optional per-run spend budget was exhausted (NFR-9).
    BudgetExhausted {
        /// The configured budget, in the same currency unit as the estimate.
        budget: f64,
        /// The amount already estimated as spent before this call.
        spent: f64,
    },
    /// Writing to the on-disk response cache failed. Reads never fail: an
    /// unreadable or corrupt entry is treated as a miss.
    Cache(String),
    /// The transport layer failed (a connection error or a timeout). Always
    /// worth retrying.
    Transport(String),
    /// The provider answered with a non-success HTTP status.
    HttpStatus {
        /// The provider that answered.
        provider: ProviderKind,
        /// The HTTP status code.
        status: u16,
        /// The provider's error message, extracted from its JSON error body
        /// when possible, stripped of control characters, truncated, and with
        /// the configured API key redacted.
        message: String,
        /// Whether a retry may succeed. Follows the provider's
        /// `x-should-retry` header when present, and otherwise holds for 408,
        /// 409, 429, and 5xx statuses.
        retryable: bool,
        /// The delay the provider asked for in `retry-after-ms` or
        /// `retry-after`, capped at [`crate::MAX_RETRY_AFTER`].
        retry_after: Option<Duration>,
    },
    /// The provider's response could not be read or decoded, or the request
    /// could not be built.
    Provider {
        /// The provider that returned the error.
        provider: ProviderKind,
        /// A human-readable description of the failure.
        message: String,
    },
    /// The model declined to answer: a `refusal` stop reason, a refusal field,
    /// or a content filter. Never cached.
    Refused {
        /// The provider that declined.
        provider: ProviderKind,
        /// The policy category the provider reported, if any.
        category: Option<String>,
        /// The provider's explanation or the model's refusal text, sanitized
        /// and truncated, if any.
        explanation: Option<String>,
    },
    /// The response hit the output-token limit before the answer finished, so
    /// it is incomplete. Never cached.
    Truncated {
        /// The provider whose response was cut off.
        provider: ProviderKind,
    },
    /// The response stopped for a reason Sextant does not accept (for example
    /// a paused turn, a tool call, or an unknown or missing stop reason). Never
    /// cached.
    UnexpectedStop {
        /// The provider that returned the response.
        provider: ProviderKind,
        /// The stop reason as reported, sanitized.
        reason: String,
    },
    /// The response finished normally but carried no text. Never cached.
    EmptyResponse {
        /// The provider that returned the response.
        provider: ProviderKind,
    },
    /// A failure that happened after the provider reported token usage for the
    /// call, so the spend can be accounted even though the response was
    /// unusable (NFR-9). [`crate::LlmClient`] records the usage and returns
    /// the inner error, so callers of the client never see this wrapper.
    WithUsage {
        /// The token usage the provider reported for the failed call.
        usage: Usage,
        /// The underlying failure.
        error: Box<LlmError>,
    },
    /// The model returned content that did not match what was requested (for
    /// example, a structured call whose body was not valid JSON).
    InvalidResponse(String),
    /// Serializing a request or deserializing a response failed.
    Serialization(String),
}

impl LlmError {
    /// Attach the token usage a provider reported for a call that then failed,
    /// so the client can still account the spend (NFR-9).
    ///
    /// Zero usage is not worth carrying, and an error that already carries
    /// usage keeps its original figure, so neither is wrapped again.
    #[must_use]
    pub fn with_usage(self, usage: Usage) -> Self {
        if usage == Usage::default() || matches!(self, Self::WithUsage { .. }) {
            return self;
        }
        Self::WithUsage {
            usage,
            error: Box::new(self),
        }
    }

    /// Split an error into the underlying failure and any token usage attached
    /// to it with [`Self::with_usage`].
    #[must_use]
    pub fn into_parts(self) -> (Self, Option<Usage>) {
        match self {
            Self::WithUsage { usage, error } => (*error, Some(usage)),
            other => (other, None),
        }
    }

    /// Whether retrying the identical request may succeed: transport failures
    /// always, and HTTP statuses the provider or the status code marks as
    /// transient.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport(_) => true,
            Self::HttpStatus { retryable, .. } => *retryable,
            Self::WithUsage { error, .. } => error.is_retryable(),
            _ => false,
        }
    }

    /// The delay the provider asked for before a retry, if it sent one.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::HttpStatus { retry_after, .. } => *retry_after,
            Self::WithUsage { error, .. } => error.retry_after(),
            _ => None,
        }
    }
}

impl fmt::Display for LlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProviderConfigured => write!(
                f,
                "no language-model provider is configured: set an API key in the environment or pass --no-llm"
            ),
            Self::AmbiguousProvider { available } => {
                write!(f, "more than one provider is configured (")?;
                for (index, kind) in available.iter().enumerate() {
                    if index > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{kind}")?;
                }
                write!(f, "); choose one with --provider")
            }
            Self::ProviderUnavailable(kind) => write!(
                f,
                "the {kind} provider was not compiled into this build; rebuild with the `{kind}` feature"
            ),
            Self::MissingCredential { provider, env_var } => write!(
                f,
                "the {provider} provider needs a credential; set {env_var} in the environment or configuration"
            ),
            Self::MissingModel { provider, env_var } => write!(
                f,
                "the {provider} provider needs a model identifier; set {env_var} in the environment or configuration"
            ),
            Self::Config(message) => write!(f, "configuration error: {message}"),
            Self::CallLimitReached { limit } => {
                write!(
                    f,
                    "the model-call limit of {limit} was reached for this run"
                )
            }
            Self::BudgetExhausted { budget, spent } => write!(
                f,
                "the model budget of {budget:.4} was exhausted (estimated spend {spent:.4})"
            ),
            Self::Cache(message) => write!(f, "response cache error: {message}"),
            Self::Transport(message) => write!(f, "transport error: {message}"),
            Self::HttpStatus {
                provider,
                status,
                message,
                ..
            } => write!(f, "{provider} provider returned HTTP {status}: {message}"),
            Self::Provider { provider, message } => {
                write!(f, "{provider} provider error: {message}")
            }
            Self::Refused {
                provider,
                category,
                explanation,
            } => {
                write!(f, "the {provider} model declined the request")?;
                if let Some(category) = category {
                    write!(f, " (category: {category})")?;
                }
                if let Some(explanation) = explanation {
                    write!(f, ": {explanation}")?;
                }
                Ok(())
            }
            Self::Truncated { provider } => write!(
                f,
                "the {provider} response hit the output-token limit before it finished; raise max_tokens"
            ),
            Self::UnexpectedStop { provider, reason } => write!(
                f,
                "the {provider} response stopped for an unsupported reason: {reason}"
            ),
            Self::EmptyResponse { provider } => {
                write!(f, "the {provider} response contained no text")
            }
            // Transparent: the wrapper only carries usage for accounting.
            Self::WithUsage { error, .. } => write!(f, "{error}"),
            Self::InvalidResponse(message) => write!(f, "invalid model response: {message}"),
            Self::Serialization(message) => write!(f, "serialization error: {message}"),
        }
    }
}

impl std::error::Error for LlmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            // The wrapper is transparent, so its source is the inner error's.
            Self::WithUsage { error, .. } => error.source(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage() -> Usage {
        Usage {
            input_tokens: 10,
            output_tokens: 5,
        }
    }

    #[test]
    fn with_usage_wraps_once_and_round_trips() {
        let error = LlmError::InvalidResponse("bad".to_owned()).with_usage(usage());
        // A second attachment keeps the first figure rather than nesting.
        let error = error.with_usage(Usage {
            input_tokens: 99,
            output_tokens: 99,
        });
        let (inner, attached) = error.into_parts();
        assert!(matches!(inner, LlmError::InvalidResponse(_)));
        assert_eq!(attached, Some(usage()));
    }

    #[test]
    fn zero_usage_is_not_wrapped() {
        let error = LlmError::EmptyResponse {
            provider: ProviderKind::Mock,
        }
        .with_usage(Usage::default());
        assert!(matches!(error, LlmError::EmptyResponse { .. }));
    }

    #[test]
    fn the_wrapper_is_transparent_for_display_and_retry() {
        let error = LlmError::HttpStatus {
            provider: ProviderKind::Mock,
            status: 529,
            message: "overloaded".to_owned(),
            retryable: true,
            retry_after: Some(Duration::from_secs(2)),
        }
        .with_usage(usage());
        assert_eq!(
            error.to_string(),
            "mock provider returned HTTP 529: overloaded"
        );
        assert!(error.is_retryable());
        assert_eq!(error.retry_after(), Some(Duration::from_secs(2)));
    }

    #[test]
    fn only_transient_failures_are_retryable() {
        assert!(LlmError::Transport("reset".to_owned()).is_retryable());
        assert!(
            !LlmError::Truncated {
                provider: ProviderKind::Mock
            }
            .is_retryable()
        );
        assert!(
            !LlmError::HttpStatus {
                provider: ProviderKind::Mock,
                status: 400,
                message: String::new(),
                retryable: false,
                retry_after: None,
            }
            .is_retryable()
        );
    }
}
