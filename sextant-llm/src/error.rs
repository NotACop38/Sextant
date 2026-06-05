//! Errors raised by the language-model layer.
//!
//! The crate follows the rest of the workspace and hand-writes its error type
//! rather than pulling in a derive macro, so the dependency surface of the
//! optional model layer stays small.

use std::fmt;

use crate::config::ProviderKind;

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
    /// Reading from or writing to the on-disk response cache failed.
    Cache(String),
    /// The transport (HTTP) layer failed after exhausting retries.
    Transport(String),
    /// The provider returned an error status or a body that could not be read.
    Provider {
        /// The provider that returned the error.
        provider: ProviderKind,
        /// A human-readable description of the failure.
        message: String,
    },
    /// The model returned content that did not match what was requested (for
    /// example, a structured call whose body was not valid JSON).
    InvalidResponse(String),
    /// Serializing a request or deserializing a response failed.
    Serialization(String),
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
            Self::Provider { provider, message } => {
                write!(f, "{provider} provider error: {message}")
            }
            Self::InvalidResponse(message) => write!(f, "invalid model response: {message}"),
            Self::Serialization(message) => write!(f, "serialization error: {message}"),
        }
    }
}

impl std::error::Error for LlmError {}
