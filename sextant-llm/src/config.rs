//! Provider selection and credential discovery.
//!
//! Secrets come only from the environment or a configuration file, never from a
//! command-line flag (FR-40). This module has no API that accepts a key as an
//! argument originating from a flag: credentials are read through an
//! [`EnvSource`], which the CLI backs with the process environment.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::LlmError;

/// The providers Sextant knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    /// Anthropic Messages API (first-class, feature `anthropic`).
    Anthropic,
    /// OpenAI chat completions (first-class, feature `openai`).
    OpenAi,
    /// A local Ollama server (optional, feature `ollama`).
    Ollama,
    /// The in-process mock used by tests; never auto-detected.
    Mock,
}

impl ProviderKind {
    /// The network providers, in auto-detection priority order. The mock is
    /// deliberately excluded: it is only ever selected explicitly by a test.
    pub const NETWORK_PROVIDERS: [ProviderKind; 3] = [
        ProviderKind::Anthropic,
        ProviderKind::OpenAi,
        ProviderKind::Ollama,
    ];

    /// The environment variable that supplies this provider's credential.
    ///
    /// For Anthropic and OpenAI this is the API key. For Ollama, which needs no
    /// key, it is the server host; its presence signals intent to use Ollama.
    pub fn credential_env_var(self) -> &'static str {
        match self {
            ProviderKind::Anthropic => "ANTHROPIC_API_KEY",
            ProviderKind::OpenAi => "OPENAI_API_KEY",
            ProviderKind::Ollama => "OLLAMA_HOST",
            ProviderKind::Mock => "SEXTANT_MOCK",
        }
    }

    /// A sensible default model identifier for this provider, used when the
    /// caller does not specify one.
    pub fn default_model(self) -> &'static str {
        match self {
            ProviderKind::Anthropic => "claude-haiku-4-5-20251001",
            ProviderKind::OpenAi => "gpt-4o-mini",
            ProviderKind::Ollama => "llama3",
            ProviderKind::Mock => "mock",
        }
    }

    /// Whether this provider was compiled into the current build. The mock is
    /// always present; the network providers depend on their feature flags.
    pub fn is_compiled_in(self) -> bool {
        match self {
            ProviderKind::Mock => true,
            ProviderKind::Anthropic => cfg!(feature = "anthropic"),
            ProviderKind::OpenAi => cfg!(feature = "openai"),
            ProviderKind::Ollama => cfg!(feature = "ollama"),
        }
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            ProviderKind::Anthropic => "anthropic",
            ProviderKind::OpenAi => "openai",
            ProviderKind::Ollama => "ollama",
            ProviderKind::Mock => "mock",
        };
        f.write_str(name)
    }
}

impl FromStr for ProviderKind {
    type Err = LlmError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "anthropic" => Ok(ProviderKind::Anthropic),
            "openai" => Ok(ProviderKind::OpenAi),
            "ollama" => Ok(ProviderKind::Ollama),
            "mock" => Ok(ProviderKind::Mock),
            other => Err(LlmError::InvalidResponse(format!(
                "unknown provider `{other}`: expected anthropic, openai, or ollama"
            ))),
        }
    }
}

/// A source of configuration secrets.
///
/// Backed by the process environment in production and by an in-memory map in
/// tests. Centralizing credential lookup here is what lets the crate guarantee
/// that no key is ever read from a flag (FR-40).
pub trait EnvSource {
    /// Return the value of a configuration variable, if present.
    fn get(&self, key: &str) -> Option<String>;
}

/// The real process environment.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

impl EnvSource for std::collections::HashMap<String, String> {
    fn get(&self, key: &str) -> Option<String> {
        std::collections::HashMap::get(self, key).cloned()
    }
}

/// Whether a provider's credential is present in the given environment.
fn credential_present(kind: ProviderKind, env: &dyn EnvSource) -> bool {
    env.get(kind.credential_env_var())
        .is_some_and(|value| !value.trim().is_empty())
}

/// The network providers that are both compiled in and have a credential
/// present, in priority order.
pub fn detect_available(env: &dyn EnvSource) -> Vec<ProviderKind> {
    ProviderKind::NETWORK_PROVIDERS
        .into_iter()
        .filter(|kind| kind.is_compiled_in() && credential_present(*kind, env))
        .collect()
}

/// Resolve which provider to use.
///
/// When `requested` is `Some`, that provider must be compiled in and have its
/// credential present. When it is `None`, the provider is auto-detected from
/// available credentials: exactly one is used, none is an error, and more than
/// one is ambiguous and must be disambiguated with `--provider` (PRD Section
/// 12).
pub fn resolve_provider(
    requested: Option<ProviderKind>,
    env: &dyn EnvSource,
) -> Result<ProviderKind, LlmError> {
    match requested {
        Some(ProviderKind::Mock) => Ok(ProviderKind::Mock),
        Some(kind) => {
            if !kind.is_compiled_in() {
                return Err(LlmError::ProviderUnavailable(kind));
            }
            if !credential_present(kind, env) {
                return Err(LlmError::MissingCredential {
                    provider: kind,
                    env_var: kind.credential_env_var(),
                });
            }
            Ok(kind)
        }
        None => {
            let available = detect_available(env);
            match available.len() {
                0 => Err(LlmError::NoProviderConfigured),
                1 => Ok(available[0]),
                _ => Err(LlmError::AmbiguousProvider { available }),
            }
        }
    }
}

/// Read a provider's credential from the environment, or report it missing.
///
/// Only the network provider builders call this, so in a build with no network
/// provider feature it is intentionally unused.
#[cfg_attr(not(feature = "http"), allow(dead_code))]
pub(crate) fn require_credential(
    kind: ProviderKind,
    env: &dyn EnvSource,
) -> Result<String, LlmError> {
    env.get(kind.credential_env_var())
        .filter(|value| !value.trim().is_empty())
        .ok_or(LlmError::MissingCredential {
            provider: kind,
            env_var: kind.credential_env_var(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn provider_kind_round_trips_through_string() {
        for kind in [
            ProviderKind::Anthropic,
            ProviderKind::OpenAi,
            ProviderKind::Ollama,
            ProviderKind::Mock,
        ] {
            let parsed: ProviderKind = kind.to_string().parse().expect("round-trips");
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn unknown_provider_name_is_an_error() {
        assert!("gemini".parse::<ProviderKind>().is_err());
    }

    #[test]
    fn no_credentials_means_no_provider() {
        let error = resolve_provider(None, &env(&[])).expect_err("nothing configured");
        assert!(matches!(error, LlmError::NoProviderConfigured));
    }

    #[test]
    fn requesting_uncompiled_provider_is_unavailable() {
        // Anthropic is compiled out in the default test build, so an explicit
        // request for it must surface as unavailable rather than a silent skip.
        if !ProviderKind::Anthropic.is_compiled_in() {
            let error = resolve_provider(Some(ProviderKind::Anthropic), &env(&[]))
                .expect_err("not compiled in");
            assert!(matches!(
                error,
                LlmError::ProviderUnavailable(ProviderKind::Anthropic)
            ));
        }
    }

    #[test]
    fn mock_resolves_without_a_credential() {
        let kind =
            resolve_provider(Some(ProviderKind::Mock), &env(&[])).expect("mock is always ok");
        assert_eq!(kind, ProviderKind::Mock);
    }

    #[test]
    fn empty_credential_is_treated_as_absent() {
        let kind = resolve_provider(None, &env(&[("ANTHROPIC_API_KEY", "   ")]));
        assert!(matches!(kind, Err(LlmError::NoProviderConfigured)));
    }
}
