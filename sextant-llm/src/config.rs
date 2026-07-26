//! Provider selection and credential discovery.
//!
//! Secrets come only from the environment or a configuration file, never from a
//! command-line flag (FR-40). This module has no API that accepts a key as an
//! argument originating from a flag: credentials are read through an
//! [`EnvSource`], which the CLI backs with a [`LayeredEnv`] of the process
//! environment over an optional key=value config file.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::LlmError;

/// Environment variable naming a Sextant config file that may hold provider
/// secrets as `KEY=VALUE` lines (FR-40). Process environment values still win
/// when both are set.
pub const SEXTANT_CONFIG_ENV: &str = "SEXTANT_CONFIG";

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

impl EnvSource for HashMap<String, String> {
    fn get(&self, key: &str) -> Option<String> {
        HashMap::get(self, key).cloned()
    }
}

/// A `KEY=VALUE` config file used as a secondary secret source (FR-40).
///
/// Lines that are empty or start with `#` are ignored. Values may be wrapped in
/// single or double quotes. The file is optional: a missing path yields an empty
/// source rather than an error, so callers can always layer it under the
/// process environment.
#[derive(Debug, Clone, Default)]
pub struct ConfigFileSource {
    values: HashMap<String, String>,
    /// Path that was loaded, when any, for diagnostics.
    pub path: Option<PathBuf>,
}

impl ConfigFileSource {
    /// Load `KEY=VALUE` pairs from `path`. A missing file yields an empty source.
    pub fn load(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self {
                values: HashMap::new(),
                path: Some(path.to_path_buf()),
            };
        };
        Self {
            values: parse_config_file(&text),
            path: Some(path.to_path_buf()),
        }
    }

    /// Resolve the config path from `SEXTANT_CONFIG`, or the platform default
    /// `~/.config/sextant/config` when that variable is unset.
    pub fn from_default_location(env: &dyn EnvSource) -> Self {
        if let Some(path) = env.get(SEXTANT_CONFIG_ENV).filter(|v| !v.trim().is_empty()) {
            return Self::load(path);
        }
        if let Some(home) = env.get("HOME").filter(|v| !v.is_empty()) {
            return Self::load(PathBuf::from(home).join(".config/sextant/config"));
        }
        Self::default()
    }
}

impl EnvSource for ConfigFileSource {
    fn get(&self, key: &str) -> Option<String> {
        self.values.get(key).cloned()
    }
}

/// Layer two secret sources: `primary` wins over `fallback` (FR-40).
///
/// Production wiring uses the process environment as primary and an optional
/// config file as fallback, so exported env vars override file contents.
#[derive(Debug, Clone)]
pub struct LayeredEnv<P, F> {
    /// Checked first (typically the process environment).
    pub primary: P,
    /// Checked when the primary has no value (typically a config file).
    pub fallback: F,
}

impl<P: EnvSource, F: EnvSource> EnvSource for LayeredEnv<P, F> {
    fn get(&self, key: &str) -> Option<String> {
        self.primary
            .get(key)
            .filter(|value| !value.trim().is_empty())
            .or_else(|| self.fallback.get(key))
    }
}

/// Build the default production secret source: process env over config file.
#[must_use]
pub fn default_secret_source() -> LayeredEnv<ProcessEnv, ConfigFileSource> {
    let process = ProcessEnv;
    let file = ConfigFileSource::from_default_location(&process);
    LayeredEnv {
        primary: process,
        fallback: file,
    }
}

/// Parse a simple `KEY=VALUE` config body.
fn parse_config_file(text: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = strip_quotes(value.trim());
        values.insert(key.to_owned(), value.to_owned());
    }
    values
}

fn strip_quotes(value: &str) -> &str {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return &value[1..value.len() - 1];
        }
    }
    value
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

    #[test]
    fn config_file_supplies_secrets_when_env_is_empty() {
        let file = ConfigFileSource {
            values: env(&[("OPENAI_API_KEY", "from-file")]),
            path: None,
        };
        let layered = LayeredEnv {
            primary: env(&[]),
            fallback: file,
        };
        assert_eq!(layered.get("OPENAI_API_KEY").as_deref(), Some("from-file"));
    }

    #[test]
    fn process_env_wins_over_config_file() {
        let file = ConfigFileSource {
            values: env(&[("OPENAI_API_KEY", "from-file")]),
            path: None,
        };
        let layered = LayeredEnv {
            primary: env(&[("OPENAI_API_KEY", "from-env")]),
            fallback: file,
        };
        assert_eq!(layered.get("OPENAI_API_KEY").as_deref(), Some("from-env"));
    }

    #[test]
    fn parse_config_file_skips_comments_and_strips_quotes() {
        let values = parse_config_file(
            "# comment\nANTHROPIC_API_KEY=\"abc\"\n\nOLLAMA_HOST='http://127.0.0.1:11434'\n",
        );
        assert_eq!(
            values.get("ANTHROPIC_API_KEY").map(String::as_str),
            Some("abc")
        );
        assert_eq!(
            values.get("OLLAMA_HOST").map(String::as_str),
            Some("http://127.0.0.1:11434")
        );
    }
}
