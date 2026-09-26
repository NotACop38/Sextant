//! Construct a boxed provider from a resolved [`ProviderKind`].
//!
//! This is the single seam the rest of the program uses to obtain a provider.
//! It compiles regardless of which provider features are enabled: a request for
//! a provider that was not compiled in returns [`LlmError::ProviderUnavailable`]
//! rather than failing to build.

use crate::config::{EnvSource, ProviderKind, resolve_model};
use crate::error::LlmError;
use crate::mock::MockProvider;
use crate::provider::LlmProvider;

/// Setting that points the Anthropic provider at another endpoint (the same
/// variable the official SDKs read).
pub const ANTHROPIC_BASE_URL_ENV: &str = "ANTHROPIC_BASE_URL";

/// Setting that points the OpenAI provider at another endpoint (the same
/// variable the official SDKs read).
pub const OPENAI_BASE_URL_ENV: &str = "OPENAI_BASE_URL";

/// Build a provider for `kind`, reading any required credential and settings
/// from `env` (FR-40).
///
/// The model is `model` when given, otherwise the provider's model setting
/// ([`ProviderKind::model_env_var`]), otherwise the provider's built-in default
/// ([`ProviderKind::default_model`]). Ollama has no default, so it needs one of
/// the first two.
///
/// Provider settings read from `env`:
///
/// - Anthropic: `ANTHROPIC_API_KEY` (required), plus
///   [`crate::ANTHROPIC_EFFORT_ENV`] (default: unset, the model's own effort),
///   [`crate::ANTHROPIC_FALLBACKS_ENV`] (default `on`), and
///   [`ANTHROPIC_BASE_URL_ENV`] to send requests to another endpoint, such as
///   a gateway.
/// - OpenAI: `OPENAI_API_KEY` (required), plus [`OPENAI_BASE_URL_ENV`].
/// - Ollama: `OLLAMA_HOST`, defaulting to `http://127.0.0.1:11434`.
///
/// A base URL override is validated like any endpoint: a provider that sends an
/// API key refuses plain `http` unless the host is loopback.
///
/// # Errors
///
/// Returns [`LlmError::ProviderUnavailable`] for a provider that was not
/// compiled in, [`LlmError::MissingCredential`] or [`LlmError::MissingModel`]
/// when a required value is absent, and [`LlmError::Config`] for a setting with
/// an invalid value or a refused endpoint.
pub fn build_provider(
    kind: ProviderKind,
    model: Option<&str>,
    env: &dyn EnvSource,
) -> Result<Box<dyn LlmProvider>, LlmError> {
    if !kind.is_compiled_in() {
        return Err(LlmError::ProviderUnavailable(kind));
    }
    let model = resolve_model(kind, model, env)?;
    match kind {
        ProviderKind::Mock => Ok(Box::new(MockProvider::new(model))),
        ProviderKind::Anthropic => build_anthropic(&model, env),
        ProviderKind::OpenAi => build_openai(&model, env),
        ProviderKind::Ollama => build_ollama(&model, env),
    }
}

#[cfg(feature = "anthropic")]
fn build_anthropic(model: &str, env: &dyn EnvSource) -> Result<Box<dyn LlmProvider>, LlmError> {
    use crate::config::{
        ANTHROPIC_EFFORT_ENV, ANTHROPIC_FALLBACKS_ENV, parse_switch, require_credential, setting,
    };
    use crate::providers::anthropic::{AnthropicProvider, Effort};

    let key = require_credential(ProviderKind::Anthropic, env)?;
    let effort = match setting(env, ANTHROPIC_EFFORT_ENV) {
        None => None,
        Some(value) => Effort::parse_setting(&value)?,
    };
    let fallbacks = match setting(env, ANTHROPIC_FALLBACKS_ENV) {
        None => true,
        Some(value) => parse_switch(ANTHROPIC_FALLBACKS_ENV, &value)?,
    };
    let mut provider = AnthropicProvider::new(key, model)?
        .with_effort(effort)
        .with_fallbacks(fallbacks);
    if let Some(base_url) = setting(env, ANTHROPIC_BASE_URL_ENV) {
        provider = provider.with_base_url(base_url)?;
    }
    Ok(Box::new(provider))
}

#[cfg(not(feature = "anthropic"))]
fn build_anthropic(_model: &str, _env: &dyn EnvSource) -> Result<Box<dyn LlmProvider>, LlmError> {
    Err(LlmError::ProviderUnavailable(ProviderKind::Anthropic))
}

#[cfg(feature = "openai")]
fn build_openai(model: &str, env: &dyn EnvSource) -> Result<Box<dyn LlmProvider>, LlmError> {
    let key = crate::config::require_credential(ProviderKind::OpenAi, env)?;
    let mut provider = crate::providers::openai::OpenAiProvider::new(key, model)?;
    if let Some(base_url) = crate::config::setting(env, OPENAI_BASE_URL_ENV) {
        provider = provider.with_base_url(base_url)?;
    }
    Ok(Box::new(provider))
}

#[cfg(not(feature = "openai"))]
fn build_openai(_model: &str, _env: &dyn EnvSource) -> Result<Box<dyn LlmProvider>, LlmError> {
    Err(LlmError::ProviderUnavailable(ProviderKind::OpenAi))
}

#[cfg(feature = "ollama")]
fn build_ollama(model: &str, env: &dyn EnvSource) -> Result<Box<dyn LlmProvider>, LlmError> {
    // Ollama needs no key. An unset or blank OLLAMA_HOST means the local
    // default, which the provider applies.
    let host =
        crate::config::setting(env, ProviderKind::Ollama.credential_env_var()).unwrap_or_default();
    let provider = crate::providers::ollama::OllamaProvider::new(host, model)?;
    Ok(Box::new(provider))
}

#[cfg(not(feature = "ollama"))]
fn build_ollama(_model: &str, _env: &dyn EnvSource) -> Result<Box<dyn LlmProvider>, LlmError> {
    Err(LlmError::ProviderUnavailable(ProviderKind::Ollama))
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
    fn builds_a_mock_provider_without_credentials() {
        let provider = build_provider(ProviderKind::Mock, Some("test-model"), &env(&[]))
            .expect("mock always builds");
        assert_eq!(provider.kind(), ProviderKind::Mock);
        assert_eq!(provider.model(), "test-model");
    }

    #[test]
    fn uncompiled_network_provider_reports_unavailable() {
        // In the default test build no network provider is compiled in, so each
        // one reports itself unavailable rather than panicking.
        for kind in ProviderKind::NETWORK_PROVIDERS {
            if !kind.is_compiled_in() {
                match build_provider(kind, None, &env(&[])) {
                    Err(LlmError::ProviderUnavailable(_)) => {}
                    Ok(_) => panic!("an uncompiled provider should not build"),
                    Err(other) => panic!("expected ProviderUnavailable, got {other}"),
                }
            }
        }
    }

    #[cfg(feature = "anthropic")]
    #[test]
    fn anthropic_defaults_to_claude_opus_5_and_honors_the_model_setting() {
        let keyed = env(&[("ANTHROPIC_API_KEY", "sk-test")]);
        let provider = build_provider(ProviderKind::Anthropic, None, &keyed).expect("builds");
        assert_eq!(provider.model(), "claude-opus-5");
        assert_eq!(provider.cache_scope()["effort"], serde_json::Value::Null);
        assert_eq!(provider.cache_scope()["fallbacks"], serde_json::json!(true));

        let configured = env(&[
            ("ANTHROPIC_API_KEY", "sk-test"),
            ("SEXTANT_ANTHROPIC_MODEL", "claude-sonnet-5"),
            ("SEXTANT_ANTHROPIC_EFFORT", "high"),
            ("SEXTANT_ANTHROPIC_FALLBACKS", "off"),
        ]);
        let provider = build_provider(ProviderKind::Anthropic, None, &configured).expect("builds");
        assert_eq!(provider.model(), "claude-sonnet-5");
        assert_eq!(provider.cache_scope()["effort"], serde_json::json!("high"));
        assert_eq!(
            provider.cache_scope()["fallbacks"],
            serde_json::json!(false)
        );
    }

    #[cfg(feature = "anthropic")]
    #[test]
    fn an_invalid_anthropic_setting_is_a_config_error() {
        for (key, value) in [
            ("SEXTANT_ANTHROPIC_EFFORT", "extreme"),
            ("SEXTANT_ANTHROPIC_FALLBACKS", "maybe"),
        ] {
            let bad = env(&[("ANTHROPIC_API_KEY", "sk-test"), (key, value)]);
            match build_provider(ProviderKind::Anthropic, None, &bad) {
                Err(LlmError::Config(message)) => assert!(message.contains(key), "{message}"),
                Err(other) => panic!("expected a config error, got {other}"),
                Ok(_) => panic!("{key}={value} was accepted"),
            }
        }
    }

    #[cfg(feature = "openai")]
    #[test]
    fn openai_has_a_verified_default_model() {
        let keyed = env(&[("OPENAI_API_KEY", "sk-test")]);
        let provider = build_provider(ProviderKind::OpenAi, None, &keyed).expect("builds");
        assert_eq!(provider.model(), "gpt-6-luna");
    }

    #[cfg(feature = "ollama")]
    #[test]
    fn ollama_requires_a_model_and_defaults_to_loopback() {
        match build_provider(ProviderKind::Ollama, None, &env(&[])) {
            Err(LlmError::MissingModel { env_var, .. }) => {
                assert_eq!(env_var, "SEXTANT_OLLAMA_MODEL");
            }
            Err(other) => panic!("expected MissingModel, got {other}"),
            Ok(_) => panic!("ollama built without a model"),
        }
        // With a model but no OLLAMA_HOST, the documented loopback default is
        // used instead of an error.
        let provider = build_provider(
            ProviderKind::Ollama,
            None,
            &env(&[("SEXTANT_OLLAMA_MODEL", "qwen3")]),
        )
        .expect("builds with the default host");
        assert_eq!(provider.model(), "qwen3");
        assert_eq!(
            provider.cache_scope()["endpoint"],
            serde_json::json!("http://127.0.0.1:11434")
        );
    }
}
