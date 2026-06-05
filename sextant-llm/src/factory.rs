//! Construct a boxed provider from a resolved [`ProviderKind`].
//!
//! This is the single seam the rest of the program uses to obtain a provider.
//! It compiles regardless of which provider features are enabled: a request for
//! a provider that was not compiled in returns [`LlmError::ProviderUnavailable`]
//! rather than failing to build.

use crate::config::{EnvSource, ProviderKind};
use crate::error::LlmError;
use crate::mock::MockProvider;
use crate::provider::LlmProvider;

/// Build a provider for `kind`, reading any required credential from `env`
/// (FR-40). When `model` is `None`, the provider's default model is used.
pub fn build_provider(
    kind: ProviderKind,
    model: Option<&str>,
    env: &dyn EnvSource,
) -> Result<Box<dyn LlmProvider>, LlmError> {
    let model = model.unwrap_or(kind.default_model()).to_string();
    match kind {
        ProviderKind::Mock => Ok(Box::new(MockProvider::new(model))),
        ProviderKind::Anthropic => build_anthropic(&model, env),
        ProviderKind::OpenAi => build_openai(&model, env),
        ProviderKind::Ollama => build_ollama(&model, env),
    }
}

#[cfg(feature = "anthropic")]
fn build_anthropic(model: &str, env: &dyn EnvSource) -> Result<Box<dyn LlmProvider>, LlmError> {
    let key = crate::config::require_credential(ProviderKind::Anthropic, env)?;
    let provider = crate::providers::anthropic::AnthropicProvider::new(key, model)?;
    Ok(Box::new(provider))
}

#[cfg(not(feature = "anthropic"))]
fn build_anthropic(_model: &str, _env: &dyn EnvSource) -> Result<Box<dyn LlmProvider>, LlmError> {
    Err(LlmError::ProviderUnavailable(ProviderKind::Anthropic))
}

#[cfg(feature = "openai")]
fn build_openai(model: &str, env: &dyn EnvSource) -> Result<Box<dyn LlmProvider>, LlmError> {
    let key = crate::config::require_credential(ProviderKind::OpenAi, env)?;
    let provider = crate::providers::openai::OpenAiProvider::new(key, model)?;
    Ok(Box::new(provider))
}

#[cfg(not(feature = "openai"))]
fn build_openai(_model: &str, _env: &dyn EnvSource) -> Result<Box<dyn LlmProvider>, LlmError> {
    Err(LlmError::ProviderUnavailable(ProviderKind::OpenAi))
}

#[cfg(feature = "ollama")]
fn build_ollama(model: &str, env: &dyn EnvSource) -> Result<Box<dyn LlmProvider>, LlmError> {
    let host = crate::config::require_credential(ProviderKind::Ollama, env)?;
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

    #[test]
    fn builds_a_mock_provider_without_credentials() {
        let env: HashMap<String, String> = HashMap::new();
        let provider = build_provider(ProviderKind::Mock, Some("test-model"), &env)
            .expect("mock always builds");
        assert_eq!(provider.kind(), ProviderKind::Mock);
        assert_eq!(provider.model(), "test-model");
    }

    #[test]
    fn uncompiled_network_provider_reports_unavailable() {
        let env: HashMap<String, String> = HashMap::new();
        // In the default test build no network provider is compiled in, so each
        // one reports itself unavailable rather than panicking.
        for kind in ProviderKind::NETWORK_PROVIDERS {
            if !kind.is_compiled_in() {
                match build_provider(kind, None, &env) {
                    Err(LlmError::ProviderUnavailable(_)) => {}
                    Ok(_) => panic!("an uncompiled provider should not build"),
                    Err(other) => panic!("expected ProviderUnavailable, got {other}"),
                }
            }
        }
    }
}
