//! The opt-in model path of `sextant infer --provider` (PRD Section 12).
//!
//! No provider is constructed unless `--provider` names one, so a run without
//! it, or with `--no-llm`, cannot send a request anywhere (NFR-4). A build
//! without the `llm` feature contains no network code at all, and `--provider`
//! then fails with an explanation instead of silently running offline.
//!
//! The model only proposes. [`sextant_engine::infer_with_llm`] applies each
//! proposal through the native executor and scorer and keeps it only when the
//! verified fit does not regress (FR-26, FR-31); when the call fails, the run
//! keeps the statistics-only result and the report records why.

use sextant_engine::{InferenceOptions, Report, SampleSet};

/// What the command line asked of the model.
// A build without providers only reports that it cannot consult one.
#[cfg_attr(not(feature = "llm"), allow(dead_code))]
pub(crate) struct ModelRequest<'a> {
    /// The provider name: anthropic, openai, or ollama.
    pub(crate) provider: &'a str,
    /// The model identifier, or `None` for the provider's default.
    pub(crate) model: Option<&'a str>,
    /// The most model calls the run may make.
    pub(crate) max_calls: u32,
}

/// A provider ready to be consulted, with its call cap.
#[cfg(feature = "llm")]
pub(crate) struct Model {
    client: sextant_llm::LlmClient<Box<dyn sextant_llm::LlmProvider>>,
}

#[cfg(feature = "llm")]
impl Model {
    /// Resolve and build the requested provider, reading its credential and
    /// settings from the environment or the Sextant config file, never from a
    /// flag (FR-40).
    ///
    /// # Errors
    ///
    /// Returns a message for an unknown provider, a missing credential or
    /// model, an unusable config file, or an invalid setting.
    pub(crate) fn prepare(request: &ModelRequest<'_>) -> Result<Self, String> {
        use sextant_llm::{
            CallLimits, LlmClient, ProviderKind, build_provider, default_secret_source,
            resolve_provider,
        };
        let kind: ProviderKind = request
            .provider
            .parse()
            .map_err(|error| format!("{error}"))?;
        if kind == ProviderKind::Mock {
            return Err(
                "unknown provider `mock`: expected anthropic, openai, or ollama".to_owned(),
            );
        }
        let env = default_secret_source().map_err(|error| error.to_string())?;
        let kind = resolve_provider(Some(kind), &env).map_err(|error| error.to_string())?;
        let provider =
            build_provider(kind, request.model, &env).map_err(|error| error.to_string())?;
        let client = LlmClient::new(provider).with_limits(CallLimits {
            max_calls: Some(request.max_calls),
            budget: None,
        });
        Ok(Self { client })
    }

    /// Run inference, then the semantic pass through the executor's gate.
    pub(crate) fn infer(&self, set: &SampleSet, options: &InferenceOptions) -> Report {
        sextant_engine::infer_with_llm(
            set,
            options,
            &self.client,
            &sextant_engine::SemanticOptions::default(),
        )
    }
}

/// Stands in for a provider in a build without the `llm` feature.
#[cfg(not(feature = "llm"))]
pub(crate) struct Model;

#[cfg(not(feature = "llm"))]
impl Model {
    /// A build without providers cannot consult a model.
    ///
    /// # Errors
    ///
    /// Always, with a message that names the feature to enable.
    pub(crate) fn prepare(_request: &ModelRequest<'_>) -> Result<Self, String> {
        Err(
            "this build of sextant has no model providers; rebuild it with `--features llm` \
             to use --provider"
                .to_owned(),
        )
    }

    /// Unreachable in practice, since [`Model::prepare`] never succeeds; runs
    /// the statistics-only pipeline so it can never send anything.
    pub(crate) fn infer(&self, set: &SampleSet, options: &InferenceOptions) -> Report {
        sextant_engine::infer(set, options)
    }
}
