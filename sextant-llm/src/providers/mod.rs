//! First-class and optional network providers, each behind a feature flag.
//!
//! These modules are the only place a real network call is made, and they are
//! compiled only when their feature is enabled. The default build, and CI's
//! default test run, contain none of this code (FR-32).

#[cfg(feature = "anthropic")]
pub mod anthropic;
#[cfg(feature = "ollama")]
pub mod ollama;
#[cfg(feature = "openai")]
pub mod openai;

#[cfg(feature = "http")]
mod http;
