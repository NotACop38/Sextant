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

// Test support shared by every provider's tests. A build with only some
// providers enabled does not use every helper.
#[cfg(all(test, feature = "http"))]
#[allow(dead_code)]
mod fake_server;
