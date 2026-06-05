//! Provider-agnostic language-model interface for Sextant.
//!
//! This crate will define the `LlmProvider` trait and its reference
//! implementations (Anthropic and OpenAI first-class, Ollama optional). The
//! language-model pass is always optional: `--no-llm` bypasses it entirely and
//! transmits nothing off the machine. Every model proposal is verified by the
//! native executor before it can be accepted, so the model never overrides
//! verification.
//!
//! The implementation lands in later checklist steps (Steps 8 and 9). This file
//! currently only establishes the crate so the workspace builds and lints
//! cleanly.
