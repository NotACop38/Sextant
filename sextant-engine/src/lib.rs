//! Inference engine for Sextant.
//!
//! This crate will hold sample ingestion, the statistical inference pass, the
//! native IR executor and scorer (the verification substrate), and the
//! refinement loop. The executor and scorer must stay native Rust, free of any
//! JVM, the Kaitai compiler, or network access, and must run under `--no-llm`
//! and offline.
//!
//! The implementation lands in later checklist steps (Steps 3 to 6). This file
//! currently only establishes the crate so the workspace builds and lints
//! cleanly.
