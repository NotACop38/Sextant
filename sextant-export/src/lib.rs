//! Exporters for Sextant.
//!
//! This crate will turn a verified Format Hypothesis IR into editable parsers:
//! Kaitai Struct (the primary export and cross-validation target), ImHex
//! patterns, Wireshark Lua dissectors, and 010 Editor templates. Exporters
//! read the IR only; they never bypass it.
//!
//! The implementation lands in a later checklist step (Step 10). This file
//! currently only establishes the crate so the workspace builds and lints
//! cleanly.
