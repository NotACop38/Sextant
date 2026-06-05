//! Format Hypothesis IR for Sextant.
//!
//! This crate defines the intermediate representation that describes a
//! hypothesized binary format: structures, fields, kinds, size and count
//! rules, roles, constraints, evidence, and confidence. It also provides JSON
//! serialization and IR validation.
//!
//! The concrete types are implemented in a later checklist step (Step 2). This
//! file currently only establishes the crate so the workspace builds and
//! lints cleanly.
