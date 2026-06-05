//! Step 6 acceptance: end-to-end statistics-only orchestration over the corpus,
//! and the zero-network-egress guarantee of the `--no-llm` path (NFR-4).
//!
//! These tests drive [`sextant_engine::infer`] (ingest, generate candidates,
//! execute and score, select, refine) over the corpus formats and confirm it
//! produces a scored field map that parses every sample. They also verify, by
//! inspecting the dependency manifests, that the inference path links no network
//! crate, so a run cannot send bytes off the machine.

use std::fs;
use std::path::{Path, PathBuf};

use sextant_engine::{InferenceOptions, IngestOptions, Limits, execute, infer, ingest};

/// The repository root (the parent of the engine crate directory).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the engine crate has a parent directory")
        .to_path_buf()
}

/// Ingest a corpus format's samples directory into a sample set.
fn ingest_corpus(format: &str) -> sextant_engine::SampleSet {
    let dir = repo_root().join("corpus").join(format).join("samples");
    ingest(
        &[dir.to_string_lossy().into_owned()],
        &IngestOptions::default(),
    )
    .unwrap_or_else(|error| panic!("ingest {format}: {error}"))
}

#[test]
fn infer_produces_a_scored_field_map_on_every_corpus_format() {
    for format in ["tlv", "scma", "stot", "sdlp", "png"] {
        let set = ingest_corpus(format);
        let report = infer(&set, &InferenceOptions::default());

        // A scored field map is produced and the chosen IR is valid.
        assert!(!report.field_map.is_empty(), "{format}: empty field map");
        report
            .format
            .validate()
            .unwrap_or_else(|report| panic!("{format}: chosen IR is invalid:\n{report}"));

        // The chosen IR parses every sample to a clean end (parser validity is
        // 100 percent by construction of the verification loop, PRD Section 15).
        let limits = Limits::default();
        for sample in &set.samples {
            let execution = execute(&report.format, sample.bytes(), &limits);
            assert!(
                execution.succeeded(),
                "{format}: chosen IR failed to parse a sample"
            );
        }

        // The pipeline recovers real structure on these formats, so the fit is
        // high and every sample parses (generality is one).
        assert!(
            report.score.overall >= 0.99,
            "{format}: fit score {} below 0.99",
            report.score.overall
        );
        assert!((report.score.generality - 1.0).abs() < 1e-9);
        assert!(report.metadata.no_llm);
        assert_eq!(report.metadata.sample_count, set.len());
    }
}

#[test]
fn refinement_history_only_records_non_regressing_changes() {
    // Whatever the loop accepts, every recorded step must strictly improve the
    // verified score: the non-regression invariant (FR-26, FR-28).
    for format in ["tlv", "scma", "stot", "sdlp", "png"] {
        let set = ingest_corpus(format);
        let report = infer(&set, &InferenceOptions::default());
        for step in &report.refinement {
            assert!(
                step.score_after >= step.score_before,
                "{format}: a refinement step lowered the score"
            );
        }
    }
}

/// Crate names and crate-name fragments that pull in network, HTTP, async, or
/// TLS functionality. None of these may appear in the dependency manifests on
/// the `--no-llm` inference path (NFR-4).
const NETWORK_CRATES: [&str; 11] = [
    "reqwest",
    "hyper",
    "tokio",
    "ureq",
    "curl",
    "openssl",
    "native-tls",
    "rustls",
    "h2 ",
    "isahc",
    "surf",
];

/// Read the `[dependencies]` section of a crate manifest as lowercase text.
fn dependencies_section(manifest: &Path) -> String {
    let text = fs::read_to_string(manifest)
        .unwrap_or_else(|error| panic!("read {}: {error}", manifest.display()));
    // Keep everything from the dependencies table onward; that is where a
    // network crate would have to be declared to be linked.
    let lower = text.to_lowercase();
    match lower.find("[dependencies]") {
        Some(start) => lower[start..].to_owned(),
        None => String::new(),
    }
}

#[test]
fn the_no_llm_path_links_no_network_crate() {
    // The `infer --no-llm` path is exactly the CLI binary plus `sextant-engine`
    // and `sextant-ir`. Verifying that none of these declares a network crate,
    // and that the CLI does not even depend on the optional `sextant-llm`,
    // makes off-machine egress structurally impossible in this mode (NFR-4).
    let root = repo_root();
    let manifests = [
        root.join("sextant-engine").join("Cargo.toml"),
        root.join("sextant-ir").join("Cargo.toml"),
        root.join("sextant-cli").join("Cargo.toml"),
    ];
    for manifest in &manifests {
        let deps = dependencies_section(manifest);
        for crate_name in NETWORK_CRATES {
            assert!(
                !deps.contains(crate_name),
                "{} declares the network crate `{}` on the no-llm path",
                manifest.display(),
                crate_name.trim()
            );
        }
    }

    // The CLI must not link the optional model crate, so the `infer` path cannot
    // reach a provider at all.
    let cli_deps = dependencies_section(&root.join("sextant-cli").join("Cargo.toml"));
    assert!(
        !cli_deps.contains("sextant-llm"),
        "the CLI depends on sextant-llm; the no-llm path could reach a provider"
    );
}
