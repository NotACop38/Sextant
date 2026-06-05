//! Integration tests for the `sextant` binary skeleton.
//!
//! These run the compiled binary so that `--version`, `--help`, and the
//! stubbed subcommands are exercised exactly as a user would invoke them.

use std::path::PathBuf;
use std::process::Command;

fn sextant() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sextant"))
}

/// Absolute path to a corpus directory, resolved from the workspace root so the
/// test does not depend on the working directory.
fn corpus_dir(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the cli crate has a parent directory")
        .join("corpus")
        .join(relative)
}

#[test]
fn version_flag_prints_version() {
    let output = sextant()
        .arg("--version")
        .output()
        .expect("run sextant --version");
    assert!(output.status.success(), "--version should exit zero");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sextant"), "version output was: {stdout}");
}

#[test]
fn help_flag_lists_all_subcommands() {
    let output = sextant()
        .arg("--help")
        .output()
        .expect("run sextant --help");
    assert!(output.status.success(), "--help should exit zero");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for subcommand in ["infer", "inspect", "export", "bench"] {
        assert!(
            stdout.contains(subcommand),
            "help is missing `{subcommand}`:\n{stdout}"
        );
    }
}

#[test]
fn stub_subcommand_reports_not_implemented() {
    let output = sextant().arg("bench").output().expect("run sextant bench");
    assert!(
        !output.status.success(),
        "a stubbed subcommand should exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not yet implemented"),
        "stderr was: {stderr}"
    );
}

#[test]
fn infer_ingests_a_directory_and_reports_count_and_sizes() {
    let samples = corpus_dir("tlv/samples");
    let output = sextant()
        .arg("infer")
        .arg(&samples)
        .output()
        .expect("run sextant infer on a corpus directory");
    assert!(
        output.status.success(),
        "infer should succeed on the corpus, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The TLV corpus has three samples; their sizes are reported in bytes.
    assert!(
        stdout.contains("Ingested 3 samples"),
        "stdout was: {stdout}"
    );
    assert!(stdout.contains("bytes"), "stdout was: {stdout}");
    assert!(
        stdout.contains("sample_01.tlv"),
        "each sample path is listed, stdout was: {stdout}"
    );
}

#[test]
fn infer_writes_a_report_that_inspect_can_render() {
    let samples = corpus_dir("tlv/samples");
    let report_path =
        std::env::temp_dir().join(format!("sextant-test-report-{}.json", std::process::id()));

    let infer = sextant()
        .arg("infer")
        .arg(&samples)
        .arg("--out")
        .arg(&report_path)
        .output()
        .expect("run sextant infer with --out");
    assert!(
        infer.status.success(),
        "infer --out should succeed, stderr: {}",
        String::from_utf8_lossy(&infer.stderr)
    );
    assert!(report_path.exists(), "infer should write the report file");

    let inspect = sextant()
        .arg("inspect")
        .arg(&report_path)
        .arg("--sample")
        .arg(corpus_dir("tlv/samples/sample_01.tlv"))
        .output()
        .expect("run sextant inspect");
    assert!(
        inspect.status.success(),
        "inspect should succeed, stderr: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let stdout = String::from_utf8_lossy(&inspect.stdout);
    assert!(stdout.contains("Offset"), "inspect output was: {stdout}");
    assert!(stdout.contains("Hex:"), "inspect output was: {stdout}");
    // The annotated hex dump shows the magic bytes in the ascii gutter.
    assert!(stdout.contains("STLV"), "inspect output was: {stdout}");

    let _ = std::fs::remove_file(&report_path);
}

#[test]
fn inspect_on_a_missing_report_is_an_input_error() {
    let output = sextant()
        .arg("inspect")
        .arg("this/report/does/not/exist.json")
        .arg("--sample")
        .arg(corpus_dir("tlv/samples/sample_01.tlv"))
        .output()
        .expect("run sextant inspect on a missing report");
    assert_eq!(
        output.status.code(),
        Some(2),
        "a missing report should exit with the PRD input-error code"
    );
}

#[test]
fn infer_on_a_missing_path_is_an_input_error() {
    let output = sextant()
        .arg("infer")
        .arg("this/path/does/not/exist.bin")
        .output()
        .expect("run sextant infer on a missing path");
    assert_eq!(
        output.status.code(),
        Some(2),
        "a missing input should exit with the PRD input-error code"
    );
}
