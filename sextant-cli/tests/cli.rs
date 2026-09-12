//! Integration tests for the `sextant` binary skeleton.
//!
//! These run the compiled binary so that `--version`, `--help`, and the
//! subcommands are exercised exactly as a user would invoke them.

use std::path::PathBuf;
use std::process::Command;

fn sextant() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sextant"))
}

#[test]
fn zero_timeout_writes_diagnostics_but_does_not_report_inference_success() {
    let dir = std::env::temp_dir().join(format!("sextant-zero-timeout-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let output = sextant()
        .current_dir(&dir)
        .arg("infer")
        .arg(corpus_dir("tlv/samples"))
        .args(["--timeout", "0", "--out", "report.json"])
        .output()
        .unwrap();
    let report_exists = dir.join("report.json").is_file();
    std::fs::remove_dir_all(dir).unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        report_exists,
        "failed verification must retain a diagnostic report"
    );
}

#[test]
fn output_creation_refuses_an_existing_file_and_preserves_its_bytes() {
    let dir = std::env::temp_dir().join(format!("sextant-output-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("report.json");
    std::fs::write(&out, b"keep this content").unwrap();
    let result = sextant()
        .current_dir(&dir)
        .args(["infer"])
        .arg(corpus_dir("tlv/samples"))
        .args(["--out", "report.json"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(std::fs::read(&out).unwrap(), b"keep this content");
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn output_creation_refuses_a_dangling_symlink_outside_the_working_directory() {
    let dir = std::env::temp_dir().join(format!("sextant-output-link-{}", std::process::id()));
    let cwd = dir.join("work");
    std::fs::create_dir_all(&cwd).unwrap();
    let outside = dir.join("outside.json");
    std::os::unix::fs::symlink(&outside, cwd.join("report.json")).unwrap();
    let result = sextant()
        .current_dir(&cwd)
        .arg("infer")
        .arg(corpus_dir("tlv/samples"))
        .args(["--out", "report.json"])
        .output()
        .unwrap();
    let escaped = outside.exists();
    std::fs::remove_dir_all(dir).unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(
        !escaped,
        "an output symlink must not create an outside file"
    );
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
fn bench_runs_over_the_corpus_and_prints_a_metrics_table() {
    let output = sextant().arg("bench").output().expect("run sextant bench");
    assert!(
        output.status.success(),
        "bench should exit zero when the corpus meets its targets; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The table reports every PRD Section 15 metric and the per-format rows.
    for token in ["format", "f1", "perfect", "role", "type", "valid", "macro"] {
        assert!(
            stdout.contains(token),
            "metrics table is missing `{token}`:\n{stdout}"
        );
    }
    assert!(
        stdout.contains("field-boundary F1"),
        "metrics table is missing the targets block:\n{stdout}"
    );
}

#[test]
fn bench_writes_machine_readable_results() {
    let dir = std::env::temp_dir().join(format!("sextant-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let out = dir.join("results.json");
    let output = sextant()
        .arg("bench")
        .arg("--out")
        .arg(&out)
        .arg("--force")
        .output()
        .expect("run sextant bench --out");
    assert!(output.status.success(), "bench --out should exit zero");
    let json = std::fs::read_to_string(&out).expect("results.json written");
    assert!(json.contains("\"boundary_f1\""), "results JSON: {json}");
    assert!(json.contains("\"parser_validity\""), "results JSON: {json}");
    std::fs::remove_dir_all(&dir).ok();
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
        .arg("--force")
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
fn export_emits_a_parser_for_every_format() {
    let samples = corpus_dir("tlv/samples");
    let report_path =
        std::env::temp_dir().join(format!("sextant-export-report-{}.json", std::process::id()));
    let infer = sextant()
        .arg("infer")
        .arg(&samples)
        .arg("--out")
        .arg(&report_path)
        .arg("--force")
        .output()
        .expect("run sextant infer with --out");
    assert!(infer.status.success(), "infer --out should succeed");

    for (format, marker) in [
        ("kaitai", "meta:"),
        ("imhex", "#pragma endian"),
        ("wireshark", "Proto("),
        ("010", "struct"),
    ] {
        let output = sextant()
            .arg("export")
            .arg(&report_path)
            .arg("--format")
            .arg(format)
            .output()
            .unwrap_or_else(|error| panic!("run sextant export --format {format}: {error}"));
        assert!(
            output.status.success(),
            "export --format {format} should succeed, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(marker),
            "export --format {format} output is missing `{marker}`:\n{stdout}"
        );
    }

    let _ = std::fs::remove_file(&report_path);
}

#[test]
fn export_with_an_unknown_format_is_an_export_error() {
    let samples = corpus_dir("tlv/samples");
    let report_path =
        std::env::temp_dir().join(format!("sextant-export-bad-{}.json", std::process::id()));
    let infer = sextant()
        .arg("infer")
        .arg(&samples)
        .arg("--out")
        .arg(&report_path)
        .arg("--force")
        .output()
        .expect("run sextant infer with --out");
    assert!(infer.status.success(), "infer --out should succeed");

    let output = sextant()
        .arg("export")
        .arg(&report_path)
        .arg("--format")
        .arg("nonsense")
        .output()
        .expect("run sextant export with a bad format");
    assert_eq!(
        output.status.code(),
        Some(4),
        "an unknown export format should exit with the PRD export-error code"
    );

    let _ = std::fs::remove_file(&report_path);
}

#[test]
fn infer_on_a_capture_produces_a_field_map_and_a_wireshark_dissector() {
    // Step 11 acceptance: infer over a Modbus/TCP capture with a transport and
    // port, then export a Wireshark dissector that decodes the capture.
    let capture = corpus_dir("modbus/samples/session_01.pcap");
    let report_path =
        std::env::temp_dir().join(format!("sextant-modbus-{}.json", std::process::id()));

    let infer = sextant()
        .arg("infer")
        .arg(&capture)
        .arg("--transport")
        .arg("tcp")
        .arg("--port")
        .arg("502")
        .arg("--out")
        .arg(&report_path)
        .arg("--force")
        .output()
        .expect("run sextant infer on a capture");
    assert!(
        infer.status.success(),
        "protocol infer should succeed, stderr: {}",
        String::from_utf8_lossy(&infer.stderr)
    );
    let stdout = String::from_utf8_lossy(&infer.stdout);
    // The field map names the protocol-oriented roles.
    assert!(stdout.contains("message type"), "stdout was: {stdout}");
    assert!(stdout.contains("sequence"), "stdout was: {stdout}");
    assert!(stdout.contains("length"), "stdout was: {stdout}");
    assert!(
        stdout.contains("Message clustering"),
        "stdout was: {stdout}"
    );

    let export = sextant()
        .arg("export")
        .arg(&report_path)
        .arg("--format")
        .arg("wireshark")
        .output()
        .expect("run sextant export --format wireshark");
    assert!(
        export.status.success(),
        "wireshark export should succeed, stderr: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    let dissector = String::from_utf8_lossy(&export.stdout);
    // The dissector reads the inferred fields and binds to the capture's port,
    // so loading it decodes the capture.
    assert!(
        dissector.contains("message_type"),
        "dissector was: {dissector}"
    );
    assert!(
        dissector.contains("DissectorTable.get(\"tcp.port\"):add(502"),
        "the dissector should bind to tcp port 502: {dissector}"
    );

    let _ = std::fs::remove_file(&report_path);
}

#[test]
fn infer_with_transport_but_no_port_is_an_input_error() {
    let capture = corpus_dir("modbus/samples/session_01.pcap");
    let output = sextant()
        .arg("infer")
        .arg(&capture)
        .arg("--transport")
        .arg("tcp")
        .output()
        .expect("run sextant infer with a transport but no port");
    assert_eq!(
        output.status.code(),
        Some(2),
        "a transport without a port should exit with the PRD input-error code"
    );
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
fn inspect_on_a_corrupt_report_is_an_input_error() {
    // A report the user hand-edited into invalid JSON must produce a clear
    // input error, never a panic or a stack trace.
    let report_path = std::env::temp_dir().join(format!(
        "sextant-corrupt-report-{}.json",
        std::process::id()
    ));
    std::fs::write(&report_path, "{ \"this is\": not valid json").expect("write corrupt report");

    let output = sextant()
        .arg("inspect")
        .arg(&report_path)
        .arg("--sample")
        .arg(corpus_dir("tlv/samples/sample_01.tlv"))
        .output()
        .expect("run sextant inspect on a corrupt report");
    assert_eq!(
        output.status.code(),
        Some(2),
        "a corrupt report should exit with the PRD input-error code"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not a valid report"),
        "stderr should explain the report is invalid, got: {stderr}"
    );

    let _ = std::fs::remove_file(&report_path);
}

#[test]
fn export_on_a_corrupt_report_is_an_input_error() {
    let report_path = std::env::temp_dir().join(format!(
        "sextant-corrupt-export-{}.json",
        std::process::id()
    ));
    std::fs::write(&report_path, "[1, 2, 3]").expect("write corrupt report");

    let output = sextant()
        .arg("export")
        .arg(&report_path)
        .arg("--format")
        .arg("kaitai")
        .output()
        .expect("run sextant export on a corrupt report");
    assert_eq!(
        output.status.code(),
        Some(2),
        "a corrupt report should exit with the PRD input-error code"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not a valid report"),
        "stderr should explain the report is invalid, got: {stderr}"
    );

    let _ = std::fs::remove_file(&report_path);
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
