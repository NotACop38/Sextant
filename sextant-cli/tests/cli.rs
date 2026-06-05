//! Integration tests for the `sextant` binary skeleton.
//!
//! These run the compiled binary so that `--version`, `--help`, and the
//! stubbed subcommands are exercised exactly as a user would invoke them.

use std::process::Command;

fn sextant() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sextant"))
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
