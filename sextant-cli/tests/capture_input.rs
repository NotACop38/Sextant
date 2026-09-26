//! Regressions for the capture-input path, command-line exit codes, and the
//! escaping of user-controlled text in `sextant` output.
//!
//! Capture inputs go through the same ingestion as sample files: caps and their
//! notices, directories, globs, `-r`, de-duplication, and refusal of FIFOs.
//! Usage errors exit 1 (PRD Section 14), and hostile file names or arguments
//! cannot inject terminal control sequences.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

fn sextant() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sextant"))
}

fn corpus(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the cli crate has a parent directory")
        .join("corpus")
        .join(relative)
}

fn modbus_capture() -> PathBuf {
    corpus("modbus/samples/session_01.pcap")
}

/// A scratch directory under the system temp directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sextant-cli-capture-{tag}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run the binary, killing it and failing the test if it does not finish
/// within a generous bound, so a blocking read fails instead of hanging.
fn run_bounded(command: &mut Command) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sextant");
    let started = Instant::now();
    loop {
        if child.try_wait().expect("poll sextant").is_some() {
            return child.wait_with_output().expect("collect output");
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            panic!("sextant did not finish; it blocked on its input");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn infer_capture(inputs: &[&Path], extra: &[&str]) -> Output {
    let mut command = sextant();
    command.arg("infer");
    for input in inputs {
        command.arg(input);
    }
    command.args(["--transport", "tcp", "--port", "502"]);
    command.args(extra);
    run_bounded(&mut command)
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_clipped_capture_is_reported_instead_of_silently_losing_messages() {
    let output = infer_capture(&[&modbus_capture()], &["--max-bytes-per-sample", "1000"]);
    let text = stdout(&output);
    assert!(
        text.contains("clipped to 1000 of 1995 bytes"),
        "stdout was: {text}"
    );
    assert!(
        text.contains("truncated or corrupt at byte offset"),
        "{text}"
    );
    assert!(text.contains("Extracted 11 tcp message(s)"), "{text}");
}

#[test]
fn the_message_cap_note_appears_only_when_messages_were_ignored() {
    let exact = infer_capture(&[&modbus_capture()], &["--max-messages", "24"]);
    assert!(exact.status.success(), "{}", stderr(&exact));
    assert!(
        !stdout(&exact).contains("--max-messages cap"),
        "exactly 24 messages exist: {}",
        stdout(&exact)
    );

    let capped = infer_capture(&[&modbus_capture()], &["--max-messages", "23"]);
    let text = stdout(&capped);
    assert!(
        text.contains("stopped at the --max-messages cap of 23"),
        "{text}"
    );
    assert!(text.contains("Extracted 23 tcp message(s)"), "{text}");
}

#[test]
fn a_capture_named_twice_is_read_once() {
    let capture = modbus_capture();
    let output = infer_capture(&[&capture, &capture], &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Ingested 1 file "), "{text}");
    assert!(text.contains("Extracted 24 tcp message(s)"), "{text}");
}

#[test]
fn captures_can_be_given_as_a_directory_a_glob_or_a_recursive_tree() {
    let samples = corpus("modbus/samples");
    let directory = infer_capture(&[&samples], &[]);
    assert!(directory.status.success(), "{}", stderr(&directory));
    assert!(stdout(&directory).contains("Extracted 24 tcp message(s)"));

    let pattern = PathBuf::from(format!("{}/*.pcap", samples.display()));
    let glob = infer_capture(&[&pattern], &[]);
    assert!(glob.status.success(), "{}", stderr(&glob));
    assert!(stdout(&glob).contains("Extracted 24 tcp message(s)"));

    // The tree holds the generator script and ground truth beside the
    // capture; files swept in that are not captures are skipped with a note.
    let tree = corpus("modbus");
    let recursive = infer_capture(&[&tree], &["-r"]);
    assert!(recursive.status.success(), "{}", stderr(&recursive));
    let text = stdout(&recursive);
    assert!(text.contains("Extracted 24 tcp message(s)"), "{text}");
    assert!(
        text.contains("generate.py: skipped, not a pcap or pcapng capture"),
        "{text}"
    );
}

#[test]
fn a_file_named_explicitly_that_is_not_a_capture_is_an_input_error() {
    let output = infer_capture(&[&corpus("modbus/generate.py")], &[]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("not a recognized pcap"));
}

/// Create a FIFO with the system `mkfifo` tool; `false` when it is missing.
#[cfg(unix)]
fn make_fifo(path: &Path) -> bool {
    Command::new("mkfifo")
        .arg(path)
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(unix)]
#[test]
fn a_fifo_capture_argument_is_refused_without_blocking() {
    let scratch = Scratch::new("fifo");
    let fifo = scratch.0.join("capture.pcap");
    if !make_fifo(&fifo) {
        eprintln!("skipping: mkfifo is not available");
        return;
    }
    let output = infer_capture(&[&fifo], &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("not regular files"),
        "stderr was: {}",
        stderr(&output)
    );

    // `inspect` reads its report and sample through the same checked reader.
    let inspect = run_bounded(
        sextant()
            .arg("inspect")
            .arg(&fifo)
            .arg("--sample")
            .arg(corpus("tlv/samples/sample_01.tlv")),
    );
    assert_eq!(inspect.status.code(), Some(2));
    assert!(stderr(&inspect).contains("not a regular file"));
}

#[test]
fn usage_errors_exit_one_and_help_and_version_exit_zero() {
    for args in [
        &["--no-such-flag"][..],
        &[][..],
        &["infer"][..],
        &["infer", "x", "--port", "not-a-port"][..],
    ] {
        let output = run_bounded(sextant().args(args));
        assert_eq!(
            output.status.code(),
            Some(1),
            "`sextant {}` should be a usage error: {}",
            args.join(" "),
            stderr(&output)
        );
    }
    for args in [
        &["--help"][..],
        &["--version"][..],
        &["infer", "--help"][..],
    ] {
        let output = run_bounded(sextant().args(args));
        assert_eq!(
            output.status.code(),
            Some(0),
            "`sextant {}`",
            args.join(" ")
        );
        assert!(!output.stdout.is_empty());
    }
}

/// Whether `text` holds a raw control or bidirectional-override character.
fn has_raw_controls(text: &str) -> bool {
    text.chars().any(|c| {
        (c.is_control() && c != '\n')
            || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    })
}

#[test]
fn a_hostile_argument_in_a_usage_error_is_escaped() {
    // A title-setting escape sequence, a carriage return, and a right-to-left
    // override: none may reach the terminal raw.
    let output = run_bounded(sextant().arg("--evil\u{1b}]0;owned\u{7}\r\u{202e}"));
    assert_eq!(output.status.code(), Some(1));
    let text = stderr(&output);
    assert!(!has_raw_controls(&text), "raw controls in: {text:?}");
    assert!(text.contains("\\u{202e}"), "{text:?}");
}

#[test]
fn a_hostile_missing_path_is_escaped_in_the_error() {
    // No glob metacharacter, so this is reported as a literal path.
    let output = run_bounded(sextant().args(["infer", "missing\u{1b}]0;x\u{7}\u{2066}.bin"]));
    assert_eq!(output.status.code(), Some(2));
    let text = stderr(&output);
    assert!(!has_raw_controls(&text), "raw controls in: {text:?}");
    assert!(
        text.contains("missing\\u{1b}]0;x\\u{7}\\u{2066}.bin"),
        "{text:?}"
    );
}

#[cfg(unix)]
#[test]
fn hostile_sample_file_names_are_escaped_in_the_listing() {
    let scratch = Scratch::new("hostile");
    let name = "evil\u{1b}[31m\u{202e}nib.exe";
    if std::fs::write(scratch.0.join(name), b"STLV-like bytes").is_err() {
        eprintln!("skipping: the filesystem refused the name");
        return;
    }
    let output = run_bounded(sextant().arg("infer").arg(&scratch.0));
    let text = stdout(&output);
    assert!(!has_raw_controls(&text), "raw controls in: {text:?}");
    assert!(
        text.contains("evil\\u{1b}[31m\\u{202e}nib.exe"),
        "stdout was: {text:?}"
    );
}
