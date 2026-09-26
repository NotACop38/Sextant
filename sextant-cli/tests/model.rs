//! The opt-in model path of `sextant infer --provider`.
//!
//! A local fake Messages API server stands in for the provider, so these tests
//! run offline. They pin that nothing is sent without `--provider`, that the
//! flags refuse contradictory combinations, that a verified proposal reaches
//! the report with its usage, and that a failed call is recorded while the
//! statistics-only result stands.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn sextant() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sextant"))
}

fn corpus_dir(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the CLI crate has a parent directory")
        .join("corpus")
        .join(relative)
}

/// A private scratch directory, used as the working directory and as HOME so
/// no real Sextant config file is read.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sextant-model-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create a scratch directory");
    dir
}

/// Run `sextant` in `dir` with a hermetic environment: no inherited provider
/// credential or config file, plus the given variables.
fn run_in(dir: &PathBuf, args: &[&str], vars: &[(&str, &str)]) -> Output {
    let mut command = sextant();
    command.current_dir(dir).args(args);
    for key in [
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_BASE_URL",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OLLAMA_HOST",
        "SEXTANT_CONFIG",
        "SEXTANT_MODEL_CACHE_DIR",
    ] {
        command.env_remove(key);
    }
    command
        .env("HOME", dir)
        .env("APPDATA", dir)
        .env("SEXTANT_CONFIG", dir.join("no-config"));
    for (key, value) in vars {
        command.env(key, value);
    }
    command.output().expect("run sextant")
}

/// A one-shot fake HTTP server on loopback. Every connection it accepts is
/// answered with `body` as a 200 JSON response, and the raw request is sent on
/// the returned channel, so a test can also prove that no request arrived.
fn fake_server(body: String) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    let address = listener.local_addr().expect("local address");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let request = answer(stream, &body);
            if sender.send(request).is_err() {
                break;
            }
        }
    });
    (format!("http://{address}"), receiver)
}

/// Read one HTTP request (headers and a Content-Length body) and answer it.
fn answer(stream: TcpStream, body: &str) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set a read timeout");
    let mut reader = BufReader::new(stream);
    let mut head = String::new();
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0);
        }
        let done = line == "\r\n";
        head.push_str(&line);
        if done {
            break;
        }
    }
    let mut request_body = vec![0u8; length];
    let _ = reader.read_exact(&mut request_body);
    let mut stream = reader.into_inner();
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    format!("{head}{}", String::from_utf8_lossy(&request_body))
}

/// A Messages API response whose only text block is `text`.
fn message(text: &str) -> String {
    serde_json::json!({
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5",
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "stop_details": null,
        "usage": {"input_tokens": 120, "output_tokens": 45}
    })
    .to_string()
}

#[test]
fn without_provider_nothing_is_sent_even_when_a_key_is_configured() {
    let dir = scratch("opt-in");
    let (base_url, requests) = fake_server(message("{}"));
    let tlv = corpus_dir("tlv/samples");
    let output = run_in(
        &dir,
        &["infer", tlv.to_str().unwrap()],
        &[
            ("ANTHROPIC_API_KEY", "sk-ant-test"),
            ("ANTHROPIC_BASE_URL", &base_url),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("mode: statistics-only"), "{stdout}");
    assert!(
        requests.recv_timeout(Duration::from_millis(300)).is_err(),
        "a request was sent without --provider"
    );
}

#[test]
fn no_llm_and_provider_contradict_each_other() {
    let dir = scratch("conflict");
    let tlv = corpus_dir("tlv/samples");
    let output = run_in(
        &dir,
        &[
            "infer",
            tlv.to_str().unwrap(),
            "--no-llm",
            "--provider",
            "anthropic",
        ],
        &[],
    );
    assert_eq!(output.status.code(), Some(1));
    let output = run_in(
        &dir,
        &["infer", tlv.to_str().unwrap(), "--model", "claude-opus-5"],
        &[],
    );
    assert_eq!(output.status.code(), Some(1), "--model needs --provider");
}

#[cfg(feature = "llm")]
#[test]
fn a_missing_credential_fails_fast_before_any_input_is_read() {
    let dir = scratch("no-key");
    let tlv = corpus_dir("tlv/samples");
    let output = run_in(
        &dir,
        &["infer", tlv.to_str().unwrap(), "--provider", "anthropic"],
        &[],
    );
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ANTHROPIC_API_KEY"), "{stderr}");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("Ingested"),
        "inputs were read before the provider was ready"
    );
    let unknown = run_in(
        &dir,
        &["infer", tlv.to_str().unwrap(), "--provider", "mock"],
        &[],
    );
    assert_eq!(unknown.status.code(), Some(1));
}

#[cfg(feature = "llm")]
#[test]
fn a_verified_model_proposal_reaches_the_report_with_its_usage() {
    let dir = scratch("proposal");
    let proposal = serde_json::json!({
        "format_family": "tlv",
        "fields": [{"index": 0, "name": "signature", "role": "magic"}]
    });
    let (base_url, requests) = fake_server(message(&proposal.to_string()));
    let tlv = corpus_dir("tlv/samples");
    let output = run_in(
        &dir,
        &[
            "infer",
            tlv.to_str().unwrap(),
            "--provider",
            "anthropic",
            "--out",
            "report.json",
        ],
        &[
            ("ANTHROPIC_API_KEY", "sk-ant-test"),
            ("ANTHROPIC_BASE_URL", &base_url),
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("mode: model-assisted"), "{stdout}");
    assert!(
        stdout.contains("model: anthropic claude-opus-5, 1 call(s)"),
        "{stdout}"
    );

    // The request carried the key in its header and at most the capped bytes.
    let request = requests
        .recv_timeout(Duration::from_secs(10))
        .expect("the provider was called");
    assert!(request.contains("x-api-key: sk-ant-test"), "{request}");
    assert!(request.contains("\"model\":\"claude-opus-5\""), "{request}");

    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("report.json")).expect("report written"),
    )
    .expect("report JSON");
    let usage = &report["metadata"]["model"];
    assert_eq!(usage["provider"], "anthropic");
    assert_eq!(usage["calls"], 1);
    assert_eq!(usage["input_tokens"], 120);
    assert_eq!(usage["output_tokens"], 45);
    assert_eq!(report["metadata"]["no_llm"], false);
    assert!(usage.get("error").is_none(), "{usage}");
    assert_eq!(
        report["format"]["metadata"]["extra"]["format_family"],
        "tlv"
    );
    assert_eq!(report["format"]["root"]["fields"][0]["name"], "signature");
}

#[cfg(feature = "llm")]
#[test]
fn a_failed_model_call_is_recorded_and_the_verified_result_stands() {
    let dir = scratch("failure");
    let (base_url, _requests) = fake_server(message("I cannot describe this format."));
    let tlv = corpus_dir("tlv/samples");
    let output = run_in(
        &dir,
        &[
            "infer",
            tlv.to_str().unwrap(),
            "--provider",
            "anthropic",
            "--out",
            "report.json",
        ],
        &[
            ("ANTHROPIC_API_KEY", "sk-ant-test"),
            ("ANTHROPIC_BASE_URL", &base_url),
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("the model contributed nothing"), "{stderr}");
    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("report.json")).expect("report written"),
    )
    .expect("report JSON");
    let usage = &report["metadata"]["model"];
    assert_eq!(usage["accepted"], 0);
    assert!(usage["error"].is_string(), "{usage}");
}

#[cfg(feature = "llm")]
#[test]
fn a_cached_response_answers_a_repeated_run_without_a_request() {
    let dir = scratch("cache");
    let proposal = serde_json::json!({
        "format_family": "tlv",
        "fields": [{"index": 0, "name": "signature", "role": "magic"}]
    });
    let (base_url, requests) = fake_server(message(&proposal.to_string()));
    let tlv = corpus_dir("tlv/samples");
    let cache = dir.join("model-cache");
    let run = |report: &str| {
        run_in(
            &dir,
            &[
                "infer",
                tlv.to_str().unwrap(),
                "--provider",
                "anthropic",
                "--out",
                report,
            ],
            &[
                ("ANTHROPIC_API_KEY", "sk-ant-test"),
                ("ANTHROPIC_BASE_URL", &base_url),
                ("SEXTANT_MODEL_CACHE_DIR", cache.to_str().unwrap()),
            ],
        )
    };
    let read = |name: &str| -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(dir.join(name)).expect("report written"))
            .expect("report JSON")
    };

    let first = run("first.json");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    requests
        .recv_timeout(Duration::from_secs(10))
        .expect("the first run called the provider");

    let second = run("second.json");
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(
        requests.recv_timeout(Duration::from_millis(300)).is_err(),
        "the repeated run called the provider despite the cache"
    );
    let (first, second) = (read("first.json"), read("second.json"));
    assert_eq!(first["metadata"]["model"]["calls"], 1);
    assert_eq!(second["metadata"]["model"]["calls"], 0);
    assert_eq!(second["metadata"]["model"]["accepted"], 1);
    assert_eq!(
        first["format"], second["format"],
        "the cached answer reproduces the result"
    );
}

#[cfg(feature = "llm")]
#[test]
fn an_unusable_cache_directory_fails_before_any_request() {
    let dir = scratch("bad-cache");
    let (base_url, requests) = fake_server(message("{}"));
    let blocker = dir.join("not-a-directory");
    std::fs::write(&blocker, b"occupied").expect("write a plain file");
    let tlv = corpus_dir("tlv/samples");
    let output = run_in(
        &dir,
        &["infer", tlv.to_str().unwrap(), "--provider", "anthropic"],
        &[
            ("ANTHROPIC_API_KEY", "sk-ant-test"),
            ("ANTHROPIC_BASE_URL", &base_url),
            ("SEXTANT_MODEL_CACHE_DIR", blocker.to_str().unwrap()),
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cache"), "{stderr}");
    assert!(
        requests.recv_timeout(Duration::from_millis(300)).is_err(),
        "a request was sent although the cache was unusable"
    );
}

#[cfg(not(feature = "llm"))]
#[test]
fn a_build_without_providers_explains_how_to_get_them() {
    let dir = scratch("no-feature");
    let tlv = corpus_dir("tlv/samples");
    let output = run_in(
        &dir,
        &["infer", tlv.to_str().unwrap(), "--provider", "anthropic"],
        &[("ANTHROPIC_API_KEY", "sk-ant-test")],
    );
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--features llm"), "{stderr}");
}
