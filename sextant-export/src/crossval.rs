//! Optional Kaitai compiler cross-validation (FR-38, NFR-5).
//!
//! The compiler and Python runtime remain optional and outside the native core.
//! Child processes have deadlines and bounded captured output. Samples live in
//! a private temporary directory; Python runs in isolated mode so the analysis
//! directory cannot replace imported runtime modules.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::naming::pascal;
use crate::{ExportFormat, export};
use sextant_ir::Format;

const MAX_OUTPUT_BYTES: usize = 256 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const COMPILE_TIMEOUT: Duration = Duration::from_secs(30);
const PARSE_TIMEOUT: Duration = Duration::from_secs(5);

/// The outcome of a Kaitai cross-validation run (FR-38).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossValidation {
    /// The optional toolchain was unavailable.
    Skipped {
        /// Why the check could not run.
        reason: String,
    },
    /// The spec compiled and every sample was fully consumed.
    Passed {
        /// How many samples were parsed.
        samples: usize,
    },
    /// Export, compilation, execution, or full-consumption checks failed.
    Failed {
        /// A bounded human-readable explanation.
        detail: String,
    },
}

impl CrossValidation {
    /// Whether the check ran and every sample parsed.
    #[must_use]
    pub fn passed(&self) -> bool {
        matches!(self, Self::Passed { .. })
    }
    /// Whether the optional toolchain was unavailable.
    #[must_use]
    pub fn skipped(&self) -> bool {
        matches!(self, Self::Skipped { .. })
    }
}

/// Compile a generated Kaitai spec and fully consume each supplied sample.
///
/// Compilation is limited to 30 seconds, parsing to five seconds, and each
/// child's stdout and stderr to 256 KiB each. The child is killed and reaped on
/// timeout or excessive output. The operator must trust the selected compiler;
/// this is process containment, not a sandbox for arbitrary external programs.
#[must_use]
pub fn cross_validate(format: &Format, samples: &[Vec<u8>]) -> CrossValidation {
    if samples.is_empty() {
        return failed("cross-validation requires at least one sample");
    }
    let ksy = match export(format, ExportFormat::Kaitai) {
        Ok(ksy) => ksy,
        Err(error) => return failed(error.to_string()),
    };
    let workdir = match private_workdir() {
        Ok(dir) => dir,
        Err(error) => {
            return failed(format!(
                "could not create private working directory: {error}"
            ));
        }
    };
    let ksc = match find_compiler(workdir.path()) {
        Ok(Some(ksc)) => ksc,
        Ok(None) => {
            return CrossValidation::Skipped {
                reason: "Kaitai compiler was not found on PATH".into(),
            };
        }
        Err(error) => return failed(error),
    };
    if !python_runtime_available(workdir.path()) {
        return CrossValidation::Skipped {
            reason: "isolated python3 with kaitaistruct was not found".into(),
        };
    }
    match run_check(format, samples, &ksy, &ksc, workdir.path()) {
        Ok(()) => CrossValidation::Passed {
            samples: samples.len(),
        },
        Err(error) => failed(error),
    }
}

fn private_workdir() -> std::io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("sextant-crossval-");
    // Tempfile directories otherwise inherit 0o777 masked by the process umask.
    // Set permissions during creation, before any sample or generated code exists.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir()
}

fn failed(detail: impl Into<String>) -> CrossValidation {
    CrossValidation::Failed {
        detail: detail.into(),
    }
}

fn run_check(
    format: &Format,
    samples: &[Vec<u8>],
    ksy: &str,
    ksc: &str,
    workdir: &Path,
) -> Result<(), String> {
    let id = sextant_id(format);
    let ksy_path = workdir.join(format!("{id}.ksy"));
    std::fs::write(&ksy_path, ksy).map_err(|error| format!("could not write spec: {error}"))?;
    let compiled = run_bounded(
        Command::new(ksc)
            .args(["--target", "python", "--outdir"])
            .arg(workdir)
            .arg(&ksy_path)
            .current_dir(workdir),
        COMPILE_TIMEOUT,
    )?;
    if !compiled.status.success() {
        return Err(compiled.failure("Kaitai compilation failed"));
    }
    let mut paths = Vec::with_capacity(samples.len());
    for (index, sample) in samples.iter().enumerate() {
        let path = workdir.join(format!("sample_{index}.bin"));
        std::fs::write(&path, sample)
            .map_err(|error| format!("could not write sample: {error}"))?;
        paths.push(path);
    }
    let driver_path = workdir.join("_sextant_driver.py");
    std::fs::write(&driver_path, driver_script(&id, format, &paths))
        .map_err(|error| format!("could not write driver: {error}"))?;
    let parsed = run_bounded(
        Command::new("python3")
            .arg("-I")
            .arg(&driver_path)
            .current_dir(workdir),
        PARSE_TIMEOUT,
    )?;
    if !parsed.status.success() {
        return Err(parsed.failure("sample parsing failed"));
    }
    Ok(())
}

fn sextant_id(format: &Format) -> String {
    crate::naming::snake(&format.name, "format")
}
fn class_name(format: &Format) -> String {
    pascal(&format.name, "Format")
}

fn driver_script(id: &str, format: &Format, samples: &[PathBuf]) -> String {
    let class = class_name(format);
    let mut script =
        String::from("import sys, os, importlib.util\nfrom kaitaistruct import KaitaiStream\n");
    // Load precisely this generated file without adding its directory to the
    // import search path. Format names such as `enum` or `kaitaistruct` cannot
    // shadow the runtime or standard library.
    script.push_str(&format!("spec = importlib.util.spec_from_file_location('_sextant_generated', os.path.join(os.path.dirname(os.path.abspath(__file__)), '{id}.py'))\nmodule = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(module)\nparser_class = module.{class}\npaths = [\n"));
    for path in samples {
        script.push_str(&format!("    {:?},\n", path.to_string_lossy()));
    }
    script.push_str("]\nfor p in paths:\n    try:\n        with open(p, 'rb') as sample:\n            stream = KaitaiStream(sample)\n");
    script.push_str("            parsed = parser_class(stream)\n");
    script.push_str("            if not stream.is_eof():\n                raise ValueError('unconsumed trailing bytes')\n    except Exception as exc:\n        print('FAILED %s: %s' % (p, exc))\n        sys.exit(1)\nprint('OK')\n");
    script
}

/// An absolute, operator-selected path to the reviewed Kaitai compiler.
/// An invalid explicit pin is an error; it never falls back to PATH.
pub const KAITAI_COMPILER_ENV: &str = "SEXTANT_KAITAI_COMPILER";

fn find_compiler(workdir: &Path) -> Result<Option<String>, String> {
    if let Some(path) = std::env::var_os(KAITAI_COMPILER_ENV) {
        let path = path
            .into_string()
            .map_err(|_| "compiler pin is not valid Unicode".to_owned())?;
        if !Path::new(&path).is_absolute() {
            return Err("compiler pin must be an absolute path".into());
        }
        let result = run_bounded(
            Command::new(&path).arg("--version").current_dir(workdir),
            PROBE_TIMEOUT,
        )
        .map_err(|error| format!("explicit compiler pin failed: {error}"))?;
        if !result.status.success() {
            return Err(result.failure("explicit compiler pin failed"));
        }
        return Ok(Some(path));
    }
    for candidate in ["kaitai-struct-compiler", "ksc"] {
        if run_bounded(
            Command::new(candidate)
                .arg("--version")
                .current_dir(workdir),
            PROBE_TIMEOUT,
        )
        .is_ok_and(|output| output.status.success())
        {
            return Ok(Some(candidate.to_owned()));
        }
    }
    Ok(None)
}

fn python_runtime_available(workdir: &Path) -> bool {
    run_bounded(
        Command::new("python3")
            .args(["-I", "-c", "import kaitaistruct"])
            .current_dir(workdir),
        PROBE_TIMEOUT,
    )
    .is_ok_and(|output| output.status.success())
}

struct BoundedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
impl BoundedOutput {
    fn failure(&self, context: &str) -> String {
        format!(
            "{context}:\n{}{}",
            String::from_utf8_lossy(&self.stdout),
            String::from_utf8_lossy(&self.stderr)
        )
    }
}

fn read_pipe(
    reader: impl Read + Send + 'static,
    index: usize,
    sender: mpsc::Sender<(usize, std::io::Result<Vec<u8>>)>,
) {
    // Each reader can allocate at most the cap plus one sentinel byte. Once the
    // cap is hit it closes the pipe; the controller kills and reaps the child.
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = reader
            .take((MAX_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send((index, result));
    });
}

fn run_bounded(command: &mut Command, timeout: Duration) -> Result<BoundedOutput, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not start child: {error}"))?;
    let (sender, receiver) = mpsc::channel();
    read_pipe(
        child.stdout.take().expect("stdout is piped"),
        0,
        sender.clone(),
    );
    read_pipe(child.stderr.take().expect("stderr is piped"), 1, sender);
    let deadline = Instant::now() + timeout;
    let mut output: [Option<Vec<u8>>; 2] = [None, None];
    let mut status = None;
    loop {
        for (index, result) in receiver.try_iter() {
            match result {
                Ok(bytes) if bytes.len() <= MAX_OUTPUT_BYTES => output[index] = Some(bytes),
                other => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(match other {
                        Ok(_) => "child output exceeded 256 KiB".into(),
                        Err(error) => format!("could not read child output: {error}"),
                    });
                }
            }
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(found) => status = found,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("could not wait for child: {error}"));
                }
            }
        }
        if let Some(status) = status {
            if output.iter().all(Option::is_some) {
                return Ok(BoundedOutput {
                    status,
                    stdout: output[0].take().unwrap(),
                    stderr: output[1].take().unwrap(),
                });
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("child timed out after {} ms", timeout.as_millis()));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn python_present() -> bool {
        let present = Command::new("python3").arg("--version").output().is_ok();
        assert!(
            present || std::env::var_os("SEXTANT_REQUIRE_KAITAI").is_none(),
            "python3 is required"
        );
        present
    }

    #[cfg(unix)]
    #[test]
    fn sample_workdir_excludes_other_users_at_creation() {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_workdir().unwrap();
        let mode = dir.path().metadata().unwrap().permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "cross-validation directory must be owner-only"
        );
        assert_eq!(mode & 0o700, 0o700);
        std::fs::write(dir.path().join("sample.bin"), b"private sample").unwrap();
    }

    #[test]
    fn id_and_class_match_the_exporter() {
        let format = sextant_ir::fixtures::tlv_ground_truth();
        assert_eq!(sextant_id(&format), "tlv");
        assert_eq!(class_name(&format), "Tlv");
    }

    #[test]
    fn children_are_bounded_and_reaped() {
        if !python_present() {
            return;
        }
        let started = Instant::now();
        let result = run_bounded(
            Command::new("python3").args(["-I", "-c", "import time; time.sleep(30)"]),
            Duration::from_millis(100),
        );
        assert!(result.err().unwrap().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(3));
        let result = run_bounded(
            Command::new("python3").args([
                "-I",
                "-c",
                "import sys; sys.stdout.write('x' * 1048576); sys.stdout.flush()",
            ]),
            PROBE_TIMEOUT,
        );
        assert!(result.err().unwrap().contains("output exceeded"));
    }

    #[test]
    fn python_probe_ignores_analysis_directory_modules() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("kaitaistruct.py"),
            "from pathlib import Path\nPath('sentinel').write_text('imported')\n",
        )
        .unwrap();
        let available = python_runtime_available(dir.path());
        assert!(
            !dir.path().join("sentinel").exists(),
            "untrusted local module was imported"
        );
        if std::env::var_os("SEXTANT_REQUIRE_KAITAI").is_some() {
            assert!(available, "isolated runtime is required");
        }
    }

    #[test]
    fn skips_cleanly_without_the_toolchain() {
        let sample = include_bytes!("../../corpus/tlv/samples/sample_01.tlv").to_vec();
        let result = cross_validate(&sextant_ir::fixtures::tlv_ground_truth(), &[sample]);
        match result {
            CrossValidation::Passed { .. } => {}
            CrossValidation::Skipped { reason }
                if std::env::var_os("SEXTANT_REQUIRE_KAITAI").is_none() =>
            {
                eprintln!("{reason}")
            }
            other => panic!("cross-validation failed: {other:?}"),
        }
    }

    #[test]
    fn empty_sample_set_cannot_pass_cross_validation() {
        assert!(matches!(
            cross_validate(&sextant_ir::fixtures::tlv_ground_truth(), &[]),
            CrossValidation::Failed { .. }
        ));
    }
}
