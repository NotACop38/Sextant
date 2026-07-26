//! Optional Kaitai compiler cross-validation (FR-38, NFR-5).
//!
//! [`cross_validate`] is an independent check that the generated `.ksy` is a real
//! Kaitai spec: it compiles the spec with the Kaitai Struct compiler and parses
//! every sample through the compiled parser. It is reported separately and is
//! never invoked by the core inference pipeline, which stays native and
//! JVM-free (FR-21). When the compiler or its Python runtime is not installed,
//! the function reports [`CrossValidation::Skipped`] instead of failing, so a
//! build without the optional toolchain still passes.
//!
//! The check compiles to the Python target and drives the generated parser with
//! a small script, because that keeps the dependency surface to two widely
//! available tools (`kaitai-struct-compiler` and `python3` with the
//! `kaitaistruct` package) and needs no JVM glue beyond the compiler itself.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sextant_ir::Format;

use crate::naming::pascal;
use crate::{ExportFormat, export};

/// The outcome of a Kaitai cross-validation run (FR-38).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossValidation {
    /// The compiler or its runtime was unavailable, so the check was skipped.
    /// This is not a failure; the core pipeline never requires this step.
    Skipped {
        /// Why the check could not run.
        reason: String,
    },
    /// The spec compiled and every sample parsed through it.
    Passed {
        /// How many samples were parsed.
        samples: usize,
    },
    /// The spec failed to compile, or a sample failed to parse.
    Failed {
        /// A human-readable explanation, including tool output.
        detail: String,
    },
}

impl CrossValidation {
    /// Whether the check ran and every sample parsed.
    #[must_use]
    pub fn passed(&self) -> bool {
        matches!(self, CrossValidation::Passed { .. })
    }

    /// Whether the check was skipped because the toolchain was unavailable.
    #[must_use]
    pub fn skipped(&self) -> bool {
        matches!(self, CrossValidation::Skipped { .. })
    }
}

/// Compile `format` to Kaitai and parse every sample through the compiled spec
/// (FR-38).
///
/// Returns [`CrossValidation::Skipped`] when the Kaitai compiler or the Python
/// `kaitaistruct` runtime is not present, [`CrossValidation::Passed`] when the
/// spec compiled and all samples parsed, and [`CrossValidation::Failed`]
/// otherwise. This function shells out to external tools and is never called by
/// the core inference pipeline.
#[must_use]
pub fn cross_validate(format: &Format, samples: &[Vec<u8>]) -> CrossValidation {
    let Some(ksc) = find_compiler() else {
        return CrossValidation::Skipped {
            reason:
                "the Kaitai Struct compiler (kaitai-struct-compiler or ksc) was not found on PATH"
                    .to_owned(),
        };
    };
    if !python_runtime_available() {
        return CrossValidation::Skipped {
            reason: "python3 with the kaitaistruct package was not found".to_owned(),
        };
    }

    let workdir = match make_workdir() {
        Ok(dir) => dir,
        Err(error) => {
            return CrossValidation::Failed {
                detail: format!("could not create a working directory: {error}"),
            };
        }
    };
    // Best-effort cleanup runs whatever the outcome.
    let result = run_check(format, samples, &ksc, &workdir);
    let _ = std::fs::remove_dir_all(&workdir);
    result
}

/// Compile the spec and parse the samples inside `workdir`.
fn run_check(format: &Format, samples: &[Vec<u8>], ksc: &str, workdir: &Path) -> CrossValidation {
    let id = sextant_id(format);
    let ksy = match export(format, ExportFormat::Kaitai) {
        Ok(text) => text,
        Err(error) => {
            return CrossValidation::Failed {
                detail: format!("the Kaitai export failed: {error}"),
            };
        }
    };
    let ksy_path = workdir.join(format!("{id}.ksy"));
    if let Err(error) = std::fs::write(&ksy_path, ksy) {
        return CrossValidation::Failed {
            detail: format!("could not write the spec: {error}"),
        };
    }

    // Compile to Python.
    let compile = Command::new(ksc)
        .arg("--target")
        .arg("python")
        .arg("--outdir")
        .arg(workdir)
        .arg(&ksy_path)
        .output();
    match compile {
        Ok(output) if !output.status.success() => {
            return CrossValidation::Failed {
                detail: format!(
                    "the Kaitai compiler rejected the spec:\n{}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            };
        }
        Ok(_) => {}
        Err(error) => {
            return CrossValidation::Failed {
                detail: format!("could not run the Kaitai compiler: {error}"),
            };
        }
    }

    // Write each sample to disk for the driver to parse.
    let mut sample_paths = Vec::with_capacity(samples.len());
    for (index, sample) in samples.iter().enumerate() {
        let path = workdir.join(format!("sample_{index}.bin"));
        if let Err(error) = std::fs::write(&path, sample) {
            return CrossValidation::Failed {
                detail: format!("could not write a sample: {error}"),
            };
        }
        sample_paths.push(path);
    }

    let driver = driver_script(&id, format, &sample_paths);
    let driver_path = workdir.join("drive.py");
    if let Err(error) = std::fs::write(&driver_path, driver) {
        return CrossValidation::Failed {
            detail: format!("could not write the driver: {error}"),
        };
    }

    let run = Command::new("python3").arg(&driver_path).output();
    match run {
        Ok(output) if output.status.success() => CrossValidation::Passed {
            samples: samples.len(),
        },
        Ok(output) => CrossValidation::Failed {
            detail: format!(
                "a sample failed to parse:\n{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        },
        Err(error) => CrossValidation::Failed {
            detail: format!("could not run the parser driver: {error}"),
        },
    }
}

/// The meta `id` the Kaitai exporter uses for the root, which is also the
/// generated module file name.
fn sextant_id(format: &Format) -> String {
    crate::naming::snake(&format.name, "format")
}

/// The generated Kaitai class name (upper camel case of the id).
fn class_name(format: &Format) -> String {
    pascal(&format.name, "Format")
}

/// Build the Python driver that imports the generated module and parses each
/// sample, exiting non-zero on the first failure.
fn driver_script(id: &str, format: &Format, samples: &[PathBuf]) -> String {
    let class = class_name(format);
    let mut script = String::new();
    script.push_str("import sys, os\n");
    script.push_str("sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n");
    script.push_str(&format!("from {id} import {class}\n"));
    script.push_str("paths = [\n");
    for path in samples {
        script.push_str(&format!("    {:?},\n", path.to_string_lossy()));
    }
    script.push_str("]\n");
    script.push_str("for p in paths:\n");
    script.push_str("    try:\n");
    script.push_str(&format!("        {class}.from_file(p)\n"));
    script.push_str("    except Exception as exc:\n");
    script.push_str("        print('FAILED %s: %s' % (p, exc))\n");
    script.push_str("        sys.exit(1)\n");
    script.push_str("print('OK')\n");
    script
}

/// Environment variable that may name an absolute path to the Kaitai Struct
/// compiler. Preferred over PATH lookup so operators can pin a reviewed binary
/// (see `docs/threat-model.md`).
pub const KAITAI_COMPILER_ENV: &str = "SEXTANT_KAITAI_COMPILER";

/// Find the Kaitai compiler, preferring an absolute path from
/// [`KAITAI_COMPILER_ENV`], then the canonical names on `PATH`.
fn find_compiler() -> Option<String> {
    if let Ok(path) = std::env::var(KAITAI_COMPILER_ENV) {
        let trimmed = path.trim();
        if !trimmed.is_empty()
            && Command::new(trimmed)
                .arg("--version")
                .output()
                .map(|out| out.status.success())
                .unwrap_or(false)
        {
            return Some(trimmed.to_owned());
        }
    }
    for candidate in ["kaitai-struct-compiler", "ksc"] {
        if Command::new(candidate)
            .arg("--version")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
        {
            return Some(candidate.to_owned());
        }
    }
    None
}

/// Whether `python3` can import the `kaitaistruct` runtime package.
fn python_runtime_available() -> bool {
    Command::new("python3")
        .args(["-c", "import kaitaistruct"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Create a unique temporary working directory.
fn make_workdir() -> std::io::Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("sextant-crossval-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_and_class_match_the_exporter() {
        let format = sextant_ir::fixtures::tlv_ground_truth();
        assert_eq!(sextant_id(&format), "tlv");
        assert_eq!(class_name(&format), "Tlv");
    }

    #[test]
    fn skips_cleanly_without_the_toolchain() {
        // When the toolchain is absent the result is Skipped, never a panic and
        // never a hard failure. When it is present, this exercises the full path.
        let format = sextant_ir::fixtures::tlv_ground_truth();
        let result = cross_validate(&format, &[]);
        match result {
            CrossValidation::Skipped { .. } | CrossValidation::Passed { .. } => {}
            CrossValidation::Failed { detail } => {
                panic!("cross-validation failed unexpectedly: {detail}");
            }
        }
    }
}
