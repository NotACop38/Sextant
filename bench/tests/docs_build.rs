//! Documentation build check (Step 14).
//!
//! "Building" the Markdown documentation means it is internally consistent: no
//! em dashes or en dashes anywhere (a hard project rule), and every relative
//! link in the user guide and examples resolves to a file that exists. These
//! checks run in CI, so the docs cannot silently rot or smuggle in a forbidden
//! dash.

use std::path::{Path, PathBuf};

/// The repository root, derived from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the bench crate always has a parent directory")
        .to_path_buf()
}

/// Collect every Markdown file under `dir`, recursively, skipping `target`.
fn markdown_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            markdown_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "md") {
            out.push(path);
        }
    }
}

/// No em dash or en dash may appear in any tracked Markdown file. Box-drawing
/// characters used in diagrams are a different code point and are allowed.
#[test]
fn no_em_or_en_dashes_in_markdown() {
    let root = repo_root();
    let mut files = Vec::new();
    markdown_files(&root, &mut files);
    assert!(!files.is_empty(), "expected to find Markdown files");

    let mut offenders = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read markdown file");
        for (line_number, line) in text.lines().enumerate() {
            if line.contains('\u{2014}') || line.contains('\u{2013}') {
                offenders.push(format!(
                    "{}:{}: {}",
                    file.strip_prefix(&root).unwrap_or(file).display(),
                    line_number + 1,
                    line.trim(),
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "em dashes or en dashes found (use hyphens, colons, or commas):\n{}",
        offenders.join("\n"),
    );
}

/// Every relative Markdown link in the user guide and examples must resolve.
#[test]
fn user_guide_links_resolve() {
    let root = repo_root();
    let mut files = Vec::new();
    markdown_files(&root.join("docs"), &mut files);
    markdown_files(&root.join("examples"), &mut files);

    assert!(
        !files.is_empty(),
        "expected docs/ and examples/ Markdown files",
    );

    let mut broken = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read markdown file");
        let base = file.parent().expect("a Markdown file has a parent dir");
        for target in link_targets(&text) {
            // Skip external links and pure in-page anchors.
            if target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with('#')
                || target.starts_with("mailto:")
            {
                continue;
            }
            // Drop any in-page anchor suffix before resolving the path.
            let path_part = target.split('#').next().unwrap_or(&target);
            if path_part.is_empty() {
                continue;
            }
            let resolved = base.join(path_part);
            if !resolved.exists() {
                broken.push(format!(
                    "{} -> {}",
                    file.strip_prefix(&root).unwrap_or(file).display(),
                    target,
                ));
            }
        }
    }

    assert!(
        broken.is_empty(),
        "broken relative links in the documentation:\n{}",
        broken.join("\n"),
    );
}

/// Extract the targets of Markdown inline links `[text](target)`. A small parser
/// is enough here and avoids pulling in a regex dependency.
fn link_targets(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut targets = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b']' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            let start = i + 2;
            if let Some(rel_end) = text[start..].find(')') {
                let raw = &text[start..start + rel_end];
                // A link target may carry a "title" after a space; keep the URL.
                let url = raw.split_whitespace().next().unwrap_or(raw);
                targets.push(url.to_string());
                i = start + rel_end + 1;
                continue;
            }
        }
        i += 1;
    }
    targets
}
