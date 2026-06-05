//! Step 4 acceptance: ingestion turns files, directories, and globs into an
//! ordered sample set with provenance, enforces byte caps, and handles every
//! pathological input without crashing (FR-1, FR-3, FR-4, FR-5).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sextant_engine::{IngestError, IngestOptions, Notice, ingest};

/// A scratch directory that cleans itself up. Avoids a `tempfile` dependency by
/// building a unique path under the system temp directory; uniqueness comes from
/// the process id plus a per-process counter, so parallel tests never collide.
struct Scratch {
    root: PathBuf,
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

impl Scratch {
    fn new(tag: &str) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut root = std::env::temp_dir();
        root.push(format!(
            "sextant-ingest-{tag}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create scratch root");
        Self { root }
    }

    /// Write a file relative to the scratch root, creating parents as needed.
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parents");
        }
        fs::write(&path, bytes).expect("write file");
        path
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn path_str(&self) -> String {
        self.root.to_str().expect("utf-8 scratch path").to_string()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn ingests_a_directory_in_sorted_order_with_provenance() {
    let scratch = Scratch::new("dir");
    scratch.write("c.bin", b"ccc");
    scratch.write("a.bin", b"a");
    scratch.write("b.bin", b"bb");

    let set = ingest(&[scratch.path_str()], &IngestOptions::default()).expect("ingest directory");

    assert_eq!(set.len(), 3);
    assert_eq!(set.total_bytes, 6);
    // Entries are sorted by path for determinism (NFR-6).
    let names: Vec<String> = set
        .samples
        .iter()
        .map(|sample| {
            sample
                .provenance
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(names, ["a.bin", "b.bin", "c.bin"]);
    // Provenance records the retained length, the full size, and a zero offset.
    assert_eq!(set.samples[0].provenance.length, 1);
    assert_eq!(set.samples[0].provenance.original_length, 1);
    assert_eq!(set.samples[0].provenance.offset, 0);
    assert!(!set.samples[0].provenance.is_truncated());
    assert!(set.notices.is_empty());
}

#[test]
fn ingests_explicit_files_in_input_order() {
    let scratch = Scratch::new("files");
    let first = scratch.write("first.bin", b"1111");
    let second = scratch.write("second.bin", b"22");

    let inputs = [
        second.to_str().unwrap().to_string(),
        first.to_str().unwrap().to_string(),
    ];
    let set = ingest(&inputs, &IngestOptions::default()).expect("ingest files");

    // Explicit files keep the order they were given on the command line.
    assert_eq!(set.len(), 2);
    assert_eq!(set.samples[0].data, b"22");
    assert_eq!(set.samples[1].data, b"1111");
}

#[test]
fn expands_glob_patterns() {
    let scratch = Scratch::new("glob");
    scratch.write("sample_01.tlv", b"aa");
    scratch.write("sample_02.tlv", b"bbb");
    scratch.write("ignore.txt", b"nope");

    let pattern = format!("{}/*.tlv", scratch.path_str());
    let set = ingest(&[pattern], &IngestOptions::default()).expect("ingest glob");

    assert_eq!(set.len(), 2);
    assert_eq!(set.total_bytes, 5);
    assert!(
        set.samples
            .iter()
            .all(|sample| sample.provenance.path.extension().unwrap() == "tlv")
    );
}

#[test]
fn directory_recursion_is_opt_in() {
    let scratch = Scratch::new("recurse");
    scratch.write("top.bin", b"top");
    scratch.write("nested/deep.bin", b"deep");

    // Default: only the top-level file is taken (FR-1).
    let shallow = ingest(&[scratch.path_str()], &IngestOptions::default()).expect("shallow");
    assert_eq!(shallow.len(), 1);
    assert_eq!(shallow.samples[0].data, b"top");

    // Recursive: the nested file is included too.
    let deep = ingest(
        &[scratch.path_str()],
        &IngestOptions::default().with_recursive(true),
    )
    .expect("recursive");
    assert_eq!(deep.len(), 2);
}

#[test]
fn the_same_file_is_ingested_once_but_identical_contents_are_kept() {
    let scratch = Scratch::new("dedup");
    let same = scratch.write("same.bin", b"DUPLICATE");
    // Two distinct files that happen to hold identical bytes (FR-4).
    scratch.write("twin_a.bin", b"TWIN");
    scratch.write("twin_b.bin", b"TWIN");

    let same_str = same.to_str().unwrap().to_string();
    let twins_glob = format!("{}/twin_*.bin", scratch.path_str());
    // Reference `same.bin` twice and pull in both twins via a glob.
    let set = ingest(
        &[same_str.clone(), same_str, twins_glob],
        &IngestOptions::default(),
    )
    .expect("ingest");

    // The repeated path collapses to one sample; the two identical-content
    // files are both retained as distinct samples.
    let same_count = set
        .samples
        .iter()
        .filter(|sample| sample.data == b"DUPLICATE")
        .count();
    assert_eq!(same_count, 1, "the same path must be ingested only once");
    let twin_count = set
        .samples
        .iter()
        .filter(|sample| sample.data == b"TWIN")
        .count();
    assert_eq!(
        twin_count, 2,
        "distinct identical-content files are both kept"
    );
}

#[test]
fn handles_empty_and_single_byte_files() {
    let scratch = Scratch::new("tiny");
    scratch.write("empty.bin", b"");
    scratch.write("one.bin", b"X");

    let set = ingest(&[scratch.path_str()], &IngestOptions::default()).expect("ingest tiny");

    assert_eq!(set.len(), 2);
    let empty = &set.samples[0];
    assert!(empty.is_empty());
    assert_eq!(empty.provenance.length, 0);
    assert_eq!(empty.provenance.original_length, 0);
    assert!(!empty.provenance.is_truncated());

    let one = &set.samples[1];
    assert_eq!(one.len(), 1);
    assert_eq!(one.data, b"X");
}

#[test]
fn a_single_sample_set_is_fine() {
    let scratch = Scratch::new("single");
    let only = scratch.write("only.bin", b"lonely");

    let set = ingest(
        &[only.to_str().unwrap().to_string()],
        &IngestOptions::default(),
    )
    .expect("ingest single");

    assert_eq!(set.len(), 1);
    assert_eq!(set.samples[0].data, b"lonely");
}

#[test]
fn per_sample_cap_clips_a_large_file_and_records_the_truncation() {
    let scratch = Scratch::new("bigsample");
    // A file far larger than the per-sample cap stands in for a "very large"
    // file: the same code path bounds a genuinely huge one (FR-4, FR-5).
    let big = vec![0xABu8; 4096];
    scratch.write("big.bin", &big);

    let options = IngestOptions::default().with_max_bytes_per_sample(16);
    let set = ingest(&[scratch.path_str()], &options).expect("ingest capped");

    assert_eq!(set.len(), 1);
    let sample = &set.samples[0];
    assert_eq!(sample.len(), 16, "only the cap's worth of bytes are kept");
    assert_eq!(sample.provenance.original_length, 4096);
    assert!(sample.provenance.is_truncated());
    assert_eq!(set.total_bytes, 16);
    assert!(
        set.notices
            .contains(&Notice::SamplesTruncated { count: 1, cap: 16 }),
        "a truncation must be surfaced, notices were {:?}",
        set.notices
    );
}

#[test]
fn total_cap_stops_ingestion_and_surfaces_a_notice() {
    let scratch = Scratch::new("totalcap");
    // Sorted order is a, b, c. With a 5-byte total budget, only a and b fit.
    scratch.write("a.bin", b"aaa");
    scratch.write("b.bin", b"bb");
    scratch.write("c.bin", b"cccc");

    let options = IngestOptions::default().with_max_total_bytes(5);
    let set = ingest(&[scratch.path_str()], &options).expect("ingest total cap");

    assert_eq!(set.len(), 2, "only the samples within the budget are kept");
    assert_eq!(set.total_bytes, 5);
    assert!(set.total_bytes <= 5, "the total cap is never exceeded");
    assert!(
        set.notices
            .contains(&Notice::TotalCapReached { cap: 5, skipped: 1 }),
        "the total cap must be surfaced, notices were {:?}",
        set.notices
    );
}

#[test]
fn missing_literal_path_is_an_input_error() {
    let scratch = Scratch::new("missing");
    let absent = scratch.path().join("does_not_exist.bin");

    let result = ingest(
        &[absent.to_str().unwrap().to_string()],
        &IngestOptions::default(),
    );
    assert!(matches!(result, Err(IngestError::PathNotFound { .. })));
}

#[test]
fn glob_matching_nothing_is_not_an_error() {
    let scratch = Scratch::new("emptyglob");
    scratch.write("present.txt", b"hi");

    let pattern = format!("{}/*.nomatch", scratch.path_str());
    let set = ingest(&[pattern], &IngestOptions::default()).expect("empty glob is ok");
    assert!(set.is_empty());
}

#[test]
fn malformed_glob_pattern_is_reported() {
    // An unclosed character class is an invalid pattern.
    let result = ingest(&["bad[pattern".to_string()], &IngestOptions::default());
    assert!(matches!(result, Err(IngestError::BadPattern { .. })));
}

#[test]
fn no_inputs_is_an_error() {
    let inputs: [String; 0] = [];
    assert!(matches!(
        ingest(&inputs, &IngestOptions::default()),
        Err(IngestError::NoInputs)
    ));
}
