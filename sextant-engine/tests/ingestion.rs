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

/// Run `work` on a helper thread and fail if it does not finish promptly, so a
/// runaway walk or a blocking open fails the test instead of hanging the suite.
/// Only the Unix symlink and FIFO tests need it.
#[cfg(unix)]
fn finishes_promptly<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(work());
    });
    receiver
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("ingestion did not finish promptly")
}

fn file_names(set: &sextant_engine::SampleSet) -> Vec<String> {
    set.samples
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
        .collect()
}

#[cfg(unix)]
#[test]
fn a_recursive_glob_does_not_follow_symlink_cycles() {
    let scratch = Scratch::new("globcycle");
    scratch.write("a.bin", b"a");
    scratch.write("sub/b.bin", b"b");
    // Two links back to the directory itself would make a following walker
    // visit an exponential number of paths through `**`.
    std::os::unix::fs::symlink(".", scratch.path().join("l1")).expect("symlink");
    std::os::unix::fs::symlink(".", scratch.path().join("l2")).expect("symlink");

    let pattern = format!("{}/**/*.bin", scratch.path_str());
    let set = finishes_promptly(move || ingest(&[pattern], &IngestOptions::default()))
        .expect("the glob expands");
    assert_eq!(file_names(&set), ["a.bin", "b.bin"]);
    assert!(
        set.notices.contains(&Notice::SymlinksSkipped { count: 2 }),
        "notices were {:?}",
        set.notices
    );
}

#[cfg(unix)]
#[test]
fn a_glob_does_not_follow_a_symlinked_directory_out_of_the_tree() {
    let outside = Scratch::new("globoutside");
    outside.write("secret.bin", b"secret");
    let scratch = Scratch::new("globinside");
    scratch.write("inside.bin", b"inside");
    std::os::unix::fs::symlink(outside.path(), scratch.path().join("escape")).expect("symlink");

    for pattern in ["**/*.bin", "*/*.bin", "*"] {
        let pattern = format!("{}/{pattern}", scratch.path_str());
        let set = ingest(
            &[pattern.clone()],
            &IngestOptions::default().with_recursive(true),
        )
        .expect("the glob expands");
        assert!(
            set.samples.iter().all(|sample| sample.data != b"secret"),
            "{pattern} followed a symlink out of the tree"
        );
    }
}

#[test]
fn the_walk_entry_limit_stops_expansion_with_a_notice() {
    let scratch = Scratch::new("walklimit");
    for name in ["a.bin", "b.bin", "c.bin", "d.bin", "e.bin"] {
        scratch.write(name, b"x");
    }
    let options = IngestOptions::default().with_max_walk_entries(3);
    let set = ingest(&[scratch.path_str()], &options).expect("ingest stops cleanly");
    assert!(set.len() < 5, "the walk ran past its limit");
    assert!(
        set.notices.contains(&Notice::WalkLimitReached { limit: 3 }),
        "notices were {:?}",
        set.notices
    );

    let glob = format!("{}/*.bin", scratch.path_str());
    let set = ingest(&[glob], &options).expect("the glob stops cleanly");
    assert!(set.notices.contains(&Notice::WalkLimitReached { limit: 3 }));
}

#[test]
fn the_input_file_limit_stops_resolution_with_a_notice() {
    let scratch = Scratch::new("filelimit");
    for name in ["a.bin", "b.bin", "c.bin", "d.bin"] {
        scratch.write(name, b"x");
    }
    let options = IngestOptions::default().with_max_input_files(2);
    let set = ingest(&[scratch.path_str()], &options).expect("ingest stops cleanly");
    assert_eq!(file_names(&set), ["a.bin", "b.bin"]);
    assert!(
        set.notices.contains(&Notice::FileLimitReached { limit: 2 }),
        "notices were {:?}",
        set.notices
    );
}

#[test]
fn an_existing_path_with_glob_metacharacters_is_taken_literally() {
    let scratch = Scratch::new("literalmeta");
    let bracketed = scratch.write("sample[1].bin", b"bracketed");
    scratch.write("sample1.bin", b"plain");

    // As a glob, `[1]` would match `sample1.bin`; the file named exactly this
    // must be ingested instead.
    let set = ingest(
        &[bracketed.to_str().unwrap().to_string()],
        &IngestOptions::default(),
    )
    .expect("ingest the literal path");
    assert_eq!(set.len(), 1);
    assert_eq!(set.samples[0].data, b"bracketed");

    // A missing path with a metacharacter is still expanded as a glob.
    let pattern = format!("{}/sample[0-9].bin", scratch.path_str());
    let set = ingest(&[pattern], &IngestOptions::default()).expect("ingest the glob");
    assert_eq!(set.len(), 1);
    assert_eq!(set.samples[0].data, b"plain");
}

#[cfg(unix)]
#[test]
fn an_existing_path_with_a_star_is_taken_literally() {
    let scratch = Scratch::new("literalstar");
    let starred = scratch.write("all*.bin", b"starred");
    scratch.write("allsorts.bin", b"other");
    let set = ingest(
        &[starred.to_str().unwrap().to_string()],
        &IngestOptions::default(),
    )
    .expect("ingest the literal path");
    assert_eq!(set.len(), 1);
    assert_eq!(set.samples[0].data, b"starred");
}

#[cfg(unix)]
#[test]
fn a_parent_component_after_a_wildcard_is_refused_even_when_the_path_exists() {
    // A directory may be named `*` on Unix, so this path exists and would be
    // taken literally. Windows makes such paths exist too, by resolving `..`
    // lexically; the rule must not depend on either.
    let scratch = Scratch::new("parentliteral");
    scratch.write("*/placeholder.bin", b"p");
    scratch.write("sub/x.bin", b"x");
    let input = format!("{}/*/../sub/x.bin", scratch.path_str());
    assert!(Path::new(&input).exists());
    let result = ingest(&[input], &IngestOptions::default());
    assert!(
        matches!(result, Err(IngestError::BadPattern { .. })),
        "got {result:?}"
    );
}

#[test]
fn a_parent_component_after_a_wildcard_is_rejected() {
    let scratch = Scratch::new("parentglob");
    scratch.write("sub/x.bin", b"x");
    let pattern = format!("{}/*/../sub/x.bin", scratch.path_str());
    let result = ingest(&[pattern], &IngestOptions::default());
    assert!(
        matches!(result, Err(IngestError::BadPattern { .. })),
        "got {result:?}"
    );
}

#[test]
fn a_recursive_glob_matches_nested_files_in_sorted_order() {
    let scratch = Scratch::new("globorder");
    scratch.write("z.bin", b"z");
    scratch.write("a/y.bin", b"y");
    scratch.write("a/b/x.bin", b"x");
    scratch.write("a/b/ignored.txt", b"no");
    let pattern = format!("{}/**/*.bin", scratch.path_str());
    let set = ingest(&[pattern], &IngestOptions::default()).expect("ingest the glob");
    // Sorted by path components: a/b/x.bin, a/y.bin, then z.bin.
    assert_eq!(file_names(&set), ["x.bin", "y.bin", "z.bin"]);

    // A trailing separator matches directories only, which contribute their
    // top-level files.
    let dirs = format!("{}/*/", scratch.path_str());
    let set = ingest(&[dirs], &IngestOptions::default()).expect("ingest the glob");
    assert_eq!(file_names(&set), ["y.bin"]);
}

/// Create a FIFO with the system `mkfifo` tool; `false` when it is missing.
#[cfg(unix)]
fn make_fifo(path: &Path) -> bool {
    std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(unix)]
#[test]
fn a_fifo_input_is_skipped_with_a_notice_and_never_blocks() {
    let scratch = Scratch::new("fifo");
    let fifo = scratch.path().join("capture.pcap");
    if !make_fifo(&fifo) {
        eprintln!("skipping: mkfifo is not available");
        return;
    }
    scratch.write("real.bin", b"real");

    // Named directly, and swept in by a directory walk.
    for input in [fifo.to_str().unwrap().to_string(), scratch.path_str()] {
        let set = finishes_promptly(move || ingest(&[input], &IngestOptions::default()))
            .expect("ingest completes");
        assert!(set.samples.iter().all(|sample| sample.data == b"real"));
        assert!(
            set.notices
                .contains(&Notice::NotRegularFilesSkipped { count: 1 }),
            "notices were {:?}",
            set.notices
        );
    }

    // The public reader refuses the FIFO instead of blocking on it.
    let target = fifo.clone();
    let result = finishes_promptly(move || sextant_engine::ingest::read_regular_file(&target, 16));
    let error = result.expect_err("a FIFO is not a regular file");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}
