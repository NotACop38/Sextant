//! On-disk response cache keyed by a hash of the exact request (NFR-6, NFR-9).
//!
//! Caching makes model-augmented runs reproducible and cheap to repeat: an
//! identical request is served from disk without touching the network. The key
//! is a content hash over a cache format version, the provider, the model, the
//! provider's endpoint and settings, the call kind, and the full request, so a
//! change to any of them produces a distinct entry.
//!
//! The cache directory is not trusted blindly. Reads accept only a regular file
//! (never a symlink, FIFO, or device), cap how much they read, and treat any
//! anomaly, including a corrupt entry, as a miss, so a bad entry can never
//! block the provider. Writes go to a fresh temporary file in the cache
//! directory that is synced and then renamed over the entry, so a reader never
//! observes a half-written entry and an existing symlink is replaced rather
//! than followed.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::config::ProviderKind;
use crate::error::LlmError;

/// The version of the cache key derivation and entry layout. Bumping it
/// orphans every older entry instead of misreading it.
pub const CACHE_FORMAT_VERSION: u32 = 2;

/// The largest cache entry that is read or written. Provider response bodies
/// are capped well below this, so a larger file is not an entry Sextant wrote.
const MAX_ENTRY_BYTES: u64 = 8 << 20;

/// A content-addressed cache of model responses stored as JSON files.
#[derive(Debug, Clone)]
pub struct ResponseCache {
    root: PathBuf,
}

impl ResponseCache {
    /// Create a cache rooted at `root`. The directory is created lazily on the
    /// first write.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The file path for a given key, or `None` when the key could name a path
    /// outside the cache directory. Keys from [`request_key`] always qualify.
    fn path_for(&self, key: &str) -> Option<PathBuf> {
        let valid = !key.is_empty()
            && key.len() <= 128
            && key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        valid.then(|| self.root.join(format!("{key}.json")))
    }

    /// Look up a cached value, returning `None` on a miss.
    ///
    /// Anything other than a readable regular file holding a parseable entry
    /// counts as a miss: a missing, oversized, corrupt, or non-UTF-8 entry, a
    /// symlink, FIFO, or other special file at the entry path, or a cache root
    /// that is itself a symlink. A miss sends the request to the provider, and
    /// the fresh response then replaces the bad entry.
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        let path = self.path_for(key)?;
        if !is_real_directory(&self.root) {
            return None;
        }
        let bytes = read_regular_file(&path, MAX_ENTRY_BYTES)?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Store a value under `key`.
    ///
    /// The entry is written to a new temporary file (created exclusively, so
    /// an existing file or symlink at that name is never opened), synced to
    /// disk, and atomically renamed over the entry path. On Unix the cache
    /// directory is set to mode 0700 and each entry to mode 0600, and a failure
    /// to set either mode is an error rather than a silent downgrade: a cached
    /// request and response can echo bytes drawn from the samples that were
    /// sent to the model, so they must not be readable by other users on a
    /// shared machine (PRD Section 16). On other platforms the files inherit
    /// the access control of the directory, so keep the cache in a private
    /// directory there.
    ///
    /// # Errors
    ///
    /// Returns [`LlmError::Cache`] when the key is not a valid cache key, the
    /// cache root is a symlink or not a directory, the permissions cannot be
    /// set, or the write fails.
    pub fn put<T: Serialize>(&self, key: &str, value: &T) -> Result<(), LlmError> {
        let path = self
            .path_for(key)
            .ok_or_else(|| LlmError::Cache(format!("`{key}` is not a valid cache key")))?;
        self.prepare_root()?;
        let bytes = serde_json::to_vec(value).map_err(|error| {
            LlmError::Cache(format!("could not serialize entry {key}: {error}"))
        })?;
        if bytes.len() as u64 > MAX_ENTRY_BYTES {
            return Err(LlmError::Cache(format!(
                "entry {key} exceeds the {MAX_ENTRY_BYTES}-byte cache entry cap"
            )));
        }
        write_atomically(&self.root, &path, &bytes)
            .map_err(|error| LlmError::Cache(format!("could not write entry {key}: {error}")))
    }

    /// Whether a readable entry is present on disk for `key`, for tests and
    /// diagnostics. A symlink or special file at the entry path does not count.
    pub fn contains(&self, key: &str) -> bool {
        self.path_for(key)
            .and_then(|path| std::fs::symlink_metadata(path).ok())
            .is_some_and(|metadata| metadata.file_type().is_file())
    }

    /// The cache root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create the cache directory now instead of on the first write, and check
    /// that it can hold entries: it must be a real directory, not a symlink,
    /// and on Unix it must accept owner-only permissions. Call this before the
    /// first provider request so a misconfigured cache fails before a billed
    /// call rather than after it.
    ///
    /// # Errors
    ///
    /// Returns [`LlmError::Cache`] when the directory cannot be created or
    /// inspected, is a symlink or not a directory, or cannot be restricted to
    /// its owner.
    pub fn prepare(&self) -> Result<(), LlmError> {
        self.prepare_root()
    }

    /// Create the cache root if needed, refuse a root that is a symlink or not
    /// a directory, and restrict it to its owner on Unix.
    fn prepare_root(&self) -> Result<(), LlmError> {
        let root = &self.root;
        match std::fs::symlink_metadata(root) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_private_dir_all(root).map_err(|error| {
                    LlmError::Cache(format!(
                        "could not create cache directory {}: {error}",
                        root.display()
                    ))
                })?;
            }
            Err(error) => {
                return Err(LlmError::Cache(format!(
                    "could not inspect cache directory {}: {error}",
                    root.display()
                )));
            }
        }
        if !is_real_directory(root) {
            return Err(LlmError::Cache(format!(
                "cache root {} is a symlink or not a directory",
                root.display()
            )));
        }
        restrict_dir_permissions(root).map_err(|error| {
            LlmError::Cache(format!(
                "could not restrict cache directory {} to its owner: {error}",
                root.display()
            ))
        })
    }
}

/// Whether `path` is a directory and not a symlink to one.
fn is_real_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
}

/// Read a regular file without following a symlink at `path`, returning `None`
/// on any anomaly: a missing file, a symlink or special file, a file that is
/// larger than `cap`, a read error, or a file swapped between the check and
/// the open.
fn read_regular_file(path: &Path, cap: u64) -> Option<Vec<u8>> {
    // `symlink_metadata` does not follow links, so a symlink, FIFO, socket, or
    // device is rejected here, before an open that could block or escape the
    // cache directory.
    let before = std::fs::symlink_metadata(path).ok()?;
    if !before.file_type().is_file() || before.len() > cap {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let after = file.metadata().ok()?;
    if !after.is_file() || !same_file(&before, &after) {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= cap).then_some(bytes)
}

/// Whether two metadata snapshots describe the same file, so an entry swapped
/// for a symlink between the check and the open is detected.
#[cfg(unix)]
fn same_file(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    before.dev() == after.dev() && before.ino() == after.ino()
}

/// Non-Unix fallback: the stable standard library exposes no file identity, so
/// only the pre-open check applies.
#[cfg(not(unix))]
fn same_file(_before: &std::fs::Metadata, _after: &std::fs::Metadata) -> bool {
    true
}

/// Write `bytes` to a new temporary file next to `destination`, sync it, and
/// rename it over `destination`. The temporary file is removed on failure.
fn write_atomically(root: &Path, destination: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if std::fs::symlink_metadata(destination).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(std::io::Error::other("a directory occupies the entry path"));
    }
    let (temporary, mut file) = create_temporary(root)?;
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            drop(file);
            // `rename` replaces the destination entry itself, even when it is
            // a symlink, and never writes through it.
            std::fs::rename(&temporary, destination)
        });
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

/// Create a uniquely named temporary file in `root`, exclusively (never
/// opening an existing file or following a symlink) and, on Unix, owner-only.
fn create_temporary(root: &Path) -> std::io::Result<(PathBuf, std::fs::File)> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut last_error = None;
    for _ in 0..16 {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.subsec_nanos());
        let path = root.join(format!(".tmp-{}-{unique}-{nanos}", std::process::id()));
        match create_new_private(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| std::io::Error::other("no free temporary name")))
}

/// Create `path` exclusively with owner-only permissions on Unix.
#[cfg(unix)]
fn create_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    // The umask can only remove bits from the mode above; set it exactly so the
    // entry ends up 0600 regardless.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

/// Non-Unix fallback: an exclusive create, since file modes are POSIX specific.
#[cfg(not(unix))]
fn create_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Create `root` and any missing parents, owner-only on Unix from the start.
#[cfg(unix)]
fn create_private_dir_all(root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)
}

/// Non-Unix fallback: an ordinary recursive create.
#[cfg(not(unix))]
fn create_private_dir_all(root: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(root)
}

/// Set the cache directory to owner-only access on Unix. Unlike before, a
/// failure is reported, because the documented guarantee depends on it.
#[cfg(unix)]
fn restrict_dir_permissions(root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
}

/// Non-Unix fallback: no POSIX mode to set.
#[cfg(not(unix))]
fn restrict_dir_permissions(_root: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Compute the cache key for a request.
///
/// The key folds in [`CACHE_FORMAT_VERSION`], the provider, the model, the
/// provider's scope (its endpoint URL and response-shaping settings, see
/// [`crate::LlmProvider::cache_scope`]), the call kind ("completion" or
/// "json"), and a canonical JSON serialization of the request. Changing any of
/// them changes the key, so a cached response can never be returned for a
/// materially different request or a different server.
pub fn request_key(
    provider: ProviderKind,
    model: &str,
    scope: &serde_json::Value,
    call_kind: &str,
    request: &serde_json::Value,
) -> String {
    // serde_json serializes struct fields in declaration order and map keys in
    // a fixed order, so this canonical form is deterministic (NFR-6).
    let canonical = serde_json::json!({
        "format_version": CACHE_FORMAT_VERSION,
        "provider": provider,
        "model": model,
        "scope": scope,
        "call": call_kind,
        "request": request,
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    format!("{call_kind}-{}", fnv1a_128_hex(&bytes))
}

/// A 128-bit FNV-1a hash rendered as 32 lowercase hex characters.
///
/// This is a content-addressing hash for cache filenames, not a security
/// boundary, so a fast non-cryptographic hash with a low collision rate is the
/// right tool. FNV-1a is a fixed, well-specified algorithm, so the same input
/// always produces the same key (NFR-6).
fn fnv1a_128_hex(bytes: &[u8]) -> String {
    const OFFSET_BASIS: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    const PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;
    let mut hash = OFFSET_BASIS;
    for &byte in bytes {
        hash ^= u128::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:032x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique temporary directory for a test, removed when the guard drops.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "sextant-llm-cache-{tag}-{}-{unique}",
                std::process::id()
            ));
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn entry_path(cache: &ResponseCache, key: &str) -> PathBuf {
        cache.path_for(key).expect("valid key")
    }

    #[test]
    fn hash_is_stable_and_distinguishes_inputs() {
        assert_eq!(fnv1a_128_hex(b"hello"), fnv1a_128_hex(b"hello"));
        assert_ne!(fnv1a_128_hex(b"hello"), fnv1a_128_hex(b"world"));
        assert_eq!(fnv1a_128_hex(b"x").len(), 32);
    }

    #[test]
    fn key_changes_with_model_and_request() {
        let request = serde_json::json!({"prompt": "hi"});
        let scope = serde_json::Value::Null;
        let a = request_key(ProviderKind::Mock, "m1", &scope, "completion", &request);
        let b = request_key(ProviderKind::Mock, "m2", &scope, "completion", &request);
        let c = request_key(ProviderKind::Mock, "m1", &scope, "json", &request);
        assert_ne!(a, b, "model must affect the key");
        assert_ne!(a, c, "call kind must affect the key");
    }

    #[test]
    fn key_changes_with_the_endpoint_and_settings() {
        let request = serde_json::json!({"prompt": "hi"});
        let official = serde_json::json!({"endpoint": "https://api.anthropic.com"});
        let proxy = serde_json::json!({"endpoint": "http://127.0.0.1:8080"});
        let a = request_key(ProviderKind::Anthropic, "m", &official, "json", &request);
        let b = request_key(ProviderKind::Anthropic, "m", &proxy, "json", &request);
        assert_ne!(a, b, "the endpoint must affect the key");
        // Keys stay valid cache file names.
        assert!(ResponseCache::new("unused").path_for(&a).is_some());
    }

    #[test]
    fn the_key_folds_in_the_format_version() {
        // The version is part of the hashed canonical form, so recomputing the
        // key by hand without it gives a different value.
        let request = serde_json::json!({"prompt": "hi"});
        let without_version = serde_json::json!({
            "provider": ProviderKind::Mock,
            "model": "m",
            "scope": serde_json::Value::Null,
            "call": "json",
            "request": request,
        });
        let bytes = serde_json::to_vec(&without_version).expect("serialize");
        let unversioned = format!("json-{}", fnv1a_128_hex(&bytes));
        let versioned = request_key(
            ProviderKind::Mock,
            "m",
            &serde_json::Value::Null,
            "json",
            &request,
        );
        assert_ne!(versioned, unversioned);
    }

    #[cfg(unix)]
    #[test]
    fn cached_entries_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new("perms");
        let cache = ResponseCache::new(&dir.0);
        let key = "completion-secret";
        cache
            .put(key, &serde_json::json!({"sample": "sensitive bytes"}))
            .expect("write");
        let mode = std::fs::metadata(entry_path(&cache, key))
            .expect("stat entry")
            .permissions()
            .mode()
            & 0o777;
        // No group or world bits: cached sample-derived data stays private.
        assert_eq!(mode, 0o600, "cache entry mode was {mode:o}");
        let dir_mode = std::fs::metadata(&dir.0)
            .expect("stat dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "cache directory mode was {dir_mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn a_pre_existing_open_directory_is_tightened() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new("open-dir");
        std::fs::create_dir_all(&dir.0).expect("mkdir");
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        ResponseCache::new(&dir.0)
            .put("json-a", &serde_json::json!(1))
            .expect("write");
        let mode = std::fs::metadata(&dir.0)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "the directory kept a broad mode: {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn rewriting_a_world_readable_entry_tightens_its_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new("upgrade");
        let cache = ResponseCache::new(&dir.0);
        std::fs::create_dir_all(&dir.0).expect("mkdir");
        let key = "completion-legacy";
        let path = entry_path(&cache, key);
        // Simulate an entry left over from an older, world-readable cache.
        std::fs::write(&path, b"{}").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        cache
            .put(key, &serde_json::json!({"sample": "sensitive bytes"}))
            .expect("rewrite");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        // The rewrite must drop the inherited group and world read bits.
        assert_eq!(mode, 0o600, "entry kept a broad mode: {mode:o}");
    }

    #[test]
    fn prepare_creates_the_directory_up_front_and_refuses_a_file() {
        let dir = TempDir::new("prepare");
        let cache = ResponseCache::new(dir.0.join("nested").join("cache"));
        cache.prepare().expect("create the cache directory");
        assert!(is_real_directory(cache.root()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(cache.root())
                .expect("stat the cache directory")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "cache directory mode was {mode:o}");
        }

        let file = dir.0.join("occupied");
        std::fs::write(&file, b"x").expect("write a plain file");
        let error = ResponseCache::new(&file)
            .prepare()
            .expect_err("a file cannot hold entries");
        assert!(matches!(error, LlmError::Cache(_)), "{error}");
    }

    #[test]
    fn round_trips_a_value_through_disk() {
        let dir = TempDir::new("round-trip");
        let cache = ResponseCache::new(&dir.0);
        let key = "completion-abc";
        assert!(cache.get::<serde_json::Value>(key).is_none());
        let value = serde_json::json!({"text": "result"});
        cache.put(key, &value).expect("write");
        assert!(cache.contains(key));
        let read: serde_json::Value = cache.get(key).expect("present");
        assert_eq!(read, value);
    }

    #[test]
    fn overwriting_is_atomic_and_leaves_no_temporary_files() {
        let dir = TempDir::new("atomic");
        let cache = ResponseCache::new(&dir.0);
        let key = "json-atomic";
        cache.put(key, &serde_json::json!({"v": 1})).expect("first");
        cache
            .put(key, &serde_json::json!({"v": 2}))
            .expect("second");
        let read: serde_json::Value = cache.get(key).expect("present");
        assert_eq!(read, serde_json::json!({"v": 2}));
        let names: Vec<String> = std::fs::read_dir(&dir.0)
            .expect("list")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, vec![format!("{key}.json")], "stray files: {names:?}");
    }

    #[test]
    fn a_corrupt_entry_is_a_miss_and_is_repaired_by_the_next_write() {
        let dir = TempDir::new("corrupt");
        let cache = ResponseCache::new(&dir.0);
        let key = "json-corrupt";
        std::fs::create_dir_all(&dir.0).expect("mkdir");
        std::fs::write(entry_path(&cache, key), b"{\"half\": ").expect("seed");
        // A corrupt entry must not become an error that blocks the provider.
        assert!(cache.get::<serde_json::Value>(key).is_none());
        cache.put(key, &serde_json::json!("fresh")).expect("repair");
        assert_eq!(
            cache.get::<serde_json::Value>(key),
            Some(serde_json::json!("fresh"))
        );
    }

    #[test]
    fn an_oversized_entry_is_a_miss() {
        let dir = TempDir::new("oversized");
        let cache = ResponseCache::new(&dir.0);
        let key = "json-big";
        std::fs::create_dir_all(&dir.0).expect("mkdir");
        let file = std::fs::File::create(entry_path(&cache, key)).expect("create");
        file.set_len(MAX_ENTRY_BYTES + 1).expect("grow");
        assert!(cache.get::<serde_json::Value>(key).is_none());
    }

    #[test]
    fn a_directory_at_the_entry_path_is_a_miss_and_a_write_error() {
        let dir = TempDir::new("dir-entry");
        let cache = ResponseCache::new(&dir.0);
        let key = "json-dir";
        std::fs::create_dir_all(entry_path(&cache, key)).expect("mkdir entry");
        assert!(cache.get::<serde_json::Value>(key).is_none());
        assert!(!cache.contains(key));
        assert!(matches!(
            cache.put(key, &serde_json::json!(1)),
            Err(LlmError::Cache(_))
        ));
    }

    #[test]
    fn keys_that_could_escape_the_directory_are_refused() {
        let dir = TempDir::new("keys");
        let cache = ResponseCache::new(&dir.0);
        for key in ["", "../escape", "a/b", "a\\b", "..", "json-ok.json"] {
            assert!(cache.get::<serde_json::Value>(key).is_none(), "{key:?}");
            assert!(
                matches!(
                    cache.put(key, &serde_json::json!(1)),
                    Err(LlmError::Cache(_))
                ),
                "{key:?} was accepted"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_entry_is_never_followed() {
        let dir = TempDir::new("symlink");
        let cache = ResponseCache::new(&dir.0);
        std::fs::create_dir_all(&dir.0).expect("mkdir");
        let outside = TempDir::new("symlink-target");
        std::fs::create_dir_all(&outside.0).expect("mkdir target");
        let target = outside.0.join("victim.json");
        std::fs::write(&target, b"{\"planted\": true}").expect("seed target");
        let key = "json-link";
        std::os::unix::fs::symlink(&target, entry_path(&cache, key)).expect("symlink");

        // Reading refuses the link, so the planted value is not served.
        assert!(cache.get::<serde_json::Value>(key).is_none());
        assert!(!cache.contains(key));
        // Writing replaces the link itself and leaves the target untouched.
        cache.put(key, &serde_json::json!("ours")).expect("write");
        assert_eq!(
            std::fs::read(&target).expect("read target"),
            b"{\"planted\": true}"
        );
        assert!(
            std::fs::symlink_metadata(entry_path(&cache, key))
                .expect("stat")
                .file_type()
                .is_file()
        );
        assert_eq!(
            cache.get::<serde_json::Value>(key),
            Some(serde_json::json!("ours"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_cache_root_is_refused() {
        let real = TempDir::new("real-root");
        std::fs::create_dir_all(&real.0).expect("mkdir");
        let link = TempDir::new("link-root");
        std::os::unix::fs::symlink(&real.0, &link.0).expect("symlink");
        let cache = ResponseCache::new(&link.0);
        assert!(matches!(
            cache.put("json-a", &serde_json::json!(1)),
            Err(LlmError::Cache(_))
        ));
        assert!(cache.get::<serde_json::Value>("json-a").is_none());
        // Remove the link itself (the guard's remove_dir_all would refuse it).
        let _ = std::fs::remove_file(&link.0);
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_entry_is_a_miss_without_blocking() {
        let dir = TempDir::new("fifo");
        let cache = ResponseCache::new(&dir.0);
        std::fs::create_dir_all(&dir.0).expect("mkdir");
        let key = "json-fifo";
        let made = std::process::Command::new("mkfifo")
            .arg(entry_path(&cache, key))
            .status();
        if !made.is_ok_and(|status| status.success()) {
            // No mkfifo on this system; the regular-file check is covered by
            // the directory and symlink tests.
            return;
        }
        // Opening a FIFO for reading would block forever; the lookup must
        // reject it without opening it.
        assert!(cache.get::<serde_json::Value>(key).is_none());
    }
}
