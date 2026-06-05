//! On-disk response cache keyed by a hash of the exact request (NFR-6, NFR-9).
//!
//! Caching makes model-augmented runs reproducible and cheap to repeat: an
//! identical request is served from disk without touching the network. The key
//! is a content hash over the provider, the model, the call kind, and the full
//! request, so a change to any of them produces a distinct entry.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::config::ProviderKind;
use crate::error::LlmError;

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

    /// The file path for a given key.
    fn path_for(&self, key: &str) -> PathBuf {
        self.root.join(format!("{key}.json"))
    }

    /// Look up a cached value. Returns `Ok(None)` on a miss.
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, LlmError> {
        let path = self.path_for(key);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let value = serde_json::from_str(&text).map_err(|error| {
                    LlmError::Cache(format!("could not parse cached entry {key}: {error}"))
                })?;
                Ok(Some(value))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(LlmError::Cache(format!(
                "could not read cached entry {key}: {error}"
            ))),
        }
    }

    /// Store a value under `key`.
    ///
    /// On Unix the cache directory and every entry are created with
    /// owner-only permissions. A cached request and response can echo bytes
    /// drawn from the samples that were sent to the model, so they must not be
    /// readable by other users on a shared machine (PRD Section 16).
    pub fn put<T: Serialize>(&self, key: &str, value: &T) -> Result<(), LlmError> {
        std::fs::create_dir_all(&self.root).map_err(|error| {
            LlmError::Cache(format!(
                "could not create cache directory {}: {error}",
                self.root.display()
            ))
        })?;
        restrict_dir_permissions(&self.root);
        let text = serde_json::to_string_pretty(value).map_err(|error| {
            LlmError::Cache(format!("could not serialize entry {key}: {error}"))
        })?;
        let path = self.path_for(key);
        write_private(&path, text.as_bytes())
            .map_err(|error| LlmError::Cache(format!("could not write entry {key}: {error}")))
    }

    /// Whether a key is present on disk, for tests and diagnostics.
    pub fn contains(&self, key: &str) -> bool {
        self.path_for(key).exists()
    }

    /// The cache root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Write `bytes` to `path`, creating the file with owner-only permissions on
/// Unix so cached sample-derived data is not world-readable. On other platforms
/// this is an ordinary write.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    // The `mode` above only takes effect when this call creates the file. An
    // entry left over from an older, world-readable cache keeps its old mode
    // through a truncating rewrite, so the refreshed sample-derived bytes would
    // stay group- or world-readable. Set the mode explicitly on the open handle
    // so both a fresh and a pre-existing entry end up owner-only.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)
}

/// Non-Unix fallback: an ordinary write, since file modes are POSIX specific.
#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

/// Tighten the cache directory to owner-only access on Unix. Best effort: a
/// failure to adjust the mode is not fatal to writing the entry.
#[cfg(unix)]
fn restrict_dir_permissions(root: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700));
}

/// Non-Unix fallback: no POSIX mode to set.
#[cfg(not(unix))]
fn restrict_dir_permissions(_root: &Path) {}

/// Compute the cache key for a request.
///
/// The key folds in the provider, the model, the call kind ("completion" or
/// "json"), and a canonical JSON serialization of the request. Changing any of
/// them changes the key, so a cached response can never be returned for a
/// materially different request.
pub fn request_key(
    provider: ProviderKind,
    model: &str,
    call_kind: &str,
    request: &serde_json::Value,
) -> String {
    // serde_json serializes struct fields in declaration order, which is stable
    // across runs, so this canonical form is deterministic (NFR-6).
    let canonical = serde_json::json!({
        "provider": provider,
        "model": model,
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

    #[test]
    fn hash_is_stable_and_distinguishes_inputs() {
        assert_eq!(fnv1a_128_hex(b"hello"), fnv1a_128_hex(b"hello"));
        assert_ne!(fnv1a_128_hex(b"hello"), fnv1a_128_hex(b"world"));
        assert_eq!(fnv1a_128_hex(b"x").len(), 32);
    }

    #[test]
    fn key_changes_with_model_and_request() {
        let request = serde_json::json!({"prompt": "hi"});
        let a = request_key(ProviderKind::Mock, "m1", "completion", &request);
        let b = request_key(ProviderKind::Mock, "m2", "completion", &request);
        let c = request_key(ProviderKind::Mock, "m1", "json", &request);
        assert_ne!(a, b, "model must affect the key");
        assert_ne!(a, c, "call kind must affect the key");
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
        let mode = std::fs::metadata(cache.path_for(key))
            .expect("stat entry")
            .permissions()
            .mode()
            & 0o777;
        // No group or world bits: cached sample-derived data stays private.
        assert_eq!(mode, 0o600, "cache entry mode was {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn rewriting_a_world_readable_entry_tightens_its_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new("upgrade");
        let cache = ResponseCache::new(&dir.0);
        std::fs::create_dir_all(&dir.0).expect("mkdir");
        let key = "completion-legacy";
        let path = cache.path_for(key);
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
    fn round_trips_a_value_through_disk() {
        let dir = TempDir::new("round-trip");
        let cache = ResponseCache::new(&dir.0);
        let key = "completion-abc";
        assert!(
            cache
                .get::<serde_json::Value>(key)
                .expect("miss is ok")
                .is_none()
        );
        let value = serde_json::json!({"text": "result"});
        cache.put(key, &value).expect("write");
        assert!(cache.contains(key));
        let read: serde_json::Value = cache.get(key).expect("read").expect("present");
        assert_eq!(read, value);
    }
}
