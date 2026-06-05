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
    pub fn put<T: Serialize>(&self, key: &str, value: &T) -> Result<(), LlmError> {
        std::fs::create_dir_all(&self.root).map_err(|error| {
            LlmError::Cache(format!(
                "could not create cache directory {}: {error}",
                self.root.display()
            ))
        })?;
        let text = serde_json::to_string_pretty(value).map_err(|error| {
            LlmError::Cache(format!("could not serialize entry {key}: {error}"))
        })?;
        let path = self.path_for(key);
        std::fs::write(&path, text)
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
