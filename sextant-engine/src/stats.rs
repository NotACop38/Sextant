//! Byte statistics over the sample set (FR-6).
//!
//! The statistical inference pass begins with cheap, classical summaries of the
//! sample bytes: Shannon entropy, byte-value frequency, and n-gram counts. These
//! summaries do not by themselves decide a field layout; they inform the
//! detectors that follow. High entropy marks a region as likely compressed or
//! encrypted payload (so it is left opaque rather than decomposed), a skewed
//! byte frequency hints at text or structure, and repeated n-grams hint at
//! record delimiters or fixed tables.
//!
//! Everything here is native, allocation-bounded, and deterministic (NFR-6): the
//! same bytes always produce the same numbers.

use std::collections::BTreeMap;

/// A byte-value frequency histogram over one or more buffers (FR-6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteHistogram {
    counts: [u64; 256],
    total: u64,
}

impl Default for ByteHistogram {
    fn default() -> Self {
        Self {
            counts: [0; 256],
            total: 0,
        }
    }
}

impl ByteHistogram {
    /// Build a histogram from a single buffer.
    #[must_use]
    pub fn of(data: &[u8]) -> Self {
        let mut histogram = Self::default();
        histogram.add(data);
        histogram
    }

    /// Build a histogram aggregated over many buffers.
    #[must_use]
    pub fn of_samples<S: AsRef<[u8]>>(samples: &[S]) -> Self {
        let mut histogram = Self::default();
        for sample in samples {
            histogram.add(sample.as_ref());
        }
        histogram
    }

    /// Fold another buffer's bytes into the histogram.
    pub fn add(&mut self, data: &[u8]) {
        for &byte in data {
            self.counts[usize::from(byte)] += 1;
        }
        self.total += data.len() as u64;
    }

    /// The number of times `byte` was seen.
    #[must_use]
    pub fn count(&self, byte: u8) -> u64 {
        self.counts[usize::from(byte)]
    }

    /// The total number of bytes counted.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }

    /// How many distinct byte values appeared at least once.
    #[must_use]
    pub fn distinct(&self) -> usize {
        self.counts.iter().filter(|&&count| count > 0).count()
    }

    /// The Shannon entropy of the byte distribution, in bits per byte (0 to 8).
    ///
    /// Constant data has entropy 0; a uniform distribution over all 256 values
    /// has entropy 8. An empty histogram has entropy 0.
    #[must_use]
    pub fn entropy(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let total = self.total as f64;
        let mut entropy = 0.0;
        for &count in &self.counts {
            if count > 0 {
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }
        // Floating-point rounding can nudge a maximal distribution a hair past
        // 8.0; clamp so callers can rely on the documented range.
        entropy.clamp(0.0, 8.0)
    }
}

/// The Shannon entropy of `data` in bits per byte (0 to 8), a convenience over
/// [`ByteHistogram::of`].
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    ByteHistogram::of(data).entropy()
}

/// The Shannon entropy of each non-overlapping window of `window` bytes.
///
/// The final window may be shorter than `window` when the buffer does not divide
/// evenly. A `window` of zero, or an empty buffer, yields an empty vector. This
/// is the windowed-entropy view of FR-6: it locates the transition from a
/// low-entropy structured header to a high-entropy payload.
#[must_use]
pub fn windowed_entropy(data: &[u8], window: usize) -> Vec<f64> {
    if window == 0 || data.is_empty() {
        return Vec::new();
    }
    data.chunks(window).map(shannon_entropy).collect()
}

/// The counts of every contiguous `n`-byte sequence (n-gram) in `data` (FR-6).
///
/// With `n` of 1 this is the byte histogram as a map; with `n` of 2 or 3 it
/// surfaces repeated pairs and triples that often mark record boundaries or
/// fixed tables. An `n` of zero, or a buffer shorter than `n`, yields an empty
/// map. The map is ordered, so iteration and any derived output are
/// deterministic (NFR-6).
#[must_use]
pub fn ngram_counts(data: &[u8], n: usize) -> BTreeMap<Vec<u8>, u64> {
    let mut counts: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
    if n == 0 || data.len() < n {
        return counts;
    }
    for window in data.windows(n) {
        *counts.entry(window.to_vec()).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_data_has_zero_entropy() {
        assert_eq!(shannon_entropy(&[0x41; 64]), 0.0);
    }

    #[test]
    fn empty_data_has_zero_entropy() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn uniform_bytes_reach_full_entropy() {
        let data: Vec<u8> = (0..=255).collect();
        let entropy = shannon_entropy(&data);
        assert!((entropy - 8.0).abs() < 1e-9, "entropy {entropy}");
    }

    #[test]
    fn two_equally_likely_values_have_one_bit_of_entropy() {
        let mut data = vec![0u8; 50];
        data.extend(std::iter::repeat_n(1u8, 50));
        assert!((shannon_entropy(&data) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn histogram_counts_and_distinct_are_correct() {
        let histogram = ByteHistogram::of(&[1, 1, 2, 3, 3, 3]);
        assert_eq!(histogram.total(), 6);
        assert_eq!(histogram.count(1), 2);
        assert_eq!(histogram.count(3), 3);
        assert_eq!(histogram.count(9), 0);
        assert_eq!(histogram.distinct(), 3);
    }

    #[test]
    fn histogram_aggregates_over_samples() {
        let samples: [&[u8]; 2] = [&[1, 2], &[2, 3, 3]];
        let histogram = ByteHistogram::of_samples(&samples);
        assert_eq!(histogram.total(), 5);
        assert_eq!(histogram.count(2), 2);
        assert_eq!(histogram.count(3), 2);
    }

    #[test]
    fn windowed_entropy_splits_into_windows() {
        // Four bytes, window two: a constant window then a two-value window.
        let entropies = windowed_entropy(&[7, 7, 0, 1], 2);
        assert_eq!(entropies.len(), 2);
        assert_eq!(entropies[0], 0.0);
        assert!((entropies[1] - 1.0).abs() < 1e-9);
    }

    #[test]
    fn windowed_entropy_handles_a_short_final_window() {
        let entropies = windowed_entropy(&[1, 2, 3], 2);
        assert_eq!(entropies.len(), 2);
    }

    #[test]
    fn windowed_entropy_rejects_degenerate_inputs() {
        assert!(windowed_entropy(&[1, 2, 3], 0).is_empty());
        assert!(windowed_entropy(&[], 4).is_empty());
    }

    #[test]
    fn ngram_counts_tallies_pairs() {
        // "abab": pairs ab, ba, ab -> ab:2, ba:1.
        let counts = ngram_counts(b"abab", 2);
        assert_eq!(counts.get(b"ab".as_slice()), Some(&2));
        assert_eq!(counts.get(b"ba".as_slice()), Some(&1));
    }

    #[test]
    fn ngram_counts_rejects_degenerate_inputs() {
        assert!(ngram_counts(b"abc", 0).is_empty());
        assert!(ngram_counts(b"a", 2).is_empty());
    }
}
