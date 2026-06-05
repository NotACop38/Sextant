//! Multi-sample positional alignment (FR-7).
//!
//! To find invariant regions, variable regions, and likely field boundaries, the
//! statistical pass aligns the samples column by column from offset zero. For
//! each offset it records whether every sample shares the same byte there (an
//! invariant column) or the bytes differ (a variable column), and how many
//! distinct values appeared.
//!
//! This is positional alignment: it compares samples at the same absolute
//! offset rather than searching for an optimal edit-distance alignment. Fixed
//! headers, the region where field boundaries are most recoverable, sit at
//! stable offsets across samples, so positional alignment recovers them directly
//! and cheaply. A future refinement can add gap-aware sequence alignment for
//! formats whose early fields shift position; the IR and the detectors that
//! consume this module do not depend on which alignment produced the columns.
//!
//! Alignment runs over the common prefix only, up to the length of the shortest
//! sample, because beyond that offset some samples have no byte to compare.

/// One aligned column: the bytes every sample holds at a single offset (FR-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Column {
    /// The byte offset this column describes.
    pub offset: usize,
    /// The shared byte when every sample agrees at this offset, else `None`.
    pub invariant: Option<u8>,
    /// How many distinct byte values appeared across the samples here.
    pub distinct: usize,
}

impl Column {
    /// Whether every sample holds the same byte at this offset.
    #[must_use]
    pub fn is_invariant(&self) -> bool {
        self.invariant.is_some()
    }
}

/// A maximal run of consecutive columns that are all invariant or all variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    /// The offset the region starts at.
    pub start: usize,
    /// The offset just past the region's last byte (exclusive).
    pub end: usize,
    /// Whether the region's columns are invariant.
    pub invariant: bool,
}

impl Region {
    /// The region's length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the region spans no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

/// The positional alignment of a sample set: one [`Column`] per offset over the
/// common prefix (FR-7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alignment {
    /// How many samples were aligned.
    pub sample_count: usize,
    /// The length of the shortest sample, the extent of the alignment.
    pub common_len: usize,
    /// The aligned columns, one per offset from zero to `common_len`.
    pub columns: Vec<Column>,
}

/// Align `samples` column by column over their common prefix (FR-7).
///
/// The result has one [`Column`] for every offset up to the length of the
/// shortest sample. An empty sample set, or one that contains an empty sample,
/// yields a zero-length alignment rather than failing.
#[must_use]
pub fn align<S: AsRef<[u8]>>(samples: &[S]) -> Alignment {
    let sample_count = samples.len();
    let common_len = samples
        .iter()
        .map(|sample| sample.as_ref().len())
        .min()
        .unwrap_or(0);

    let mut columns = Vec::with_capacity(common_len);
    for offset in 0..common_len {
        // Track the distinct byte values at this offset with a 256-bit presence
        // set, so the work is bounded and independent of the sample count.
        let mut seen = [false; 256];
        let mut distinct = 0usize;
        let mut first = None;
        let mut invariant = true;
        for sample in samples {
            let byte = sample.as_ref()[offset];
            if first.is_none() {
                first = Some(byte);
            } else if first != Some(byte) {
                invariant = false;
            }
            if !seen[usize::from(byte)] {
                seen[usize::from(byte)] = true;
                distinct += 1;
            }
        }
        columns.push(Column {
            offset,
            invariant: if invariant { first } else { None },
            distinct,
        });
    }

    Alignment {
        sample_count,
        common_len,
        columns,
    }
}

impl Alignment {
    /// The length of the invariant byte run starting at offset zero (FR-7, FR-8).
    ///
    /// This is the candidate magic or signature length: the number of leading
    /// bytes that are identical across every sample. It is zero when the first
    /// byte already varies, or when there are fewer than two samples (a single
    /// sample makes every column trivially invariant, which is not evidence of
    /// an invariant region).
    #[must_use]
    pub fn invariant_prefix_len(&self) -> usize {
        if self.sample_count < 2 {
            return 0;
        }
        self.columns
            .iter()
            .take_while(|column| column.is_invariant())
            .count()
    }

    /// The maximal invariant and variable [`Region`]s over the common prefix, in
    /// offset order (FR-7).
    #[must_use]
    pub fn regions(&self) -> Vec<Region> {
        let mut regions = Vec::new();
        let mut iter = self.columns.iter();
        let Some(first) = iter.next() else {
            return regions;
        };
        let mut start = first.offset;
        let mut invariant = first.is_invariant();
        let mut end = first.offset + 1;
        for column in iter {
            if column.is_invariant() == invariant {
                end = column.offset + 1;
            } else {
                regions.push(Region {
                    start,
                    end,
                    invariant,
                });
                start = column.offset;
                invariant = column.is_invariant();
                end = column.offset + 1;
            }
        }
        regions.push(Region {
            start,
            end,
            invariant,
        });
        regions
    }

    /// Candidate field boundaries: every offset where an invariant region meets
    /// a variable region, plus the start and end of the aligned prefix (FR-7).
    ///
    /// A transition between an unchanging region and a changing one is the
    /// strongest positional cue that one field ends and another begins. The
    /// returned offsets are sorted and unique.
    #[must_use]
    pub fn boundaries(&self) -> Vec<usize> {
        let mut boundaries = vec![0usize];
        for region in self.regions() {
            boundaries.push(region.start);
            boundaries.push(region.end);
        }
        boundaries.sort_unstable();
        boundaries.dedup();
        boundaries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligns_over_the_common_prefix() {
        let samples: [&[u8]; 2] = [&[1, 2, 3, 4], &[1, 2, 9]];
        let alignment = align(&samples);
        assert_eq!(alignment.common_len, 3);
        assert_eq!(alignment.columns.len(), 3);
        assert_eq!(alignment.columns[0].invariant, Some(1));
        assert_eq!(alignment.columns[1].invariant, Some(2));
        assert_eq!(alignment.columns[2].invariant, None);
        assert_eq!(alignment.columns[2].distinct, 2);
    }

    #[test]
    fn invariant_prefix_is_the_leading_constant_run() {
        let samples: [&[u8]; 3] = [b"SCMA\xa1", b"SCMA\xa5", b"SCMA\xa2"];
        let alignment = align(&samples);
        assert_eq!(alignment.invariant_prefix_len(), 4);
    }

    #[test]
    fn a_single_sample_has_no_invariant_prefix() {
        let samples: [&[u8]; 1] = [b"anything"];
        let alignment = align(&samples);
        // Every column is trivially invariant with one sample, but that is not
        // evidence of a real invariant region, so the prefix length is zero.
        assert_eq!(alignment.invariant_prefix_len(), 0);
    }

    #[test]
    fn empty_inputs_yield_an_empty_alignment() {
        let none: [&[u8]; 0] = [];
        assert_eq!(align(&none).common_len, 0);
        let with_empty: [&[u8]; 2] = [&[], &[1, 2]];
        assert_eq!(align(&with_empty).common_len, 0);
    }

    #[test]
    fn regions_and_boundaries_split_at_transitions() {
        let samples: [&[u8]; 2] = [&[1, 1, 9, 9, 5], &[1, 1, 8, 7, 5]];
        let alignment = align(&samples);
        let regions = alignment.regions();
        assert_eq!(
            regions,
            vec![
                Region {
                    start: 0,
                    end: 2,
                    invariant: true
                },
                Region {
                    start: 2,
                    end: 4,
                    invariant: false
                },
                Region {
                    start: 4,
                    end: 5,
                    invariant: true
                },
            ]
        );
        assert_eq!(alignment.boundaries(), vec![0, 2, 4, 5]);
    }
}
