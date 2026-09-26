//! Candidate IR assembly and ranking (FR-12).
//!
//! [`infer_candidates`] runs the statistical pass end to end. It proposes
//! hypotheses from several independent families, each built from verified
//! detector findings and typed by [`segment`](crate::segment):
//!
//! - **fixed**: every sample has the same length, so the whole sample is one
//!   typed fixed layout;
//! - **remaining**: a size field measures the bytes from a header boundary to
//!   the end (a RIFF or BMP size), optionally followed by a fixed trailer that
//!   may verify as a checksum (FR-9, FR-10). The governed region is proposed
//!   as an opaque payload and, when a nested section inferred over it
//!   verifies, as a sized struct holding that nested structure;
//! - **counted**: a count field gives the number of fixed-size records that
//!   fill the sample, and the records are typed from every record pooled
//!   together;
//! - **sequential**: one or two length fields govern variable regions laid out
//!   in sequence after the header (a file name, then its data), and the layout
//!   is confirmed by what follows: the sample end, a fixed trailer, or an
//!   invariant marker that begins the next section, which is inferred
//!   recursively;
//! - **chunked**: a repeating length-prefixed record array (PNG chunks, RIFF
//!   chunks, capture records), with every consistent layout proposed;
//! - **offset**: a header field points at an invariant marker further in;
//! - **prefix**: the typed common prefix, then an opaque payload;
//!
//! plus the magic-only and structureless fallbacks, so the pass always returns
//! a usable, fully covering candidate.
//!
//! Every proposal is validated against the IR rules and scored by the native
//! executor and scorer. Candidates are ranked by full verification, then fit,
//! then the number of checksum checks that pass, then the number of
//! relationships they encode (each one re-checked by the executor), then
//! [structure](crate::scorer::Score::structure), with the name as a final
//! deterministic tie-break: among hypotheses that all parse every sample, the
//! one that verifies the most and then explains the most of the samples'
//! content wins, and an opaque blob, which explains nothing, comes last (FR-12,
//! FR-26).

use std::collections::{HashMap, HashSet};

use sextant_ir::{
    Bytes, ChecksumAlgorithm, ChecksumSpec, Confidence, Constraint, CountRule, CoveredRange,
    Endianness, Evidence, Field, FieldOffset, FieldRef, Format, Kind, Metadata, RangeAnchor, Role,
    SampleSupport, Signedness, SizeRule, StringEncoding, Structure,
};

use crate::checksum;
use crate::chunk::{ChunkChecksumStart, ChunkLayout, detect_chunk_layouts};
use crate::detect::{
    IntField, IntRelation, MAX_HEADER_SCAN, Reading, detect_bitfields, detect_int_fields,
    detect_offsets,
};
use crate::limits::Limits;
use crate::scorer::{Score, ScoreWeights, score_with};
use crate::segment::{Extent, Forced, Segment, SegmentKind, segment};
use crate::stats::shannon_entropy;

/// Bits-per-byte above which a payload region is treated as opaque rather than
/// structured. Compressed or encrypted data sits near eight; plain records sit
/// well below.
const OPAQUE_ENTROPY: f64 = 6.5;
/// The deepest nesting of sections inferred recursively (a sequential
/// family's following section, or a governed body).
const MAX_SECTION_DEPTH: usize = 3;
/// How many governed bodies one section types by nested inference, which
/// bounds the extra inference work a section can cause.
const MAX_TYPED_BODIES: usize = 2;
/// The most chunk layouts turned into candidates.
const MAX_CHUNK_CANDIDATES: usize = 12;
/// The most sequential layouts turned into candidates per section.
const MAX_SEQUENTIAL_CANDIDATES: usize = 6;
/// The longest fixed trailer a sequential layout may end with.
const MAX_TRAILER: usize = 64;
/// The shortest invariant marker that confirms the start of a following
/// section.
const MIN_MARKER: usize = 2;
/// Candidate proposals examine at most this many bytes of the common prefix.
const MAX_PREFIX: usize = crate::segment::MAX_REGION;
/// The most bytes, across all rows, a following section may hold for it to be
/// inferred recursively. Larger tails are left opaque, which bounds the work a
/// marker that matches by chance can cause.
const MAX_TAIL_BYTES: usize = 1 << 20;
/// Above this many input bytes, proposals are first ranked on a few small
/// samples and only the leaders are scored on the whole set (NFR-3).
const STAGED_SCORING_BYTES: usize = 4 << 20;
/// How many samples the first scoring stage uses.
const STAGE_SAMPLES: usize = 4;
/// How many proposals survive the first scoring stage.
const STAGE_SURVIVORS: usize = 6;
/// Unix times, in seconds, treated as plausible timestamps: 2000 to 2040.
const TIMESTAMP_RANGE: std::ops::RangeInclusive<u64> = 946_684_800..=2_208_988_800;

/// One candidate Format Hypothesis IR with its verified preliminary score
/// (FR-12).
#[derive(Debug, Clone)]
pub struct Candidate {
    /// The hypothesized format.
    pub format: Format,
    /// The score of the format over the sample set, from the native scorer.
    pub score: Score,
    /// How many cross-field relationships (length, count, offset, checksum) the
    /// candidate encodes. Breaks ties between candidates that score equally.
    pub relations: usize,
}

/// Run the statistical inference pass and return candidate IRs ranked by
/// verified score, best first (FR-6 to FR-12).
///
/// The result always contains at least one valid, executable candidate. The
/// pass never panics on any input: empty sets, a single sample, identical
/// samples, and hostile bytes all produce a (possibly trivial) ranked list.
#[must_use]
pub fn infer_candidates<S: AsRef<[u8]>>(samples: &[S], limits: &Limits) -> Vec<Candidate> {
    let slices: Vec<&[u8]> = samples.iter().map(AsRef::as_ref).collect();
    let section = Section::new(&slices, 0);
    let proposals = section.propose(limits);
    rank(proposals, &slices, limits)
}

/// A hypothesis before scoring.
#[derive(Debug, Clone)]
struct Proposal {
    /// The family that built it, used as the candidate name.
    family: &'static str,
    /// The root fields.
    fields: Vec<Field>,
    /// The default byte order.
    big_endian: bool,
    /// How many relationships the fields encode.
    relations: usize,
}

/// A proposal whose relationship count is read from the fields themselves.
fn proposal(family: &'static str, fields: Vec<Field>, big_endian: bool) -> Proposal {
    Proposal {
        family,
        relations: encoded_relations(&fields),
        fields,
        big_endian,
    }
}

impl Proposal {
    fn into_format(self) -> Format {
        let mut metadata = Metadata {
            source: Some("statistical inference pass".to_owned()),
            ..Metadata::default()
        };
        metadata
            .extra
            .insert("family".to_owned(), self.family.to_owned());
        Format {
            name: format!("candidate-{}", self.family),
            endianness: if self.big_endian {
                Endianness::Big
            } else {
                Endianness::Little
            },
            root: Structure::new(self.fields),
            enums: Default::default(),
            metadata,
        }
    }
}

/// Validate, score, deduplicate, and order the proposals (FR-12).
///
/// On large inputs every proposal is first scored on the few smallest samples,
/// and only the leaders (plus the structureless fallback, which always
/// verifies) are scored on the whole set, so the cost of scoring stays a small
/// multiple of one pass over the input.
fn rank(proposals: Vec<Proposal>, slices: &[&[u8]], limits: &Limits) -> Vec<Candidate> {
    let mut formats: Vec<(Format, usize)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for proposal in proposals {
        let relations = proposal.relations;
        let format = proposal.into_format();
        if format.validate().is_err() {
            continue;
        }
        let Ok(key) = serde_json::to_string(&format.root) else {
            continue;
        };
        if seen.insert(key) {
            formats.push((format, relations));
        }
    }

    let total: usize = slices.iter().map(|slice| slice.len()).sum();
    if total > STAGED_SCORING_BYTES && formats.len() > STAGE_SURVIVORS {
        let mut order: Vec<usize> = (0..slices.len()).collect();
        order.sort_by_key(|&index| slices[index].len());
        let probe: Vec<&[u8]> = order
            .into_iter()
            .take(STAGE_SAMPLES)
            .map(|index| slices[index])
            .collect();
        let mut staged: Vec<Candidate> = formats
            .into_iter()
            .map(|(format, relations)| Candidate {
                score: score_with(&format, &probe, limits, ScoreWeights::default()),
                format,
                relations,
            })
            .collect();
        staged.sort_by(compare_candidates);
        let fallback = staged
            .iter()
            .position(|candidate| candidate.format.name == "candidate-opaque");
        formats = staged
            .into_iter()
            .enumerate()
            .filter(|(index, _)| *index < STAGE_SURVIVORS || Some(*index) == fallback)
            .map(|(_, candidate)| (candidate.format, candidate.relations))
            .collect();
    }

    let mut candidates: Vec<Candidate> = formats
        .into_iter()
        .map(|(format, relations)| Candidate {
            score: score_with(&format, slices, limits, ScoreWeights::default()),
            format,
            relations,
        })
        .collect();
    candidates.sort_by(compare_candidates);
    candidates
}

/// The candidate order: fully verified first, then higher fit, then more
/// checksum checks passed, then more encoded relationships, then higher
/// structure, then name for determinism.
///
/// Encoded relationships (derived sizes, counts, and offsets, and checksums)
/// are re-checked by the executor on every sample, which makes them stronger
/// evidence than a description-length saving: a hypothesis that verifies a
/// count or a checksum has found real structure, while typing a few more
/// header bytes can win on bits alone by unrolling what the samples happen to
/// share. A passing checksum is the strongest of these, since it verifies by
/// chance only rarely, so the number of checksum instances that verify ranks
/// first. Structure decides among hypotheses that verify as much.
fn compare_candidates(a: &Candidate, b: &Candidate) -> std::cmp::Ordering {
    b.score
        .fully_verified()
        .cmp(&a.score.fully_verified())
        .then(total_order(b.score.overall, a.score.overall))
        .then(b.score.checksums_passed().cmp(&a.score.checksums_passed()))
        .then(b.relations.cmp(&a.relations))
        .then(total_order(b.score.structure, a.score.structure))
        .then(a.format.name.cmp(&b.format.name))
}

fn total_order(a: f64, b: f64) -> std::cmp::Ordering {
    a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal)
}

/// A set of rows analyzed together: the samples at the root, or the tails of
/// the samples after a variable-length region.
struct Section<'a> {
    rows: Vec<&'a [u8]>,
    lens: Vec<usize>,
    min_len: usize,
    depth: usize,
    /// A prefix that keeps field names unique across nested sections.
    prefix: String,
    /// How many leading bytes every row shares (zero for fewer than two rows).
    invariant_prefix: usize,
    /// The length of the leading signature.
    magic: usize,
}

impl<'a> Section<'a> {
    fn new(rows: &[&'a [u8]], depth: usize) -> Self {
        let lens: Vec<usize> = rows.iter().map(|row| row.len()).collect();
        let invariant_prefix = invariant_prefix(rows);
        Self {
            rows: rows.to_vec(),
            min_len: lens.iter().copied().min().unwrap_or(0),
            lens,
            depth,
            prefix: if depth == 0 {
                String::new()
            } else {
                format!("s{}_", depth + 1)
            },
            invariant_prefix,
            magic: magic_len(rows, invariant_prefix),
        }
    }

    fn total(&self) -> usize {
        self.rows.len()
    }

    /// Every proposal for this section, before scoring.
    fn propose(&self, limits: &Limits) -> Vec<Proposal> {
        let mut out = Vec::new();
        if self.rows.len() >= 2 && self.min_len > 0 {
            let relations = detect_int_fields(&self.rows);
            out.extend(self.fixed());
            out.extend(self.remaining(&relations, limits));
            out.extend(self.counted(&relations));
            out.extend(self.sequential(&relations, limits));
            out.extend(self.chunked(&relations, limits));
            out.extend(self.offset(&relations));
            out.extend(self.prefix(&relations));
            out.extend(self.magic_only());
        }
        out.push(self.opaque());
        out
    }

    // ----- families -------------------------------------------------------

    /// Every sample has the same length: type all of it.
    fn fixed(&self) -> Option<Proposal> {
        if self.lens.iter().any(|&len| len != self.min_len) || self.min_len > MAX_PREFIX {
            return None;
        }
        let mut namer = Namer::new(&self.prefix);
        let header = self.header(
            self.min_len,
            &[],
            &Labels::default(),
            &mut namer,
            Extent::Exact,
        );
        Some(proposal("fixed", header.fields, header.big_endian))
    }

    /// Relationship findings with one width per field: readings at the same
    /// offset that satisfy the same relationship (a small value read as one,
    /// two, or four bytes) collapse to the width whose header segmentation is
    /// cheapest.
    fn distinct_relations<'r>(&self, relations: &'r [IntField]) -> Vec<&'r IntField> {
        let mut groups: Vec<Vec<&IntField>> = Vec::new();
        for found in relations {
            match groups.iter_mut().find(|group| {
                group[0].reading.offset == found.reading.offset
                    && group[0].reading.big_endian == found.reading.big_endian
                    && group[0].relation == found.relation
            }) {
                Some(group) => group.push(found),
                None => groups.push(vec![found]),
            }
        }
        groups
            .into_iter()
            .filter_map(|group| {
                let header_len = match group[0].relation {
                    IntRelation::Remaining { start, .. } | IntRelation::Count { start, .. } => {
                        start
                    }
                    IntRelation::TotalLength => group[0].reading.end(),
                }
                .min(MAX_PREFIX);
                group.into_iter().min_by(|a, b| {
                    let cost = |found: &IntField| {
                        segment(
                            &self.rows,
                            header_len.max(found.reading.end()),
                            0,
                            self.magic.min(found.reading.offset),
                            &[forced(found.reading)],
                            Extent::Exact,
                        )
                        .cost
                    };
                    total_order(cost(a), cost(b))
                })
            })
            .collect()
    }

    /// A size field measures the region from a header boundary to the end.
    ///
    /// The region is proposed as an opaque payload and, when a nested section
    /// inferred over the regions verifies, also as a sized struct holding that
    /// nested structure, so a container's body (a RIFF form, a bitmap's pixel
    /// header) is typed rather than left opaque whenever that verifies.
    fn remaining(&self, relations: &[IntField], limits: &Limits) -> Vec<Proposal> {
        let mut out = Vec::new();
        let mut typed = 0;
        for found in self.distinct_relations(relations) {
            let IntRelation::Remaining { start, trailing } = found.relation else {
                continue;
            };
            if start > MAX_PREFIX {
                continue;
            }
            let mut namer = Namer::new(&self.prefix);
            let size_name = namer.name("length");
            let mut labels = Labels::from_relations(relations);
            labels.assign(found.reading, Role::Length, size_name.clone());
            let forced = [forced(found.reading)];
            let header = self.header(start, &forced, &labels, &mut namer, Extent::Exact);
            let mut fields = header.fields;
            let regions: Vec<&[u8]> = self
                .rows
                .iter()
                .map(|row| &row[start..row.len() - trailing])
                .collect();
            let payload_name = namer.name("payload");
            let size = SizeRule::Derived {
                length_field: FieldRef::new(size_name),
            };
            let payload_index = fields.len();
            fields.push(region_field(
                &payload_name,
                size.clone(),
                &regions,
                self.total(),
                "region sized by the length field",
            ));
            if trailing > 0 {
                let trailer_start: Vec<usize> =
                    self.lens.iter().map(|&len| len - trailing).collect();
                fields.extend(self.trailer(
                    &trailer_start,
                    trailing,
                    &fields,
                    &payload_name,
                    &mut namer,
                ));
            }

            // The typed body replaces the opaque payload in place. It keeps the
            // payload's name and extent, so a trailer checksum anchored to the
            // payload covers the same bytes.
            let body = (typed < MAX_TYPED_BODIES)
                .then(|| self.best_nested(&regions, limits))
                .flatten()
                .filter(|nested| nested.family != "opaque");
            if let Some(nested) = body {
                typed += 1;
                let mut typed_fields = fields.clone();
                typed_fields[payload_index] =
                    body_field(&payload_name, size, nested.fields, self.total());
                out.push(proposal("remaining-typed", typed_fields, header.big_endian));
            }
            out.push(proposal("remaining", fields, header.big_endian));
        }
        out
    }

    /// A count field gives the number of fixed-size records that fill the rest.
    fn counted(&self, relations: &[IntField]) -> Vec<Proposal> {
        let mut out = Vec::new();
        for found in self.distinct_relations(relations) {
            let IntRelation::Count { record_size, start } = found.relation else {
                continue;
            };
            let Ok(record_size) = usize::try_from(record_size) else {
                continue;
            };
            if start > MAX_PREFIX || record_size > MAX_PREFIX {
                continue;
            }
            let mut namer = Namer::new(&self.prefix);
            let count_name = namer.name("count");
            let mut labels = Labels::from_relations(relations);
            labels.assign(found.reading, Role::Count, count_name.clone());
            let header = self.header(
                start,
                &[forced(found.reading)],
                &labels,
                &mut namer,
                Extent::Exact,
            );
            let records: Vec<&[u8]> = self
                .rows
                .iter()
                .flat_map(|row| row[start..].chunks_exact(record_size))
                .collect();
            let element = pooled_element(&records, record_size, "record", &mut namer, self.total());
            let mut fields = header.fields;
            fields.push(array_field(
                &namer.name("records"),
                element,
                CountRule::FromField {
                    count_field: FieldRef::new(count_name),
                },
                self.total(),
                "fixed-size records repeated as many times as the count field says",
            ));
            out.push(proposal("counted", fields, header.big_endian));
        }
        out
    }

    /// One or two length fields govern regions laid out after the header,
    /// confirmed by the sample end, a fixed trailer, or a following section.
    fn sequential(&self, relations: &[IntField], limits: &Limits) -> Vec<Proposal> {
        let scan = self.min_len.min(MAX_HEADER_SCAN);
        let prefix = segment(&self.rows, scan, 0, self.magic, &[], Extent::Exact);
        // Candidate length fields: varying integers of the typed prefix whose
        // values never exceed their sample.
        let lengths: Vec<(Reading, Vec<usize>)> = prefix
            .segments
            .iter()
            .filter_map(|piece| match piece.kind {
                SegmentKind::Integer {
                    width,
                    big_endian,
                    constant: None,
                } => Some(Reading {
                    offset: piece.offset,
                    width,
                    big_endian,
                }),
                _ => None,
            })
            .filter_map(|reading| {
                let values: Option<Vec<usize>> = self
                    .rows
                    .iter()
                    .map(|row| {
                        let value = read_uint(row, reading)?;
                        usize::try_from(value).ok().filter(|&v| v <= row.len())
                    })
                    .collect();
                values.map(|values| (reading, values))
            })
            .collect();

        let mut layouts: Vec<Sequential> = Vec::new();
        for (a, (first, first_values)) in lengths.iter().enumerate() {
            for second in std::iter::once(None).chain(
                lengths
                    .iter()
                    .enumerate()
                    .filter(|&(b, _)| b != a)
                    .map(|(_, entry)| Some(entry)),
            ) {
                let governing: Vec<(Reading, &Vec<usize>)> =
                    std::iter::once((*first, first_values))
                        .chain(second.map(|(reading, values)| (*reading, values)))
                        .collect();
                let header_min = governing.iter().map(|(r, _)| r.end()).max().unwrap_or(0);
                for header in header_min..=scan {
                    if let Some(layout) = self.check_sequential(header, &governing) {
                        layouts.push(layout);
                    }
                }
            }
        }
        // Prefer confirmations that are hard to satisfy by chance, then fewer
        // governed regions, then earlier headers.
        layouts.sort_by_key(|layout| (layout.end.rank(), layout.governing.len(), layout.header));
        layouts.dedup_by(|a, b| a.header == b.header && a.governing == b.governing);
        layouts.truncate(MAX_SEQUENTIAL_CANDIDATES);

        layouts
            .into_iter()
            .map(|layout| self.build_sequential(&layout, relations, limits))
            .collect()
    }

    /// Whether `governing` lengths, read in order after a header of `header`
    /// bytes, land on a confirmed position in every sample.
    fn check_sequential(
        &self,
        header: usize,
        governing: &[(Reading, &Vec<usize>)],
    ) -> Option<Sequential> {
        let mut ends = Vec::with_capacity(self.rows.len());
        for (index, &len) in self.lens.iter().enumerate() {
            let mut position = header;
            for (_, values) in governing {
                position = position.checked_add(values[index])?;
            }
            if position > len {
                return None;
            }
            ends.push(position);
        }
        // A single region that ends at the sample end or before a fixed
        // trailer is the remaining family's job; one region here must be
        // confirmed by a following section.
        let single = governing.len() < 2;
        let end = if ends.iter().zip(&self.lens).all(|(&end, &len)| end == len) {
            if single {
                return None;
            }
            SequentialEnd::Exact
        } else if let Some(trailer) = constant_trailer(&ends, &self.lens).filter(|_| !single) {
            SequentialEnd::Trailer(trailer)
        } else {
            let marker = common_prefix(&self.rows, &ends);
            let first = &self.rows[0][ends[0]..];
            // Shared padding bytes are no evidence of a section boundary.
            let meaningful = first[..marker]
                .iter()
                .any(|&byte| byte != 0x00 && byte != 0xFF);
            if marker < MIN_MARKER || !meaningful {
                return None;
            }
            SequentialEnd::Marker
        };
        Some(Sequential {
            header,
            governing: governing.iter().map(|(reading, _)| *reading).collect(),
            ends,
            end,
        })
    }

    fn build_sequential(
        &self,
        layout: &Sequential,
        relations: &[IntField],
        limits: &Limits,
    ) -> Proposal {
        let mut namer = Namer::new(&self.prefix);
        let mut labels = Labels::from_relations(relations);
        let mut forced_pieces = Vec::new();
        let mut length_names = Vec::new();
        for (index, reading) in layout.governing.iter().enumerate() {
            let name = namer.name(&format!("length_{}", index + 1));
            labels.assign(*reading, Role::Length, name.clone());
            forced_pieces.push(forced(*reading));
            length_names.push(name);
        }
        let header = self.header(
            layout.header,
            &forced_pieces,
            &labels,
            &mut namer,
            Extent::Exact,
        );
        let offsets = header.offsets;
        let mut fields = header.fields;

        // The governed regions, in order.
        let mut starts: Vec<usize> = vec![layout.header; self.rows.len()];
        let mut region_names = Vec::new();
        for (reading, length_name) in layout.governing.iter().zip(&length_names) {
            let regions: Vec<&[u8]> = self
                .rows
                .iter()
                .zip(&mut starts)
                .map(|(row, start)| {
                    let len = read_uint(row, *reading).unwrap_or(0) as usize;
                    let region = &row[*start..*start + len];
                    *start += len;
                    region
                })
                .collect();
            let name = namer.name(&format!("region_{}", region_names.len() + 1));
            fields.push(region_field(
                &name,
                SizeRule::Derived {
                    length_field: FieldRef::new(length_name.clone()),
                },
                &regions,
                self.total(),
                "region sized by a header length field",
            ));
            region_names.push((name, regions));
        }
        attach_region_checksums(&mut fields, &offsets, &region_names, &self.rows);

        match layout.end {
            SequentialEnd::Exact => {}
            SequentialEnd::Trailer(len) => {
                let last = region_names
                    .last()
                    .map_or_else(String::new, |(name, _)| name.clone());
                fields.extend(self.trailer(&layout.ends, len, &fields, &last, &mut namer));
            }
            SequentialEnd::Marker => {
                let tails: Vec<&[u8]> = self
                    .rows
                    .iter()
                    .zip(&layout.ends)
                    .map(|(row, &end)| &row[end..])
                    .collect();
                fields.extend(self.infer_tail(&tails, limits));
            }
        }
        proposal("sequential", fields, header.big_endian)
    }

    /// Infer the section that follows a marker and return its best fully
    /// verified hypothesis's fields, or an opaque tail when none verifies.
    fn infer_tail(&self, tails: &[&[u8]], limits: &Limits) -> Vec<Field> {
        if let Some(nested) = self.best_nested(tails, limits) {
            return nested.fields;
        }
        let name = format!("{}tail", self.prefix);
        vec![region_field(
            &name,
            SizeRule::ToEnd,
            tails,
            self.total(),
            "section after the governed regions",
        )]
    }

    /// Infer `regions` (one slice per row) as a nested section and return its
    /// best fully verified hypothesis by structure, or `None` when nothing
    /// verifies or the nesting depth or byte budget is spent.
    fn best_nested(&self, regions: &[&[u8]], limits: &Limits) -> Option<Proposal> {
        let bytes: usize = regions.iter().map(|region| region.len()).sum();
        if self.depth + 1 >= MAX_SECTION_DEPTH || bytes > MAX_TAIL_BYTES {
            return None;
        }
        let section = Section::new(regions, self.depth + 1);
        let mut best: Option<(Score, Proposal)> = None;
        for proposal in section.propose(limits) {
            let format = proposal.clone().into_format();
            if format.validate().is_err() {
                continue;
            }
            let score = score_with(&format, regions, limits, ScoreWeights::default());
            if !score.fully_verified() {
                continue;
            }
            let better = best
                .as_ref()
                .is_none_or(|(current, _)| total_order(score.structure, current.structure).is_gt());
            if better {
                best = Some((score, proposal));
            }
        }
        best.map(|(_, proposal)| proposal)
    }

    /// A repeating length-prefixed record array. Layouts with more records
    /// than the executor's field and output budgets can hold are skipped:
    /// they cannot verify, and scoring them would only exhaust those budgets.
    fn chunked(&self, relations: &[IntField], limits: &Limits) -> Vec<Proposal> {
        // A record contributes a handful of field instances; each instance
        // costs a few hundred bytes of the executor's output budget.
        const INSTANCES_PER_RECORD: usize = 8;
        const BYTES_PER_INSTANCE: usize = 512;
        let max_records = (limits.max_total_fields / INSTANCES_PER_RECORD)
            .min(limits.max_output_bytes / (INSTANCES_PER_RECORD * BYTES_PER_INSTANCE));
        detect_chunk_layouts(&self.rows)
            .into_iter()
            .filter(|layout| {
                layout
                    .record_counts
                    .iter()
                    .all(|&count| count <= max_records)
            })
            .take(MAX_CHUNK_CANDIDATES)
            .map(|layout| self.build_chunked(&layout, relations))
            .collect()
    }

    fn build_chunked(&self, layout: &ChunkLayout, relations: &[IntField]) -> Proposal {
        let mut namer = Namer::new(&self.prefix);
        let labels = Labels::from_relations(relations);
        // A header that is nothing but an invariant signature is one magic.
        let whole_magic = layout.header_len <= 8
            && layout.header_len >= 2
            && self.invariant_prefix >= layout.header_len;
        let magic = if whole_magic {
            layout.header_len
        } else {
            self.magic.min(layout.header_len)
        };
        let header = self.header_with_magic(
            layout.header_len,
            magic,
            &[],
            &labels,
            &mut namer,
            Extent::Exact,
        );
        let mut fields = header.fields;
        let total = self.total();
        // A header integer that equals the record count in every sample is the
        // record count.
        for (field, &offset) in fields.iter_mut().zip(&header.offsets) {
            let Kind::Integer {
                width, endianness, ..
            } = field.kind
            else {
                continue;
            };
            if !field.constraints.is_empty() {
                continue;
            }
            let reading = Reading {
                offset,
                width,
                big_endian: endianness == Some(Endianness::Big),
            };
            let counts_records = self
                .rows
                .iter()
                .zip(&layout.record_counts)
                .all(|(row, &count)| read_uint(row, reading) == Some(count as u64));
            if counts_records {
                field.role = Some(Role::Count);
                field.confidence = Confidence::clamped(0.85);
                field
                    .evidence
                    .notes
                    .push("value equals the number of records that follow".to_owned());
                // Nothing references a generically named piece, so it can be
                // named for the role it now has.
                let generic = format!("{}field_{offset}", self.prefix);
                if field.name.as_deref() == Some(generic.as_str()) {
                    field.name = Some(namer.name("count"));
                }
            }
        }

        // Pool every record of every sample to type the fixed sections.
        let mut records: Vec<(&[u8], usize)> = Vec::new();
        for row in &self.rows {
            let mut cursor = layout.header_len;
            while cursor < row.len() {
                let length = read_uint(
                    row,
                    Reading {
                        offset: cursor + layout.pre,
                        width: layout.width,
                        big_endian: layout.big_endian,
                    },
                )
                .unwrap_or(0) as usize;
                let end = cursor + layout.fixed() + length;
                if end > row.len() {
                    break;
                }
                records.push((&row[cursor..end], length));
                cursor = end;
            }
        }
        let data_offset = layout.pre + usize::from(layout.width) + layout.mid;
        let section = |start: usize, len: usize| -> Vec<&[u8]> {
            records
                .iter()
                .map(|&(record, _)| &record[start..start + len])
                .collect()
        };

        let mut inner = Vec::new();
        let mut first_name = None;
        if layout.pre > 0 {
            let pooled = section(0, layout.pre);
            let pieces = pooled_fields(&pooled, layout.pre, "tag", &mut namer, total);
            first_name = pieces.first().and_then(|field| field.name.clone());
            inner.extend(pieces);
        }
        let length_name = namer.name("length");
        let mut length = integer_field(
            &length_name,
            Reading {
                offset: layout.pre,
                width: layout.width,
                big_endian: layout.big_endian,
            },
            Role::Length,
            0.9,
            total,
            &["value equals the byte length of the record data"],
        );
        length.evidence.notes.push(format!(
            "records per sample: {}",
            layout
                .record_counts
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
        inner.push(length);
        let first_name = first_name.unwrap_or_else(|| length_name.clone());
        if layout.mid > 0 {
            let pooled = section(layout.pre + usize::from(layout.width), layout.mid);
            inner.extend(pooled_fields(
                &pooled, layout.mid, "type", &mut namer, total,
            ));
        }
        let data: Vec<&[u8]> = records
            .iter()
            .map(|&(record, len)| &record[data_offset..data_offset + len])
            .collect();
        let data_name = namer.name("data");
        inner.push(region_field(
            &data_name,
            SizeRule::Derived {
                length_field: FieldRef::new(length_name.clone()),
            },
            &data,
            total,
            "record data sized by the length field",
        ));
        if layout.tail > 0 {
            if let Some(found) = layout.checksum {
                let from = match found.start {
                    ChunkChecksumStart::RecordStart => RangeAnchor::FieldStart {
                        field: FieldRef::new(first_name),
                    },
                    ChunkChecksumStart::AfterLength => RangeAnchor::FieldEnd {
                        field: FieldRef::new(length_name),
                    },
                };
                inner.push(checksum_field(
                    &namer.name("checksum"),
                    layout.tail as u8,
                    found.big_endian,
                    found.algorithm,
                    from,
                    RangeAnchor::FieldEnd {
                        field: FieldRef::new(data_name),
                    },
                    total,
                    "value verifies as a per-record checksum over the covered range",
                ));
            } else {
                let pooled: Vec<&[u8]> = records
                    .iter()
                    .map(|&(record, len)| &record[data_offset + len..])
                    .collect();
                inner.extend(pooled_fields(
                    &pooled,
                    layout.tail,
                    "trailer",
                    &mut namer,
                    total,
                ));
            }
        }
        let element = Field {
            name: Some(namer.name("record")),
            kind: Kind::Struct {
                structure: Structure::new(inner),
            },
            size: None,
            offset: None,
            role: None,
            constraints: Vec::new(),
            confidence: Confidence::clamped(0.75),
            evidence: evidence(total, &["one length-prefixed record"]),
        };
        fields.push(array_field(
            &namer.name("records"),
            element,
            CountRule::ToEnd,
            total,
            "repeating length-prefixed records to the end of the sample",
        ));
        proposal("chunked", fields, header.big_endian)
    }

    /// A header field that points at an invariant marker further in.
    fn offset(&self, relations: &[IntField]) -> Option<Proposal> {
        let pointer = detect_offsets(&self.rows).into_iter().min_by(|a, b| {
            a.offset
                .cmp(&b.offset)
                .then(a.width.cmp(&b.width))
                .then(a.big_endian.cmp(&b.big_endian))
        })?;
        let reading = Reading {
            offset: pointer.offset,
            width: pointer.width,
            big_endian: pointer.big_endian,
        };
        let mut namer = Namer::new(&self.prefix);
        let pointer_name = namer.name("data_offset");
        let mut labels = Labels::from_relations(relations);
        labels.assign(reading, Role::Offset, pointer_name.clone());
        let header = self.header(
            reading.end(),
            &[forced(reading)],
            &labels,
            &mut namer,
            Extent::Exact,
        );
        let mut fields = header.fields;
        let targets: Vec<&[u8]> = self
            .rows
            .iter()
            .zip(&pointer.values)
            .map(|(row, &target)| &row[(target as usize).min(row.len())..])
            .collect();
        let mut payload = region_field(
            &namer.name("payload"),
            SizeRule::ToEnd,
            &targets,
            self.total(),
            "starts at the decoded data_offset value",
        );
        payload.offset = Some(FieldOffset::Derived {
            offset_field: FieldRef::new(pointer_name),
        });
        fields.push(payload);
        Some(proposal("offset", fields, header.big_endian))
    }

    /// The typed common prefix, then an opaque payload.
    fn prefix(&self, relations: &[IntField]) -> Option<Proposal> {
        let mut namer = Namer::new(&self.prefix);
        let labels = Labels::from_relations(relations);
        let header = self.header(
            self.min_len.min(MAX_PREFIX),
            &[],
            &labels,
            &mut namer,
            Extent::Prefix,
        );
        let covered = header.covered;
        let mut fields = header.fields;
        if fields.is_empty() {
            return None;
        }
        let rest: Vec<&[u8]> = self.rows.iter().map(|row| &row[covered..]).collect();
        fields.push(region_field(
            &namer.name("payload"),
            SizeRule::ToEnd,
            &rest,
            self.total(),
            "bytes after the typed prefix",
        ));
        Some(proposal("prefix", fields, header.big_endian))
    }

    /// The signature, then an opaque payload.
    fn magic_only(&self) -> Option<Proposal> {
        let magic = self.magic;
        if magic < 2 {
            return None;
        }
        let mut namer = Namer::new(&self.prefix);
        let rest: Vec<&[u8]> = self.rows.iter().map(|row| &row[magic..]).collect();
        let fields = vec![
            magic_field(&namer.name("magic"), &self.rows[0][..magic], self.total()),
            region_field(
                &namer.name("payload"),
                SizeRule::ToEnd,
                &rest,
                self.total(),
                "bytes after the signature",
            ),
        ];
        Some(proposal("magic", fields, false))
    }

    /// The structureless fallback: always valid and fully covering.
    fn opaque(&self) -> Proposal {
        let field = Field {
            name: Some(format!("{}data", self.prefix)),
            kind: Kind::Opaque,
            size: Some(SizeRule::ToEnd),
            offset: None,
            role: Some(Role::Payload),
            constraints: Vec::new(),
            confidence: Confidence::clamped(0.2),
            evidence: evidence(0, &["no structure recovered; whole sample left opaque"]),
        };
        proposal("opaque", vec![field], false)
    }

    // ----- shared builders ------------------------------------------------

    /// Type the header region `[0, len)` with the section's signature.
    fn header(
        &self,
        len: usize,
        forced: &[Forced],
        labels: &Labels,
        namer: &mut Namer,
        extent: Extent,
    ) -> Header {
        self.header_with_magic(len, self.magic.min(len), forced, labels, namer, extent)
    }

    fn header_with_magic(
        &self,
        len: usize,
        magic: usize,
        forced: &[Forced],
        labels: &Labels,
        namer: &mut Namer,
        extent: Extent,
    ) -> Header {
        let segmentation = segment(&self.rows, len, 0, magic, forced, extent);
        let bitfields = detect_bitfields(&self.rows, 0, len);
        let covered = segmentation.end();
        let mut fields = Vec::with_capacity(segmentation.segments.len());
        let offsets = segmentation
            .segments
            .iter()
            .map(|piece| piece.offset)
            .collect();
        for piece in &segmentation.segments {
            let values: Vec<&[u8]> = self
                .rows
                .iter()
                .map(|row| &row[piece.offset..piece.end()])
                .collect();
            let is_magic = piece.offset == 0 && magic >= 2 && piece.len == magic;
            fields.push(segment_field(
                piece,
                &values,
                is_magic,
                labels,
                &bitfields,
                namer,
                self.total(),
            ));
        }
        label_version(&mut fields);
        Header {
            fields,
            offsets,
            big_endian: segmentation.big_endian,
            covered,
        }
    }

    /// Model a fixed trailer at each row's `starts` position of `len` bytes:
    /// a checksum over everything before it when one verifies, otherwise typed
    /// pieces. Returns the fields and how many relationships they add.
    fn trailer(
        &self,
        starts: &[usize],
        len: usize,
        fields: &[Field],
        last_region: &str,
        namer: &mut Namer,
    ) -> Vec<Field> {
        let first = fields.first().and_then(|field| field.name.clone());
        let magic = fields
            .first()
            .filter(|field| field.role == Some(Role::Magic))
            .and_then(|field| field.name.clone());
        if matches!(len, 1 | 2 | 4) && !last_region.is_empty() {
            let covered_from = [
                first.clone().map(|name| {
                    (
                        0usize,
                        RangeAnchor::FieldStart {
                            field: FieldRef::new(name),
                        },
                    )
                }),
                magic.clone().map(|name| {
                    (
                        fields.first().map_or(0, field_width),
                        RangeAnchor::FieldEnd {
                            field: FieldRef::new(name),
                        },
                    )
                }),
            ];
            for (from, anchor) in covered_from.into_iter().flatten() {
                for algorithm in algorithms_for_width(len) {
                    for big in [false, true] {
                        if len == 1 && big {
                            continue;
                        }
                        let holds = self.rows.iter().zip(starts).all(|(row, &start)| {
                            from < start
                                && read_uint(
                                    row,
                                    Reading {
                                        offset: start,
                                        width: len as u8,
                                        big_endian: big,
                                    },
                                )
                                .is_some_and(|stored| {
                                    checksum::verify(
                                        algorithm,
                                        &row[from..start],
                                        stored,
                                        len as u8,
                                    )
                                })
                        });
                        if holds && (len > 1 || self.rows.len() >= 3) {
                            return vec![checksum_field(
                                &namer.name("checksum"),
                                len as u8,
                                big,
                                algorithm,
                                anchor,
                                RangeAnchor::FieldEnd {
                                    field: FieldRef::new(last_region),
                                },
                                self.total(),
                                "value verifies as a checksum over the covered range",
                            )];
                        }
                    }
                }
            }
        }
        let pooled: Vec<&[u8]> = self
            .rows
            .iter()
            .zip(starts)
            .map(|(row, &start)| &row[start..start + len])
            .collect();
        pooled_fields(&pooled, len, "trailer", namer, self.total())
    }
}

/// Label a small constant integer directly after the signature as a version:
/// file formats commonly follow their magic with a format version.
fn label_version(fields: &mut [Field]) {
    let [magic, next, ..] = fields else {
        return;
    };
    if magic.role != Some(Role::Magic) || next.role != Some(Role::Unknown) {
        return;
    }
    let small = next.constraints.iter().any(|constraint| match constraint {
        Constraint::Constant { value } => {
            let bytes = value.as_slice();
            let little = bytes
                .iter()
                .rev()
                .fold(0u64, |acc, &byte| (acc << 8) | u64::from(byte));
            let big = bytes
                .iter()
                .fold(0u64, |acc, &byte| (acc << 8) | u64::from(byte));
            (1..=100).contains(&little.min(big))
        }
        _ => false,
    });
    if small && matches!(next.kind, Kind::Integer { .. }) {
        next.role = Some(Role::Version);
        next.evidence.notes.push(
            "small constant directly after the signature, a common version position".to_owned(),
        );
        if let Some(name) = &next.name {
            if name.contains("const_") {
                next.name = Some(name.replacen("const_", "version_", 1));
            }
        }
    }
}

/// How many leading bytes every row shares, or zero for fewer than two rows (a
/// single row makes every byte trivially invariant, which is not evidence).
fn invariant_prefix(rows: &[&[u8]]) -> usize {
    let Some((first, rest)) = rows.split_first() else {
        return 0;
    };
    if rest.is_empty() {
        return 0;
    }
    rest.iter().fold(first.len(), |shared, row| {
        shared.min(first.iter().zip(*row).take_while(|(a, b)| a == b).count())
    })
}

/// The length of the leading signature: an invariant printable prefix of at
/// least three characters, up to where the text ends (at most eight), or only
/// its first four-character code when the text is a run of such codes, as the
/// header segmentation splits them; else the whole invariant prefix when it is
/// two to eight bytes; else four bytes of a longer invariant run, since a
/// signature is rarely longer and the rest is usually constant header fields.
fn magic_len(rows: &[&[u8]], invariant: usize) -> usize {
    if invariant < 2 {
        return 0;
    }
    let text = rows[0][..invariant]
        .iter()
        .take_while(|&&byte| (0x20..0x7f).contains(&byte))
        .count();
    if text >= 8 && text % 4 == 0 {
        4
    } else if text >= 3 {
        text.min(8)
    } else if invariant <= 8 {
        invariant
    } else {
        4
    }
}

/// A typed header region.
struct Header {
    fields: Vec<Field>,
    /// Each field's offset within the section, parallel to `fields`.
    offsets: Vec<usize>,
    big_endian: bool,
    covered: usize,
}

/// A sequential layout: a header, governed regions in order, and what
/// confirms where they end.
#[derive(Debug, Clone)]
struct Sequential {
    header: usize,
    governing: Vec<Reading>,
    ends: Vec<usize>,
    end: SequentialEnd,
}

/// What confirms a sequential layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SequentialEnd {
    /// The regions end exactly at the sample end.
    Exact,
    /// A fixed trailer of this many bytes follows.
    Trailer(usize),
    /// An invariant marker begins the next section.
    Marker,
}

impl SequentialEnd {
    fn rank(self) -> u8 {
        match self {
            SequentialEnd::Exact => 0,
            SequentialEnd::Marker => 1,
            SequentialEnd::Trailer(_) => 2,
        }
    }
}

/// The length every row has after its `ends` position, when it is the same
/// small nonzero number of bytes.
fn constant_trailer(ends: &[usize], lens: &[usize]) -> Option<usize> {
    let first = lens[0].checked_sub(ends[0])?;
    ((1..=MAX_TRAILER).contains(&first)
        && ends
            .iter()
            .zip(lens)
            .all(|(&end, &len)| len.checked_sub(end) == Some(first)))
    .then_some(first)
}

/// The number of leading bytes every row shares from its `starts` position.
fn common_prefix(rows: &[&[u8]], starts: &[usize]) -> usize {
    let first = &rows[0][starts[0]..];
    let mut len = first.len();
    for (row, &start) in rows.iter().zip(starts).skip(1) {
        let other = &row[start..];
        len = len.min(first.iter().zip(other).take_while(|(a, b)| a == b).count());
    }
    len
}

/// Look for header integers that verify as a CRC over one governed region in
/// every sample, and turn each into a checksum field. `offsets` gives each
/// field's offset within the section, parallel to `fields`.
fn attach_region_checksums(
    fields: &mut [Field],
    offsets: &[usize],
    regions: &[(String, Vec<&[u8]>)],
    rows: &[&[u8]],
) {
    for (field, &offset) in fields.iter_mut().zip(offsets) {
        let Kind::Integer {
            width, endianness, ..
        } = field.kind
        else {
            continue;
        };
        if !matches!(width, 2 | 4) || !field.constraints.is_empty() {
            continue;
        }
        let reading = Reading {
            offset,
            width,
            big_endian: endianness == Some(Endianness::Big),
        };
        let algorithm = if width == 4 {
            ChecksumAlgorithm::Crc32
        } else {
            ChecksumAlgorithm::Crc16
        };
        let matched = regions.iter().find(|(_, region_rows)| {
            rows.iter().zip(region_rows).all(|(row, region)| {
                read_uint(row, reading)
                    .is_some_and(|stored| checksum::verify(algorithm, region, stored, width))
            })
        });
        if let Some((region_name, _)) = matched {
            field.role = Some(Role::Checksum);
            field.confidence = Confidence::clamped(0.95);
            field.evidence.notes.push(format!(
                "value verifies as a {algorithm:?} over {region_name} in every sample"
            ));
            field.constraints.push(Constraint::Checksum {
                spec: ChecksumSpec {
                    algorithm,
                    covered: CoveredRange {
                        from: RangeAnchor::FieldStart {
                            field: FieldRef::new(region_name.clone()),
                        },
                        to: RangeAnchor::FieldEnd {
                            field: FieldRef::new(region_name.clone()),
                        },
                    },
                },
            });
        }
    }
}

/// The byte width of a fixed-size field, for checksum ranges that start after
/// a leading signature.
fn field_width(field: &Field) -> usize {
    match (&field.kind, &field.size) {
        (Kind::Integer { width, .. }, _) => usize::from(*width),
        (_, Some(SizeRule::Fixed { bytes })) => *bytes as usize,
        _ => 0,
    }
}

fn algorithms_for_width(width: usize) -> Vec<ChecksumAlgorithm> {
    match width {
        4 => vec![ChecksumAlgorithm::Crc32, ChecksumAlgorithm::Additive],
        2 => vec![
            ChecksumAlgorithm::Crc16,
            ChecksumAlgorithm::Additive,
            ChecksumAlgorithm::Xor,
        ],
        _ => vec![ChecksumAlgorithm::Additive, ChecksumAlgorithm::Xor],
    }
}

/// How header pieces that match known integer readings are labeled.
#[derive(Debug, Default)]
struct Labels {
    /// Roles (and name stems) from every detected relationship, so a piece that
    /// matches one is labeled as a length or count even when a different
    /// relationship drives the layout.
    roles: HashMap<Reading, (Role, &'static str)>,
    /// Names fixed in advance for the fields a layout references.
    names: HashMap<Reading, String>,
}

impl Labels {
    fn from_relations(relations: &[IntField]) -> Self {
        let mut roles = HashMap::new();
        for found in relations {
            let label = match found.relation {
                IntRelation::TotalLength => (Role::Length, "total_length"),
                IntRelation::Remaining { .. } => (Role::Length, "size"),
                IntRelation::Count { .. } => (Role::Count, "count"),
            };
            roles.entry(found.reading).or_insert(label);
        }
        Self {
            roles,
            names: HashMap::new(),
        }
    }

    /// Fix `reading`'s role and name for a layout that references it.
    fn assign(&mut self, reading: Reading, role: Role, name: String) {
        self.roles.insert(reading, (role, "field"));
        self.names.insert(reading, name);
    }
}

/// The number of cross-field relationships a field list encodes: derived
/// sizes, counts, and offsets, and checksum constraints.
fn encoded_relations(fields: &[Field]) -> usize {
    fields
        .iter()
        .map(|field| {
            let own = usize::from(matches!(field.size, Some(SizeRule::Derived { .. })))
                + usize::from(matches!(field.offset, Some(FieldOffset::Derived { .. })))
                + field
                    .constraints
                    .iter()
                    .filter(|c| matches!(c, Constraint::Checksum { .. }))
                    .count();
            let nested = match &field.kind {
                Kind::Struct { structure } => encoded_relations(&structure.fields),
                Kind::Array { element, count } => {
                    usize::from(matches!(
                        count,
                        CountRule::FromField { .. } | CountRule::BoundedBy { .. }
                    )) + encoded_relations(std::slice::from_ref(element))
                }
                _ => 0,
            };
            own + nested
        })
        .sum()
}

fn forced(reading: Reading) -> Forced {
    Forced {
        offset: reading.offset,
        width: reading.width,
        big_endian: reading.big_endian,
    }
}

fn read_uint(row: &[u8], reading: Reading) -> Option<u64> {
    let bytes = row.get(reading.offset..reading.end())?;
    let mut value = 0u64;
    if reading.big_endian {
        for &byte in bytes {
            value = (value << 8) | u64::from(byte);
        }
    } else {
        for (index, &byte) in bytes.iter().enumerate() {
            value |= u64::from(byte) << (8 * index);
        }
    }
    Some(value)
}

/// Generates unique field names within one hypothesis.
struct Namer {
    prefix: String,
    used: HashSet<String>,
}

impl Namer {
    fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_owned(),
            used: HashSet::new(),
        }
    }

    /// `base` with the section prefix, made unique with a numeric suffix.
    fn name(&mut self, base: &str) -> String {
        let stem = format!("{}{base}", self.prefix);
        let mut name = stem.clone();
        let mut next = 2;
        while !self.used.insert(name.clone()) {
            name = format!("{stem}_{next}");
            next += 1;
        }
        name
    }

    /// A namer for the pieces of a pooled section: names start with `stem`,
    /// or are exactly `stem` when the section is a single piece. Names stay
    /// unique across the whole hypothesis.
    fn scoped(&mut self, stem: &str, single: bool) -> ScopedNamer<'_> {
        ScopedNamer {
            parent: self,
            stem: stem.to_owned(),
            single,
        }
    }
}

/// Names the pieces of one pooled section; see [`Namer::scoped`].
struct ScopedNamer<'a> {
    parent: &'a mut Namer,
    stem: String,
    single: bool,
}

/// Something that hands out unique field names.
trait Names {
    fn name(&mut self, base: &str) -> String;
}

impl Names for Namer {
    fn name(&mut self, base: &str) -> String {
        Namer::name(self, base)
    }
}

impl Names for ScopedNamer<'_> {
    fn name(&mut self, base: &str) -> String {
        if self.single {
            self.parent.name(&self.stem)
        } else {
            self.parent.name(&format!("{}_{base}", self.stem))
        }
    }
}

/// Build the IR field for one typed header piece.
fn segment_field(
    piece: &Segment,
    values: &[&[u8]],
    is_magic: bool,
    labels: &Labels,
    bitfields: &[crate::detect::Bitfield],
    namer: &mut impl Names,
    total: usize,
) -> Field {
    let offset = piece.offset;
    match &piece.kind {
        SegmentKind::Constant { bytes, text } => {
            if is_magic {
                return magic_field(&namer.name("magic"), bytes, total);
            }
            let (base, role, note) = if *text {
                (
                    tag_name(bytes).unwrap_or_else(|| format!("tag_{offset}")),
                    Role::Magic,
                    "invariant text shared by every sample",
                )
            } else if bytes.iter().all(|&byte| byte == 0) {
                (
                    format!("reserved_{offset}"),
                    Role::Reserved,
                    "zero bytes in every sample",
                )
            } else {
                (
                    format!("const_{offset}"),
                    Role::Unknown,
                    "invariant bytes in every sample",
                )
            };
            let mut field = fixed_bytes_field(
                &namer.name(&base),
                bytes.len() as u64,
                role,
                0.8,
                total,
                note,
            );
            field.constraints.push(Constraint::Constant {
                value: Bytes::new(bytes.clone()),
            });
            field
        }
        SegmentKind::Integer {
            width,
            big_endian,
            constant,
        } => {
            let reading = Reading {
                offset,
                width: *width,
                big_endian: *big_endian,
            };
            if let Some(constant) = constant {
                if is_magic {
                    return magic_field(&namer.name("magic"), constant, total);
                }
                let zero = constant.iter().all(|&byte| byte == 0);
                let (base, role, note) = if zero {
                    (
                        format!("reserved_{offset}"),
                        Role::Reserved,
                        "zero in every sample",
                    )
                } else {
                    (
                        format!("const_{offset}"),
                        Role::Unknown,
                        "the same value in every sample",
                    )
                };
                let mut field =
                    integer_field(&namer.name(&base), reading, role, 0.8, total, &[note]);
                field.constraints.push(Constraint::Constant {
                    value: Bytes::new(constant.clone()),
                });
                return field;
            }
            if let Some(&(role, stem)) = labels.roles.get(&reading) {
                let note = match role {
                    Role::Count => "value tracks a record count in every sample",
                    Role::Offset => "value points at an invariant downstream marker",
                    _ => "value tracks a region or sample length in every sample",
                };
                let name = labels
                    .names
                    .get(&reading)
                    .cloned()
                    .unwrap_or_else(|| namer.name(stem));
                let mut field = integer_field(&name, reading, role, 0.9, total, &[note]);
                field.evidence.notes.push(values_note(values, reading));
                return field;
            }
            let decoded: Vec<u64> = values
                .iter()
                .map(|value| {
                    read_uint(
                        value,
                        Reading {
                            offset: 0,
                            ..reading
                        },
                    )
                    .unwrap_or(0)
                })
                .collect();
            let (base, role, confidence, note) =
                if *width == 4 && decoded.iter().all(|value| TIMESTAMP_RANGE.contains(value)) {
                    (
                        format!("timestamp_{offset}"),
                        Role::Timestamp,
                        0.5,
                        "values are plausible Unix times in seconds",
                    )
                } else if *width == 1
                    && bitfields
                        .iter()
                        .any(|bits| bits.offset == offset && !bits.is_small_unsigned())
                {
                    (
                        format!("flags_{offset}"),
                        Role::Flags,
                        0.5,
                        "some bits are constant and others vary across samples",
                    )
                } else {
                    (
                        format!("field_{offset}"),
                        Role::Unknown,
                        0.5,
                        "varying integer of undetermined role",
                    )
                };
            let mut field = integer_field(
                &namer.name(&base),
                reading,
                role,
                confidence,
                total,
                &[note],
            );
            field.evidence.notes.push(values_note(values, reading));
            field
        }
        SegmentKind::Text => {
            let mut field = fixed_bytes_field(
                &namer.name(&format!("text_{offset}")),
                piece.len as u64,
                Role::Unknown,
                0.6,
                total,
                "printable text, optionally zero-padded, in every sample",
            );
            field.kind = Kind::String {
                encoding: StringEncoding::Ascii,
            };
            field
        }
        SegmentKind::Bytes => {
            let mut field = fixed_bytes_field(
                &namer.name(&format!("bytes_{offset}")),
                piece.len as u64,
                Role::Unknown,
                0.4,
                total,
                "varying bytes with no integer or text reading",
            );
            if entropy_of(values) >= OPAQUE_ENTROPY {
                field.kind = Kind::Opaque;
            }
            field
        }
    }
}

/// A readable name for a text constant: its letters and digits in lowercase,
/// with `_tag` appended.
fn tag_name(bytes: &[u8]) -> Option<String> {
    let mut name = String::new();
    for &byte in bytes {
        let ch = char::from(byte);
        if ch.is_ascii_alphanumeric() {
            name.push(ch.to_ascii_lowercase());
        } else if !name.is_empty() && !name.ends_with('_') {
            name.push('_');
        }
    }
    let name = name.trim_end_matches('_').to_owned();
    (!name.is_empty() && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic()))
        .then(|| format!("{name}_tag"))
}

/// Type the fields of a fixed-size section shared by pooled rows (records,
/// record prefixes, trailers). A section of one piece is a single field named
/// `stem`; otherwise each piece's name starts with `stem`.
fn pooled_fields(
    rows: &[&[u8]],
    len: usize,
    stem: &str,
    namer: &mut Namer,
    total: usize,
) -> Vec<Field> {
    let segmentation = segment(rows, len, 0, 0, &[], Extent::Exact);
    if segmentation.end() != len || segmentation.segments.is_empty() {
        let name = namer.name(stem);
        return vec![fixed_bytes_field(
            &name,
            len as u64,
            Role::Unknown,
            0.4,
            total,
            "fixed bytes",
        )];
    }
    let single = segmentation.segments.len() == 1;
    let mut scoped = namer.scoped(stem, single);
    let mut fields = Vec::with_capacity(segmentation.segments.len());
    for piece in &segmentation.segments {
        let values: Vec<&[u8]> = rows
            .iter()
            .map(|row| &row[piece.offset..piece.end()])
            .collect();
        let mut field = segment_field(
            piece,
            &values,
            false,
            &Labels::default(),
            &[],
            &mut scoped,
            total,
        );
        if matches!(stem, "tag" | "type") && field.role == Some(Role::Unknown) {
            field.role = Some(Role::Enum);
        }
        fields.push(field);
    }
    fields
}

/// The element of a fixed-size record array: a single field when the record
/// is one piece, otherwise a struct of the record's typed pieces.
fn pooled_element(
    records: &[&[u8]],
    record_size: usize,
    stem: &str,
    namer: &mut Namer,
    total: usize,
) -> Field {
    let segmentation = segment(records, record_size, 0, 0, &[], Extent::Exact);
    if segmentation.segments.len() <= 1 {
        return pooled_fields(records, record_size, stem, namer, total)
            .into_iter()
            .next()
            .unwrap_or_else(|| {
                fixed_bytes_field(
                    &namer.name(stem),
                    record_size as u64,
                    Role::Unknown,
                    0.4,
                    total,
                    "fixed bytes",
                )
            });
    }
    let fields = pooled_fields(records, record_size, "item", namer, total);
    Field {
        name: Some(namer.name(stem)),
        kind: Kind::Struct {
            structure: Structure::new(fields),
        },
        size: None,
        offset: None,
        role: None,
        constraints: Vec::new(),
        confidence: Confidence::clamped(0.7),
        evidence: evidence(total, &["one fixed-size record, typed from every record"]),
    }
}

fn array_field(name: &str, element: Field, count: CountRule, total: usize, note: &str) -> Field {
    Field {
        name: Some(name.to_owned()),
        kind: Kind::Array {
            element: Box::new(element),
            count,
        },
        size: None,
        offset: None,
        role: None,
        constraints: Vec::new(),
        confidence: Confidence::clamped(0.85),
        evidence: evidence(total, &[note]),
    }
}

/// A variable region: text when every row is printable ASCII, opaque when its
/// bytes are high-entropy, otherwise raw bytes.
fn region_field(name: &str, size: SizeRule, rows: &[&[u8]], total: usize, note: &str) -> Field {
    let text = rows.iter().any(|row| !row.is_empty())
        && rows
            .iter()
            .all(|row| row.iter().all(|&byte| (0x20..0x7f).contains(&byte)));
    let (kind, role, detail) = if text {
        (
            Kind::String {
                encoding: StringEncoding::Ascii,
            },
            Role::Unknown,
            "printable text in every sample",
        )
    } else if entropy_of(rows) >= OPAQUE_ENTROPY {
        (
            Kind::Opaque,
            Role::Payload,
            "high-entropy bytes, left opaque",
        )
    } else {
        (Kind::Bytes, Role::Payload, "payload bytes")
    };
    Field {
        name: Some(name.to_owned()),
        kind,
        size: Some(size),
        offset: None,
        role: Some(role),
        constraints: Vec::new(),
        confidence: Confidence::clamped(0.6),
        evidence: evidence(total, &[note, detail]),
    }
}

/// A governed body typed by nested inference: a struct holding the nested
/// hypothesis's fields, bounded to the region its size rule gives.
fn body_field(name: &str, size: SizeRule, fields: Vec<Field>, total: usize) -> Field {
    Field {
        name: Some(name.to_owned()),
        kind: Kind::Struct {
            structure: Structure::new(fields),
        },
        size: Some(size),
        offset: None,
        role: Some(Role::Payload),
        constraints: Vec::new(),
        confidence: Confidence::clamped(0.6),
        evidence: evidence(
            total,
            &[
                "region sized by the length field",
                "typed by inferring the region as a nested section",
            ],
        ),
    }
}

fn entropy_of(rows: &[&[u8]]) -> f64 {
    let bytes: Vec<u8> = rows.iter().flat_map(|row| row.iter().copied()).collect();
    shannon_entropy(&bytes)
}

fn magic_field(name: &str, bytes: &[u8], total: usize) -> Field {
    Field {
        name: Some(name.to_owned()),
        kind: Kind::Bytes,
        size: Some(SizeRule::Fixed {
            bytes: bytes.len() as u64,
        }),
        offset: None,
        role: Some(Role::Magic),
        constraints: vec![Constraint::Constant {
            value: Bytes::new(bytes.to_vec()),
        }],
        confidence: Confidence::clamped(1.0),
        evidence: evidence(
            total,
            &["invariant leading bytes shared by every sample (magic signature)"],
        ),
    }
}

/// A fixed-size bytes field with a name, role, confidence, and one note.
fn fixed_bytes_field(
    name: &str,
    bytes: u64,
    role: Role,
    confidence: f64,
    total: usize,
    note: &str,
) -> Field {
    Field {
        name: Some(name.to_owned()),
        kind: Kind::Bytes,
        size: Some(SizeRule::Fixed { bytes }),
        offset: None,
        role: Some(role),
        constraints: Vec::new(),
        confidence: Confidence::clamped(confidence),
        evidence: evidence(total, &[note]),
    }
}

#[allow(clippy::too_many_arguments)]
fn checksum_field(
    name: &str,
    width: u8,
    big_endian: bool,
    algorithm: ChecksumAlgorithm,
    from: RangeAnchor,
    to: RangeAnchor,
    total: usize,
    note: &str,
) -> Field {
    let mut field = integer_field(
        name,
        Reading {
            offset: 0,
            width,
            big_endian,
        },
        Role::Checksum,
        0.95,
        total,
        &[note],
    );
    field.constraints.push(Constraint::Checksum {
        spec: ChecksumSpec {
            algorithm,
            covered: CoveredRange { from, to },
        },
    });
    field
}

fn integer_field(
    name: &str,
    reading: Reading,
    role: Role,
    confidence: f64,
    total: usize,
    notes: &[&str],
) -> Field {
    let endianness = if reading.width == 1 {
        None
    } else if reading.big_endian {
        Some(Endianness::Big)
    } else {
        Some(Endianness::Little)
    };
    Field {
        name: Some(name.to_owned()),
        kind: Kind::Integer {
            width: reading.width,
            signed: Signedness::Unsigned,
            endianness,
        },
        size: None,
        offset: None,
        role: Some(role),
        constraints: Vec::new(),
        confidence: Confidence::clamped(confidence),
        evidence: evidence(total, notes),
    }
}

fn evidence(total: usize, notes: &[&str]) -> Evidence {
    Evidence {
        detector: Some("statistics".to_owned()),
        support: (total > 0).then_some(SampleSupport {
            agreeing: total as u64,
            total: total as u64,
        }),
        model_rationale: None,
        notes: notes.iter().map(|note| (*note).to_owned()).collect(),
    }
}

/// A short note listing the first decoded values of an integer piece.
fn values_note(values: &[&[u8]], reading: Reading) -> String {
    let shown: Vec<String> = values
        .iter()
        .take(8)
        .map(|value| {
            read_uint(
                value,
                Reading {
                    offset: 0,
                    ..reading
                },
            )
            .map_or_else(|| "?".to_owned(), |value| value.to_string())
        })
        .collect();
    format!("decoded values: {}", shown.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits::default()
    }

    fn roles(candidate: &Candidate) -> Vec<Role> {
        candidate
            .format
            .root
            .fields
            .iter()
            .filter_map(|f| f.role)
            .collect()
    }

    #[test]
    fn empty_set_yields_a_valid_fallback() {
        let samples: [&[u8]; 0] = [];
        let candidates = infer_candidates(&samples, &limits());
        assert!(!candidates.is_empty());
        assert!(candidates[0].format.validate().is_ok());
    }

    #[test]
    fn single_sample_does_not_panic_and_validates() {
        let samples: [&[u8]; 1] = [b"\x00\x01\x02\x03garbage"];
        let candidates = infer_candidates(&samples, &limits());
        assert!(!candidates.is_empty());
        for candidate in &candidates {
            assert!(candidate.format.validate().is_ok());
        }
    }

    #[test]
    fn total_length_format_is_recovered() {
        let make = |payload: &[u8]| {
            let mut data = b"STOT".to_vec();
            data.extend_from_slice(&((8 + payload.len()) as u32).to_le_bytes());
            data.extend_from_slice(payload);
            data
        };
        let samples = [make(&[1, 2, 3]), make(&[4; 10]), make(&[7]), make(&[9; 6])];
        let candidates = infer_candidates(&samples, &limits());
        let best = &candidates[0];
        assert!(best.score.fully_verified(), "{:?}", best.score);
        let found = roles(best);
        assert!(found.contains(&Role::Magic), "{found:?}");
        assert!(found.contains(&Role::Length), "{found:?}");
    }

    #[test]
    fn a_size_field_governing_the_region_after_the_header_is_recovered() {
        // A RIFF-like container: a tag, a u32 size of everything after it, then
        // a second tag and data.
        let make = |data: &[u8]| {
            let mut out = b"RIFF".to_vec();
            out.extend_from_slice(&((4 + data.len()) as u32).to_le_bytes());
            out.extend_from_slice(b"WAVE");
            out.extend_from_slice(data);
            out
        };
        let samples = [make(&[1, 2, 3]), make(&[9; 12]), make(&[4, 4])];
        let candidates = infer_candidates(&samples, &limits());
        let best = &candidates[0];
        assert!(best.score.fully_verified());
        assert_eq!(best.format.name, "candidate-remaining-typed");
        let fields = &best.format.root.fields;
        let size = fields
            .iter()
            .find(|field| field.role == Some(Role::Length))
            .expect("the size field is recognized as a length");
        assert!(matches!(size.kind, Kind::Integer { width: 4, .. }));
        // The size governs a body typed as a sized struct: the second tag is a
        // verified constant inside it, not part of an opaque payload.
        let body = fields.last().expect("a body");
        assert!(
            matches!(&body.size, Some(SizeRule::Derived { length_field }) if Some(length_field.as_str()) == size.name.as_deref())
        );
        let Kind::Struct { structure } = &body.kind else {
            panic!("the body is a sized struct: {body:#?}");
        };
        assert!(
            structure.fields[0]
                .constraints
                .iter()
                .any(|constraint| matches!(
                    constraint,
                    Constraint::Constant { value } if value.as_slice() == b"WAVE"
                ))
        );
        // The layout with an opaque payload is still proposed.
        let governed = candidates
            .iter()
            .find(|candidate| candidate.format.name == "candidate-remaining")
            .expect("remaining-length candidate");
        assert!(governed.score.fully_verified());
        assert_eq!(governed.relations, 1);
    }

    #[test]
    fn sequential_regions_and_a_following_section_are_recovered() {
        // A ZIP-like entry: header with a u16 name length and u32 data length,
        // then the name, the data, and a trailer section with its own magic.
        let make = |name: &[u8], data: &[u8]| {
            let mut out = b"HDR1".to_vec();
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(name);
            out.extend_from_slice(data);
            out.extend_from_slice(b"END!");
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out
        };
        let samples = [
            make(b"a.txt", &[1, 2, 3]),
            make(b"notes.md", &[9; 12]),
            make(b"x", &[4, 4, 0x80, 0x81]),
        ];
        let best = &infer_candidates(&samples, &limits())[0];
        assert!(best.score.fully_verified(), "{:?}", best.format.name);
        let derived = best
            .format
            .root
            .fields
            .iter()
            .filter(|field| matches!(field.size, Some(SizeRule::Derived { .. })))
            .count();
        assert_eq!(derived, 2, "both governed regions: {:#?}", best.format.root);
        assert!(
            best.format
                .root
                .fields
                .iter()
                .any(|field| matches!(field.kind, Kind::String { .. })
                    && matches!(field.size, Some(SizeRule::Derived { .. }))),
            "the name region is text"
        );
    }

    #[test]
    fn counted_records_are_typed_from_the_pooled_records() {
        let make = |records: &[(u16, u16)]| {
            let mut out = b"SCMA".to_vec();
            out.push(records.len() as u8);
            for (id, value) in records {
                out.extend_from_slice(&id.to_le_bytes());
                out.extend_from_slice(&value.to_le_bytes());
            }
            out
        };
        let samples = [
            make(&[(1, 0x1111), (2, 0x2222)]),
            make(&[(3, 0xABCD), (4, 0x0102), (5, 0x7777)]),
            make(&[(6, 0x9999)]),
        ];
        let best = &infer_candidates(&samples, &limits())[0];
        assert!(best.score.fully_verified());
        let records = best
            .format
            .root
            .fields
            .iter()
            .find(|field| matches!(field.kind, Kind::Array { .. }))
            .expect("records array");
        let Kind::Array { element, count } = &records.kind else {
            unreachable!()
        };
        assert!(matches!(count, CountRule::FromField { .. }));
        assert!(
            matches!(&element.kind, Kind::Struct { structure } if structure.fields.len() == 2),
            "{element:#?}"
        );
    }

    #[test]
    fn an_opaque_blob_ranks_below_any_structure_that_verifies() {
        let make = |payload: &[u8]| {
            let mut data = b"SDLP".to_vec();
            data.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            data.extend_from_slice(payload);
            let crc = checksum::crc32(&data);
            data.extend_from_slice(&crc.to_le_bytes());
            data
        };
        let samples = [make(&[1, 2, 3]), make(&[9; 8]), make(&[4, 5])];
        let candidates = infer_candidates(&samples, &limits());
        let best = &candidates[0];
        assert!(best.format.name != "candidate-opaque");
        assert!(
            roles(best).contains(&Role::Checksum),
            "{:#?}",
            best.format.root
        );
        let opaque = candidates
            .iter()
            .find(|candidate| candidate.format.name == "candidate-opaque")
            .expect("opaque fallback");
        assert!(opaque.score.structure < best.score.structure);
    }

    #[test]
    fn offset_relationships_are_assembled_into_candidates() {
        let samples = [
            b"OF\x05aaDxy".to_vec(),
            b"OF\x07bbbbDzz".to_vec(),
            b"OF\x06cccDq".to_vec(),
        ];
        let candidates = infer_candidates(&samples, &limits());
        let offset = candidates
            .iter()
            .find(|candidate| candidate.format.name == "candidate-offset")
            .expect("offset detector evidence should produce an offset candidate");
        assert!(
            offset.format.root.fields.iter().any(|field| matches!(
                &field.offset,
                Some(FieldOffset::Derived { offset_field }) if offset_field.as_str() == "data_offset"
            )),
            "candidate must include a payload field located through the pointer"
        );
    }

    #[test]
    fn names_are_unique_within_every_candidate() {
        let samples = [
            b"MAGC\x11\xEE\xEE\x03\x01\x01\x01".to_vec(),
            b"MAGC\x57\xEE\xEE\x05\x02\x02\x02\x02\x02".to_vec(),
            b"MAGC\xd2\xEE\xEE\x08\x03\x03\x03\x03\x03\x03\x03\x03".to_vec(),
        ];
        for candidate in infer_candidates(&samples, &limits()) {
            let mut names = HashSet::new();
            fn walk<'a>(fields: &'a [Field], names: &mut HashSet<&'a str>) {
                for field in fields {
                    if let Some(name) = field.name.as_deref() {
                        assert!(names.insert(name), "duplicate name {name}");
                    }
                    match &field.kind {
                        Kind::Struct { structure } => walk(&structure.fields, names),
                        Kind::Array { element, .. } => walk(std::slice::from_ref(element), names),
                        _ => {}
                    }
                }
            }
            walk(&candidate.format.root.fields, &mut names);
        }
    }
}
