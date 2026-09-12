//! The heuristic refinement loop (FR-25 to FR-28).
//!
//! Starting from the best statistical candidate, [`refine`] proposes small local
//! changes (integer endianness swaps, integer width swaps, and fixed-size
//! boundary nudges), executes and re-scores each, and accepts a change only when
//! the verified fit score over the full sample set strictly improves. This is the
//! non-regression invariant (FR-26): a heuristic may propose anything, but the
//! native executor and scorer decide, and a change that would lower the verified
//! score is never accepted. Because each accepted change strictly increases a
//! score bounded above by one, and the loop also has a hard pass cap, the loop
//! always terminates (FR-27). Every accepted change is recorded for
//! explainability (FR-28).
//!
//! Step 6 keeps the proposal set deliberately small and model-free. The
//! language-model semantic pass and its richer proposals arrive in Step 9 and
//! flow through the very same non-regression gate.

use serde::{Deserialize, Serialize};
use sextant_ir::{Endianness, Field, Format, Kind, SizeRule, Structure};

use crate::limits::Limits;
use crate::scorer::{Score, ScoreWeights, score_with};

/// The smallest score gain treated as a real improvement. Changes below this are
/// not accepted, so floating-point noise cannot cause churn.
const MIN_GAIN: f64 = 1e-9;

/// A hard cap on refinement passes, a backstop on top of the convergence check
/// so the loop always terminates even on a pathological score surface (FR-27).
const MAX_PASSES: usize = 64;

/// The integer widths a width swap will try, in bytes.
const WIDTHS: [u8; 4] = [1, 2, 4, 8];

/// Whether a refinement proposal was accepted or rejected by the scorer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefineOutcome {
    /// The change improved the verified score and was applied.
    Accepted,
    /// The change did not improve the verified score and was discarded.
    Rejected,
}

/// One step in the refinement history (FR-28).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RefineStep {
    /// A human-readable description of the proposed change.
    pub description: String,
    /// Whether the change was accepted or rejected.
    pub outcome: RefineOutcome,
    /// The verified score before the change.
    pub score_before: f64,
    /// The verified score the change would produce (after, when accepted).
    pub score_after: f64,
}

/// The result of refining a candidate (FR-25 to FR-28).
#[derive(Debug, Clone)]
pub struct Refinement {
    /// The refined IR. Equal to the input when nothing improved it.
    pub format: Format,
    /// The verified score of the refined IR over the sample set.
    pub score: Score,
    /// The accepted refinement steps, in order.
    pub history: Vec<RefineStep>,
}

/// One segment of a path to a field inside a format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Seg {
    /// Select a field by index within the current structure.
    Field(usize),
    /// Descend into the element of the current array field.
    Element,
}

/// Enumerate a path to every field in `format`, in pre-order (each field before
/// its descendants). The order matches the flattened field map in
/// [`crate::report`], so a position in this list is a stable index a caller can
/// hand to and receive back from an external proposer such as the semantic pass.
#[must_use]
pub(crate) fn field_paths(format: &Format) -> Vec<Vec<Seg>> {
    let mut out = Vec::new();
    let mut prefix = Vec::new();
    collect_paths(&format.root, &mut prefix, &mut out);
    out
}

/// Walk a structure in pre-order, recording the path to each field and
/// descending into nested structures and array elements.
fn collect_paths(structure: &Structure, prefix: &mut Vec<Seg>, out: &mut Vec<Vec<Seg>>) {
    for (index, field) in structure.fields.iter().enumerate() {
        prefix.push(Seg::Field(index));
        out.push(prefix.clone());
        match &field.kind {
            Kind::Struct { structure } => collect_paths(structure, prefix, out),
            Kind::Array { element, .. } => {
                prefix.push(Seg::Element);
                out.push(prefix.clone());
                if let Kind::Struct { structure } = &element.kind {
                    collect_paths(structure, prefix, out);
                }
                prefix.pop();
            }
            _ => {}
        }
        prefix.pop();
    }
}

/// A local change to a single field.
#[derive(Debug, Clone, Copy)]
enum Mutation {
    /// Set an integer field's endianness override.
    Endianness(Endianness),
    /// Set an integer field's width in bytes.
    Width(u8),
    /// Set a fixed-size field's byte length.
    FixedSize(u64),
}

/// Refine `format` against `samples`, returning the best IR the local search
/// reaches without ever lowering the verified score (FR-26).
#[must_use]
pub fn refine(format: &Format, samples: &[&[u8]], limits: &Limits) -> Refinement {
    let weights = ScoreWeights::default();
    let mut best = format.clone();
    let mut best_score = score_with(&best, samples, limits, weights);
    let mut history = Vec::new();

    for _ in 0..MAX_PASSES {
        if best_score.overall >= 1.0 {
            break;
        }
        let proposals = enumerate(&best);
        let mut chosen: Option<(Format, Score, String)> = None;

        for (path, mutation, description) in proposals {
            let Some(candidate) = apply_at(&best, &path, mutation) else {
                continue;
            };
            if candidate.validate().is_err() {
                continue;
            }
            let score = score_with(&candidate, samples, limits, weights);
            if score.preserves_verified_fit(&best_score)
                && score.overall > best_score.overall + MIN_GAIN
                && chosen
                    .as_ref()
                    .is_none_or(|(_, current, _)| score.overall > current.overall)
            {
                chosen = Some((candidate, score, description));
            }
        }

        match chosen {
            Some((candidate, score, description)) => {
                history.push(RefineStep {
                    description,
                    outcome: RefineOutcome::Accepted,
                    score_before: best_score.overall,
                    score_after: score.overall,
                });
                best = candidate;
                best_score = score;
            }
            None => break,
        }
    }

    Refinement {
        format: best,
        score: best_score,
        history,
    }
}

/// Enumerate every (path, mutation, description) proposal for a format.
fn enumerate(format: &Format) -> Vec<(Vec<Seg>, Mutation, String)> {
    let mut out = Vec::new();
    let mut prefix = Vec::new();
    enumerate_structure(&format.root, &mut prefix, &mut out);
    out
}

/// Walk a structure, recording proposals for each field and descending into
/// nested structures and array elements.
fn enumerate_structure(
    structure: &Structure,
    prefix: &mut Vec<Seg>,
    out: &mut Vec<(Vec<Seg>, Mutation, String)>,
) {
    for (index, field) in structure.fields.iter().enumerate() {
        prefix.push(Seg::Field(index));
        proposals_for_field(field, prefix, out);
        match &field.kind {
            Kind::Struct { structure } => enumerate_structure(structure, prefix, out),
            Kind::Array { element, .. } => {
                prefix.push(Seg::Element);
                proposals_for_field(element, prefix, out);
                if let Kind::Struct { structure } = &element.kind {
                    enumerate_structure(structure, prefix, out);
                }
                prefix.pop();
            }
            _ => {}
        }
        prefix.pop();
    }
}

/// Record the mutation proposals applicable to one field.
fn proposals_for_field(field: &Field, path: &[Seg], out: &mut Vec<(Vec<Seg>, Mutation, String)>) {
    let name = field.name.clone().unwrap_or_else(|| "(unnamed)".to_owned());
    match &field.kind {
        Kind::Integer {
            width, endianness, ..
        } => {
            for order in [Endianness::Little, Endianness::Big] {
                if *endianness != Some(order) {
                    out.push((
                        path.to_vec(),
                        Mutation::Endianness(order),
                        format!("set {name} endianness to {order:?}"),
                    ));
                }
            }
            for candidate in WIDTHS {
                if candidate != *width {
                    out.push((
                        path.to_vec(),
                        Mutation::Width(candidate),
                        format!("set {name} width to {candidate} bytes"),
                    ));
                }
            }
        }
        Kind::Bytes => {
            if let Some(SizeRule::Fixed { bytes }) = &field.size {
                if *bytes > 1 {
                    out.push((
                        path.to_vec(),
                        Mutation::FixedSize(bytes - 1),
                        format!("nudge {name} size to {} bytes", bytes - 1),
                    ));
                }
                out.push((
                    path.to_vec(),
                    Mutation::FixedSize(bytes + 1),
                    format!("nudge {name} size to {} bytes", bytes + 1),
                ));
            }
        }
        _ => {}
    }
}

/// Clone `format` and apply `mutation` at `path`, returning the new format, or
/// `None` if the path does not resolve or the mutation does not fit the field.
fn apply_at(format: &Format, path: &[Seg], mutation: Mutation) -> Option<Format> {
    let mut clone = format.clone();
    let field = navigate(&mut clone.root, path)?;
    match mutation {
        Mutation::Endianness(order) => match &mut field.kind {
            Kind::Integer { endianness, .. } | Kind::Enum { endianness, .. } => {
                *endianness = Some(order);
            }
            _ => return None,
        },
        Mutation::Width(width) => match &mut field.kind {
            Kind::Integer { width: w, .. } | Kind::Enum { width: w, .. } => *w = width,
            _ => return None,
        },
        Mutation::FixedSize(bytes) => {
            field.size = Some(SizeRule::Fixed { bytes });
        }
    }
    Some(clone)
}

/// Resolve a path to a mutable field reference inside a structure.
pub(crate) fn navigate<'a>(root: &'a mut Structure, path: &[Seg]) -> Option<&'a mut Field> {
    let (first, rest) = path.split_first()?;
    let Seg::Field(index) = first else {
        return None;
    };
    let mut field = root.fields.get_mut(*index)?;
    for seg in rest {
        field = match seg {
            Seg::Field(index) => match &mut field.kind {
                Kind::Struct { structure } => structure.fields.get_mut(*index)?,
                _ => return None,
            },
            Seg::Element => match &mut field.kind {
                Kind::Array { element, .. } => element.as_mut(),
                _ => return None,
            },
        };
    }
    Some(field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sextant_ir::{
        ChecksumSpec, Confidence, Constraint, CoveredRange, Endianness, FieldRef, Kind,
        RangeAnchor, Role, Signedness, SizeRule, Structure,
    };

    /// Build SDLP-like samples: magic(4) length(u16le) payload crc(u32le over all
    /// preceding bytes).
    fn sdlp_samples() -> Vec<Vec<u8>> {
        let make = |payload: &[u8]| {
            let mut data = b"SDLP".to_vec();
            data.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            data.extend_from_slice(payload);
            let crc = crate::checksum::crc32(&data);
            data.extend_from_slice(&crc.to_le_bytes());
            data
        };
        vec![make(&[1, 2, 3]), make(&[9; 8]), make(&[4, 5])]
    }

    fn int_field(name: &str, width: u8, endianness: Option<Endianness>, role: Role) -> Field {
        Field {
            name: Some(name.to_owned()),
            kind: Kind::Integer {
                width,
                signed: Signedness::Unsigned,
                endianness,
            },
            size: None,
            offset: None,
            role: Some(role),
            constraints: Vec::new(),
            confidence: Confidence::clamped(0.8),
            evidence: Default::default(),
        }
    }

    /// An SDLP IR whose checksum endianness is wrong (big instead of little), so
    /// the checksum fails to verify and the consistency score is depressed.
    fn sdlp_with_wrong_checksum_endianness() -> Format {
        let magic = Field {
            name: Some("magic".to_owned()),
            kind: Kind::Bytes,
            size: Some(SizeRule::Fixed { bytes: 4 }),
            offset: None,
            role: Some(Role::Magic),
            constraints: vec![Constraint::Constant {
                value: sextant_ir::Bytes::new(b"SDLP".to_vec()),
            }],
            confidence: Confidence::clamped(1.0),
            evidence: Default::default(),
        };
        let length = int_field("length", 2, Some(Endianness::Little), Role::Length);
        let payload = Field {
            name: Some("payload".to_owned()),
            kind: Kind::Bytes,
            size: Some(SizeRule::Derived {
                length_field: FieldRef::new("length"),
            }),
            offset: None,
            role: Some(Role::Payload),
            constraints: Vec::new(),
            confidence: Confidence::clamped(0.6),
            evidence: Default::default(),
        };
        let mut checksum = int_field("crc", 4, Some(Endianness::Big), Role::Checksum);
        checksum.constraints.push(Constraint::Checksum {
            spec: ChecksumSpec {
                algorithm: sextant_ir::ChecksumAlgorithm::Crc32,
                covered: CoveredRange {
                    from: RangeAnchor::FieldStart {
                        field: FieldRef::new("magic"),
                    },
                    to: RangeAnchor::FieldEnd {
                        field: FieldRef::new("payload"),
                    },
                },
            },
        });
        Format {
            name: "sdlp-wrong".to_owned(),
            endianness: Endianness::Little,
            root: Structure::new(vec![magic, length, payload, checksum]),
            enums: Default::default(),
            metadata: Default::default(),
        }
    }

    #[test]
    fn endianness_swap_is_accepted_when_it_verifies_the_checksum() {
        let samples = sdlp_samples();
        let slices: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
        let format = sdlp_with_wrong_checksum_endianness();
        let before = score_with(
            &format,
            &slices,
            &Limits::default(),
            ScoreWeights::default(),
        );
        let refinement = refine(&format, &slices, &Limits::default());

        // The refinement strictly improved the verified score and never lowered
        // it (the non-regression invariant, FR-26).
        assert!(
            refinement.score.overall > before.overall,
            "refinement did not improve the score: {} to {}",
            before.overall,
            refinement.score.overall
        );
        assert!(refinement.score.overall >= before.overall);
        assert!(!refinement.history.is_empty());
        for step in &refinement.history {
            assert_eq!(step.outcome, RefineOutcome::Accepted);
            assert!(step.score_after > step.score_before);
        }
    }

    #[test]
    fn a_perfect_ir_is_left_unchanged() {
        // The hand-authored PNG ground truth already scores at the top, so there
        // is no strict improvement to make and refinement must not churn it.
        let format = sextant_ir::fixtures::png_ground_truth();
        let samples = png_samples();
        let slices: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
        let before = score_with(
            &format,
            &slices,
            &Limits::default(),
            ScoreWeights::default(),
        );
        let refinement = refine(&format, &slices, &Limits::default());
        assert!(refinement.history.is_empty());
        assert_eq!(refinement.format, format);
        assert!((refinement.score.overall - before.overall).abs() < 1e-9);
    }

    fn png_samples() -> Vec<Vec<u8>> {
        use std::fs;
        use std::path::PathBuf;
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("engine crate has a parent")
            .join("corpus")
            .join("png")
            .join("samples");
        let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
            .expect("read png samples")
            .map(|entry| entry.expect("entry").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "png"))
            .collect();
        paths.sort();
        paths
            .into_iter()
            .map(|path| fs::read(&path).expect("read sample"))
            .collect()
    }

    #[test]
    fn refinement_never_lowers_the_score_on_garbage() {
        // On hostile or trivial inputs the loop must still terminate and never
        // return a worse score than it started with.
        let format = sextant_ir::fixtures::png_ground_truth();
        let cases: Vec<Vec<&[u8]>> = vec![vec![&[]], vec![&[0x00], &[0xFF]], vec![&[1, 2, 3, 4]]];
        for case in cases {
            let before = score_with(&format, &case, &Limits::default(), ScoreWeights::default());
            let refinement = refine(&format, &case, &Limits::default());
            assert!(refinement.score.overall >= before.overall - 1e-9);
        }
    }
}
