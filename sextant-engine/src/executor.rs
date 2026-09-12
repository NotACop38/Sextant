//! The native IR executor (FR-20, FR-21, FR-24).
//!
//! [`execute`] runs a [`Format`] against a single sample and produces a parse: a
//! tree of [`FieldInstance`]s with concrete byte ranges and decoded values, the
//! list of constraint checks it performed (constants, integer ranges, and
//! checksums), and either a clean end or a localized [`ParseFailure`] (an offset
//! and a reason). It is pure, native Rust with no JVM, no Kaitai compiler, and
//! no network, so it runs offline and under `--no-llm` (FR-21).
//!
//! Every input-facing path is bounded by [`Limits`] (FR-24): recursion depth,
//! array length, total field count, owned output bytes, total work, and an optional wall-clock
//! deadline. The executor never panics on any input; a malformed IR or hostile
//! sample yields a localized failure, not a crash.
//!
//! # Design: structure versus constraints
//!
//! The executor separates parsing the byte layout from checking constraints. It
//! reads fields by their size and count rules, recording exactly the bytes each
//! field explains. A failed constraint (a wrong magic, a checksum that does not
//! verify) does not stop the parse; it is recorded as a failed
//! [`ConstraintCheck`]. Only a structural problem (running out of bytes, an
//! unresolvable reference, a limit) stops the parse with a [`ParseFailure`].
//! This keeps coverage (which bytes are explained) independent from consistency
//! (which relationships hold), so the scorer can report each separately.

use std::time::Instant;

use serde::{Deserialize, Serialize};
use sextant_ir::{
    ChecksumAlgorithm, Constraint, CountRule, Endianness, Field, FieldOffset, Format, Kind,
    RangeAnchor, Role, SizeRule, StringEncoding,
};

use crate::checksum;
use crate::limits::Limits;

/// How often, in work units, the executor consults the wall clock. Checking
/// every unit would dominate run time; a few thousand keeps the deadline tight
/// while staying cheap.
const CLOCK_CHECK_INTERVAL: u64 = 4096;

/// The result of executing an IR against one sample (FR-20).
///
/// `fields` is the parsed tree (top-level fields that completed before any
/// failure). `leaf_ranges` is the flat list of byte ranges every leaf field
/// explained, the basis for coverage scoring, and is populated even when the
/// parse later stops. `failure` is `Some` exactly when the parse stopped at a
/// localized error.
#[derive(Debug, Clone, PartialEq)]
pub struct Execution {
    /// The parsed field tree, in order. On failure this holds the top-level
    /// fields that completed before the parse stopped.
    pub fields: Vec<FieldInstance>,
    /// The total number of bytes consumed sequentially from offset zero.
    pub consumed: usize,
    /// The length of the sample that was executed.
    pub sample_len: usize,
    /// Every leaf byte range explained during the parse, as half-open
    /// `[start, end)` pairs. The source of truth for coverage.
    pub leaf_ranges: Vec<(usize, usize)>,
    /// Every constraint check performed, in the order it was checked.
    pub checks: Vec<ConstraintCheck>,
    /// `Some` when the parse stopped at a localized failure; `None` on success.
    pub failure: Option<ParseFailure>,
}

impl Execution {
    /// Whether the parse reached a clean end with no localized failure.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.failure.is_none()
    }

    /// How many of the recorded constraint checks passed.
    #[must_use]
    pub fn constraints_passed(&self) -> usize {
        self.checks.iter().filter(|check| check.passed).count()
    }
}

/// One parsed field with its concrete byte range and decoded value (FR-20).
#[derive(Debug, Clone, PartialEq)]
pub struct FieldInstance {
    /// The field name, when the IR gave one.
    pub name: Option<String>,
    /// The field's semantic role, when the IR gave one.
    pub role: Option<Role>,
    /// The absolute start offset of the field in the sample.
    pub start: usize,
    /// The absolute end offset (exclusive) of the field in the sample.
    pub end: usize,
    /// The decoded value.
    pub value: Value,
}

/// A decoded field value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// An integer, sign- or zero-extended into an `i128` so it holds the full
    /// signed and unsigned 64-bit range.
    Integer(i128),
    /// A run of raw bytes. The bytes themselves are addressed by the instance's
    /// range, not copied here, to bound memory.
    Bytes,
    /// A decoded string (best effort, lossy on invalid encodings).
    Text(String),
    /// An enumerated value, with the symbolic name when the IR's enum defines
    /// one for this value.
    Enum {
        /// The underlying integer value.
        value: i128,
        /// The symbolic name, if the referenced enum names this value.
        name: Option<String>,
    },
    /// A nested structure's fields.
    Struct(Vec<FieldInstance>),
    /// An array's elements.
    Array(Vec<FieldInstance>),
    /// Opaque or high-entropy bytes that were not decomposed.
    Opaque,
}

/// A localized parse failure: where it happened and why (FR-20).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseFailure {
    /// The byte offset at which the parse stopped.
    pub offset: usize,
    /// Why the parse stopped.
    pub reason: FailureReason,
}

/// Why a parse stopped at a localized failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FailureReason {
    /// A field needed more bytes than the buffer or parent had left.
    UnexpectedEndOfInput {
        /// How many bytes the field needed.
        needed: usize,
        /// How many bytes were available.
        available: usize,
    },
    /// A size, count, or offset reference named a field not in scope or not yet
    /// parsed. A validated IR never triggers this, but the executor stays
    /// robust to unvalidated input.
    ReferenceUnresolved {
        /// The referenced field name.
        field: String,
    },
    /// A size, count, or offset reference resolved to a field with no integer
    /// value.
    ReferenceNotInteger {
        /// The referenced field name.
        field: String,
    },
    /// A derived size, count, or offset was negative or larger than any buffer.
    ValueOutOfRange {
        /// The offending value.
        value: i128,
    },
    /// A delimited field never found its terminator before the buffer end.
    TerminatorNotFound,
    /// A delimited field declared an empty terminator.
    EmptyTerminator,
    /// A repeated element consumed zero bytes, which would loop forever.
    ZeroWidthRepeat,
    /// An integer or enum field declared a width that is not 1, 2, 4, or 8.
    InvalidWidth {
        /// The declared width in bytes.
        width: u8,
    },
    /// The recursion-depth limit was reached.
    DepthLimit {
        /// The configured limit.
        limit: usize,
    },
    /// The per-array element limit was reached.
    ArrayLimit {
        /// The configured limit.
        limit: usize,
    },
    /// The total field-count limit was reached.
    FieldLimit {
        /// The configured limit.
        limit: usize,
    },
    /// The owned output and parsing-metadata byte budget was reached.
    OutputLimit {
        /// The configured byte budget.
        limit: usize,
    },
    /// The total work limit was reached.
    StepLimit {
        /// The configured limit.
        limit: u64,
    },
    /// The wall-clock deadline passed.
    Timeout,
}

/// One constraint check the executor performed (FR-22, FR-23).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintCheck {
    /// The field the constraint is attached to, when named.
    pub field: Option<String>,
    /// The byte offset of that field.
    pub at: usize,
    /// What kind of constraint was checked.
    pub kind: CheckKind,
    /// Whether the constraint held.
    pub passed: bool,
    /// A short human-readable explanation, useful for the report.
    pub detail: String,
}

/// The kind of a [`ConstraintCheck`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckKind {
    /// A constant (magic or signature) constraint.
    Constant,
    /// An integer-range constraint.
    IntRange,
    /// A checksum constraint over a covered byte range.
    Checksum(ChecksumAlgorithm),
}

/// Execute `format` against `sample`, bounded by `limits` (FR-20, FR-24).
///
/// Returns an [`Execution`] describing the parse. This never panics on any
/// input: a malformed IR or hostile sample produces a localized
/// [`ParseFailure`] inside the result, not a crash.
#[must_use]
pub fn execute(format: &Format, sample: &[u8], limits: &Limits) -> Execution {
    // Durations beyond the clock's representable range cannot expire during
    // this run. Work and output budgets still apply to those configurations.
    let deadline = limits
        .timeout
        .and_then(|timeout| Instant::now().checked_add(timeout));
    let mut ctx = Ctx {
        sample,
        default_endianness: format.endianness,
        format,
        limits,
        deadline,
        steps: 0,
        steps_since_clock: 0,
        total_fields: 0,
        output_bytes: 0,
        leaf_ranges: Vec::new(),
        checks: Vec::new(),
        scopes: Vec::new(),
        failure: None,
    };

    let (fields, consumed) = if ctx.check_deadline(0) {
        ctx.parse_structure(&format.root, 0, sample.len(), 0)
    } else {
        (Vec::new(), 0)
    };
    ctx.check_deadline(consumed);

    Execution {
        fields,
        consumed,
        sample_len: sample.len(),
        leaf_ranges: ctx.leaf_ranges,
        checks: ctx.checks,
        failure: ctx.failure,
    }
}

/// A name bound while parsing the current structure: its integer value when it
/// has one, and its absolute byte range.
#[derive(Debug, Clone, Copy)]
struct Binding<'a> {
    name: &'a str,
    value: Option<i128>,
    start: usize,
    end: usize,
}

/// A checksum constraint deferred until its enclosing structure is fully parsed,
/// so its covered range can reference any sibling, including one parsed later.
struct PendingChecksum<'a> {
    field: Option<&'a str>,
    at: usize,
    width: u8,
    stored: i128,
    algorithm: ChecksumAlgorithm,
    from: &'a RangeAnchor,
    to: &'a RangeAnchor,
}

/// The successful parse of a single field.
struct Parsed {
    instance: FieldInstance,
    end: usize,
    int_value: Option<i128>,
}

/// Mutable execution state threaded through the recursive parse.
struct Ctx<'a> {
    sample: &'a [u8],
    default_endianness: Endianness,
    format: &'a Format,
    limits: &'a Limits,
    deadline: Option<Instant>,
    steps: u64,
    steps_since_clock: u64,
    total_fields: usize,
    output_bytes: usize,
    leaf_ranges: Vec<(usize, usize)>,
    checks: Vec<ConstraintCheck>,
    scopes: Vec<Vec<Binding<'a>>>,
    failure: Option<ParseFailure>,
}

impl<'a> Ctx<'a> {
    fn failed(&self) -> bool {
        self.failure.is_some()
    }

    /// Record a localized failure, keeping the first one seen.
    fn fail(&mut self, offset: usize, reason: FailureReason) {
        if self.failure.is_none() {
            self.failure = Some(ParseFailure { offset, reason });
        }
    }

    /// Charge `units` of work and check the work and wall-clock limits.
    /// Returns `false` (after recording a failure) when a limit is hit.
    fn charge(&mut self, units: u64, at: usize) -> bool {
        if self.failed() {
            return false;
        }
        let total = self.steps.checked_add(units);
        if total.is_none_or(|total| total > self.limits.max_steps) {
            self.fail(
                at,
                FailureReason::StepLimit {
                    limit: self.limits.max_steps,
                },
            );
            return false;
        }
        self.steps = total.unwrap_or(self.limits.max_steps);
        if let Some(deadline) = self.deadline {
            self.steps_since_clock = self.steps_since_clock.saturating_add(units);
            if self.steps_since_clock >= CLOCK_CHECK_INTERVAL {
                self.steps_since_clock = 0;
                if Instant::now() >= deadline {
                    self.fail(at, FailureReason::Timeout);
                    return false;
                }
            }
        }
        true
    }

    fn check_deadline(&mut self, at: usize) -> bool {
        if self.failed() {
            return false;
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.fail(at, FailureReason::Timeout);
            return false;
        }
        true
    }

    /// Account before allocating. Four slots per pushed vector entry cover
    /// initial capacity and geometric growth; dropped allocations stay charged.
    fn retain(&mut self, bytes: usize, at: usize) -> bool {
        let Some(total) = self.output_bytes.checked_add(bytes) else {
            self.fail(
                at,
                FailureReason::OutputLimit {
                    limit: self.limits.max_output_bytes,
                },
            );
            return false;
        };
        if total > self.limits.max_output_bytes {
            self.fail(
                at,
                FailureReason::OutputLimit {
                    limit: self.limits.max_output_bytes,
                },
            );
            return false;
        }
        if !self.charge((bytes as u64).div_ceil(64), at) {
            return false;
        }
        self.output_bytes = total;
        true
    }

    fn copy_string(&mut self, text: &str, at: usize) -> Option<String> {
        self.retain(text.len(), at).then(|| text.to_owned())
    }

    /// Reserve the fixed check, bounded diagnostic scratch space, and its name
    /// before constructing any owned diagnostic text.
    fn retain_check(&mut self, name: Option<&str>, at: usize) -> bool {
        let bytes = (4 * std::mem::size_of::<ConstraintCheck>() + 512)
            .saturating_add(name.map_or(0, str::len));
        self.retain(bytes, at)
    }

    /// Count one field instance against the total-field limit. Returns `false`
    /// (after recording a failure) when the limit is hit.
    fn account_field(&mut self, at: usize) -> bool {
        if self.total_fields >= self.limits.max_total_fields {
            self.fail(
                at,
                FailureReason::FieldLimit {
                    limit: self.limits.max_total_fields,
                },
            );
            return false;
        }
        self.total_fields += 1;
        true
    }

    /// Resolve a referenced field's integer value in the current scope chain.
    fn resolve_value(&mut self, name: &str, at: usize) -> Option<i128> {
        for frame in (0..self.scopes.len()).rev() {
            for index in (0..self.scopes[frame].len()).rev() {
                let binding = self.scopes[frame][index];
                if !self.charge(1 + binding.name.len().min(name.len()) as u64, at) {
                    return None;
                }
                if binding.name != name {
                    continue;
                }
                return match binding.value {
                    Some(value) => Some(value),
                    None => {
                        let field = self.copy_string(name, at)?;
                        self.fail(at, FailureReason::ReferenceNotInteger { field });
                        None
                    }
                };
            }
        }
        let field = self.copy_string(name, at)?;
        self.fail(at, FailureReason::ReferenceUnresolved { field });
        None
    }

    /// Resolve a referenced field's byte range in the current scope chain.
    fn resolve_range(&mut self, name: &str, at: usize) -> Option<(usize, usize)> {
        for frame in (0..self.scopes.len()).rev() {
            for index in (0..self.scopes[frame].len()).rev() {
                let binding = self.scopes[frame][index];
                if !self.charge(1 + binding.name.len().min(name.len()) as u64, at) {
                    return None;
                }
                if binding.name == name {
                    return Some((binding.start, binding.end));
                }
            }
        }
        None
    }

    /// Convert a derived size, count, or offset value into a usable byte length,
    /// failing if it is negative or beyond any addressable buffer.
    fn value_as_len(&mut self, value: i128, at: usize) -> Option<usize> {
        if value < 0 {
            self.fail(at, FailureReason::ValueOutOfRange { value });
            return None;
        }
        match usize::try_from(value) {
            Ok(len) => Some(len),
            Err(_) => {
                self.fail(at, FailureReason::ValueOutOfRange { value });
                None
            }
        }
    }

    /// Parse a structure starting at `base`, bounded above by `limit`, at the
    /// given recursion `depth`. Returns the parsed fields and the cursor after
    /// the last field.
    fn parse_structure(
        &mut self,
        structure: &'a sextant_ir::Structure,
        base: usize,
        limit: usize,
        depth: usize,
    ) -> (Vec<FieldInstance>, usize) {
        let mut fields = Vec::new();
        let mut cursor = base;
        if !self.retain(4 * std::mem::size_of::<Vec<Binding<'a>>>(), base) {
            return (fields, cursor);
        }
        self.scopes.push(Vec::new());
        let mut pending: Vec<PendingChecksum<'a>> = Vec::new();

        for field in &structure.fields {
            if self.failed() {
                break;
            }
            let start = match self.field_start(field, base, cursor, limit) {
                Some(start) => start,
                None => break,
            };
            let Some(parsed) = self.parse_field(field, start, limit, depth) else {
                cursor = cursor.max(start);
                break;
            };
            self.note_pending_checksum(field, &parsed, &mut pending);
            if self.failed() {
                break;
            }
            if field.name.is_some() && !self.retain(4 * std::mem::size_of::<Binding<'a>>(), start) {
                break;
            }
            if let Some(frame) = self.scopes.last_mut() {
                if let Some(name) = &field.name {
                    frame.push(Binding {
                        name,
                        value: parsed.int_value,
                        start: parsed.instance.start,
                        end: parsed.instance.end,
                    });
                }
            }
            cursor = parsed.end;
            fields.push(parsed.instance);
        }

        self.evaluate_pending_checksums(pending);
        self.scopes.pop();
        (fields, cursor)
    }

    /// Determine where a field begins, honoring an explicit absolute or derived
    /// offset, otherwise continuing sequentially from `cursor`.
    fn field_start(
        &mut self,
        field: &'a Field,
        base: usize,
        cursor: usize,
        limit: usize,
    ) -> Option<usize> {
        let start = match &field.offset {
            None => cursor,
            Some(FieldOffset::Absolute { bytes }) => {
                let offset = self.value_as_len(i128::from(*bytes), cursor)?;
                base.saturating_add(offset)
            }
            Some(FieldOffset::Derived { offset_field }) => {
                let value = self.resolve_value(offset_field.as_str(), cursor)?;
                let offset = self.value_as_len(value, cursor)?;
                base.saturating_add(offset)
            }
        };
        if start > limit {
            self.fail(
                start.min(self.sample.len()),
                FailureReason::UnexpectedEndOfInput {
                    needed: 0,
                    available: limit.saturating_sub(start.min(limit)),
                },
            );
            return None;
        }
        Some(start)
    }

    /// Parse one field at `start`, bounded above by `limit`.
    fn parse_field(
        &mut self,
        field: &'a Field,
        start: usize,
        limit: usize,
        depth: usize,
    ) -> Option<Parsed> {
        if !self.charge(1, start) || !self.account_field(start) {
            return None;
        }
        let storage = (4 * std::mem::size_of::<FieldInstance>()
            + 4 * std::mem::size_of::<(usize, usize)>())
        .saturating_add(field.name.as_ref().map_or(0, String::len));
        if !self.retain(storage, start) {
            return None;
        }
        match &field.kind {
            Kind::Integer {
                width,
                signed,
                endianness,
            } => self.parse_integer(field, start, limit, *width, *signed, *endianness),
            Kind::Enum {
                width,
                endianness,
                enum_ref,
            } => self.parse_enum(field, start, limit, *width, *endianness, enum_ref),
            Kind::Bytes => self.parse_sized(field, start, limit, ValueShape::Bytes),
            Kind::Opaque => self.parse_sized(field, start, limit, ValueShape::Opaque),
            Kind::String { encoding } => {
                self.parse_sized(field, start, limit, ValueShape::Text(*encoding))
            }
            Kind::Struct { structure } => {
                if depth + 1 > self.limits.max_depth {
                    self.fail(
                        start,
                        FailureReason::DepthLimit {
                            limit: self.limits.max_depth,
                        },
                    );
                    return None;
                }
                let (inner, end) = self.parse_structure(structure, start, limit, depth + 1);
                if self.failed() {
                    // The nested structure stopped at a localized failure. Drop
                    // the partial struct so the returned tree holds only fields
                    // that completed (the leaf ranges already captured coverage).
                    return None;
                }
                Some(Parsed {
                    instance: FieldInstance {
                        name: field.name.clone(),
                        role: field.role,
                        start,
                        end,
                        value: Value::Struct(inner),
                    },
                    end,
                    int_value: None,
                })
            }
            Kind::Array { element, count } => {
                self.parse_array(field, element, count, start, limit, depth)
            }
        }
    }

    fn parse_integer(
        &mut self,
        field: &'a Field,
        start: usize,
        limit: usize,
        width: u8,
        signed: sextant_ir::Signedness,
        endianness: Option<Endianness>,
    ) -> Option<Parsed> {
        let span = self.read_int_span(start, limit, width)?;
        let bytes = &self.sample[start..span];
        let order = endianness.unwrap_or(self.default_endianness);
        let value = decode_int(bytes, order, signed);
        self.leaf_ranges.push((start, span));
        self.check_constant(field, bytes, start);
        self.check_int_range(field, value, start);
        if self.failed() {
            return None;
        }
        Some(Parsed {
            instance: FieldInstance {
                name: field.name.clone(),
                role: field.role,
                start,
                end: span,
                value: Value::Integer(value),
            },
            end: span,
            int_value: Some(value),
        })
    }

    fn parse_enum(
        &mut self,
        field: &'a Field,
        start: usize,
        limit: usize,
        width: u8,
        endianness: Option<Endianness>,
        enum_ref: &str,
    ) -> Option<Parsed> {
        let span = self.read_int_span(start, limit, width)?;
        let bytes = &self.sample[start..span];
        let order = endianness.unwrap_or(self.default_endianness);
        let value = decode_int(bytes, order, sextant_ir::Signedness::Unsigned);
        // Charge key comparison work before the map lookup, then each variant
        // examined. Enum definitions are not required to have been validated.
        let map_work = enum_ref
            .len()
            .saturating_mul(self.format.enums.len().max(1));
        if !self.charge(map_work as u64, start) {
            return None;
        }
        let format = self.format;
        let mut name = None;
        if let Some(def) = format.enums.get(enum_ref) {
            for variant in &def.variants {
                if !self.charge(1, start) {
                    return None;
                }
                if variant.value == value {
                    name = Some(self.copy_string(&variant.name, start)?);
                    break;
                }
            }
        }
        self.leaf_ranges.push((start, span));
        self.check_constant(field, bytes, start);
        self.check_int_range(field, value, start);
        if self.failed() {
            return None;
        }
        Some(Parsed {
            instance: FieldInstance {
                name: field.name.clone(),
                role: field.role,
                start,
                end: span,
                value: Value::Enum { value, name },
            },
            end: span,
            int_value: Some(value),
        })
    }

    /// Read the byte span of an integer or enum field, checking the width and
    /// that the bytes are available.
    fn read_int_span(&mut self, start: usize, limit: usize, width: u8) -> Option<usize> {
        if !matches!(width, 1 | 2 | 4 | 8) {
            self.fail(start, FailureReason::InvalidWidth { width });
            return None;
        }
        let end = start.saturating_add(usize::from(width));
        if end > limit {
            self.fail(
                start,
                FailureReason::UnexpectedEndOfInput {
                    needed: usize::from(width),
                    available: limit.saturating_sub(start),
                },
            );
            return None;
        }
        Some(end)
    }

    /// Parse a sized field (bytes, opaque, or string) according to its size
    /// rule.
    fn parse_sized(
        &mut self,
        field: &'a Field,
        start: usize,
        limit: usize,
        shape: ValueShape,
    ) -> Option<Parsed> {
        let Some(size) = field.size.as_ref() else {
            // A bytes, string, or opaque field with no size rule cannot be
            // sized. A validated IR always has one; treat the absence as a
            // zero-length field rather than panicking.
            return self.finish_sized(field, start, start, start, shape);
        };
        match size {
            SizeRule::Fixed { bytes } => {
                let len = self.value_as_len(i128::from(*bytes), start)?;
                let end = start.saturating_add(len);
                if end > limit {
                    self.fail(
                        start,
                        FailureReason::UnexpectedEndOfInput {
                            needed: len,
                            available: limit.saturating_sub(start),
                        },
                    );
                    return None;
                }
                self.finish_sized(field, start, end, end, shape)
            }
            SizeRule::Derived { length_field } => {
                let value = self.resolve_value(length_field.as_str(), start)?;
                let len = self.value_as_len(value, start)?;
                let end = start.saturating_add(len);
                if end > limit {
                    self.fail(
                        start,
                        FailureReason::UnexpectedEndOfInput {
                            needed: len,
                            available: limit.saturating_sub(start),
                        },
                    );
                    return None;
                }
                self.finish_sized(field, start, end, end, shape)
            }
            SizeRule::ToEnd => self.finish_sized(field, start, limit, limit, shape),
            SizeRule::Delimited {
                terminator,
                include_terminator,
            } => {
                let term = terminator.as_slice();
                if term.is_empty() {
                    self.fail(start, FailureReason::EmptyTerminator);
                    return None;
                }
                match self.find_terminator(start, limit, term) {
                    Some(found) => {
                        let consumed_end = found + term.len();
                        let value_end = if *include_terminator {
                            consumed_end
                        } else {
                            found
                        };
                        self.finish_sized(field, start, value_end, consumed_end, shape)
                    }
                    None => {
                        self.fail(start, FailureReason::TerminatorNotFound);
                        None
                    }
                }
            }
        }
    }

    /// Scan for `term` in `sample[start..limit]`, charging one work unit per
    /// byte so the search is bounded and visible to the work limit.
    fn find_terminator(&mut self, start: usize, limit: usize, term: &[u8]) -> Option<usize> {
        if term.len() > limit.saturating_sub(start) {
            // Still charge for the bytes we would scan so the work limit sees
            // the effort, then report not found.
            let _ = self.charge((limit.saturating_sub(start)) as u64, start);
            return None;
        }
        let last = limit - term.len();
        let mut pos = start;
        while pos <= last {
            if !self.charge(term.len() as u64, pos) {
                return None;
            }
            if &self.sample[pos..pos + term.len()] == term {
                return Some(pos);
            }
            pos += 1;
        }
        None
    }

    /// Finish a sized field: record its leaf range over the bytes it consumed,
    /// check a constant constraint against the value bytes, and build the
    /// instance.
    fn finish_sized(
        &mut self,
        field: &'a Field,
        start: usize,
        value_end: usize,
        consumed_end: usize,
        shape: ValueShape,
    ) -> Option<Parsed> {
        self.leaf_ranges.push((start, consumed_end));
        let value_bytes = &self.sample[start..value_end];
        self.check_constant(field, value_bytes, start);
        if self.failed() {
            return None;
        }
        let value = match shape {
            ValueShape::Bytes => Value::Bytes,
            ValueShape::Opaque => Value::Opaque,
            ValueShape::Text(encoding) => {
                // Lossy UTF-8 expands one byte to at most three bytes. Allow
                // another factor of two for String growth during decoding.
                let storage = value_bytes.len().min(MAX_TEXT_PREVIEW_BYTES) * 6;
                if !self.retain(storage, start) {
                    return None;
                }
                Value::Text(decode_text(value_bytes, encoding))
            }
        };
        Some(Parsed {
            instance: FieldInstance {
                name: field.name.clone(),
                role: field.role,
                start,
                end: consumed_end,
                value,
            },
            end: consumed_end,
            int_value: None,
        })
    }

    /// Parse an array field according to its count rule.
    fn parse_array(
        &mut self,
        field: &'a Field,
        element: &'a Field,
        count: &CountRule,
        start: usize,
        limit: usize,
        depth: usize,
    ) -> Option<Parsed> {
        if depth + 1 > self.limits.max_depth {
            self.fail(
                start,
                FailureReason::DepthLimit {
                    limit: self.limits.max_depth,
                },
            );
            return None;
        }

        // Resolve the count target and the element boundary up front.
        let (target, element_limit): (Option<usize>, usize) = match count {
            CountRule::Fixed { count } => {
                let n = self.value_as_len(i128::from(*count), start)?;
                (Some(n), limit)
            }
            CountRule::FromField { count_field } => {
                let value = self.resolve_value(count_field.as_str(), start)?;
                let n = self.value_as_len(value, start)?;
                (Some(n), limit)
            }
            CountRule::BoundedBy { length_field } => {
                let value = self.resolve_value(length_field.as_str(), start)?;
                let len = self.value_as_len(value, start)?;
                let end = start.saturating_add(len);
                if end > limit {
                    // The declared byte length runs past the bytes available, so
                    // the sample is truncated. Reject it like a derived-size
                    // field rather than silently shortening the bound, which
                    // would let the scorer mark a truncated sample as parsed.
                    self.fail(
                        start,
                        FailureReason::UnexpectedEndOfInput {
                            needed: len,
                            available: limit.saturating_sub(start),
                        },
                    );
                    return None;
                }
                (None, end)
            }
            CountRule::ToEnd => (None, limit),
        };

        let mut elements = Vec::new();
        let mut cursor = start;
        let mut produced = 0usize;
        // Checksum constraints attached directly to the element field are
        // deferred like those on a structure's fields, then evaluated once the
        // array is parsed. Constants and ranges on the element are checked
        // inline by the element's own parse.
        let mut pending = Vec::new();

        loop {
            if self.failed() {
                break;
            }
            // Termination by count or by boundary.
            match target {
                Some(n) if produced >= n => break,
                None if cursor >= element_limit => break,
                _ => {}
            }
            if produced >= self.limits.max_array_elements {
                self.fail(
                    cursor,
                    FailureReason::ArrayLimit {
                        limit: self.limits.max_array_elements,
                    },
                );
                break;
            }

            let before = cursor;
            let Some(parsed) = self.parse_field(element, cursor, element_limit, depth + 1) else {
                break;
            };
            if parsed.end == before {
                self.fail(before, FailureReason::ZeroWidthRepeat);
                break;
            }
            self.note_pending_checksum(element, &parsed, &mut pending);
            cursor = parsed.end;
            elements.push(parsed.instance);
            produced += 1;
        }

        if self.failed() {
            return None;
        }

        self.evaluate_pending_checksums(pending);
        if self.failed() {
            return None;
        }

        Some(Parsed {
            instance: FieldInstance {
                name: field.name.clone(),
                role: field.role,
                start,
                end: cursor,
                value: Value::Array(elements),
            },
            end: cursor,
            int_value: None,
        })
    }

    /// Check a field's constant constraints against the bytes it parsed.
    fn check_constant(&mut self, field: &'a Field, bytes: &[u8], at: usize) {
        for constraint in &field.constraints {
            if !self.charge(1, at) {
                return;
            }
            if let Constraint::Constant { value } = constraint {
                if !self.retain_check(field.name.as_deref(), at) {
                    return;
                }
                if value.as_slice().len() == bytes.len() && !self.charge(bytes.len() as u64, at) {
                    return;
                }
                let passed = value.as_slice() == bytes;
                let detail = if passed {
                    "constant matched".to_owned()
                } else {
                    format!(
                        "expected {}, found {}",
                        hex_of(value.as_slice()),
                        hex_of(bytes)
                    )
                };
                self.checks.push(ConstraintCheck {
                    field: field.name.clone(),
                    at,
                    kind: CheckKind::Constant,
                    passed,
                    detail,
                });
            }
        }
    }

    /// Check a field's integer-range constraints against its decoded value.
    fn check_int_range(&mut self, field: &'a Field, value: i128, at: usize) {
        for constraint in &field.constraints {
            if !self.charge(1, at) {
                return;
            }
            if let Constraint::IntRange { min, max } = constraint {
                if !self.retain_check(field.name.as_deref(), at) {
                    return;
                }
                let passed = value >= *min && value <= *max;
                let detail = if passed {
                    format!("{value} within {min}..={max}")
                } else {
                    format!("{value} outside {min}..={max}")
                };
                self.checks.push(ConstraintCheck {
                    field: field.name.clone(),
                    at,
                    kind: CheckKind::IntRange,
                    passed,
                    detail,
                });
            }
        }
    }

    /// Record a field's checksum constraints to evaluate once the enclosing
    /// structure has parsed every sibling its covered range might reference.
    fn note_pending_checksum(
        &mut self,
        field: &'a Field,
        parsed: &Parsed,
        pending: &mut Vec<PendingChecksum<'a>>,
    ) {
        for constraint in &field.constraints {
            if !self.charge(1, parsed.instance.start) {
                return;
            }
            if let Constraint::Checksum { spec } = constraint {
                let start = parsed.instance.start;
                if !self.retain(4 * std::mem::size_of::<PendingChecksum<'a>>(), start) {
                    return;
                }
                let width = (parsed.instance.end - start).min(8) as u8;
                let stored = match parsed.int_value {
                    Some(value) => value,
                    // A checksum stored in a bytes field: interpret only its low
                    // `width` (at most eight) bytes, so a field wider than eight
                    // bytes cannot overflow the integer decoder and panic.
                    None => decode_int(
                        &self.sample[start..start + usize::from(width)],
                        self.default_endianness,
                        sextant_ir::Signedness::Unsigned,
                    ),
                };
                pending.push(PendingChecksum {
                    field: field.name.as_deref(),
                    at: parsed.instance.start,
                    width,
                    stored,
                    algorithm: spec.algorithm,
                    from: &spec.covered.from,
                    to: &spec.covered.to,
                });
            }
        }
    }

    /// Evaluate the deferred checksum constraints of one structure.
    fn evaluate_pending_checksums(&mut self, pending: Vec<PendingChecksum<'a>>) {
        for item in pending {
            if !self.charge(1, item.at) || !self.retain_check(item.field, item.at) {
                break;
            }
            let check = self.evaluate_checksum(&item);
            self.checks.push(check);
            if self.failed() {
                break;
            }
        }
    }

    fn evaluate_checksum(&mut self, item: &PendingChecksum<'a>) -> ConstraintCheck {
        let from = self.anchor_offset(item.from, item.at);
        let to = self.anchor_offset(item.to, item.at);
        let (passed, detail) = match (from, to) {
            (Some(from), Some(to)) if from <= to && to <= self.sample.len() => {
                // Hashing the covered range is work proportional to its length,
                // so charge it before hashing. A checksum over a huge range
                // therefore cannot exceed the work or wall-clock limit (FR-24).
                if !self.charge((to - from) as u64, from) {
                    (
                        false,
                        format!("{:?} not evaluated: resource limit reached", item.algorithm),
                    )
                } else {
                    let data = &self.sample[from..to];
                    let computed = checksum::compute(item.algorithm, data, item.width);
                    let stored = mask_to_width(item.stored, item.width);
                    let passed = computed == stored;
                    let detail = if passed {
                        format!("{:?} verified over [{from}, {to})", item.algorithm)
                    } else {
                        format!(
                            "{:?} over [{from}, {to}) expected {computed:#x}, stored {stored:#x}",
                            item.algorithm
                        )
                    };
                    (passed, detail)
                }
            }
            _ => (
                false,
                format!(
                    "{:?} covered range did not resolve to valid bytes",
                    item.algorithm
                ),
            ),
        };
        ConstraintCheck {
            field: item.field.map(str::to_owned),
            at: item.at,
            kind: CheckKind::Checksum(item.algorithm),
            passed,
            detail,
        }
    }

    /// Resolve a checksum range anchor to an absolute byte offset.
    fn anchor_offset(&mut self, anchor: &RangeAnchor, at: usize) -> Option<usize> {
        let (start, end) = self.resolve_range(anchor.field().as_str(), at)?;
        match anchor {
            RangeAnchor::FieldStart { .. } => Some(start),
            RangeAnchor::FieldEnd { .. } => Some(end),
        }
    }
}

/// Which decoded value a sized field produces.
enum ValueShape {
    Bytes,
    Opaque,
    Text(StringEncoding),
}

/// Reduce a stored `i128` checksum value to its low `width` bytes for an
/// unsigned comparison.
fn mask_to_width(value: i128, width: u8) -> u64 {
    let raw = value as u64;
    if width == 0 || width >= 8 {
        raw
    } else {
        let bits = u32::from(width) * 8;
        raw & ((1u64 << bits) - 1)
    }
}

/// Decode `bytes` (length 1, 2, 4, or 8) as an integer in the given order and
/// signedness, into an `i128`.
///
/// Callers pass a validated width of at most eight bytes. As a safety guard
/// against misuse, a longer slice is clamped to its first eight bytes so a
/// little-endian shift can never overflow and panic.
fn decode_int(bytes: &[u8], order: Endianness, signed: sextant_ir::Signedness) -> i128 {
    let bytes = if bytes.len() > 8 { &bytes[..8] } else { bytes };
    let mut acc: u64 = 0;
    match order {
        Endianness::Big => {
            for &byte in bytes {
                acc = (acc << 8) | u64::from(byte);
            }
        }
        Endianness::Little => {
            for (index, &byte) in bytes.iter().enumerate() {
                acc |= u64::from(byte) << (8 * index);
            }
        }
    }
    match signed {
        sextant_ir::Signedness::Unsigned => i128::from(acc),
        sextant_ir::Signedness::Signed => {
            let width = bytes.len();
            if width == 0 || width >= 8 {
                i128::from(acc as i64)
            } else {
                let shift = 64 - 8 * width as u32;
                let extended = ((acc << shift) as i64) >> shift;
                i128::from(extended)
            }
        }
    }
}

/// The most input bytes [`decode_text`] will materialize into a string. The
/// decoded text is a preview for the report and inspect view, not used by the
/// scorer, so a hostile field with a huge string value cannot force an
/// allocation proportional to the whole sample (FR-24). The field's full byte
/// range is still recorded on its instance.
const MAX_TEXT_PREVIEW_BYTES: usize = 4096;

/// Decode bytes into a best-effort string for the given encoding. Lossy on
/// invalid input so it never fails, and capped at [`MAX_TEXT_PREVIEW_BYTES`] so
/// the allocation stays bounded. The scorer does not use the text, only the
/// byte range.
fn decode_text(bytes: &[u8], encoding: StringEncoding) -> String {
    let bytes = &bytes[..bytes.len().min(MAX_TEXT_PREVIEW_BYTES)];
    match encoding {
        StringEncoding::Ascii | StringEncoding::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
        StringEncoding::Latin1 => bytes.iter().map(|&byte| byte as char).collect(),
        StringEncoding::Utf16Le => decode_utf16(bytes, false),
        StringEncoding::Utf16Be => decode_utf16(bytes, true),
    }
}

fn decode_utf16(bytes: &[u8], big_endian: bool) -> String {
    let units = bytes.chunks_exact(2).map(|pair| {
        if big_endian {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_le_bytes([pair[0], pair[1]])
        }
    });
    char::decode_utf16(units)
        .map(|result| result.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Render bytes as a lowercase hex string for diagnostics, truncating very long
/// runs so a failure detail stays small.
fn hex_of(bytes: &[u8]) -> String {
    const MAX: usize = 32;
    let shown = &bytes[..bytes.len().min(MAX)];
    let mut out = String::with_capacity(shown.len() * 2 + 3);
    for &byte in shown {
        out.push_str(&format!("{byte:02x}"));
    }
    if bytes.len() > MAX {
        out.push_str("...");
    }
    out
}
