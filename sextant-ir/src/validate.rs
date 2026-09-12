//! Semantic validation of a [`Format`].
//!
//! Deserialization (FR-19) is purely structural: any well-formed JSON becomes a
//! [`Format`] so that round-tripping never loses information. This module adds
//! the semantic layer that the Step 2 acceptance criteria require: it rejects
//! dangling length, count, offset, and checksum references, overlapping fixed
//! fields, and sizes that are not sane, each with a clear, located error.
//!
//! Validation first checks the tree's shape without recursion, before any
//! recursive layout or semantic helper runs. Diagnostics are bounded and report
//! when validation stopped early; long diagnostic labels are shortened without
//! changing the input IR.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::rc::Rc;

use crate::model::{
    Constraint, CountRule, Field, FieldOffset, Format, Kind, RangeAnchor, SizeRule, Structure,
};

/// The largest size, in bytes, a single fixed-size field may declare before it
/// is treated as insane. Aligned with the executor's per-array element cap so a
/// validated IR cannot declare a fixed blob the executor would refuse to allocate
/// for (FR-24).
pub const MAX_FIXED_FIELD_BYTES: u64 = 1 << 24;

/// The largest element count a fixed-count array may declare before it is
/// treated as insane. Aligned with [`MAX_FIXED_FIELD_BYTES`] and the executor's
/// `max_array_elements` default (FR-24).
pub const MAX_ARRAY_COUNT: u64 = 1 << 24;

/// The deepest nesting of structures and arrays a format may declare. Matches
/// the executor's default depth cap so validation rejects IR the executor would
/// stop on for depth alone (FR-24).
pub const MAX_NESTING_DEPTH: usize = 64;

/// The most field nodes a format may contain (counting every nested field and
/// array element descriptor). Bounds IR size independently of sample bytes.
pub const MAX_FIELD_COUNT: usize = 1 << 20;

/// The most diagnostics retained for one malformed IR. Validation stops when
/// this limit is reached and reports that additional problems may remain.
pub const MAX_VALIDATION_ERRORS: usize = 128;

/// The maximum UTF-8 byte length of one diagnostic path or input-derived label.
/// Longer text is visibly shortened; this does not restrict valid IR names.
pub const MAX_DIAGNOSTIC_TEXT_BYTES: usize = 256;

/// The integer widths, in bytes, the IR supports (FR-16).
pub const VALID_INT_WIDTHS: [u8; 4] = [1, 2, 4, 8];

/// One problem found during validation, with the path to the offending node.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationError {
    /// A dotted path to the node, for example `root.fields[1].kind.element`.
    pub path: String,
    /// What went wrong.
    pub kind: ValidationErrorKind,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.kind)
    }
}

/// The category of a [`ValidationError`].
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationErrorKind {
    /// Two fields in the same structure share a name, so references to it are
    /// ambiguous.
    DuplicateFieldName {
        /// The repeated name.
        name: String,
    },
    /// A reference names a field that does not exist in scope.
    DanglingFieldRef {
        /// The referenced name.
        name: String,
    },
    /// A reference names a field that is parsed after the field that depends on
    /// it, so its value is not yet known.
    ForwardReference {
        /// The referenced name.
        name: String,
    },
    /// A length, count, or offset reference resolves to a field that is not an
    /// integer.
    ReferenceNotInteger {
        /// The referenced name.
        name: String,
    },
    /// An enum field references a named enum that the format does not define.
    DanglingEnumRef {
        /// The referenced enum name.
        name: String,
    },
    /// Two fixed-size, positioned fields overlap.
    OverlappingFields {
        /// The earlier field.
        first: String,
        /// The later field.
        second: String,
        /// The byte offset at which they overlap.
        at: u64,
    },
    /// A fixed-size field declares a size of zero bytes.
    ZeroSizedField,
    /// A fixed-size field declares an implausibly large size.
    InsaneFixedSize {
        /// The declared size in bytes.
        bytes: u64,
    },
    /// An integer or enum field has a width that is not 1, 2, 4, or 8 bytes.
    InvalidIntegerWidth {
        /// The declared width in bytes.
        width: u8,
    },
    /// A delimited field declares an empty terminator.
    EmptyTerminator,
    /// A confidence value is not a finite number in 0.0 to 1.0.
    ConfidenceOutOfRange {
        /// The offending value.
        value: f64,
    },
    /// A field's kind and size rule are inconsistent.
    SizeKindMismatch {
        /// What is inconsistent and how to fix it.
        detail: String,
    },
    /// A constraint cannot apply to the field's kind.
    ConstraintKindMismatch {
        /// What is inconsistent and how to fix it.
        detail: String,
    },
    /// A constant constraint's length does not match the field's fixed size.
    ConstantSizeMismatch {
        /// The size the field declares.
        expected: u64,
        /// The length of the constant.
        actual: u64,
    },
    /// An integer-range constraint has its bounds inverted.
    IntRangeInverted {
        /// The lower bound.
        min: i128,
        /// The upper bound.
        max: i128,
    },
    /// A fixed-count array declares an implausibly large count.
    InsaneArrayCount {
        /// The declared count.
        count: u64,
    },
    /// The IR nests structures or arrays deeper than [`MAX_NESTING_DEPTH`].
    NestingTooDeep {
        /// The depth that exceeded the cap.
        depth: usize,
    },
    /// The IR declares more field nodes than [`MAX_FIELD_COUNT`].
    TooManyFields {
        /// At least this many field nodes were found before stopping.
        count: usize,
    },
    /// Sample support claims more agreeing samples than total samples.
    SampleSupportInconsistent {
        /// How many samples were said to agree.
        agreeing: u64,
        /// How many samples there were in total.
        total: u64,
    },
    /// A named enum lists the same value twice.
    DuplicateEnumValue {
        /// The enum's name.
        enum_name: String,
        /// The repeated value.
        value: i128,
    },
    /// An enum field's declared width disagrees with the fixed width of the
    /// enum it references.
    EnumWidthMismatch {
        /// The referenced enum name.
        enum_name: String,
        /// The width the field declares.
        field_width: u8,
        /// The width the enum fixes.
        enum_width: u8,
    },
    /// A checksum covered range starts after it ends, so it is not a real byte
    /// span.
    InvertedChecksumRange {
        /// The field the range starts from.
        from: String,
        /// The field the range ends at.
        to: String,
    },
}

impl fmt::Display for ValidationErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationErrorKind::DuplicateFieldName { name } => {
                write!(f, "duplicate field name {name:?} in the same structure")
            }
            ValidationErrorKind::DanglingFieldRef { name } => {
                write!(f, "reference to unknown field {name:?}")
            }
            ValidationErrorKind::ForwardReference { name } => write!(
                f,
                "reference to field {name:?} that is parsed after the field that depends on it"
            ),
            ValidationErrorKind::ReferenceNotInteger { name } => {
                write!(
                    f,
                    "field {name:?} is referenced as a number but is not an integer"
                )
            }
            ValidationErrorKind::DanglingEnumRef { name } => {
                write!(
                    f,
                    "reference to enum {name:?} that the format does not define"
                )
            }
            ValidationErrorKind::OverlappingFields { first, second, at } => write!(
                f,
                "fixed fields {first} and {second} overlap at byte offset {at}"
            ),
            ValidationErrorKind::ZeroSizedField => {
                write!(f, "fixed-size field declares a size of zero bytes")
            }
            ValidationErrorKind::InsaneFixedSize { bytes } => write!(
                f,
                "fixed-size field declares {bytes} bytes, above the sane limit of {MAX_FIXED_FIELD_BYTES}"
            ),
            ValidationErrorKind::InvalidIntegerWidth { width } => {
                write!(f, "integer width of {width} bytes is not 1, 2, 4, or 8")
            }
            ValidationErrorKind::EmptyTerminator => {
                write!(f, "delimited field declares an empty terminator")
            }
            ValidationErrorKind::ConfidenceOutOfRange { value } => {
                write!(f, "confidence {value} is not a finite value in 0.0 to 1.0")
            }
            ValidationErrorKind::SizeKindMismatch { detail } => {
                write!(f, "size rule does not match the field kind: {detail}")
            }
            ValidationErrorKind::ConstraintKindMismatch { detail } => {
                write!(f, "constraint does not match the field kind: {detail}")
            }
            ValidationErrorKind::ConstantSizeMismatch { expected, actual } => write!(
                f,
                "constant constraint is {actual} bytes but the field is {expected} bytes"
            ),
            ValidationErrorKind::IntRangeInverted { min, max } => {
                write!(f, "integer range has min {min} greater than max {max}")
            }
            ValidationErrorKind::InsaneArrayCount { count } => write!(
                f,
                "fixed array count of {count} is above the sane limit of {MAX_ARRAY_COUNT}"
            ),
            ValidationErrorKind::NestingTooDeep { depth } => write!(
                f,
                "nesting depth of {depth} exceeds the limit of {MAX_NESTING_DEPTH}"
            ),
            ValidationErrorKind::TooManyFields { count } => write!(
                f,
                "format declares {count} fields, above the limit of {MAX_FIELD_COUNT}"
            ),
            ValidationErrorKind::SampleSupportInconsistent { agreeing, total } => write!(
                f,
                "sample support claims {agreeing} agreeing of {total} total samples"
            ),
            ValidationErrorKind::DuplicateEnumValue { enum_name, value } => {
                write!(
                    f,
                    "enum {enum_name:?} lists the value {value} more than once"
                )
            }
            ValidationErrorKind::EnumWidthMismatch {
                enum_name,
                field_width,
                enum_width,
            } => write!(
                f,
                "enum field width of {field_width} bytes disagrees with enum {enum_name:?} \
                 fixed width of {enum_width} bytes"
            ),
            ValidationErrorKind::InvertedChecksumRange { from, to } => write!(
                f,
                "checksum covered range runs backward, from field {from:?} to field {to:?}"
            ),
        }
    }
}

/// Bounded diagnostics from validating a [`Format`].
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationReport {
    /// At most [`MAX_VALIDATION_ERRORS`] diagnostics, in deterministic order.
    /// Input-derived labels and paths are shortened when necessary.
    pub errors: Vec<ValidationError>,
    /// Whether validation stopped early, either at a shape limit or the
    /// diagnostic cap. Additional problems may exist in unexamined input.
    pub truncated: bool,
}

impl ValidationReport {
    /// Whether the format passed with no errors.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty() && !self.truncated
    }
}

impl fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "IR validation failed with {} error(s):",
            self.errors.len()
        )?;
        for error in &self.errors {
            writeln!(f, "  - {error}")?;
        }
        if self.truncated {
            writeln!(
                f,
                "  Validation stopped early; additional problems may exist."
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationReport {}

/// A borrowed name index, constructed once for each lexical scope. Preserve the
/// first declaration when an invalid scope contains duplicate names.
#[derive(Debug)]
struct Scope<'a> {
    fields: &'a [Field],
    indices: BTreeMap<&'a str, usize>,
}

impl<'a> Scope<'a> {
    fn new(fields: &'a [Field]) -> Self {
        let mut indices = BTreeMap::new();
        for (index, field) in fields.iter().enumerate() {
            if let Some(name) = field.name.as_deref() {
                indices.entry(name).or_insert(index);
            }
        }
        Self { fields, indices }
    }

    fn resolve(&self, name: &str, bound: usize) -> Option<&'a Field> {
        let index = *self.indices.get(name)?;
        (index < bound).then(|| &self.fields[index])
    }
}

/// An ancestor index is shared, not copied, when descending into a child.
#[derive(Debug, Clone)]
struct Frame<'a> {
    scope: Rc<Scope<'a>>,
    visible: usize,
}

/// Resolve a field name in lexical scope: the current structure up to `bound`,
/// then each ancestor up to the point we descended from it.
fn resolve_field<'a>(
    ancestors: &[Frame<'a>],
    current: &Scope<'a>,
    bound: usize,
    name: &str,
) -> Option<&'a Field> {
    if let Some(found) = current.resolve(name, bound) {
        return Some(found);
    }
    for frame in ancestors.iter().rev() {
        if let Some(found) = frame.scope.resolve(name, frame.visible) {
            return Some(found);
        }
    }
    None
}

fn is_integer_like(kind: &Kind) -> bool {
    matches!(kind, Kind::Integer { .. } | Kind::Enum { .. })
}

/// The statically known fixed length of a field in bytes, or `None` if it is
/// variable or position-dependent.
fn fixed_len(field: &Field) -> Option<u64> {
    match &field.kind {
        Kind::Integer { width, .. } | Kind::Enum { width, .. } => Some(u64::from(*width)),
        Kind::Bytes | Kind::Opaque | Kind::String { .. } => match &field.size {
            Some(SizeRule::Fixed { bytes }) => Some(*bytes),
            _ => None,
        },
        Kind::Struct { structure } => struct_fixed_len(structure),
        Kind::Array { element, count } => match count {
            CountRule::Fixed { count } => {
                fixed_len(element).and_then(|len| len.checked_mul(*count))
            }
            _ => None,
        },
    }
}

fn struct_fixed_len(structure: &Structure) -> Option<u64> {
    // The struct's byte extent is the furthest end reached by any field. This
    // handles both sequential layouts (the running cursor) and absolute
    // positioned fields, so a positioned but statically sized child struct
    // still reports a known extent and is overlap-checked in its parent.
    let mut cursor: u64 = 0;
    let mut extent: u64 = 0;
    for field in &structure.fields {
        let start = match &field.offset {
            None => cursor,
            Some(FieldOffset::Absolute { bytes }) => *bytes,
            Some(FieldOffset::Derived { .. }) => return None,
        };
        let end = start.checked_add(fixed_len(field)?)?;
        cursor = end;
        extent = extent.max(end);
    }
    Some(extent)
}

fn field_label(field: &Field, index: usize) -> String {
    match &field.name {
        Some(name) => diagnostic_text(&format!("{:?} (index {index})", diagnostic_text(name))),
        None => format!("the field at index {index}"),
    }
}

/// Bound diagnostic amplification while preserving arbitrary source labels.
fn diagnostic_text(text: &str) -> String {
    const SUFFIX: &str = "... [truncated]";
    if text.len() <= MAX_DIAGNOSTIC_TEXT_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_DIAGNOSTIC_TEXT_BYTES - SUFFIX.len();
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{SUFFIX}", &text[..end])
}

/// Check depth and descriptor count before any recursive helper sees the tree.
/// The iterator stack grows only to the depth limit; wide child slices are
/// counted before traversal, without allocating one stack entry per field.
fn check_shape(root: &Structure) -> Option<ValidationError> {
    struct Pending<'a> {
        fields: &'a [Field],
        next: usize,
        depth: usize,
        path: String,
        element: bool,
    }
    let mut count = root.fields.len();
    if count > MAX_FIELD_COUNT {
        return Some(ValidationError {
            path: "root".to_owned(),
            kind: ValidationErrorKind::TooManyFields { count },
        });
    }
    let mut pending = vec![Pending {
        fields: &root.fields,
        next: 0,
        depth: 0,
        path: "root".to_owned(),
        element: false,
    }];
    while let Some(frame) = pending.last_mut() {
        let Some(field) = frame.fields.get(frame.next) else {
            pending.pop();
            continue;
        };
        let index = frame.next;
        frame.next += 1;
        if !matches!(field.kind, Kind::Struct { .. } | Kind::Array { .. }) {
            continue;
        }
        let field_path = if frame.element {
            frame.path.clone()
        } else {
            format!("{}.fields[{index}]", frame.path)
        };
        let (fields, path, element) = match &field.kind {
            Kind::Struct { structure } => (
                structure.fields.as_slice(),
                format!("{field_path}.kind.structure"),
                false,
            ),
            Kind::Array { element, .. } => (
                std::slice::from_ref(element.as_ref()),
                format!("{field_path}.kind.element"),
                true,
            ),
            _ => continue,
        };
        let depth = frame.depth + 1;
        let kind = if depth > MAX_NESTING_DEPTH {
            Some(ValidationErrorKind::NestingTooDeep { depth })
        } else {
            count = count.saturating_add(fields.len());
            (count > MAX_FIELD_COUNT).then_some(ValidationErrorKind::TooManyFields { count })
        };
        if let Some(kind) = kind {
            return Some(ValidationError {
                path: diagnostic_text(&path),
                kind,
            });
        }
        pending.push(Pending {
            fields,
            next: 0,
            depth,
            path,
            element,
        });
    }
    None
}

/// Validate a [`Format`] against the Step 2 semantic rules.
pub(crate) fn validate(format: &Format) -> ValidationReport {
    if let Some(error) = check_shape(&format.root) {
        return ValidationReport {
            errors: vec![error],
            truncated: true,
        };
    }
    let mut validator = Validator {
        format,
        errors: Vec::new(),
        truncated: false,
    };
    validator.validate_structure(&format.root, "root", &[], 0);
    validator.validate_enums();
    ValidationReport {
        errors: validator.errors,
        truncated: validator.truncated,
    }
}

struct Validator<'a> {
    format: &'a Format,
    errors: Vec<ValidationError>,
    truncated: bool,
}

impl<'a> Validator<'a> {
    fn push(&mut self, path: impl Into<String>, kind: ValidationErrorKind) {
        if self.stopped() {
            return;
        }
        self.errors.push(ValidationError {
            path: diagnostic_text(&path.into()),
            kind,
        });
    }

    /// Called only when work remains, so a full report is not labeled complete
    /// merely because subsequent checks were skipped.
    fn stopped(&mut self) -> bool {
        if self.errors.len() >= MAX_VALIDATION_ERRORS {
            self.truncated = true;
            true
        } else {
            false
        }
    }

    fn validate_enums(&mut self) {
        for (name, def) in &self.format.enums {
            if self.stopped() {
                return;
            }
            let path = format!("enums.{}", diagnostic_text(name));
            if let Some(width) = def.width {
                if !VALID_INT_WIDTHS.contains(&width) {
                    self.push(
                        path.clone(),
                        ValidationErrorKind::InvalidIntegerWidth { width },
                    );
                }
            }
            let mut seen = BTreeSet::new();
            for variant in &def.variants {
                if self.stopped() {
                    return;
                }
                if !seen.insert(variant.value) {
                    self.push(
                        path.clone(),
                        ValidationErrorKind::DuplicateEnumValue {
                            enum_name: diagnostic_text(name),
                            value: variant.value,
                        },
                    );
                }
            }
        }
    }

    fn validate_structure(
        &mut self,
        structure: &'a Structure,
        path: &str,
        ancestors: &[Frame<'a>],
        depth: usize,
    ) {
        if self.stopped() {
            return;
        }
        let scope = Rc::new(Scope::new(&structure.fields));
        self.check_duplicate_names(&scope, path);
        self.check_layout(structure, path);
        for (index, field) in structure.fields.iter().enumerate() {
            if self.stopped() {
                return;
            }
            let field_path = format!("{path}.fields[{index}]");
            self.validate_field(field, &field_path, ancestors, &scope, index, depth);
        }
    }

    fn check_duplicate_names(&mut self, scope: &Scope<'_>, path: &str) {
        for (index, field) in scope.fields.iter().enumerate() {
            if self.stopped() {
                return;
            }
            if let Some(name) = field.name.as_deref() {
                if scope.indices.get(name) != Some(&index) {
                    self.push(
                        format!("{path}.fields[{index}]"),
                        ValidationErrorKind::DuplicateFieldName {
                            name: diagnostic_text(name),
                        },
                    );
                }
            }
        }
    }

    fn check_layout(&mut self, structure: &Structure, path: &str) {
        if self.stopped() {
            return;
        }
        let mut cursor: Option<u64> = Some(0);
        let mut placed: Vec<(usize, u64, u64)> = Vec::new();
        for (index, field) in structure.fields.iter().enumerate() {
            let start = match &field.offset {
                Some(FieldOffset::Absolute { bytes }) => Some(*bytes),
                Some(FieldOffset::Derived { .. }) => None,
                None => cursor,
            };
            let len = fixed_len(field);
            let end = match (start, len) {
                (Some(start), Some(len)) => start.checked_add(len),
                _ => None,
            };
            if let (Some(start), Some(end)) = (start, end) {
                // Empty structs and zero-count arrays occupy no bytes.
                if start < end {
                    placed.push((index, start, end));
                }
                cursor = Some(end);
            } else {
                cursor = None;
            }
        }
        // Sweep by start position. Removing expired intervals costs O(log n),
        // and each active interval is a real overlap. Enumeration stops at the
        // diagnostic cap, giving O(n log n + MAX_VALIDATION_ERRORS) work rather
        // than a pairwise comparison for every valid wide structure.
        placed.sort_unstable_by_key(|&(index, start, end)| (start, end, index));
        let mut active = BTreeSet::new();
        for (index, start, end) in placed {
            while let Some(&(other_end, _)) = active.first() {
                if other_end > start {
                    break;
                }
                active.pop_first();
            }
            for &(_, other_index) in &active {
                if self.stopped() {
                    return;
                }
                let first = index.min(other_index);
                let second = index.max(other_index);
                self.push(
                    format!("{path}.fields[{second}]"),
                    ValidationErrorKind::OverlappingFields {
                        first: field_label(&structure.fields[first], first),
                        second: field_label(&structure.fields[second], second),
                        at: start,
                    },
                );
            }
            active.insert((end, index));
        }
    }

    fn validate_field(
        &mut self,
        field: &'a Field,
        path: &str,
        ancestors: &[Frame<'a>],
        current: &Rc<Scope<'a>>,
        index: usize,
        depth: usize,
    ) {
        if self.stopped() {
            return;
        }
        if !field.confidence.is_valid() {
            self.push(
                format!("{path}.confidence"),
                ValidationErrorKind::ConfidenceOutOfRange {
                    value: field.confidence.get(),
                },
            );
        }
        if let Some(support) = field.evidence.support {
            if support.agreeing > support.total {
                self.push(
                    format!("{path}.evidence.support"),
                    ValidationErrorKind::SampleSupportInconsistent {
                        agreeing: support.agreeing,
                        total: support.total,
                    },
                );
            }
        }

        self.validate_kind_and_size(field, path);

        if let Some(FieldOffset::Derived { offset_field }) = &field.offset {
            self.resolve_number(ancestors, current, index, offset_field.as_str(), path);
        }
        if let Some(SizeRule::Derived { length_field }) = &field.size {
            self.resolve_number(ancestors, current, index, length_field.as_str(), path);
        }

        self.validate_constraints(field, path, ancestors, current);

        match &field.kind {
            Kind::Struct { structure } => {
                let child = push_frame(ancestors, current, index);
                self.validate_structure(
                    structure,
                    &format!("{path}.kind.structure"),
                    &child,
                    depth + 1,
                );
            }
            Kind::Array { element, count } => {
                self.validate_count(count, ancestors, current, index, path);
                let child = push_frame(ancestors, current, index);
                let element_slice = std::slice::from_ref(element.as_ref());
                let element_scope = Rc::new(Scope::new(element_slice));
                self.validate_field(
                    element,
                    &format!("{path}.kind.element"),
                    &child,
                    &element_scope,
                    0,
                    depth + 1,
                );
            }
            Kind::Enum {
                enum_ref, width, ..
            } => match self.format.enums.get(enum_ref) {
                None => self.push(
                    format!("{path}.kind"),
                    ValidationErrorKind::DanglingEnumRef {
                        name: diagnostic_text(enum_ref),
                    },
                ),
                Some(def) => {
                    if let Some(enum_width) = def.width {
                        if enum_width != *width {
                            self.push(
                                format!("{path}.kind"),
                                ValidationErrorKind::EnumWidthMismatch {
                                    enum_name: diagnostic_text(enum_ref),
                                    field_width: *width,
                                    enum_width,
                                },
                            );
                        }
                    }
                }
            },
            Kind::Integer { .. } | Kind::Bytes | Kind::String { .. } | Kind::Opaque => {}
        }
    }

    fn validate_kind_and_size(&mut self, field: &Field, path: &str) {
        match &field.kind {
            Kind::Integer { width, .. } | Kind::Enum { width, .. } => {
                if !VALID_INT_WIDTHS.contains(width) {
                    self.push(
                        format!("{path}.kind"),
                        ValidationErrorKind::InvalidIntegerWidth { width: *width },
                    );
                }
                match &field.size {
                    None => {}
                    Some(SizeRule::Fixed { bytes }) if *bytes == u64::from(*width) => {}
                    Some(_) => self.push(
                        format!("{path}.size"),
                        ValidationErrorKind::SizeKindMismatch {
                            detail: "integer and enum fields take their size from their width; \
                                     omit the size rule or use a matching fixed size"
                                .to_owned(),
                        },
                    ),
                }
            }
            Kind::Bytes | Kind::Opaque | Kind::String { .. } => match &field.size {
                Some(rule) => self.validate_size_sanity(rule, path),
                None => self.push(
                    format!("{path}.size"),
                    ValidationErrorKind::SizeKindMismatch {
                        detail: "bytes, string, and opaque fields require a size rule".to_owned(),
                    },
                ),
            },
            Kind::Struct { .. } | Kind::Array { .. } => {
                if field.size.is_some() {
                    self.push(
                        format!("{path}.size"),
                        ValidationErrorKind::SizeKindMismatch {
                            detail: "structs and arrays size themselves from their contents; \
                                     omit the size rule"
                                .to_owned(),
                        },
                    );
                }
            }
        }
    }

    fn validate_size_sanity(&mut self, rule: &SizeRule, path: &str) {
        match rule {
            SizeRule::Fixed { bytes } => {
                if *bytes == 0 {
                    self.push(format!("{path}.size"), ValidationErrorKind::ZeroSizedField);
                } else if *bytes > MAX_FIXED_FIELD_BYTES {
                    self.push(
                        format!("{path}.size"),
                        ValidationErrorKind::InsaneFixedSize { bytes: *bytes },
                    );
                }
            }
            SizeRule::Delimited { terminator, .. } => {
                if terminator.is_empty() {
                    self.push(format!("{path}.size"), ValidationErrorKind::EmptyTerminator);
                }
            }
            SizeRule::Derived { .. } | SizeRule::ToEnd => {}
        }
    }

    fn validate_count(
        &mut self,
        count: &CountRule,
        ancestors: &[Frame<'a>],
        current: &Scope<'a>,
        index: usize,
        path: &str,
    ) {
        match count {
            CountRule::Fixed { count } => {
                if *count > MAX_ARRAY_COUNT {
                    self.push(
                        format!("{path}.kind.count"),
                        ValidationErrorKind::InsaneArrayCount { count: *count },
                    );
                }
            }
            CountRule::FromField { count_field } => {
                self.resolve_number(
                    ancestors,
                    current,
                    index,
                    count_field.as_str(),
                    &format!("{path}.kind.count"),
                );
            }
            CountRule::BoundedBy { length_field } => {
                self.resolve_number(
                    ancestors,
                    current,
                    index,
                    length_field.as_str(),
                    &format!("{path}.kind.count"),
                );
            }
            CountRule::ToEnd => {}
        }
    }

    fn validate_constraints(
        &mut self,
        field: &Field,
        path: &str,
        ancestors: &[Frame<'a>],
        current: &Scope<'a>,
    ) {
        for (index, constraint) in field.constraints.iter().enumerate() {
            if self.stopped() {
                return;
            }
            let cpath = format!("{path}.constraints[{index}]");
            match constraint {
                Constraint::Constant { value } => {
                    self.validate_constant(field, value.len(), &cpath)
                }
                Constraint::IntRange { min, max } => {
                    if min > max {
                        self.push(
                            cpath.clone(),
                            ValidationErrorKind::IntRangeInverted {
                                min: *min,
                                max: *max,
                            },
                        );
                    }
                    if !is_integer_like(&field.kind) {
                        self.push(
                            cpath,
                            ValidationErrorKind::ConstraintKindMismatch {
                                detail: "an integer range applies only to integer or enum fields"
                                    .to_owned(),
                            },
                        );
                    }
                }
                Constraint::Checksum { spec } => {
                    if !matches!(field.kind, Kind::Integer { .. } | Kind::Bytes) {
                        self.push(
                            cpath.clone(),
                            ValidationErrorKind::ConstraintKindMismatch {
                                detail: "a checksum value must be an integer or bytes field"
                                    .to_owned(),
                            },
                        );
                    }
                    let from_idx =
                        self.resolve_anchor(&spec.covered.from, ancestors, current, &cpath);
                    let to_idx = self.resolve_anchor(&spec.covered.to, ancestors, current, &cpath);
                    // When both anchors resolve within this structure, the range
                    // must run forward. A range that starts after it ends is not
                    // a real byte span.
                    if let (Some(from_idx), Some(to_idx)) = (from_idx, to_idx) {
                        if anchor_key(&spec.covered.from, from_idx)
                            > anchor_key(&spec.covered.to, to_idx)
                        {
                            self.push(
                                cpath,
                                ValidationErrorKind::InvertedChecksumRange {
                                    from: diagnostic_text(spec.covered.from.field().as_str()),
                                    to: diagnostic_text(spec.covered.to.field().as_str()),
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    fn validate_constant(&mut self, field: &Field, value_len: usize, path: &str) {
        let value_len = value_len as u64;
        match &field.kind {
            Kind::Integer { width, .. } | Kind::Enum { width, .. } => {
                if value_len != u64::from(*width) {
                    self.push(
                        path.to_owned(),
                        ValidationErrorKind::ConstantSizeMismatch {
                            expected: u64::from(*width),
                            actual: value_len,
                        },
                    );
                }
            }
            Kind::Bytes | Kind::Opaque | Kind::String { .. } => {
                if let Some(SizeRule::Fixed { bytes }) = &field.size {
                    if value_len != *bytes {
                        self.push(
                            path.to_owned(),
                            ValidationErrorKind::ConstantSizeMismatch {
                                expected: *bytes,
                                actual: value_len,
                            },
                        );
                    }
                }
            }
            Kind::Struct { .. } | Kind::Array { .. } => self.push(
                path.to_owned(),
                ValidationErrorKind::ConstraintKindMismatch {
                    detail: "a constant cannot constrain a struct or array field".to_owned(),
                },
            ),
        }
    }

    /// Resolve a length, count, or offset reference and require it to be an
    /// integer that is parsed before the dependent field.
    fn resolve_number(
        &mut self,
        ancestors: &[Frame<'a>],
        current: &Scope<'a>,
        bound: usize,
        name: &str,
        path: &str,
    ) {
        match resolve_field(ancestors, current, bound, name) {
            Some(target) => {
                if !is_integer_like(&target.kind) {
                    self.push(
                        path.to_owned(),
                        ValidationErrorKind::ReferenceNotInteger {
                            name: diagnostic_text(name),
                        },
                    );
                }
            }
            None => {
                let defined_later = current
                    .indices
                    .get(name)
                    .is_some_and(|index| *index >= bound);
                if defined_later {
                    self.push(
                        path.to_owned(),
                        ValidationErrorKind::ForwardReference {
                            name: diagnostic_text(name),
                        },
                    );
                } else {
                    self.push(
                        path.to_owned(),
                        ValidationErrorKind::DanglingFieldRef {
                            name: diagnostic_text(name),
                        },
                    );
                }
            }
        }
    }

    /// Resolve a checksum range anchor. Anchors may reference any field in
    /// scope. Returns the anchor field's index within the current structure
    /// when it resolves there, so the caller can check the range ordering;
    /// returns `None` when it resolves in an ancestor (where indices are not
    /// comparable) or, after pushing a dangling-reference error, when it does
    /// not resolve at all.
    fn resolve_anchor(
        &mut self,
        anchor: &RangeAnchor,
        ancestors: &[Frame<'a>],
        current: &Scope<'a>,
        path: &str,
    ) -> Option<usize> {
        let name = anchor.field().as_str();
        if resolve_field(ancestors, current, current.fields.len(), name).is_none() {
            self.push(
                path.to_owned(),
                ValidationErrorKind::DanglingFieldRef {
                    name: diagnostic_text(name),
                },
            );
            return None;
        }
        current.indices.get(name).copied()
    }
}

/// A comparable position for a checksum range anchor: the field index paired
/// with 0 for its start and 1 for its end.
fn anchor_key(anchor: &RangeAnchor, index: usize) -> (usize, u8) {
    match anchor {
        RangeAnchor::FieldStart { .. } => (index, 0),
        RangeAnchor::FieldEnd { .. } => (index, 1),
    }
}

fn push_frame<'a>(
    ancestors: &[Frame<'a>],
    current: &Rc<Scope<'a>>,
    visible: usize,
) -> Vec<Frame<'a>> {
    let mut child = ancestors.to_vec();
    child.push(Frame {
        scope: Rc::clone(current),
        visible,
    });
    child
}
