//! Semantic validation of a [`Format`].
//!
//! Deserialization (FR-19) is purely structural: any well-formed JSON becomes a
//! [`Format`] so that round-tripping never loses information. This module adds
//! the semantic layer that the Step 2 acceptance criteria require: it rejects
//! dangling length, count, offset, and checksum references, overlapping fixed
//! fields, and sizes that are not sane, each with a clear, located error.
//!
//! Validation collects every problem it finds rather than stopping at the
//! first, so a malformed IR yields a complete report.

use std::fmt;

use crate::model::{
    Constraint, CountRule, Field, FieldOffset, Format, Kind, RangeAnchor, SizeRule, Structure,
};

/// The largest size, in bytes, a single fixed-size field may declare before it
/// is treated as insane. Larger values are almost certainly a misparse and
/// would invite unbounded allocation downstream (FR-24).
pub const MAX_FIXED_FIELD_BYTES: u64 = 1 << 32;

/// The largest element count a fixed-count array may declare before it is
/// treated as insane (FR-24).
pub const MAX_ARRAY_COUNT: u64 = 1 << 32;

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
        }
    }
}

/// The full result of validating a [`Format`]: every problem found.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationReport {
    /// All errors, in traversal order.
    pub errors: Vec<ValidationError>,
}

impl ValidationReport {
    /// Whether the format passed with no errors.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
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
        Ok(())
    }
}

impl std::error::Error for ValidationReport {}

/// A frame in the lexical scope chain: the fields of an enclosing structure and
/// how many of them are visible (parsed) at the point we descended.
#[derive(Debug, Clone, Copy)]
struct Frame<'a> {
    fields: &'a [Field],
    visible: usize,
}

/// Resolve a field name in lexical scope: the current structure up to `bound`,
/// then each ancestor up to the point we descended from it.
fn resolve_field<'a>(
    ancestors: &[Frame<'a>],
    current: &'a [Field],
    bound: usize,
    name: &str,
) -> Option<&'a Field> {
    if let Some(found) = current
        .iter()
        .take(bound)
        .find(|field| field.name.as_deref() == Some(name))
    {
        return Some(found);
    }
    for frame in ancestors.iter().rev() {
        if let Some(found) = frame
            .fields
            .iter()
            .take(frame.visible)
            .find(|field| field.name.as_deref() == Some(name))
        {
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
    let mut total: u64 = 0;
    for field in &structure.fields {
        if field.offset.is_some() {
            return None;
        }
        total = total.checked_add(fixed_len(field)?)?;
    }
    Some(total)
}

fn field_label(field: &Field, index: usize) -> String {
    match &field.name {
        Some(name) => format!("{name:?} (index {index})"),
        None => format!("the field at index {index}"),
    }
}

/// Validate a [`Format`] against the Step 2 semantic rules.
pub(crate) fn validate(format: &Format) -> ValidationReport {
    let mut validator = Validator {
        format,
        errors: Vec::new(),
    };
    validator.validate_structure(&format.root, "root", &[]);
    validator.validate_enums();
    ValidationReport {
        errors: validator.errors,
    }
}

struct Validator<'a> {
    format: &'a Format,
    errors: Vec<ValidationError>,
}

impl<'a> Validator<'a> {
    fn push(&mut self, path: impl Into<String>, kind: ValidationErrorKind) {
        self.errors.push(ValidationError {
            path: path.into(),
            kind,
        });
    }

    fn validate_enums(&mut self) {
        for (name, def) in &self.format.enums {
            let path = format!("enums.{name}");
            if let Some(width) = def.width {
                if !VALID_INT_WIDTHS.contains(&width) {
                    self.push(
                        path.clone(),
                        ValidationErrorKind::InvalidIntegerWidth { width },
                    );
                }
            }
            let mut seen: Vec<i128> = Vec::new();
            for variant in &def.variants {
                if seen.contains(&variant.value) {
                    self.push(
                        path.clone(),
                        ValidationErrorKind::DuplicateEnumValue {
                            enum_name: name.clone(),
                            value: variant.value,
                        },
                    );
                } else {
                    seen.push(variant.value);
                }
            }
        }
    }

    fn validate_structure(
        &mut self,
        structure: &'a Structure,
        path: &str,
        ancestors: &[Frame<'a>],
    ) {
        self.check_duplicate_names(structure, path);
        self.check_layout(structure, path);
        for (index, field) in structure.fields.iter().enumerate() {
            let field_path = format!("{path}.fields[{index}]");
            self.validate_field(field, &field_path, ancestors, &structure.fields, index);
        }
    }

    fn check_duplicate_names(&mut self, structure: &Structure, path: &str) {
        let mut seen: Vec<&str> = Vec::new();
        for (index, field) in structure.fields.iter().enumerate() {
            if let Some(name) = field.name.as_deref() {
                if seen.contains(&name) {
                    self.push(
                        format!("{path}.fields[{index}]"),
                        ValidationErrorKind::DuplicateFieldName {
                            name: name.to_owned(),
                        },
                    );
                } else {
                    seen.push(name);
                }
            }
        }
    }

    fn check_layout(&mut self, structure: &Structure, path: &str) {
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
                for (other_index, other_start, other_end) in &placed {
                    if start < *other_end && *other_start < end {
                        let at = start.max(*other_start);
                        self.push(
                            format!("{path}.fields[{index}]"),
                            ValidationErrorKind::OverlappingFields {
                                first: field_label(&structure.fields[*other_index], *other_index),
                                second: field_label(field, index),
                                at,
                            },
                        );
                    }
                }
                placed.push((index, start, end));
                cursor = Some(end);
            } else {
                cursor = None;
            }
        }
    }

    fn validate_field(
        &mut self,
        field: &'a Field,
        path: &str,
        ancestors: &[Frame<'a>],
        current: &'a [Field],
        index: usize,
    ) {
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
                self.validate_structure(structure, &format!("{path}.kind.structure"), &child);
            }
            Kind::Array { element, count } => {
                self.validate_count(count, ancestors, current, index, path);
                let child = push_frame(ancestors, current, index);
                let element_slice = std::slice::from_ref(element.as_ref());
                self.validate_field(
                    element,
                    &format!("{path}.kind.element"),
                    &child,
                    element_slice,
                    0,
                );
            }
            Kind::Enum { enum_ref, .. } => {
                if !self.format.enums.contains_key(enum_ref) {
                    self.push(
                        format!("{path}.kind"),
                        ValidationErrorKind::DanglingEnumRef {
                            name: enum_ref.clone(),
                        },
                    );
                }
            }
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
        current: &'a [Field],
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
        current: &'a [Field],
    ) {
        for (index, constraint) in field.constraints.iter().enumerate() {
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
                    self.resolve_anchor(&spec.covered.from, ancestors, current, &cpath);
                    self.resolve_anchor(&spec.covered.to, ancestors, current, &cpath);
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
        current: &'a [Field],
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
                            name: name.to_owned(),
                        },
                    );
                }
            }
            None => {
                let defined_later = current
                    .iter()
                    .skip(bound)
                    .any(|field| field.name.as_deref() == Some(name));
                if defined_later {
                    self.push(
                        path.to_owned(),
                        ValidationErrorKind::ForwardReference {
                            name: name.to_owned(),
                        },
                    );
                } else {
                    self.push(
                        path.to_owned(),
                        ValidationErrorKind::DanglingFieldRef {
                            name: name.to_owned(),
                        },
                    );
                }
            }
        }
    }

    /// Resolve a checksum range anchor. Anchors may reference any field in
    /// scope, with no ordering requirement.
    fn resolve_anchor(
        &mut self,
        anchor: &RangeAnchor,
        ancestors: &[Frame<'a>],
        current: &'a [Field],
        path: &str,
    ) {
        let name = anchor.field().as_str();
        if resolve_field(ancestors, current, current.len(), name).is_none() {
            self.push(
                path.to_owned(),
                ValidationErrorKind::DanglingFieldRef {
                    name: name.to_owned(),
                },
            );
        }
    }
}

fn push_frame<'a>(ancestors: &[Frame<'a>], current: &'a [Field], visible: usize) -> Vec<Frame<'a>> {
    let mut child = ancestors.to_vec();
    child.push(Frame {
        fields: current,
        visible,
    });
    child
}
