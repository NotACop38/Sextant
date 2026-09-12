//! Conservative preflight for layouts and resource use of generated source.

use crate::naming::{Allocator, pascal, snake};
use crate::{ExportError, ExportFormat};
use sextant_ir::{
    Constraint, CountRule, Field, FieldOffset, Format, Kind, SizeRule, StringEncoding, Structure,
};
use std::collections::{BTreeMap, BTreeSet};

const MAX_NODES: usize = 4096;
const MAX_TEXT_BYTES: usize = 256 * 1024;
const MAX_RENDER_COST: usize = 16 * 1024 * 1024;

pub(crate) fn check(format: &Format, target: ExportFormat) -> Result<(), ExportError> {
    let mut text = format
        .name
        .len()
        .saturating_add(format.metadata.description.as_ref().map_or(0, String::len));
    let mut nodes = 0usize;
    for (name, def) in &format.enums {
        nodes = nodes.saturating_add(def.variants.len()).saturating_add(1);
        if nodes > MAX_NODES {
            return Err(ExportError::Unsupported {
                format: target,
                detail: "too many enum nodes to export".into(),
            });
        }
        text = text.saturating_add(name.len());
        for variant in &def.variants {
            text = text
                .saturating_add(variant.name.len())
                .saturating_add(variant.description.as_ref().map_or(0, String::len));
        }
    }
    if text > MAX_TEXT_BYTES {
        return Err(ExportError::Unsupported {
            format: target,
            detail: "export metadata exceeds the source-data budget".into(),
        });
    }
    let mut check = Check {
        target,
        nodes,
        text,
        format_name_len: format.name.len(),
        paths: BTreeSet::new(),
        render_cost: 0,
        scopes: Vec::new(),
        enum_costs: format
            .enums
            .iter()
            .map(|(name, def)| {
                let cost = def.variants.iter().fold(0usize, |sum, variant| {
                    sum.saturating_add(variant.name.len()).saturating_add(64)
                });
                (name.clone(), cost.saturating_mul(8))
            })
            .collect(),
        enum_widths: format
            .enums
            .iter()
            .map(|(name, def)| (name.clone(), def.width.unwrap_or(4)))
            .collect(),
    };
    check.structure(&format.root, "")?;
    if check.nodes > MAX_NODES || check.text > MAX_TEXT_BYTES {
        return Err(check.error("export source-data budget exceeded"));
    }
    check_type_names(format, target)?;
    Ok(())
}

struct Check<'a> {
    target: ExportFormat,
    nodes: usize,
    text: usize,
    format_name_len: usize,
    paths: BTreeSet<String>,
    enum_widths: BTreeMap<String, u8>,
    enum_costs: BTreeMap<String, usize>,
    render_cost: usize,
    scopes: Vec<Scope<'a>>,
}

struct Scope<'a> {
    names: BTreeSet<&'a str>,
    parsed: BTreeSet<&'a str>,
    enum_names: BTreeSet<&'a str>,
    synthetic: bool,
}

impl<'a> Check<'a> {
    fn error(&self, detail: impl Into<String>) -> ExportError {
        ExportError::Unsupported {
            format: self.target,
            detail: detail.into(),
        }
    }

    fn structure(&mut self, structure: &'a Structure, prefix: &str) -> Result<(), ExportError> {
        if structure.fields.len() > MAX_NODES {
            return Err(self.error("too many fields to export"));
        }
        let names: BTreeSet<&str> = structure
            .fields
            .iter()
            .filter_map(|field| field.name.as_deref())
            .collect();
        self.scopes.push(Scope {
            names,
            parsed: BTreeSet::new(),
            enum_names: structure
                .fields
                .iter()
                .filter(|field| matches!(field.kind, Kind::Enum { .. }))
                .filter_map(|field| field.name.as_deref())
                .collect(),
            synthetic: false,
        });
        let mut ids = BTreeSet::new();
        for (index, field) in structure.fields.iter().enumerate() {
            if field
                .name
                .as_ref()
                .is_some_and(|name| name.len() > MAX_TEXT_BYTES)
            {
                return Err(self.error("field name exceeds the source-data budget"));
            }
            let id = field.name.as_deref().map_or_else(
                || format!("field_{index}"),
                |name| snake(name, &format!("field_{index}")),
            );
            if !ids.insert(id.clone()) && self.target != ExportFormat::Kaitai {
                return Err(self.error("field names collide after identifier sanitization"));
            }
            let path = if prefix.is_empty() {
                id
            } else {
                format!("{prefix}_{id}")
            };
            if self.target == ExportFormat::Wireshark && !self.paths.insert(path.clone()) {
                return Err(self.error("nested field paths collide in generated Lua identifiers"));
            }
            self.field(field, &path)?;
            if let Some(name) = field.name.as_deref() {
                self.scopes.last_mut().unwrap().parsed.insert(name);
            }
        }
        self.scopes.pop();
        Ok(())
    }

    fn field(&mut self, field: &'a Field, path: &str) -> Result<(), ExportError> {
        self.nodes = self
            .nodes
            .saturating_add(1)
            .saturating_add(field.constraints.len())
            .saturating_add(field.evidence.notes.len());
        if self.nodes > MAX_NODES {
            return Err(self.error("too many field or annotation nodes to export"));
        }
        // Names of enclosing fields are repeated in descendant Lua paths, and
        // enum value tables are repeated at each use. Bound those amplification
        // factors before collecting output, independently of input text size.
        self.render_cost = self.render_cost.saturating_add(2048).saturating_add(
            path.len()
                .saturating_add(self.format_name_len)
                .saturating_mul(32),
        );
        if let Kind::Enum { enum_ref, .. } = &field.kind {
            self.render_cost = self
                .render_cost
                .saturating_add(self.enum_costs.get(enum_ref).copied().unwrap_or(0));
        }
        if self.render_cost > MAX_RENDER_COST {
            return Err(self.error("generated source expansion exceeds the 16 MiB render budget"));
        }
        self.text = self
            .text
            .saturating_add(field.name.as_ref().map_or(0, String::len));
        self.text = self
            .text
            .saturating_add(field.evidence.detector.as_ref().map_or(0, String::len))
            .saturating_add(
                field
                    .evidence
                    .model_rationale
                    .as_ref()
                    .map_or(0, String::len),
            );
        for note in &field.evidence.notes {
            self.text = self.text.saturating_add(note.len());
        }
        for constraint in &field.constraints {
            match constraint {
                Constraint::Constant { value } => self.text = self.text.saturating_add(value.len()),
                Constraint::Checksum { spec } => {
                    self.text = self
                        .text
                        .saturating_add(spec.covered.from.field().as_str().len());
                    self.text = self
                        .text
                        .saturating_add(spec.covered.to.field().as_str().len());
                }
                _ => {}
            }
        }
        if self.nodes > MAX_NODES || self.text > MAX_TEXT_BYTES {
            return Err(self.error("export exceeds the 4096-node or 256 KiB source-data budget"));
        }
        if field.offset.is_some() && self.target != ExportFormat::Wireshark {
            return Err(self.error("this target cannot faithfully preserve explicit field offsets"));
        }
        if let Some(FieldOffset::Derived { offset_field }) = &field.offset {
            self.reference(offset_field.as_str())?;
        }
        if let Some(SizeRule::Delimited { terminator, .. }) = &field.size {
            self.text = self.text.saturating_add(terminator.len());
            match self.target {
                ExportFormat::ImHex | ExportFormat::Bt => {
                    return Err(
                        self.error("delimited fields are unsupported by this template exporter")
                    );
                }
                ExportFormat::Kaitai if terminator.len() != 1 => {
                    return Err(self.error("Kaitai export requires a one-byte terminator"));
                }
                _ => {}
            }
        }
        if let Some(SizeRule::Derived { length_field }) = &field.size {
            self.reference(length_field.as_str())?;
        }
        if self.target == ExportFormat::Kaitai
            && matches!(field.kind, Kind::Bytes | Kind::Opaque | Kind::String { .. })
            && !matches!(field.size, Some(SizeRule::Fixed { .. }))
            && field
                .constraints
                .iter()
                .any(|c| matches!(c, Constraint::Constant { .. }))
        {
            return Err(
                self.error("a variable-size constant cannot be replaced with Kaitai contents")
            );
        }
        if self.target != ExportFormat::Kaitai
            && matches!(
                field.kind,
                Kind::String {
                    encoding: StringEncoding::Utf16Le | StringEncoding::Utf16Be
                }
            )
        {
            return Err(self.error(
                "UTF-16 fields do not preserve all byte lengths and encodings in this target",
            ));
        }
        match &field.kind {
            Kind::Enum {
                enum_ref, width, ..
            } if matches!(self.target, ExportFormat::ImHex | ExportFormat::Bt)
                && self.enum_widths.get(enum_ref) != Some(width) =>
            {
                return Err(
                    self.error("enum definition width does not match the generated template field")
                );
            }
            Kind::Struct { structure } => self.structure(structure, path)?,
            Kind::Array { element, count } => {
                if matches!(self.target, ExportFormat::ImHex | ExportFormat::Bt)
                    && matches!(count, CountRule::BoundedBy { .. })
                {
                    return Err(
                        self.error("byte-bounded arrays are unsupported by this template exporter")
                    );
                }
                match count {
                    CountRule::FromField { count_field } => self.reference(count_field.as_str())?,
                    CountRule::BoundedBy { length_field } => {
                        self.reference(length_field.as_str())?
                    }
                    _ => {}
                }
                if self.target != ExportFormat::Wireshark && minimum_size(element) == 0 {
                    return Err(self.error(
                        "repeated elements must have a provably positive minimum byte size",
                    ));
                }
                // Some targets wrap element descriptors in a single-field
                // type. Its unparsed name must not hide an ancestor reference.
                self.scopes.push(Scope {
                    names: element.name.as_deref().into_iter().collect(),
                    parsed: BTreeSet::new(),
                    enum_names: BTreeSet::new(),
                    synthetic: true,
                });
                self.field(element, path)?;
                self.scopes.pop();
            }
            _ => {}
        }
        if self.text > MAX_TEXT_BYTES {
            return Err(self.error("export source-data budget exceeded"));
        }
        Ok(())
    }

    fn reference(&mut self, name: &str) -> Result<(), ExportError> {
        self.text = self.text.saturating_add(name.len());
        if self.target != ExportFormat::Kaitai && snake(name, "").is_empty() {
            return Err(self.error("field dependency has no stable identifier after sanitization"));
        }
        // Renderers resolve against all declared names, whereas execution only
        // sees fields already parsed. Reject a future declaration that would
        // hide the earlier ancestor used by the native executor.
        for scope in self.scopes.iter().rev() {
            if scope.names.contains(name) {
                if !scope.parsed.contains(name) {
                    return Err(
                        self.error("field dependency is shadowed by a not-yet-parsed local field")
                    );
                }
                if self.target == ExportFormat::Kaitai && scope.enum_names.contains(name) {
                    return Err(
                        self.error("Kaitai numeric dependencies on enum fields are unsupported")
                    );
                }
                break;
            }
        }
        if matches!(
            self.target,
            ExportFormat::ImHex | ExportFormat::Bt | ExportFormat::Wireshark
        ) && !self
            .scopes
            .iter()
            .rev()
            .find(|scope| !scope.synthetic)
            .is_some_and(|scope| scope.parsed.contains(name))
        {
            return Err(self.error("ancestor field dependencies are unsupported by this target"));
        }
        Ok(())
    }
}

/// Follow the type allocator used by each renderer so enum names cannot hide
/// root, nested, or synthetic wrapper types, including allocated suffixes.
fn check_type_names(format: &Format, target: ExportFormat) -> Result<(), ExportError> {
    if target == ExportFormat::Wireshark {
        return Ok(());
    }
    let error = || ExportError::Unsupported {
        format: target,
        detail: "enum or type identifiers collide after sanitization".into(),
    };
    let mut reserved = BTreeSet::new();
    let mut global_variants = BTreeSet::new();
    for (name, def) in &format.enums {
        let id = match target {
            ExportFormat::Kaitai => pascal(&snake(name, "values"), "Values"),
            _ => pascal(name, "Enum"),
        };
        if !reserved.insert(id) {
            return Err(error());
        }
        let mut variants = BTreeSet::new();
        for variant in &def.variants {
            let id = match target {
                ExportFormat::Kaitai => snake(&variant.name, "value"),
                _ => pascal(&variant.name, "VALUE"),
            };
            if !variants.insert(id.clone())
                || (target == ExportFormat::Bt && !global_variants.insert(id))
            {
                return Err(error());
            }
        }
    }
    for id in global_variants {
        if !reserved.insert(id) {
            return Err(error());
        }
    }
    let mut names = TypeNames {
        target,
        reserved,
        alloc: Allocator::new(),
        generated: BTreeSet::new(),
    };
    match target {
        ExportFormat::Kaitai => names.reserve(&format.name, "format")?,
        ExportFormat::ImHex => names.reserve(&format.name, "Format")?,
        _ => {}
    }
    names.structure(&format.root)
}

struct TypeNames {
    target: ExportFormat,
    reserved: BTreeSet<String>,
    alloc: Allocator,
    generated: BTreeSet<String>,
}

impl TypeNames {
    fn reserve(&mut self, name: &str, fallback: &str) -> Result<(), ExportError> {
        let base = if self.target == ExportFormat::Kaitai {
            snake(name, fallback)
        } else {
            pascal(name, fallback)
        };
        let id = self.alloc.allocate(&base);
        // Kaitai types and enums share the generated class namespace.
        let key = if self.target == ExportFormat::Kaitai {
            pascal(&id, "Type")
        } else {
            id
        };
        if self.reserved.contains(&key) || !self.generated.insert(key) {
            return Err(ExportError::Unsupported {
                format: self.target,
                detail: "enum or type identifiers collide after sanitization".into(),
            });
        }
        Ok(())
    }

    fn structure(&mut self, structure: &Structure) -> Result<(), ExportError> {
        for field in &structure.fields {
            self.field(field, false)?;
        }
        Ok(())
    }

    fn field(&mut self, field: &Field, element: bool) -> Result<(), ExportError> {
        let kaitai = self.target == ExportFormat::Kaitai;
        if element {
            if kaitai && matches!(field.kind, Kind::Array { .. }) {
                self.reserve(field.name.as_deref().unwrap_or("inner"), "inner")?;
            } else if !kaitai && !matches!(field.kind, Kind::Integer { .. } | Kind::Enum { .. }) {
                self.reserve(field.name.as_deref().unwrap_or("Element"), "Element")?;
            }
        }
        match &field.kind {
            Kind::Struct { structure } => {
                if kaitai || !element {
                    let fallback = if kaitai { "type" } else { "Inner" };
                    self.reserve(field.name.as_deref().unwrap_or(fallback), fallback)?;
                }
                self.structure(structure)?;
            }
            Kind::Array { element, count } => {
                if kaitai && matches!(count, CountRule::BoundedBy { .. }) {
                    self.reserve("bounded_array", "bounded_array")?;
                }
                self.field(element, true)?;
            }
            _ => {}
        }
        Ok(())
    }
}

fn minimum_size(field: &Field) -> u64 {
    match &field.kind {
        Kind::Integer { width, .. } | Kind::Enum { width, .. } => u64::from(*width),
        Kind::Bytes | Kind::Opaque | Kind::String { .. } => match &field.size {
            Some(SizeRule::Fixed { bytes }) => *bytes,
            Some(SizeRule::Delimited { terminator, .. }) => terminator.len() as u64,
            _ => 0,
        },
        Kind::Struct { structure } => structure
            .fields
            .iter()
            .fold(0u64, |size, field| size.saturating_add(minimum_size(field))),
        Kind::Array {
            element,
            count: CountRule::Fixed { count },
        } => minimum_size(element).saturating_mul(*count),
        Kind::Array { .. } => 0,
    }
}
