//! Identifier helpers shared by the exporters.
//!
//! Field names in the IR are free-form and may be absent, but every target
//! language needs a valid identifier for each field and type. These helpers turn
//! an optional, arbitrary name into a deterministic, syntactically valid
//! identifier and allocate unique type names so that two distinct structures
//! never collide.

use std::collections::BTreeSet;
use std::fmt::Write as _;

/// Keep arbitrary text on one physical source line inside a line comment.
pub(crate) fn comment_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{2028}' | '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", u32::from(ch));
            }
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// Turn an arbitrary name into a `snake_case` identifier valid in every target.
///
/// Lowercases, replaces any character that is not ASCII alphanumeric with an
/// underscore, collapses runs of underscores, trims leading and trailing
/// underscores, and prefixes a leading digit so the result always starts with a
/// letter. An empty or fully stripped name falls back to `fallback`.
#[must_use]
pub(crate) fn snake(name: &str, fallback: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_underscore = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            for lowered in ch.to_lowercase() {
                out.push(lowered);
            }
            last_underscore = false;
        } else if !last_underscore {
            out.push('_');
            last_underscore = true;
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        return fallback.to_owned();
    }
    if trimmed.starts_with(|c: char| c.is_ascii_digit()) {
        format!("n_{trimmed}")
    } else {
        trimmed.to_owned()
    }
}

/// Turn an arbitrary name into a `PascalCase` type identifier.
///
/// Used for the type names that ImHex and 010 templates need. Falls back to
/// `fallback` (which must already be a valid identifier) when the name has no
/// usable characters.
#[must_use]
pub(crate) fn pascal(name: &str, fallback: &str) -> String {
    let snake = snake(name, fallback);
    let mut out = String::with_capacity(snake.len());
    let mut upper_next = true;
    for ch in snake.chars() {
        if ch == '_' {
            upper_next = true;
        } else if upper_next {
            for upper in ch.to_uppercase() {
                out.push(upper);
            }
            upper_next = false;
        } else {
            out.push(ch);
        }
    }
    if out.is_empty() {
        fallback.to_owned()
    } else {
        out
    }
}

/// Allocates unique identifiers so generated type names never collide.
#[derive(Debug, Default)]
pub(crate) struct Allocator {
    used: BTreeSet<String>,
}

impl Allocator {
    /// Create an empty allocator.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Reserve `name`, appending a numeric suffix until it is unique.
    #[must_use]
    pub(crate) fn allocate(&mut self, name: &str) -> String {
        if self.used.insert(name.to_owned()) {
            return name.to_owned();
        }
        let mut counter = 2;
        loop {
            let candidate = format!("{name}_{counter}");
            if self.used.insert(candidate.clone()) {
                return candidate;
            }
            counter += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snake_sanitizes_and_falls_back() {
        assert_eq!(snake("Chunk Type", "field"), "chunk_type");
        assert_eq!(snake("123", "field"), "n_123");
        assert_eq!(snake("", "field_0"), "field_0");
        assert_eq!(snake("--__--", "field_0"), "field_0");
        assert_eq!(snake("CRC32", "field"), "crc32");
    }

    #[test]
    fn pascal_capitalizes_each_word() {
        assert_eq!(pascal("record", "Root"), "Record");
        assert_eq!(pascal("chunk_type", "Root"), "ChunkType");
        assert_eq!(pascal("", "Root"), "Root");
    }

    #[test]
    fn allocator_makes_names_unique() {
        let mut alloc = Allocator::new();
        assert_eq!(alloc.allocate("record"), "record");
        assert_eq!(alloc.allocate("record"), "record_2");
        assert_eq!(alloc.allocate("record"), "record_3");
    }
}
