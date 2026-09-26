//! Identifier and comment helpers shared by the exporters.
//!
//! Field names in the IR are free-form and may be absent, but every target
//! language needs a valid identifier for each field and type. These helpers turn
//! an optional, arbitrary name into a deterministic, syntactically valid
//! identifier, keep it clear of each target's reserved words (see
//! [`crate::reserved`]), and allocate unique type names so that two distinct
//! structures never collide. [`comment_text`] is the one sanitizer for IR text
//! that ends up inside a generated comment or doc string.

use std::collections::BTreeSet;

use crate::ExportFormat;
use crate::reserved::{self, KaitaiRole};

/// Neutralize IR-derived text for any generated comment or doc string.
///
/// Every exporter routes IR text (field names in checksum notes, the format
/// description) through this one function before placing it in a comment. The
/// Kaitai compiler copies `doc` text into `/** */` blocks (C++, Go, Java,
/// JavaScript, PHP, Rust), Nim `##[ ]##` blocks, Python docstrings, and `//`,
/// `///`, `#`, or `--` line comments, and the template exporters write `//`
/// comments, so the text must be inert in all of them at once.
///
/// Only ASCII letters, digits, space, and the punctuation
/// `_ . , : ; = + ( ) { } ! ? @ # % ^ | ~ -` are kept, and a hyphen never follows
/// another hyphen. Every other character becomes `_`: line breaks and every
/// other control, format, or non-ASCII character (including U+2028, U+2029, and
/// bidirectional overrides), backslashes (C line splicing, Java `\u` escapes,
/// Python string escapes), quotes and backticks (docstrings, templates), `/`
/// and `*` (C-style comment delimiters), square brackets (Lua long brackets,
/// Nim `]##`), angle brackets (`-->`, PHP `?>`, XML docs), `&`, and `$`. The
/// result can therefore contain none of `*/`, `/*`, `//`, `-->`, `--[[`, `]]`,
/// `"""`, or a newline, and it is unchanged by a second pass.
#[must_use]
pub(crate) fn comment_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        let keep = ch.is_ascii_alphanumeric()
            || matches!(
                ch,
                ' ' | '_'
                    | '.'
                    | ','
                    | ':'
                    | ';'
                    | '='
                    | '+'
                    | '('
                    | ')'
                    | '{'
                    | '}'
                    | '!'
                    | '?'
                    | '@'
                    | '#'
                    | '%'
                    | '^'
                    | '|'
                    | '~'
            )
            || (ch == '-' && !out.ends_with('-'));
        out.push(if keep { ch } else { '_' });
    }
    out
}

/// The Kaitai `seq` attribute id for a field name: [`snake`] plus the Kaitai
/// reserved-word suffix.
#[must_use]
pub(crate) fn kaitai_field_id(name: &str, fallback: &str) -> String {
    reserved::kaitai(snake(name, fallback), KaitaiRole::Field)
}

/// The Kaitai user type, enum, or root id for a name: [`snake`] plus the Kaitai
/// reserved-word suffix for the shared class namespace.
#[must_use]
pub(crate) fn kaitai_type_id(name: &str, fallback: &str) -> String {
    reserved::kaitai(snake(name, fallback), KaitaiRole::Type)
}

/// The Kaitai enum variant name for an IR variant name.
#[must_use]
pub(crate) fn kaitai_variant_id(name: &str) -> String {
    reserved::kaitai(snake(name, "value"), KaitaiRole::Variant)
}

/// The snake_case member or variable identifier an ImHex or 010 template emits
/// for `name`, clear of that language's keywords and built-in types. A reference
/// to a field must use this same function so it names the declared member.
#[must_use]
pub(crate) fn member_id(target: ExportFormat, name: &str, fallback: &str) -> String {
    reserved::member(target, snake(name, fallback))
}

/// The PascalCase type, enum, or enum constant identifier an ImHex or 010
/// template emits for `name`, clear of the target's global built-in names.
#[must_use]
pub(crate) fn type_id(target: ExportFormat, name: &str, fallback: &str) -> String {
    reserved::type_name(target, pascal(name, fallback))
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

    /// Sequences that end or open a comment, docstring, or string in at least
    /// one language the exporters or the Kaitai compiler generate.
    const TERMINATORS: &[&str] = &[
        "*/", "/*", "//", "-->", "<!--", "--[[", "]]", "]##", "##[", "#[", "]#", "\"\"\"", "'''",
        "`", "\\", "?>", "<?", "\n", "\r", "\u{2028}", "\u{2029}", "\u{85}", "\u{202e}",
        "\u{2066}", "\t", "\u{0}", "\u{1b}",
    ];

    #[test]
    fn comment_text_removes_every_comment_terminator() {
        for terminator in TERMINATORS {
            for text in [
                (*terminator).to_owned(),
                format!("a{terminator}b"),
                format!("{terminator}{terminator}"),
                format!("x {terminator} throw new Error('pwn'); {terminator} y"),
            ] {
                let clean = comment_text(&text);
                for forbidden in TERMINATORS {
                    assert!(!clean.contains(forbidden), "{text:?} -> {clean:?}");
                }
                assert!(!clean.contains("--"), "{text:?} -> {clean:?}");
                assert!(!clean.contains('\''), "{text:?} -> {clean:?}");
                assert!(!clean.contains('"'), "{text:?} -> {clean:?}");
                assert_eq!(comment_text(&clean), clean, "not idempotent");
            }
        }
    }

    #[test]
    fn comment_text_keeps_ordinary_names_readable() {
        assert_eq!(comment_text("chunk_type"), "chunk_type");
        assert_eq!(
            comment_text("Record count: 3 (max)"),
            "Record count: 3 (max)"
        );
        assert_eq!(comment_text("a-b--c"), "a-b-_c");
        assert_eq!(comment_text("while(1) {}"), "while(1) {}");
        assert_eq!(comment_text("p */ q"), "p __ q");
        assert_eq!(comment_text("gr\u{f6}\u{df}e"), "gr__e");
        // One replacement per character keeps the output length bounded.
        let hostile = "\u{1f600}\u{202e}\n*/".repeat(64);
        assert_eq!(comment_text(&hostile).len(), hostile.chars().count());
    }

    #[test]
    fn composed_identifiers_apply_each_target_policy() {
        assert_eq!(kaitai_field_id("Class", "field_0"), "class_x");
        assert_eq!(kaitai_field_id("", "field_0"), "field_0");
        assert_eq!(kaitai_type_id("f4", "type"), "f4_x");
        assert_eq!(kaitai_variant_id("def"), "def_x");
        assert_eq!(kaitai_variant_id(""), "value");
        assert_eq!(
            member_id(ExportFormat::ImHex, "Struct", "field_0"),
            "struct_"
        );
        assert_eq!(member_id(ExportFormat::Bt, "Struct", "field_0"), "struct_");
        assert_eq!(type_id(ExportFormat::Bt, "file size", "Inner"), "FileSize_");
        assert_eq!(
            type_id(ExportFormat::ImHex, "file size", "Inner"),
            "FileSize"
        );
    }
}
