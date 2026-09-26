//! Display-safe rendering of untrusted text.
//!
//! Sample file names, names read from a report or proposed by a model, and
//! decoded field text are all untrusted. Printed raw, a control character can
//! drive the terminal (an escape sequence can move the cursor, rewrite earlier
//! output, or set the window title), and a bidirectional control or an
//! invisible formatting character can make the displayed text differ from the
//! bytes it holds. Every place Sextant shows such text routes it through this
//! module, so the set of characters that is never shown raw is defined once.

use std::borrow::Cow;

/// Whether `c` must never reach a terminal or text view as itself.
///
/// This covers every control character (C0, DEL, and C1), the Unicode line and
/// paragraph separators, the bidirectional embedding, override, isolate, and
/// mark characters, zero-width and other invisible formatting characters, the
/// interlinear annotation controls, the byte order mark, the Hangul filler
/// characters that render as blank space, and the tag characters that can hide
/// text inside a string.
#[must_use]
pub fn is_unsafe_to_display(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            // Soft hyphen and Arabic letter mark.
            '\u{00AD}' | '\u{061C}'
                // Hangul fillers, which render as blank space.
                | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}'
                // Mongolian vowel separator.
                | '\u{180E}'
                // Zero-width space, joiners, and the left-to-right and
                // right-to-left marks.
                | '\u{200B}'..='\u{200F}'
                // Line and paragraph separators, then the bidirectional
                // embeddings and overrides.
                | '\u{2028}'..='\u{202E}'
                // Word joiner, invisible operators, bidirectional isolates, and
                // the deprecated format controls.
                | '\u{2060}'..='\u{206F}'
                // Byte order mark (zero-width no-break space).
                | '\u{FEFF}'
                // Interlinear annotation controls.
                | '\u{FFF9}'..='\u{FFFB}'
                // Tag characters.
                | '\u{E0000}'..='\u{E007F}'
        )
}

/// `text` with every character [`is_unsafe_to_display`] rejects replaced by a
/// visible Rust-style escape (`\n`, `\t`, `\u{1b}`, `\u{202e}`), borrowing
/// the input when nothing needs escaping. Every other character, including
/// ordinary non-ASCII text, is kept.
#[must_use]
pub fn escape_for_display(text: &str) -> Cow<'_, str> {
    if !text.chars().any(is_unsafe_to_display) {
        return Cow::Borrowed(text);
    }
    let mut escaped = String::with_capacity(text.len() + 16);
    for c in text.chars() {
        if is_unsafe_to_display(c) {
            escaped.extend(c.escape_default());
        } else {
            escaped.push(c);
        }
    }
    Cow::Owned(escaped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_international_text_is_borrowed_unchanged() {
        for text in [
            "sample_01.bin",
            "caf\u{e9}/\u{65e5}\u{672c}.dat",
            "a \"quoted\" \\ path",
        ] {
            assert!(matches!(escape_for_display(text), Cow::Borrowed(same) if same == text));
        }
    }

    #[test]
    fn terminal_controls_become_visible_escapes() {
        assert_eq!(
            escape_for_display("a\u{1b}[2Jb\r\nc\u{9b}d\u{7f}"),
            "a\\u{1b}[2Jb\\r\\nc\\u{9b}d\\u{7f}"
        );
    }

    #[test]
    fn bidirectional_and_invisible_characters_are_escaped() {
        for c in [
            '\u{202e}',
            '\u{2066}',
            '\u{2069}',
            '\u{200b}',
            '\u{200f}',
            '\u{2028}',
            '\u{feff}',
            '\u{00ad}',
            '\u{3164}',
            '\u{e0041}',
        ] {
            let text = format!("x{c}y");
            let escaped = escape_for_display(&text);
            assert!(!escaped.contains(c), "{c:?} survived: {escaped}");
            assert!(escaped.starts_with('x') && escaped.ends_with('y'));
        }
    }
}
