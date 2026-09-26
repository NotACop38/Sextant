//! Make externally supplied text safe to put in an error message.
//!
//! Provider error bodies, stop reasons, and setting values end up in messages
//! that a terminal prints. They can be long, can contain terminal escape
//! sequences or bidirectional-override characters that disguise output, and a
//! misbehaving endpoint or proxy can echo the request's API key back. Every
//! such string passes through here first.

/// The most bytes of external text an error message keeps.
pub(crate) const MAX_MESSAGE_BYTES: usize = 300;

/// The marker that replaces a redacted secret.
const REDACTED: &str = "[redacted]";

/// Redact every occurrence of `secret`, replace control and bidirectional
/// formatting characters and runs of whitespace with single spaces, and
/// truncate to [`MAX_MESSAGE_BYTES`] on a character boundary, marking a cut
/// with `...`.
pub(crate) fn message(text: &str, secret: Option<&str>) -> String {
    let secret = secret.map(str::trim).filter(|secret| !secret.is_empty());
    let redacted = match secret {
        Some(secret) => text.replace(secret, REDACTED),
        None => text.to_owned(),
    };
    let cleaned = clean(&redacted);
    // Cleaning only removes or replaces characters, but run redaction once more
    // in case collapsing whitespace joined the pieces of a secret.
    match secret {
        Some(secret) if cleaned.contains(secret) => clean(&cleaned.replace(secret, REDACTED)),
        _ => cleaned,
    }
}

/// [`message`] without a secret to redact, for values such as a setting the
/// user typed.
pub(crate) fn for_display(text: &str) -> String {
    message(text, None)
}

/// Collapse unsafe characters and whitespace, then truncate.
fn clean(text: &str) -> String {
    let mut cleaned = String::with_capacity(text.len().min(MAX_MESSAGE_BYTES + 3));
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() || ch.is_control() || is_bidi_control(ch) {
            pending_space = !cleaned.is_empty();
            continue;
        }
        let space = usize::from(pending_space);
        if cleaned.len() + space + ch.len_utf8() > MAX_MESSAGE_BYTES {
            cleaned.push_str("...");
            return cleaned;
        }
        if pending_space {
            cleaned.push(' ');
            pending_space = false;
        }
        cleaned.push(ch);
    }
    cleaned
}

/// Unicode bidirectional formatting characters, which can reorder how a
/// terminal displays the surrounding text.
fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_and_escape_sequences_are_neutralized() {
        let shown = message("bad\u{1b}[31m red\r\nnext\u{7}\u{202e}line", None);
        assert!(!shown.chars().any(char::is_control), "{shown:?}");
        assert!(!shown.contains('\u{202e}'));
        assert_eq!(shown, "bad [31m red next line");
    }

    #[test]
    fn the_secret_is_redacted_everywhere() {
        let key = "sk-ant-api03-secret-value";
        let shown = message(&format!("invalid key {key}; you sent {key}"), Some(key));
        assert!(!shown.contains(key));
        assert_eq!(shown.matches(REDACTED).count(), 2);
    }

    #[test]
    fn long_text_is_truncated_on_a_character_boundary() {
        let long = "\u{e9}".repeat(1000);
        let shown = message(&long, None);
        assert!(shown.len() <= MAX_MESSAGE_BYTES + 3);
        assert!(shown.ends_with("..."));
        // A secret near the cut is redacted before truncation, so no prefix of
        // it survives.
        let key = "sk-0123456789abcdef";
        let text = format!("{}{key}", "x".repeat(MAX_MESSAGE_BYTES - 5));
        assert!(!message(&text, Some(key)).contains("sk-01"));
    }
}
