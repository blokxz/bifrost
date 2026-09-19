//! Asking the terminal to copy text, with the OSC 52 escape sequence.
//!
//! The clipboard belongs to the terminal, not to Bifrost, so this works over
//! SSH and needs no library: the text travels to the terminal as part of the
//! output, base64-encoded. It is a *request*. Bifrost cannot tell whether it
//! worked: terminals that do not support the sequence ignore it, some ask the
//! user first or have it switched off, and tmux only forwards it when its
//! `set-clipboard` option allows. Whatever is copied is therefore always shown
//! on screen as well, and the wording says "copy requested", never "copied".
//!
//! Only writing is ever done. Bifrost never asks the terminal for the
//! clipboard's contents.

use std::io::{self, Write};

use crate::sanitize::has_unsafe_chars;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 (RFC 4648) with padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let group = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let index = |shift: u32| ALPHABET[((group >> shift) & 0x3f) as usize] as char;
        out.push(index(18));
        out.push(index(12));
        out.push(if chunk.len() > 1 { index(6) } else { '=' });
        out.push(if chunk.len() > 2 { index(0) } else { '=' });
    }
    out
}

/// The escape sequence that asks a terminal to put `text` on its clipboard.
///
/// Returns `None` for empty text and for text with control characters: what is
/// copied is a command to paste into a shell, and a line break or escape in it
/// could run something the user did not see.
pub fn osc52(text: &str) -> Option<String> {
    if text.is_empty() || has_unsafe_chars(text) {
        return None;
    }
    Some(format!("\x1b]52;c;{}\x07", base64_encode(text.as_bytes())))
}

/// Writes the request to `out` (the terminal). Text that must not be copied is
/// silently not sent; the caller still shows it on screen.
pub fn copy_to_terminal(out: &mut impl Write, text: &str) -> io::Result<()> {
    if let Some(sequence) = osc52(text) {
        out.write_all(sequence.as_bytes())?;
        out.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_4648_test_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes()), expected, "{input:?}");
        }
    }

    #[test]
    fn base64_handles_every_byte_value() {
        let all: Vec<u8> = (0..=255).collect();
        let encoded = base64_encode(&all);
        assert_eq!(encoded.len(), 344);
        assert!(
            encoded
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
        );
        assert!(encoded.starts_with("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"));
        assert!(
            encoded.ends_with("/w=="),
            "256 bytes leave one byte over: {encoded}"
        );
    }

    #[test]
    fn base64_handles_non_ascii_text() {
        assert_eq!(base64_encode("ñ".as_bytes()), "w7E=");
        assert_eq!(base64_encode("日本".as_bytes()), "5pel5pys");
    }

    #[test]
    fn the_sequence_frames_the_encoded_text_for_the_system_clipboard() {
        assert_eq!(
            osc52("ssh -- web").unwrap(),
            format!("\x1b]52;c;{}\x07", base64_encode(b"ssh -- web"))
        );
        assert_eq!(osc52("foobar").unwrap(), "\x1b]52;c;Zm9vYmFy\x07");
    }

    #[test]
    fn the_text_is_encoded_so_it_cannot_end_the_sequence_early() {
        // The payload is base64: the terminator (BEL) and ESC cannot appear in it.
        let sequence = osc52("a'b;c\"d $(x) `y` \\ &").unwrap();
        let payload = &sequence["\x1b]52;c;".len()..sequence.len() - 1];
        assert!(!payload.contains(['\x07', '\x1b', '\\']));
        assert!(sequence.ends_with('\x07'));
        assert_eq!(sequence.matches('\x07').count(), 1);
        assert_eq!(sequence.matches('\x1b').count(), 1);
    }

    #[test]
    fn text_with_control_characters_is_never_copied() {
        for bad in ["a\nb", "a\rb", "a\x1b[2Jb", "a\x07b", "a\u{202e}b", "a\0b"] {
            assert_eq!(osc52(bad), None, "{bad:?}");
        }
        assert_eq!(osc52(""), None);
    }

    #[test]
    fn copy_to_terminal_writes_the_sequence_and_nothing_for_refused_text() {
        let mut out = Vec::new();
        copy_to_terminal(&mut out, "foobar").unwrap();
        assert_eq!(out, b"\x1b]52;c;Zm9vYmFy\x07");

        let mut refused = Vec::new();
        copy_to_terminal(&mut refused, "bad\ntext").unwrap();
        assert!(refused.is_empty());
    }

    #[test]
    fn a_failing_terminal_is_an_error() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("closed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert!(copy_to_terminal(&mut Broken, "foobar").is_err());
    }
}
