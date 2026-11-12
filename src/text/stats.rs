//! `wc` parity: bytes, characters, words, lines and longest line, counted in
//! one streaming pass over the raw bytes.
//!
//! Semantics follow GNU `wc` in a UTF-8 locale: `lines` counts `\n`; a word
//! is a run of non-whitespace (non-breaking spaces are not whitespace);
//! `chars` counts Unicode scalar values, including a BOM; `max_line_length`
//! is the display width of the widest line, with tabs advancing to the next
//! multiple of 8 and `\r` / `\f` ending a line.

use encoding_rs::{Decoder, Encoding};
use unicode_width::UnicodeWidthChar;

use crate::report::TextPhysical;

/// Streaming `wc`.
#[allow(clippy::struct_excessive_bools)] // independent scanner states, not options
pub struct WcCounter {
    decoder: Decoder,
    buf: String,
    bytes: u64,
    chars: u64,
    words: u64,
    lines: u64,
    blank_lines: u64,
    max_line: u64,
    line_width: u64,
    line_has_text: bool,
    in_word: bool,
    lf: u64,
    crlf: u64,
    cr: u64,
    prev_cr: bool,
    bom: bool,
    started: bool,
}

impl WcCounter {
    /// A counter for text in `encoding`.
    pub fn new(encoding: &'static Encoding) -> Self {
        Self {
            decoder: encoding.new_decoder_without_bom_handling(),
            buf: String::new(),
            bytes: 0,
            chars: 0,
            words: 0,
            lines: 0,
            blank_lines: 0,
            max_line: 0,
            line_width: 0,
            line_has_text: false,
            in_word: false,
            lf: 0,
            crlf: 0,
            cr: 0,
            prev_cr: false,
            bom: false,
            started: false,
        }
    }

    /// Count a chunk; `last` marks the end of the input.
    pub fn feed(&mut self, bytes: &[u8], last: bool) {
        if !self.started && !bytes.is_empty() {
            self.started = true;
            self.bom = Encoding::for_bom(bytes).is_some();
        }
        self.bytes += bytes.len() as u64;
        let mut input = bytes;
        loop {
            self.buf.clear();
            let room = (input.len() * 3 + 16).min(1 << 20);
            self.buf.reserve(room);
            let (result, read, _) = self.decoder.decode_to_string(input, &mut self.buf, last);
            input = &input[read..];
            let chunk = std::mem::take(&mut self.buf);
            self.count(&chunk);
            self.buf = chunk;
            if matches!(result, encoding_rs::CoderResult::InputEmpty) {
                break;
            }
        }
    }

    fn count(&mut self, text: &str) {
        for c in text.chars() {
            self.chars += 1;
            if self.prev_cr && c != '\n' {
                self.cr += 1;
            }
            match c {
                '\n' => {
                    self.lines += 1;
                    if self.prev_cr {
                        self.crlf += 1;
                    } else {
                        self.lf += 1;
                    }
                    if !self.line_has_text {
                        self.blank_lines += 1;
                    }
                    self.line_has_text = false;
                    self.end_display_line();
                }
                '\r' | '\x0c' => self.end_display_line(),
                '\t' => self.line_width += 8 - self.line_width % 8,
                _ => self.line_width += c.width().unwrap_or(0) as u64,
            }
            self.prev_cr = c == '\r';
            let space = is_wc_space(c);
            if !space {
                self.line_has_text = true;
                if !self.in_word {
                    self.words += 1;
                }
            }
            self.in_word = !space;
        }
    }

    fn end_display_line(&mut self) {
        self.max_line = self.max_line.max(self.line_width);
        self.line_width = 0;
    }

    /// The counts, as `physical.text`.
    pub fn finish(mut self) -> TextPhysical {
        if self.prev_cr {
            self.cr += 1;
        }
        self.end_display_line();
        let endings = [("lf", self.lf), ("crlf", self.crlf), ("cr", self.cr)];
        let used: Vec<&str> = endings.iter().filter(|(_, n)| *n > 0).map(|(k, _)| *k).collect();
        TextPhysical {
            bytes: Some(self.bytes),
            chars: Some(self.chars),
            words: Some(self.words),
            lines: Some(self.lines),
            max_line_length: Some(self.max_line),
            line_endings: match used.as_slice() {
                [] => None,
                [one] => Some((*one).to_string()),
                _ => Some("mixed".to_string()),
            },
            bom: Some(self.bom),
            blank_lines: Some(self.blank_lines),
        }
    }
}

/// Whitespace as glibc's `iswspace` sees it: Unicode whitespace except the
/// non-breaking spaces.
fn is_wc_space(c: char) -> bool {
    c.is_whitespace() && !matches!(c, '\u{a0}' | '\u{2007}' | '\u{202f}')
}

/// Count `bytes` in one go (for the tests).
#[cfg(test)]
pub fn count(bytes: &[u8]) -> TextPhysical {
    let (encoding, _) = super::decode::detect(bytes);
    let mut wc = WcCounter::new(encoding);
    wc.feed(bytes, true);
    wc.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_wc() {
        let t = count(b"hello world\nsecond  line here\n\nlast");
        assert_eq!(
            (t.bytes, t.chars, t.words, t.lines, t.max_line_length, t.blank_lines),
            (Some(35), Some(35), Some(6), Some(3), Some(17), Some(1))
        );
        assert_eq!(t.line_endings.as_deref(), Some("lf"));
        let t = count("a\tb\r\nnaïve café\r\n".as_bytes());
        assert_eq!((t.chars, t.words, t.lines, t.max_line_length), (Some(17), Some(4), Some(2), Some(10)));
        assert_eq!(t.line_endings.as_deref(), Some("crlf"));
        assert_eq!(count(b"a\rb\nc").line_endings.as_deref(), Some("mixed"));
        assert_eq!(count(b"x\r").line_endings.as_deref(), Some("cr"));
        // Wide characters count double for -L; non-breaking space joins words.
        let t = count("日本語\nno\u{a0}break".as_bytes());
        assert_eq!((t.max_line_length, t.words), (Some(8), Some(2)));
    }

    #[test]
    fn streaming_equals_one_shot() {
        let text = "Grüße aus Köln\r\n\tund 日本\n".repeat(50);
        let whole = count(text.as_bytes());
        let mut wc = WcCounter::new(encoding_rs::UTF_8);
        for chunk in text.as_bytes().chunks(7) {
            wc.feed(chunk, false);
        }
        wc.feed(&[], true);
        assert_eq!(wc.finish(), whole);
    }

    #[test]
    fn utf16_with_bom() {
        let mut b = vec![0xFF, 0xFE];
        for u in "hi there\n".encode_utf16() {
            b.extend_from_slice(&u.to_le_bytes());
        }
        let t = count(&b);
        assert_eq!((t.bytes, t.chars, t.words, t.lines, t.bom), (Some(20), Some(10), Some(2), Some(1), Some(true)));
    }
}
