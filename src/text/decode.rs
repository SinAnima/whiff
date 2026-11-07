//! Bytes → text: BOM, UTF-8 validation, legacy-encoding guess.

use encoding_rs::{Encoding, UTF_8};

/// Decoded text and how it was decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// The text, with any byte-order mark removed.
    pub text: String,
    /// Lowercase encoding name (`utf-8`, `us-ascii`, `utf-16le`, `windows-1252`, …).
    pub encoding: String,
    /// A byte-order mark was present.
    pub bom: bool,
    /// Some bytes were invalid and replaced with U+FFFD.
    pub lossy: bool,
}

/// Decode `bytes`: a BOM wins, then valid UTF-8, then `chardetng`'s guess.
pub fn decode(bytes: &[u8]) -> Decoded {
    let (encoding, bom_len) = detect(bytes);
    let body = &bytes[bom_len..];
    let (text, lossy) = encoding.decode_without_bom_handling(body);
    let name = if encoding == UTF_8 && bom_len == 0 && body.is_ascii() {
        "us-ascii".to_string()
    } else {
        encoding.name().to_ascii_lowercase()
    };
    Decoded { text: text.into_owned(), encoding: name, bom: bom_len > 0, lossy }
}

/// The encoding of `bytes` and the length of its BOM.
pub fn detect(bytes: &[u8]) -> (&'static Encoding, usize) {
    if let Some((enc, len)) = Encoding::for_bom(bytes) {
        return (enc, len);
    }
    match std::str::from_utf8(bytes) {
        Ok(_) => (UTF_8, 0),
        // A character cut at the very end (a partial read) is still UTF-8.
        Err(e) if e.error_len().is_none() => (UTF_8, 0),
        Err(_) => (guess_legacy(bytes), 0),
    }
}

/// `chardetng`'s guess for non-UTF-8 text.
///
/// The text sniffers each look at the same head of every file, so the last
/// guess is kept per thread, keyed by a hash of the input: hashing costs a
/// small fraction of the guess.
pub fn guess_legacy(bytes: &[u8]) -> &'static Encoding {
    use std::hash::{Hash, Hasher};
    thread_local! {
        static LAST: std::cell::Cell<Option<(u64, &'static Encoding)>> = const { std::cell::Cell::new(None) };
    }
    let bytes = &bytes[..bytes.len().min(256 * 1024)];
    let mut h = std::hash::DefaultHasher::new();
    bytes.hash(&mut h);
    let key = h.finish();
    if let Some((k, enc)) = LAST.get()
        && k == key
    {
        return enc;
    }
    let mut det = chardetng::EncodingDetector::new(chardetng::Iso2022JpDetection::Deny);
    det.feed(bytes, true);
    let enc = det.guess(None, chardetng::Utf8Detection::Allow);
    LAST.set(Some((key, enc)));
    enc
}

/// The upper half of code page 437, sixteen to a row.
const CP437_HIGH: [&str; 8] = [
    "ÇüéâäàåçêëèïîìÄÅ",
    "ÉæÆôöòûùÿÖÜ¢£¥₧ƒ",
    "áíóúñÑªº¿⌐¬½¼¡«»",
    "░▒▓│┤╡╢╖╕╣║╗╝╜╛┐",
    "└┴┬├─┼╞╟╚╔╩╦╠═╬╧",
    "╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀",
    "αßΓπΣσµτΦΘΩδ∞φε∩",
    "≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ",
];

/// Text in code page 437 (IBM PC: DOS file names, NFO and ANSI art).
pub fn cp437(raw: &[u8]) -> String {
    raw.iter()
        .map(|&b| {
            if b < 0x80 {
                char::from(b)
            } else {
                CP437_HIGH[usize::from(b - 0x80) / 16].chars().nth(usize::from(b % 16)).unwrap_or('?')
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_common_encodings() {
        let d = decode(b"plain");
        assert_eq!((d.text.as_str(), d.encoding.as_str(), d.bom), ("plain", "us-ascii", false));
        let d = decode("\u{feff}héllo".as_bytes());
        assert_eq!((d.text.as_str(), d.encoding.as_str(), d.bom), ("héllo", "utf-8", true));
        let d = decode(&[0xFF, 0xFE, b'h', 0, b'i', 0]);
        assert_eq!((d.text.as_str(), d.encoding.as_str()), ("hi", "utf-16le"));
        let d = decode(b"caf\xe9 cr\xe8me br\xfbl\xe9e, d\xe9j\xe0 vu");
        assert_eq!(d.encoding, "windows-1252");
        assert_eq!(d.text, "café crème brûlée, déjà vu");
        assert!(!d.lossy);
    }
}
