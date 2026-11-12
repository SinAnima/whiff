//! Property lists (XML, binary `bplist00` and old-style ASCII) through the
//! `plist` crate, after a bounded pass over its event stream: a binary
//! plist may reference one object from many places, so a few hundred bytes
//! can expand to billions of values, and the crate guards against cycles
//! but not against that. The pass also caps the nesting depth, since a
//! deeply nested value is dropped recursively.

use std::io::Cursor;

use plist::Value;
use serde_json::{Map, Value as Json, json};

/// Values (events) a plist may expand to.
const MAX_EVENTS: usize = 2_000_000;
/// Nesting accepted.
const MAX_DEPTH: usize = 128;

/// How a plist is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// `<plist>` XML.
    Xml,
    /// `bplist00`.
    Binary,
    /// Old-style (`OpenStep`) text: `{ key = value; }`.
    Ascii,
}

impl Encoding {
    /// `xml`, `binary` or `ascii`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Xml => "xml",
            Self::Binary => "binary",
            Self::Ascii => "ascii",
        }
    }
}

/// UTF-16 text (with its byte-order mark) as UTF-8; `None` for other input.
fn from_utf16(data: &[u8]) -> Option<Vec<u8>> {
    let big = match data.get(..2)? {
        [0xff, 0xfe] => false,
        [0xfe, 0xff] => true,
        _ => return None,
    };
    let units =
        data[2..].as_chunks::<2>().0.iter().map(|c| if big { u16::from_be_bytes(*c) } else { u16::from_le_bytes(*c) });
    Some(char::decode_utf16(units).map(|c| c.unwrap_or('\u{fffd}')).collect::<String>().into_bytes())
}

/// The encoding a plist's first bytes announce (`None`: not a plist).
pub fn encoding(head: &[u8]) -> Option<Encoding> {
    if head.starts_with(b"bplist00") {
        return Some(Encoding::Binary);
    }
    if let Some(utf8) = from_utf16(&head[..head.len().min(4096) & !1]) {
        return encoding(&utf8);
    }
    let head = head.strip_prefix(b"\xef\xbb\xbf").unwrap_or(head);
    let text = &head[..head.len().min(1024)];
    let start = text.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(text.len());
    let text = &text[start..];
    let has = |needle: &[u8]| text.windows(needle.len()).any(|w| w == needle);
    if text.starts_with(b"<plist") || (text.starts_with(b"<?xml") && (has(b"<!DOCTYPE plist") || has(b"<plist"))) {
        return Some(Encoding::Xml);
    }
    if text.starts_with(b"// !$*UTF8*$!")
        || after_comments(text).is_some_and(|t| t.starts_with(b"{") || t.starts_with(b"("))
    {
        return Some(Encoding::Ascii);
    }
    None
}

/// `text` after leading `//` and `/* */` comments (`None` if one is unclosed).
fn after_comments(mut text: &[u8]) -> Option<&[u8]> {
    loop {
        text = text.trim_ascii_start();
        if let Some(rest) = text.strip_prefix(b"//") {
            text = &rest[rest.iter().position(|&c| c == b'\n')?..];
        } else if let Some(rest) = text.strip_prefix(b"/*") {
            text = &rest[rest.windows(2).position(|w| w == b"*/")? + 2..];
        } else {
            return Some(text);
        }
    }
}

thread_local! {
    /// Events seen and current depth of the bounded pass.
    static PASS: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

/// A value that only counts: the bounded first pass. Refuses past the
/// event or depth limits, before the visitor recursion gets deep.
struct Counted;

impl Counted {
    fn tick<E: serde::de::Error>(nested: isize) -> Result<(), E> {
        PASS.with(|p| {
            let (n, d) = p.get();
            let d = d.saturating_add_signed(nested);
            p.set((n + 1, d));
            if n >= MAX_EVENTS || d > MAX_DEPTH { Err(E::custom("plist beyond limits")) } else { Ok(()) }
        })
    }
}

impl<'de> serde::Deserialize<'de> for Counted {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(Counted)
    }
}

impl<'de> serde::de::Visitor<'de> for Counted {
    type Value = Counted;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a plist value")
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Counted, A::Error> {
        Self::tick(1)?;
        while seq.next_element::<Counted>()?.is_some() {}
        Self::tick(-1)?;
        Ok(Counted)
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Counted, A::Error> {
        Self::tick(1)?;
        while map.next_entry::<Counted, Counted>()?.is_some() {}
        Self::tick(-1)?;
        Ok(Counted)
    }

    fn visit_enum<A: serde::de::EnumAccess<'de>>(self, data: A) -> Result<Counted, A::Error> {
        use serde::de::VariantAccess;
        Self::tick(0)?;
        let (Counted, v) = data.variant::<Counted>()?;
        v.newtype_variant::<Counted>()
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Counted, E> {
        Self::tick(0).map(|()| Counted)
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Counted, E> {
        Self::tick(0).map(|()| Counted)
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Counted, E> {
        Self::tick(0).map(|()| Counted)
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Counted, E> {
        Self::tick(0).map(|()| Counted)
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Counted, E> {
        Self::tick(0).map(|()| Counted)
    }

    fn visit_bytes<E: serde::de::Error>(self, _: &[u8]) -> Result<Counted, E> {
        Self::tick(0).map(|()| Counted)
    }
}

/// Parse a plist of any encoding. `None` when it is malformed or beyond
/// the limits.
pub fn parse(data: &[u8]) -> Option<(Value, Encoding)> {
    if let Some(utf8) = from_utf16(data) {
        // The declaration may still name UTF-16: the reader only takes UTF-8.
        let text = String::from_utf8_lossy(&utf8).replacen("encoding=\"UTF-16\"", "encoding=\"UTF-8\"", 1);
        return parse(text.as_bytes());
    }
    let enc = encoding(data)?;
    PASS.with(|p| p.set((0, 0)));
    plist::from_reader::<_, Counted>(Cursor::new(data)).ok()?;
    let v = Value::from_reader(Cursor::new(data)).ok()?;
    Some((v, enc))
}

/// A date value as RFC 3339 UTC.
pub fn date(v: &Value) -> Option<String> {
    let t: std::time::SystemTime = v.as_date()?.into();
    jiff::Timestamp::try_from(t).ok().map(|ts| ts.to_string())
}

/// A plist value as JSON, cut at `depth` levels and 64 items per
/// collection; data becomes its length, UIDs `{"uid": n}`.
pub fn to_json(v: &Value, depth: usize) -> Json {
    if depth == 0 {
        return json!("…");
    }
    match v {
        Value::Array(a) => Json::Array(a.iter().take(64).map(|x| to_json(x, depth - 1)).collect()),
        Value::Dictionary(d) => {
            Json::Object(d.iter().take(64).map(|(k, x)| (k.clone(), to_json(x, depth - 1))).collect::<Map<_, _>>())
        }
        Value::Boolean(b) => json!(b),
        Value::Data(d) => json!({ "bytes": d.len() }),
        Value::Date(_) => date(v).map_or(Json::Null, Json::String),
        Value::Real(r) => json!(r),
        Value::Integer(i) => i.as_signed().map_or_else(|| json!(i.as_unsigned()), |n| json!(n)),
        Value::String(s) => json!(crate::text::truncate_chars(s, 512)),
        Value::Uid(u) => json!({ "uid": u.get() }),
        _ => Json::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binary(v: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        v.to_writer_binary(&mut out).unwrap();
        out
    }

    #[test]
    fn all_encodings() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>a</key><integer>1</integer></dict></plist>"#;
        let (v, e) = parse(xml).unwrap();
        assert_eq!((e, to_json(&v, 4)), (Encoding::Xml, json!({ "a": 1 })));
        let (v2, e) = parse(&binary(&v)).unwrap();
        assert_eq!((e, v2), (Encoding::Binary, v));
        assert_eq!(encoding(b"// note\n/* more */ { a = 1; }"), Some(Encoding::Ascii));
        let (v, e) = parse(b"{ a = (x, \"y z\"); }").unwrap();
        assert_eq!((e, to_json(&v, 4)), (Encoding::Ascii, json!({ "a": ["x", "y z"] })));
        assert!(parse(b"\x00\x01garbage").is_none());
        let utf16: Vec<u8> = [0xff, 0xfe]
            .into_iter()
            .chain(String::from_utf8_lossy(xml).encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(parse(&utf16).map(|(v, e)| (to_json(&v, 4), e)), Some((json!({ "a": 1 }), Encoding::Xml)));
    }

    #[test]
    fn deep_nesting_is_refused() {
        let mut xml = String::from("<plist>");
        xml.push_str(&"<array>".repeat(MAX_DEPTH + 1));
        xml.push_str(&"</array>".repeat(MAX_DEPTH + 1));
        xml.push_str("</plist>");
        assert!(parse(xml.as_bytes()).is_none());
    }

    #[test]
    #[cfg_attr(miri, ignore = "expands to the 2,000,000-event cap: hours under Miri")]
    fn shared_references_are_bounded() {
        // A binary plist of 40 arrays, each holding the next one twice:
        // 2^40 values once expanded.
        let n = 40u8;
        let mut objects: Vec<Vec<u8>> = vec![vec![0x50]]; // the innermost: an empty array
        for i in 1..n {
            objects.push(vec![0xa2, i - 1, i - 1]);
        }
        let mut out = b"bplist00".to_vec();
        let mut offsets = Vec::new();
        for o in &objects {
            offsets.push(u8::try_from(out.len()).unwrap());
            out.extend(o);
        }
        let table = out.len();
        out.extend(&offsets);
        let mut trailer = [0u8; 32];
        trailer[6] = 1; // offset size
        trailer[7] = 1; // reference size
        trailer[15] = n; // objects
        trailer[23] = n - 1; // root
        trailer[31] = u8::try_from(table).unwrap();
        out.extend(trailer);
        assert!(parse(&out).is_none());
    }
}
