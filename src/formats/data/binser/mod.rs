//! `data.binser` extractors: binary serialisations (self-describing ones
//! decoded to a bounded JSON tree for schema inference, opcode and wire
//! walkers for the rest) and the text data formats without a crate.

#![allow(clippy::many_single_char_names)] // bytes `b`, cursor `c`, walk `w`, as in the specifications

pub(crate) mod android;
pub(crate) mod asn1;
pub(crate) mod avro;
pub(crate) mod flatbuffers;
pub(crate) mod godot;
pub(crate) mod javaser;
pub(crate) mod pickle;
pub(crate) mod protobuf;
pub(crate) mod selfdesc;
pub(crate) mod textdata;
pub(crate) mod unity;
pub(crate) mod xdr;

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::schema::{Schema, top_level};
use crate::plugin::{Context, MAX_NESTING, TextRole, truncate_chars};

// Helpers shared with other groups.
pub(crate) use super::super::archive::unix_time;
pub(crate) use super::super::audio::vorbis::base64;
pub(crate) use super::super::exec::hex;
pub(crate) use super::super::package::android::{Element, binary_xml, string_pool};

/// Values decoded per file.
pub(crate) const MAX_VALUES: u64 = 2_000_000;
/// Items of one collection kept in the tree (the rest are walked and counted).
pub(crate) const KEEP: usize = 1000;
/// Documents of a stream given to the schema.
pub(crate) const SAMPLE_DOCS: usize = 1000;
/// Characters of string values emitted for the secret and privacy scan.
const MAX_TEXT: usize = 1 << 20;

/// Why a decode stopped.
pub(crate) type Fail = &'static str;

/// Counters and collected text shared by the decoders.
#[derive(Default)]
pub(crate) struct Walk {
    pub values: u64,
    pub depth: usize,
    pub max_depth: usize,
    pub text: String,
    /// Tags, extension types, classes … by name.
    pub tags: BTreeMap<String, u64>,
}

impl Walk {
    /// One more value.
    pub fn value(&mut self) -> Result<(), Fail> {
        self.values += 1;
        if self.values > MAX_VALUES { Err("too many values") } else { Ok(()) }
    }

    /// Into a container.
    pub fn enter(&mut self) -> Result<(), Fail> {
        self.depth += 1;
        self.max_depth = self.max_depth.max(self.depth);
        if self.depth > MAX_NESTING { Err("nested too deeply") } else { Ok(()) }
    }

    pub fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// A string value: kept for the text scan.
    pub fn string(&mut self, s: &str) {
        if self.text.len() + s.len() < MAX_TEXT {
            self.text.push_str(s);
            self.text.push('\n');
        }
    }

    pub fn tag(&mut self, name: impl Into<String>) {
        *self.tags.entry(name.into()).or_default() += 1;
    }
}

/// A placeholder for binary data in the tree.
pub(crate) fn bytes(n: usize) -> Value {
    Value::String(format!("<{n} bytes>"))
}

/// A key for a non-string map key.
pub(crate) fn key_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => truncate_chars(&other.to_string(), 100),
    }
}

/// Bytes as text when they are printable UTF-8, else a placeholder.
pub(crate) fn text_or_bytes(b: &[u8], w: &mut Walk) -> Value {
    match std::str::from_utf8(b) {
        Ok(s) if !s.chars().any(|c| c.is_control() && !c.is_whitespace()) => {
            w.string(s);
            Value::String(truncate_chars(s, 2000))
        }
        _ => bytes(b.len()),
    }
}

/// What a decoder produced.
#[derive(Default)]
pub(crate) struct Decoded {
    /// The first documents (sampled for the schema).
    pub docs: Vec<Value>,
    /// Documents in the stream.
    pub documents: u64,
    /// Bytes left after the last document.
    pub trailing: usize,
    /// The error that stopped decoding, if any.
    pub error: Option<Fail>,
}

/// Write the common fields: top-level type and keys, documents, schema,
/// counts, tags, and emit the string values as data text.
pub(crate) fn report(cx: &mut Context<'_>, d: &Decoded, w: &Walk) {
    if let Some(first) = d.docs.first() {
        cx.format_set("top_level", top_level(first));
        match first {
            Value::Object(o) => {
                let keys: Vec<&String> = o.keys().take(50).collect();
                cx.format_set("keys", json!(keys));
                cx.format_set("key_count", o.len());
            }
            Value::Array(a) => cx.format_set("length", a.len()),
            _ => {}
        }
    }
    if d.documents != 1 {
        cx.format_set("documents", d.documents);
    }
    cx.format_set("values", w.values);
    cx.format_set("max_depth", w.max_depth);
    if !w.tags.is_empty() {
        let m: Map<String, Value> = w.tags.iter().map(|(k, n)| (k.clone(), (*n).into())).collect();
        cx.format_set("tags", Value::Object(m));
    }
    if d.trailing > 0 {
        cx.format_set("trailing_bytes", d.trailing);
    }
    if let Some(e) = d.error {
        cx.format_set("decode_error", e);
    }
    if !d.docs.is_empty() {
        let mut s = Schema::default();
        for doc in d.docs.iter().take(SAMPLE_DOCS) {
            s.add(doc);
        }
        cx.format_set("schema", s.to_json());
    }
    if !w.text.is_empty() {
        cx.emit_text(TextRole::Data, &w.text);
    }
}

/// Decode a stream of values with `one` (which returns the value and the
/// bytes it used) until the input ends or a value fails.
pub(crate) fn stream(
    data: &[u8],
    w: &mut Walk,
    mut one: impl FnMut(&[u8], &mut Walk) -> Result<(Value, usize), Fail>,
) -> Decoded {
    let mut d = Decoded::default();
    let mut at = 0;
    while at < data.len() {
        match one(&data[at..], w) {
            Ok((v, used)) if used > 0 => {
                d.documents += 1;
                if d.docs.len() < SAMPLE_DOCS {
                    d.docs.push(v);
                }
                at += used;
            }
            Ok(_) => break,
            Err(e) => {
                if d.documents == 0 {
                    d.error = Some(e);
                } else if !data[at..].iter().all(|&b| b == 0) {
                    d.error = Some(e);
                    d.trailing = data.len() - at;
                }
                break;
            }
        }
    }
    d
}
