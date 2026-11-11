//! XDR (External Data Representation, RFC 4506) data. XDR carries no
//! schema or signature, so a `.xdr` file is read as what the encoding
//! allows: a stream of 4-byte big-endian words. The report gives the word
//! count and alignment, the strings found (a length word, the bytes, zero
//! padding to 4), a census of the remaining words (zero, small and
//! negative integers, plausible single-precision floats, other), and ONC
//! RPC messages (RFC 5531) when the data is a call or reply, with or
//! without record marking. Base64 text (as Stellar and other tools write
//! XDR) is decoded first.
//!
//! Specifications: RFC 4506 (XDR), RFC 5531 (ONC RPC v2).

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Source, TextRole, redact_sensitive,
    truncate_chars,
};

/// Extractor for XDR data.
pub struct Xdr;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.xdr",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "xdr",
        name: "XDR data",
        family: "data.binser",
        mimes: &["application/x-xdr"],
        extensions: &["xdr"],
        magic: &[],
        parent: None,
    }],
};

/// Strings listed.
const MAX_STRINGS: usize = 50;
/// Longest string accepted as one (longer length words are counted as data).
const MAX_STRING: usize = 64 * 1024;
/// RPC messages walked.
const MAX_MESSAGES: usize = 100_000;

impl Extractor for Xdr {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (raw, cut) = cx.read_bytes(src)?;
        if cut {
            cx.format_set("truncated", true);
        }
        let decoded = base64_text(&raw);
        let b: &[u8] = match &decoded {
            Some(d) => {
                cx.format_set("encoding", "base64");
                d
            }
            None => &raw,
        };
        cx.format_set("bytes", b.len());
        cx.format_set("words", b.len() / 4);
        cx.format_set("aligned", b.len().is_multiple_of(4));
        if let Some(rpc) = rpc(b) {
            cx.format_set("rpc", rpc);
        }
        let census = walk(b);
        if !census.strings.is_empty() {
            let mut text = String::new();
            let listed: Vec<Value> = census
                .strings
                .iter()
                .take(MAX_STRINGS)
                .map(|s| {
                    text.push_str(s);
                    text.push('\n');
                    json!(truncate_chars(&redact_sensitive(s), 200))
                })
                .collect();
            cx.emit_text(TextRole::Data, &text);
            cx.format_set("string_count", census.string_count);
            cx.format_set("strings", listed);
        }
        let words: Map<String, Value> = census.words.into_iter().map(|(k, v)| (k.to_string(), json!(v))).collect();
        if !words.is_empty() {
            cx.format_set("word_kinds", Value::Object(words));
        }
        if census.padding_errors > 0 {
            cx.format_set("nonzero_padding", census.padding_errors);
        }
        Ok(())
    }
}

crate::register_extractor!(Xdr);

/// `b` decoded from base64, when the whole file is base64 text whose
/// length decodes to whole words.
fn base64_text(b: &[u8]) -> Option<Vec<u8>> {
    let t = std::str::from_utf8(b).ok()?.trim();
    if t.len() < 8 || !t.bytes().all(|c| c.is_ascii_alphanumeric() || b"+/=\r\n".contains(&c)) {
        return None;
    }
    let d = super::base64(t)?;
    (d.len() >= 4 && d.len().is_multiple_of(4)).then_some(d)
}

fn word(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

#[derive(Default)]
struct Census {
    strings: Vec<String>,
    string_count: u64,
    words: BTreeMap<&'static str, u64>,
    padding_errors: u64,
}

/// A string at `at`: a length word, printable UTF-8, zero padding.
fn string_at(b: &[u8], at: usize) -> Option<(String, usize, bool)> {
    let n = word(b, at)? as usize;
    if n == 0 || n > MAX_STRING {
        return None;
    }
    let body = b.get(at + 4..at + 4 + n)?;
    let s = std::str::from_utf8(body).ok()?;
    if !s.chars().all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t')) {
        return None;
    }
    let padded = n.div_ceil(4) * 4;
    let pad = b.get(at + 4 + n..at + 4 + padded)?;
    Some((s.to_string(), 4 + padded, pad.iter().all(|&p| p == 0)))
}

/// Strings and word kinds, reading greedily from the start.
fn walk(b: &[u8]) -> Census {
    let mut c = Census::default();
    let mut at = 0;
    while at + 4 <= b.len() {
        if let Some((s, len, clean)) = string_at(b, at) {
            c.string_count += 1;
            if !clean {
                c.padding_errors += 1;
            }
            if c.strings.len() < MAX_STRINGS && !c.strings.contains(&s) {
                c.strings.push(s);
            }
            at += len;
            continue;
        }
        let w = word(b, at).unwrap_or(0);
        let f = f32::from_bits(w);
        let kind = if w == 0 {
            "zero"
        } else if w < 0x1_0000 {
            "small_integer"
        } else if w >= 0xFFFF_0000 {
            "negative_integer"
        } else if f.is_finite() && (1e-6..1e9).contains(&f.abs()) {
            "float"
        } else {
            "other"
        };
        *c.words.entry(kind).or_insert(0) += 1;
        at += 4;
    }
    c
}

/// Well-known ONC RPC program numbers (IANA "RPC Program Numbers").
fn program_name(p: u32) -> Option<&'static str> {
    Some(match p {
        100_000 => "portmapper",
        100_001 => "rstatd",
        100_002 => "rusersd",
        100_003 => "nfs",
        100_004 => "ypserv",
        100_005 => "mountd",
        100_007 => "ypbind",
        100_011 => "rquotad",
        100_021 => "nlockmgr",
        100_024 => "status",
        100_227 => "nfs_acl",
        _ => return None,
    })
}

/// ONC RPC calls and replies in `b`: record-marked fragments, or one bare
/// message.
fn rpc(b: &[u8]) -> Option<Value> {
    let mut messages: Vec<&[u8]> = Vec::new();
    let mut at = 0;
    let mut marked = false;
    // Record marking: a word with the last-fragment bit and a length.
    while let Some(mark) = word(b, at) {
        let len = (mark & 0x7FFF_FFFF) as usize;
        let Some(frag) = b.get(at + 4..at + 4 + len) else { break };
        if len < 12 || messages.len() >= MAX_MESSAGES {
            break;
        }
        messages.push(frag);
        at += 4 + len;
        marked = true;
    }
    if !marked || at != b.len() {
        messages = vec![b];
        marked = false;
    }
    let (mut calls, mut replies) = (0u64, 0u64);
    let mut programs: BTreeMap<String, u64> = BTreeMap::new();
    for m in &messages {
        match (word(m, 4)?, word(m, 8)) {
            // Call: rpcvers 2, program, version, procedure.
            (0, Some(2)) => {
                let (prog, vers, proc_) = (word(m, 12)?, word(m, 16)?, word(m, 20)?);
                calls += 1;
                let name = program_name(prog).map_or_else(|| prog.to_string(), str::to_string);
                *programs.entry(format!("{name} v{vers} procedure {proc_}")).or_insert(0) += 1;
            }
            // Reply: accepted (0) or denied (1).
            (1, Some(0 | 1)) => replies += 1,
            _ => return None,
        }
    }
    let mut out = Map::new();
    out.insert("record_marking".into(), json!(marked));
    out.insert("calls".into(), json!(calls));
    out.insert("replies".into(), json!(replies));
    if !programs.is_empty() {
        out.insert("procedures".into(), json!(programs));
    }
    Some(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("xdr");

    #[test]
    fn strings_words_and_rpc() {
        // "tide" (4 bytes, no padding), 7, "harbour" padded to 8.
        let mut b = Vec::new();
        b.extend_from_slice(&4u32.to_be_bytes());
        b.extend_from_slice(b"tide");
        b.extend_from_slice(&7u32.to_be_bytes());
        b.extend_from_slice(&7u32.to_be_bytes());
        b.extend_from_slice(b"harbour\0");
        b.extend_from_slice(&4.1f32.to_bits().to_be_bytes());
        let c = walk(&b);
        assert_eq!(c.strings, vec!["tide", "harbour"]);
        assert_eq!(c.words.get("float"), Some(&1));
        // A record-marked NFS NULL call: xid, call, rpcvers 2, 100003 v3 proc 0.
        let mut call = Vec::new();
        for w in [0x8000_0028u32, 0x1234, 0, 2, 100_003, 3, 0, 0, 0, 0, 0] {
            call.extend_from_slice(&w.to_be_bytes());
        }
        let r = rpc(&call).unwrap();
        assert_eq!(r["calls"], 1);
        assert_eq!(r["record_marking"], true);
        assert_eq!(r["procedures"]["nfs v3 procedure 0"], 1);
        assert!(rpc(&b).is_none());
    }
}
