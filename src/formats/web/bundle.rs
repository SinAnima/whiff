//! Web Bundles (`.wbn`) and Signed HTTP Exchanges (`.sxg`):
//!
//! * a bundle's version, primary URL, sections, the resources it holds and
//!   their content types and statuses;
//! * a signed exchange's fallback URL, signature parameters (certificate
//!   and validity URLs, signing date and expiry, integrity scheme), the
//!   response status, content type and header names, and the payload size.
//!
//! Specifications: draft-ietf-wpack-bundled-responses (`b1` / `b2`) and
//! draft-yasskin-http-origin-signed-responses (`sxg1-b3`).

use std::collections::BTreeMap;

use serde_json::json;

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, filetime,
};

/// Extractor for web bundles and signed exchanges.
pub struct Bundle;

/// CBOR array of two, then the 🌐📦 magic as an 8-byte string.
const WBN: &[u8] = b"\x48\xF0\x9F\x8C\x90\xF0\x9F\x93\xA6";
const SXG: &[u8] = b"sxg1-b3\0";

static META: ExtractorMeta = ExtractorMeta {
    id: "web.bundle",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "web_bundle",
            name: "Web Bundle",
            family: "web.misc",
            mimes: &["application/webbundle"],
            extensions: &["wbn"],
            magic: &[Magic::at(1, WBN)],
            parent: None,
        },
        FormatSpec {
            id: "signed_exchange",
            name: "Signed HTTP exchange",
            family: "web.misc",
            mimes: &["application/signed-exchange"],
            extensions: &["sxg"],
            magic: &[Magic::prefix(SXG)],
            parent: None,
        },
    ],
};

/// URLs listed.
const MAX_LISTED: usize = 100;

impl Extractor for Bundle {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.len() > 10 && matches!(h[0], 0x84..=0x86) && h[1..].starts_with(WBN) {
            return Some(Sniff { format: "web_bundle", confidence: 0.99 });
        }
        h.starts_with(SXG).then_some(Sniff { format: "signed_exchange", confidence: 0.99 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, _) = cx.read_bytes(src)?;
        if cx.format_id() == "signed_exchange" {
            sxg(cx, &b);
        } else {
            bundle(cx, &b);
        }
        Ok(())
    }
}

crate::register_extractor!(Bundle);

/// A CBOR item, as far as these formats need: no floats, no tags kept.
#[derive(Debug, Clone)]
enum Cbor<'a> {
    /// Integers and simple values (only skipped over here).
    Number,
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<Cbor<'a>>),
    Map(Vec<(Cbor<'a>, Cbor<'a>)>),
}

impl<'a> Cbor<'a> {
    fn text(&self) -> Option<&'a str> {
        match self {
            Cbor::Text(t) => Some(t),
            Cbor::Bytes(b) => std::str::from_utf8(b).ok(),
            _ => None,
        }
    }
}

/// Items decoded per file at most (arrays and maps are sized by their
/// header, so a hostile length cannot allocate ahead of the data).
const MAX_ITEMS: usize = 200_000;

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
    items: usize,
}

impl<'a> Reader<'a> {
    fn arg(&mut self, info: u8) -> Option<u64> {
        let n = match info {
            0..=23 => return Some(u64::from(info)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return None,
        };
        let s = self.b.get(self.at..self.at + n)?;
        self.at += n;
        Some(s.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x)))
    }

    fn item(&mut self, depth: usize) -> Option<Cbor<'a>> {
        self.items += 1;
        if self.items > MAX_ITEMS || depth > 32 {
            return None;
        }
        let first = *self.b.get(self.at)?;
        self.at += 1;
        let (major, info) = (first >> 5, first & 31);
        let n = self.arg(info)?;
        let len = usize::try_from(n).ok();
        Some(match major {
            0 | 1 | 7 => Cbor::Number,
            2 | 3 => {
                let l = len?;
                let s = self.b.get(self.at..self.at.checked_add(l)?)?;
                self.at += l;
                if major == 2 { Cbor::Bytes(s) } else { Cbor::Text(std::str::from_utf8(s).ok()?) }
            }
            4 => {
                let l = len?;
                if l > self.b.len() - self.at {
                    return None;
                }
                let mut v = Vec::with_capacity(l.min(1024));
                for _ in 0..l {
                    v.push(self.item(depth + 1)?);
                }
                Cbor::Array(v)
            }
            5 => {
                let l = len?;
                if l > (self.b.len() - self.at) / 2 {
                    return None;
                }
                let mut v = Vec::with_capacity(l.min(1024));
                for _ in 0..l {
                    let k = self.item(depth + 1)?;
                    v.push((k, self.item(depth + 1)?));
                }
                Cbor::Map(v)
            }
            _ => self.item(depth + 1)?, // 6: a tag, then its item
        })
    }
}

fn decode(b: &[u8]) -> Option<Cbor<'_>> {
    Reader { b, at: 0, items: 0 }.item(0)
}

/// HTTP response headers encoded as a CBOR map of byte strings.
fn headers(item: &Cbor<'_>) -> BTreeMap<String, String> {
    let Cbor::Map(m) = item else { return BTreeMap::new() };
    m.iter().filter_map(|(k, v)| Some((k.text()?.to_ascii_lowercase(), v.text().unwrap_or("").to_string()))).collect()
}

fn bundle(cx: &mut Context<'_>, b: &[u8]) {
    let Some(Cbor::Array(top)) = decode(b) else {
        cx.warn("the bundle's CBOR structure could not be read");
        return;
    };
    let version = top.get(1).and_then(Cbor::text).unwrap_or("").trim_end_matches('\0').to_string();
    cx.format_set("version", version.clone());
    // b1: [magic, version, primary URL, section lengths, sections, length].
    let (mut primary, lengths_at) = match top.get(2) {
        Some(Cbor::Text(u)) => (Some((*u).to_string()), 3),
        _ => (None, 2),
    };
    let names: Vec<String> = match top.get(lengths_at) {
        Some(Cbor::Bytes(enc)) => match decode(enc) {
            Some(Cbor::Array(v)) => v.iter().step_by(2).filter_map(|n| n.text().map(str::to_string)).collect(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };
    cx.format_set("sections", names.clone());
    let Some(Cbor::Array(sections)) = top.get(lengths_at + 1) else { return };
    let (mut urls, mut types, mut statuses, mut responses) = (Vec::new(), BTreeMap::new(), BTreeMap::new(), 0usize);
    for (name, section) in names.iter().zip(sections) {
        match (name.as_str(), section) {
            ("index", Cbor::Map(m)) => {
                urls.extend(m.iter().filter_map(|(k, _)| k.text().map(str::to_string)));
            }
            ("primary", s) => primary = s.text().map(str::to_string),
            ("manifest", s) => {
                if let Some(u) = s.text() {
                    cx.format_set("manifest", u);
                }
            }
            ("signatures", _) => cx.format_set("signed", true),
            ("responses", Cbor::Array(rs)) => {
                responses = rs.len();
                for r in rs {
                    let Cbor::Array(parts) = r else { continue };
                    let h = match parts.first() {
                        Some(Cbor::Bytes(enc)) => decode(enc).map(|c| headers(&c)).unwrap_or_default(),
                        _ => BTreeMap::new(),
                    };
                    if let Some(s) = h.get(":status") {
                        *statuses.entry(s.clone()).or_insert(0u64) += 1;
                    }
                    if let Some(t) = h.get("content-type") {
                        let t = t.split(';').next().unwrap_or(t).trim().to_string();
                        *types.entry(t).or_insert(0u64) += 1;
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(p) = primary {
        cx.format_set("primary_url", p);
    }
    cx.format_set("resources", urls.len().max(responses));
    urls.truncate(MAX_LISTED);
    cx.format_set("urls", urls);
    cx.format_set("content_types", json!(types));
    cx.format_set("statuses", json!(statuses));
}

/// Seconds since 1970 as an RFC 3339 time (through the FILETIME helper).
fn unix(secs: i64) -> Option<String> {
    let ticks = secs.checked_add(11_644_473_600)?.checked_mul(10_000_000)?;
    filetime(u64::try_from(ticks).ok()?)
}

fn be(b: &[u8]) -> usize {
    b.iter().fold(0usize, |a, &x| (a << 8) | usize::from(x))
}

/// `sig1; sig=*…*; integrity="…"; cert-url="…"; date=…` → parameters.
fn signature_params(sig: &str) -> BTreeMap<String, String> {
    sig.split(',')
        .next()
        .unwrap_or("")
        .split(';')
        .skip(1)
        .filter_map(|p| {
            let (k, v) = p.trim().split_once('=')?;
            Some((k.to_string(), v.trim_matches('"').to_string()))
        })
        .collect()
}

fn sxg(cx: &mut Context<'_>, b: &[u8]) {
    let mut at = SXG.len();
    let Some(n) = b.get(at..at + 2).map(be) else { return };
    at += 2;
    let Some(url) = b.get(at..at + n).and_then(|u| std::str::from_utf8(u).ok()) else { return };
    cx.format_set("fallback_url", url);
    at += n;
    let (Some(sig_len), Some(head_len)) = (b.get(at..at + 3).map(be), b.get(at + 3..at + 6).map(be)) else { return };
    at += 6;
    let sig = b.get(at..at + sig_len).map(String::from_utf8_lossy).unwrap_or_default();
    let params = signature_params(&sig);
    for (k, key) in [("cert-url", "certificate_url"), ("validity-url", "validity_url"), ("integrity", "integrity")] {
        if let Some(v) = params.get(k) {
            cx.format_set(key, v.as_str());
        }
    }
    for (k, key) in [("date", "signed"), ("expires", "expires")] {
        if let Some(t) = params.get(k).and_then(|v| v.parse::<i64>().ok()).and_then(unix) {
            cx.format_set(key, t);
        }
    }
    at += sig_len;
    let h = b.get(at..at + head_len).and_then(decode).map(|c| headers(&c)).unwrap_or_default();
    if let Some(s) = h.get(":status") {
        cx.format_set("status", s.as_str());
    }
    if let Some(t) = h.get("content-type") {
        cx.format_set("content_type", t.as_str());
    }
    cx.format_set("headers", h.keys().filter(|k| !k.starts_with(':')).cloned().collect::<Vec<_>>());
    cx.format_set("payload_bytes", b.len().saturating_sub(at + head_len));
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("web_bundle", "signed_exchange");

    #[test]
    fn cbor_and_params() {
        let Some(Cbor::Array(v)) = decode(&[0x82, 0x01, 0x63, b'a', b'b', b'c']) else { panic!() };
        assert!(matches!(v[1], Cbor::Text("abc")));
        // A length beyond the data is refused, not allocated.
        assert!(decode(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_none());
        let p = signature_params("sig1; sig=*AA==*; cert-url=\"https://a.example/c\"; date=1700000000");
        assert_eq!(p["cert-url"], "https://a.example/c");
        assert_eq!(p["date"], "1700000000");
    }
}
