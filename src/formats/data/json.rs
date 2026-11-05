//! JSON, JSON with comments, JSON5 and newline-delimited JSON: validity,
//! top-level shape, inferred schema, and known schemas (`OpenAPI`, JSON Schema,
//! `GeoJSON`, HAR, SARIF, manifests, …).
//!
//! Specifications: <https://www.rfc-editor.org/rfc/rfc8259>, <https://json5.org/>,
//! <https://github.com/ndjson/ndjson-spec>

use serde_json::{Value, json};

use super::known;
use super::schema::{Schema, top_level};
use crate::plugin::{
    AnyValue, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, MAX_NESTING, Probe, Sniff, Source,
    TextRole, nesting_depth, truncate_chars,
};

/// Extractor for JSON and its relatives.
pub struct Json;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.json",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "json",
            name: "JSON",
            family: "data.json",
            mimes: &["application/json"],
            extensions: &[
                "json",
                "jsonc",
                "har",
                "geojson",
                "topojson",
                "jsonld",
                "webmanifest",
                "sarif",
                "lottie",
                "excalidraw",
                "code-workspace",
            ],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "ndjson",
            name: "Newline-delimited JSON",
            family: "data.json",
            mimes: &["application/x-ndjson"],
            extensions: &["ndjson", "jsonl", "ldjson"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "json5",
            name: "JSON5",
            family: "data.json",
            mimes: &["application/json5"],
            extensions: &["json5"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

/// NDJSON records parsed for the schema; the rest are only counted.
const NDJSON_SAMPLE: usize = 1000;

impl Extractor for Json {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // The whole head window: the first value is parsed below.
        let head =
            std::str::from_utf8(probe.head).or_else(|e| std::str::from_utf8(&probe.head[..e.valid_up_to()])).ok()?;
        let t = head.trim_start_matches('\u{feff}').trim_start();
        let first = t.chars().next()?;
        if first != '{' && first != '[' {
            return None;
        }
        if probe.extension.is_some_and(|e| matches!(e, "ndjson" | "jsonl" | "ldjson")) {
            return Some(Sniff { format: "ndjson", confidence: 0.6 });
        }
        let lines: Vec<&str> = t.lines().filter(|l| !l.trim().is_empty()).take(5).collect();
        let complete = lines.len() >= 2
            && lines.iter().take(lines.len() - 1).all(|l| {
                let l = l.trim();
                l.starts_with('{') && l.ends_with('}') && serde_json::from_str::<Value>(l).is_ok()
            });
        if complete {
            return Some(Sniff { format: "ndjson", confidence: 0.6 });
        }
        // The first value must parse; running out of input (a long document
        // cut by the head window) still counts.
        let mut values = serde_json::Deserializer::from_str(t).into_iter::<serde::de::IgnoredAny>();
        let parses = match values.next() {
            Some(Ok(_)) => true,
            Some(Err(e)) => e.is_eof() && probe.len > probe.head.len() as u64,
            None => false,
        };
        parses.then_some(Sniff { format: "json", confidence: 0.55 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (bytes, cut) = cx.read_bytes(src)?;
        let text = String::from_utf8_lossy(bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes)).into_owned();
        cx.emit_text(TextRole::Data, &text);
        let name = src.name_hint().map(str::to_string);
        if cx.format_id() == "ndjson" {
            ndjson(&text, cut, name.as_deref(), cx)
        } else {
            document(&text, cut, name.as_deref(), cx);
            Ok(())
        }
    }
}

crate::register_extractor!(Json);

fn document(text: &str, cut: bool, name: Option<&str>, cx: &mut Context<'_>) {
    let (value, dialect) = match parse(text, cx.format_id() == "json5") {
        Ok(v) => v,
        Err(e) => {
            cx.format_set("valid", false);
            cx.format_set("error", truncate_chars(&e, 300));
            if cut {
                cx.format_set("truncated", true);
            }
            return;
        }
    };
    cx.format_set("valid", true);
    cx.format_set("dialect", dialect);
    describe(&value, cx);
    let mut schema = Schema::default();
    schema.add(&value);
    cx.format_set("schema", schema.to_json());
    if let Some(k) = known::detect(std::slice::from_ref(&value), name, cx) {
        cx.format_set("known_schema", k);
    }
}

/// Parse strict JSON, then JSON with comments / trailing commas, then JSON5.
/// The error reported is the one for the dialect the file claims.
pub(crate) fn parse(text: &str, json5_file: bool) -> Result<(Value, &'static str), String> {
    let strict = if json5_file { None } else { Some(serde_json::from_str::<Value>(text)) };
    if let Some(Ok(v)) = strict {
        return Ok((v, "json"));
    }
    let relaxed = strip_comments(text);
    if relaxed != text
        && let Ok(v) = serde_json::from_str::<Value>(&relaxed)
    {
        return Ok((v, "jsonc"));
    }
    let json5 = if nesting_depth(text) > MAX_NESTING {
        Err(format!("nested deeper than {MAX_NESTING} levels"))
    } else {
        json5::from_str::<AnyValue>(text).map(|v| (v.0, "json5")).map_err(|e| e.to_string())
    };
    match (json5, strict) {
        (Ok(v), _) => Ok(v),
        (Err(_), Some(Err(e))) => Err(e.to_string()),
        (Err(e), _) => Err(e),
    }
}

/// Remove `//` and `/* */` comments and trailing commas outside strings.
fn strip_comments(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c);
            if c == b'\\' && i + 1 < b.len() {
                out.push(b[i + 1]);
                i += 1;
            } else if c == b'"' {
                in_str = false;
            }
        } else if c == b'"' {
            in_str = true;
            out.push(c);
        } else if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
            continue;
        } else if c == b',' {
            let next = b[i + 1..].iter().find(|x| !x.is_ascii_whitespace());
            if !matches!(next, Some(b']' | b'}')) {
                out.push(c);
            }
        } else {
            out.push(c);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Top-level type, keys or length.
fn describe(v: &Value, cx: &mut Context<'_>) {
    cx.format_set("top_level", top_level(v));
    match v {
        Value::Object(o) => {
            let keys: Vec<&String> = o.keys().take(50).collect();
            cx.format_set("keys", json!(keys));
            cx.format_set("key_count", o.len());
        }
        Value::Array(a) => cx.format_set("length", a.len()),
        _ => {}
    }
}

fn ndjson(text: &str, cut: bool, name: Option<&str>, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut schema = Schema::default();
    let (mut records, mut invalid, mut blank) = (0u64, 0u64, 0u64);
    let mut first_error = None;
    let mut sample: Vec<Value> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if n % 4096 == 0 {
            cx.checkpoint()?;
        }
        let line = line.trim();
        if line.is_empty() {
            blank += 1;
            continue;
        }
        records += 1;
        if sample.len() >= NDJSON_SAMPLE {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(v) => {
                schema.add(&v);
                sample.push(v);
            }
            Err(e) => {
                invalid += 1;
                first_error.get_or_insert_with(|| format!("line {}: {e}", n + 1));
            }
        }
    }
    // The last line of a cut input is usually incomplete.
    if cut && invalid > 0 {
        invalid -= 1;
    }
    cx.format_set("records", records);
    cx.format_set("records_examined", sample.len() + usize::try_from(invalid).unwrap_or(0));
    cx.format_set("invalid_records", invalid);
    if blank > 0 {
        cx.format_set("blank_lines", blank);
    }
    if let Some(e) = first_error {
        cx.format_set("first_error", truncate_chars(&e, 300));
    }
    cx.format_set("schema", schema.to_json());
    if let Some(k) = known::detect(&sample, name, cx) {
        cx.format_set("known_schema", k);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relaxed_parsing() {
        assert_eq!(parse("{\"a\": 1}", false).unwrap().1, "json");
        let (v, d) = parse("{\n  // comment\n  \"a\": [1, 2,],\n}", false).unwrap();
        assert_eq!((v, d), (json!({ "a": [1, 2] }), "jsonc"));
        let (v, d) = parse("{a: 'x', b: 0x10,}", false).unwrap();
        assert_eq!((v["a"].clone(), d), (json!("x"), "json5"));
        assert!(parse(&"[".repeat(1000), false).is_err());
        assert_eq!(strip_comments("{\"u\": \"http://x\"} // c"), "{\"u\": \"http://x\"} ");
    }

    crate::fixture_tests!("json", "ndjson", "json5");
}
