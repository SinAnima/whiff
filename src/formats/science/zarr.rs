//! Zarr metadata documents (the files of a Zarr store that describe it):
//! v2 `.zarray` (shape, chunks, dtype, compressor, filters, fill value,
//! order), `.zgroup`, `.zattrs` and consolidated `.zmetadata`; v3
//! `zarr.json` for arrays (shape, data type, chunk grid, codecs, dimension
//! names) and groups, with their attributes.
//!
//! Specifications: Zarr storage specification 2.0; Zarr core
//! specification 3.0.

use serde_json::{Map, Value};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, redact_sensitive,
    truncate_chars,
};

/// Extractor for Zarr metadata.
pub struct Zarr;

static META: ExtractorMeta = ExtractorMeta {
    id: "science.zarr",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "zarr",
        name: "Zarr",
        family: "sci",
        mimes: &[],
        extensions: &["zarray", "zgroup", "zattrs", "zmetadata"],
        magic: &[],
        parent: Some("json"),
    }],
};

fn has(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

fn attrs(cx: &mut Context<'_>, a: &Value) {
    let Some(o) = a.as_object().filter(|o| !o.is_empty()) else { return };
    let m: Map<String, Value> = o
        .iter()
        .take(100)
        .map(|(k, v)| {
            let v = match v {
                Value::String(s) => Value::String(truncate_chars(&redact_sensitive(s), 300)),
                Value::Array(x) if x.len() > 16 => Value::String(format!("({} values)", x.len())),
                Value::Object(x) => Value::String(format!("({} keys)", x.len())),
                other => other.clone(),
            };
            (truncate_chars(k, 100), v)
        })
        .collect();
    if let Some(t) = o.get("title").and_then(Value::as_str) {
        cx.content().source("zarr.attributes.title").title(truncate_chars(t, 300));
    }
    cx.format_set("attributes", Value::Object(m));
}

fn array(cx: &mut Context<'_>, v: &Value) {
    for (k, out) in [
        ("shape", "shape"),
        ("chunks", "chunks"),
        ("order", "order"),
        ("fill_value", "fill_value"),
        ("dimension_names", "dimension_names"),
    ] {
        if let Some(x) = v.get(k).filter(|x| !x.is_null()) {
            cx.format_set(out, x.clone());
        }
    }
    if let Some(d) = v.get("dtype").or_else(|| v.get("data_type")) {
        cx.format_set("data_type", truncate_chars(&d.as_str().map_or_else(|| d.to_string(), str::to_string), 200));
    }
    if let Some(c) = v.get("compressor").and_then(|c| c.get("id")).and_then(Value::as_str) {
        cx.format_set("compressor", truncate_chars(c, 50));
    }
    if let Some(f) = v.get("filters").and_then(Value::as_array) {
        let ids: Vec<&str> = f.iter().filter_map(|x| x.get("id").and_then(Value::as_str)).collect();
        if !ids.is_empty() {
            cx.format_set("filters", ids);
        }
    }
    if let Some(c) = v.pointer("/chunk_grid/configuration/chunk_shape") {
        cx.format_set("chunks", c.clone());
    }
    if let Some(c) = v.get("codecs").and_then(Value::as_array) {
        let names: Vec<&str> = c.iter().filter_map(|x| x.get("name").and_then(Value::as_str)).collect();
        cx.format_set("codecs", names);
    }
}

impl Extractor for Zarr {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let json = h.trim_ascii_start().starts_with(b"{");
        let v3 = json && has(h, b"\"zarr_format\"") && (has(h, b"\"node_type\"") || has(h, b": 3"));
        let v2 = json
            && has(h, b"\"zarr_format\"")
            && matches!(probe.extension, Some("zarray" | "zgroup" | "zmetadata" | "json"));
        // `.zattrs`: a plain JSON object, known by its name.
        let attrs = json && probe.extension == Some("zattrs");
        (v3 || v2 || attrs).then_some(Sniff { format: "zarr", confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        let v: Value = serde_json::from_str(&text).map_err(|_| ExtractError::malformed("Zarr metadata JSON"))?;
        let version = v.get("zarr_format").and_then(Value::as_u64);
        if let Some(z) = version {
            cx.format_set("zarr_format", z);
        }
        let node = match (version, v.get("node_type").and_then(Value::as_str)) {
            (Some(3), Some(n)) => n.to_string(),
            (Some(2), _) if v.get("shape").is_some() => "array".into(),
            (Some(2), _) if v.get("metadata").is_some() => "consolidated".into(),
            (Some(2), _) => "group".into(),
            // `.zattrs` holds the attributes alone.
            (None, _) => "attributes".into(),
            _ => "unknown".into(),
        };
        cx.format_set("node", node.clone());
        match node.as_str() {
            "array" => {
                array(cx, &v);
                if let Some(a) = v.get("attributes") {
                    attrs(cx, a);
                }
            }
            "group" => {
                if let Some(a) = v.get("attributes") {
                    attrs(cx, a);
                }
            }
            "consolidated" => {
                let m = v.get("metadata").and_then(Value::as_object);
                let arrays: Vec<String> = m
                    .into_iter()
                    .flatten()
                    .filter(|(k, _)| k.ends_with(".zarray"))
                    .map(|(k, _)| truncate_chars(k.trim_end_matches(".zarray").trim_end_matches('/'), 200))
                    .take(500)
                    .collect();
                cx.format_set("arrays", arrays);
            }
            "attributes" => attrs(cx, &v),
            _ => {}
        }
        Ok(())
    }
}

crate::register_extractor!(Zarr);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("zarr");
}
