//! safetensors files: the JSON header (tensors with their dtypes and
//! shapes, the `__metadata__` strings), the parameter count and the
//! tensor-type histogram; the header must account for the data that
//! follows.
//!
//! Specification: huggingface/safetensors "Format".

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::super::product;
use super::tensors;
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, redact_sensitive,
    truncate_chars,
};

/// Extractor for safetensors files.
pub struct Safetensors;

static META: ExtractorMeta = ExtractorMeta {
    id: "columnar.safetensors",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "safetensors",
        name: "Safetensors",
        family: "columnar",
        mimes: &[],
        extensions: &["safetensors"],
        magic: &[],
        parent: None,
    }],
};

/// Header size accepted (the format caps it at 100 MB).
const MAX_HEADER: u64 = 100_000_000;
/// Tensor names listed.
const MAX_NAMES: usize = 50;

impl Extractor for Safetensors {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let n = u64::from_le_bytes(probe.head.get(..8)?.try_into().ok()?);
        let ok = (2..=MAX_HEADER).contains(&n) && n + 8 <= probe.len && probe.head.get(8) == Some(&b'{');
        ok.then_some(Sniff {
            format: "safetensors",
            confidence: if probe.extension == Some("safetensors") { 0.98 } else { 0.85 },
        })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.read_vec(0, 8).map_err(|_| ExtractError::malformed("header length"))?;
        let n = u64::from_le_bytes(head[..8].try_into().map_err(|_| ExtractError::malformed("header length"))?);
        if n > MAX_HEADER || n + 8 > src.len() {
            return Err(ExtractError::malformed("header length"));
        }
        let size = usize::try_from(n).map_err(|_| ExtractError::malformed("header length"))?;
        if size > cx.parse_limit() {
            return Err(ExtractError::LimitExceeded("max_parse_bytes".into()));
        }
        let json = src.read_vec(8, size).map_err(|_| ExtractError::malformed("header"))?;
        let Value::Object(h) =
            serde_json::from_slice::<Value>(&json).map_err(|_| ExtractError::malformed("header JSON"))?
        else {
            return Err(ExtractError::malformed("header is not an object"));
        };
        cx.format_set("header_bytes", n);
        let mut params = 0u64;
        let mut types: BTreeMap<String, u64> = BTreeMap::new();
        let mut end = 0u64;
        let mut names = Vec::new();
        let mut count = 0;
        for (name, t) in &h {
            if name == "__metadata__" {
                let m: Map<String, Value> = t
                    .as_object()
                    .into_iter()
                    .flatten()
                    .take(100)
                    .map(|(k, v)| {
                        let s = v.as_str().map_or_else(|| v.to_string(), str::to_string);
                        (truncate_chars(k, 100), Value::String(truncate_chars(&redact_sensitive(&s), 500)))
                    })
                    .collect();
                cx.format_set("metadata", Value::Object(m));
                continue;
            }
            count += 1;
            let dtype = t.get("dtype").and_then(Value::as_str).unwrap_or("?");
            let shape: Vec<u64> =
                t.get("shape").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_u64).collect();
            let elems = product(&shape);
            params = params.saturating_add(elems);
            *types.entry(dtype.to_string()).or_default() += elems;
            if let Some(e) =
                t.get("data_offsets").and_then(Value::as_array).and_then(|o| o.get(1)).and_then(Value::as_u64)
            {
                end = end.max(e);
            }
            if names.len() < MAX_NAMES {
                names.push(truncate_chars(name, 200));
            }
        }
        tensors(cx, count, params, types);
        cx.format_set("tensor_names", names);
        let data = src.len() - 8 - n;
        cx.format_set("data_bytes", data);
        if end != data {
            cx.warn(format!("header accounts for {end} data bytes, the file has {data}"));
        }
        Ok(())
    }
}

crate::register_extractor!(Safetensors);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("safetensors");
}
