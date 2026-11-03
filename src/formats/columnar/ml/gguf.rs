//! GGUF models (llama.cpp), v1–v3: the metadata (architecture, name, author, licence,
//!   description, size label, base models, context length, embedding size,
//!   blocks, heads, experts, RoPE settings, the file type / quantisation,
//!   tokenizer model and vocabulary size, chat template presence), the
//!   tensors with their types and the parameter count. (The legacy GGML /
//!   GGMF / GGJT containers are not read.)
//!
//! Specification: ggml `docs/gguf.md` (GGUF v3) and `ggml.h` (tensor
//! types); llama.cpp `llama_ftype`.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::super::product;
use super::tensors;
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, redact_sensitive, truncate_chars,
};

/// Extractor for GGUF and GGML files.
pub struct Gguf;

static META: ExtractorMeta = ExtractorMeta {
    id: "columnar.gguf",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "gguf",
        name: "GGUF model",
        family: "columnar",
        mimes: &[],
        extensions: &["gguf"],
        magic: &[Magic::at(0, b"GGUF")],
        parent: None,
    }],
};

/// Key-value pairs read.
const MAX_KV: u64 = 100_000;
/// Tensors read.
const MAX_TENSORS: u64 = 1_000_000;
/// Elements of one array value walked (vocabularies, merges).
const MAX_ARRAY: u64 = 10_000_000;

/// GGML tensor types (`ggml_type`).
fn ggml_type(t: u32) -> String {
    let s = match t {
        0 => "F32",
        1 => "F16",
        2 => "Q4_0",
        3 => "Q4_1",
        6 => "Q5_0",
        7 => "Q5_1",
        8 => "Q8_0",
        9 => "Q8_1",
        10 => "Q2_K",
        11 => "Q3_K",
        12 => "Q4_K",
        13 => "Q5_K",
        14 => "Q6_K",
        15 => "Q8_K",
        16 => "IQ2_XXS",
        17 => "IQ2_XS",
        18 => "IQ3_XXS",
        19 => "IQ1_S",
        20 => "IQ4_NL",
        21 => "IQ3_S",
        22 => "IQ2_S",
        23 => "IQ4_XS",
        24 => "I8",
        25 => "I16",
        26 => "I32",
        27 => "I64",
        28 => "F64",
        29 => "IQ1_M",
        30 => "BF16",
        34 => "TQ1_0",
        35 => "TQ2_0",
        39 => "MXFP4",
        _ => return format!("type {t}"),
    };
    s.to_string()
}

/// The `general.file_type` (`llama_ftype`).
fn file_type(t: u64) -> String {
    let s = match t {
        0 => "ALL_F32",
        1 => "MOSTLY_F16",
        2 => "MOSTLY_Q4_0",
        3 => "MOSTLY_Q4_1",
        7 => "MOSTLY_Q8_0",
        8 => "MOSTLY_Q5_0",
        9 => "MOSTLY_Q5_1",
        10 => "MOSTLY_Q2_K",
        11 => "MOSTLY_Q3_K_S",
        12 => "MOSTLY_Q3_K_M",
        13 => "MOSTLY_Q3_K_L",
        14 => "MOSTLY_Q4_K_S",
        15 => "MOSTLY_Q4_K_M",
        16 => "MOSTLY_Q5_K_S",
        17 => "MOSTLY_Q5_K_M",
        18 => "MOSTLY_Q6_K",
        19 => "MOSTLY_IQ2_XXS",
        20 => "MOSTLY_IQ2_XS",
        21 => "MOSTLY_Q2_K_S",
        22 => "MOSTLY_IQ3_XS",
        23 => "MOSTLY_IQ3_XXS",
        24 => "MOSTLY_IQ1_S",
        25 => "MOSTLY_IQ4_NL",
        26 => "MOSTLY_IQ3_S",
        27 => "MOSTLY_IQ3_M",
        28 => "MOSTLY_IQ2_S",
        29 => "MOSTLY_IQ2_M",
        30 => "MOSTLY_IQ4_XS",
        31 => "MOSTLY_IQ1_M",
        32 => "MOSTLY_BF16",
        36 => "MOSTLY_TQ1_0",
        37 => "MOSTLY_TQ2_0",
        38 => "MOSTLY_MXFP4_MOE",
        _ => return format!("file type {t}"),
    };
    s.to_string()
}

/// A cursor over the bytes read so far.
struct Cur<'a> {
    b: &'a [u8],
    at: usize,
    v1: bool,
}

impl Cur<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    /// A count: 32-bit in GGUF v1, 64-bit after.
    fn count(&mut self) -> Option<u64> {
        if self.v1 { self.u32().map(u64::from) } else { self.u64() }
    }

    fn string(&mut self) -> Option<String> {
        let n = usize::try_from(self.count()?).ok()?;
        Some(String::from_utf8_lossy(self.take(n)?).into_owned())
    }

    /// A value of type `t`: scalars and short strings kept, arrays counted.
    fn value(&mut self, t: u32, depth: usize) -> Option<Value> {
        Some(match t {
            0 => self.take(1)?[0].into(),
            1 => self.take(1)?[0].cast_signed().into(),
            2 => u16::from_le_bytes(self.take(2)?.try_into().ok()?).into(),
            3 => i16::from_le_bytes(self.take(2)?.try_into().ok()?).into(),
            4 => self.u32()?.into(),
            5 => self.u32()?.cast_signed().into(),
            6 => super::super::number(f64::from(f32::from_le_bytes(self.take(4)?.try_into().ok()?))),
            7 => (self.take(1)?[0] != 0).into(),
            8 => self.string()?.into(),
            9 if depth < 4 => {
                let et = self.u32()?;
                let n = self.count()?;
                if n > MAX_ARRAY {
                    return None;
                }
                let mut first = Vec::new();
                for i in 0..n {
                    let v = self.value(et, depth + 1)?;
                    if i < 8 {
                        first.push(v);
                    }
                }
                let mut m = Map::new();
                m.insert("length".into(), n.into());
                m.insert("first".into(), Value::Array(first));
                Value::Object(m)
            }
            10 => self.u64()?.into(),
            11 => self.u64()?.cast_signed().into(),
            12 => super::super::number(f64::from_le_bytes(self.take(8)?.try_into().ok()?)),
            _ => return None,
        })
    }
}

/// Keys reported as text (others as their value), with their output name.
const GENERAL: [(&str, &str); 16] = [
    ("general.architecture", "architecture"),
    ("general.name", "name"),
    ("general.basename", "basename"),
    ("general.finetune", "finetune"),
    ("general.size_label", "size_label"),
    ("general.version", "model_version"),
    ("general.author", "author"),
    ("general.organization", "organization"),
    ("general.license", "license"),
    ("general.license.name", "license_name"),
    ("general.license.link", "license_link"),
    ("general.url", "url"),
    ("general.repo_url", "repo_url"),
    ("general.quantized_by", "quantized_by"),
    ("general.description", "description"),
    ("tokenizer.ggml.model", "tokenizer"),
];

/// Architecture keys (`<arch>.<key>`) reported.
const ARCH: [&str; 13] = [
    "context_length",
    "embedding_length",
    "block_count",
    "feed_forward_length",
    "attention.head_count",
    "attention.head_count_kv",
    "attention.layer_norm_rms_epsilon",
    "rope.dimension_count",
    "rope.freq_base",
    "expert_count",
    "expert_used_count",
    "vocab_size",
    "attention.sliding_window",
];

#[allow(clippy::too_many_lines)] // the metadata, then the tensor infos
fn gguf(cx: &mut Context<'_>, b: &[u8], cut: bool) -> Result<(), ExtractError> {
    let bad = |what: &str| ExtractError::malformed(what.to_string());
    let version =
        u32::from_le_bytes(b.get(4..8).ok_or_else(|| bad("version"))?.try_into().map_err(|_| bad("version"))?);
    cx.format_set("gguf_version", version);
    let mut c = Cur { b, at: 8, v1: version == 1 };
    let n_tensors = c.count().ok_or_else(|| bad("tensor count"))?;
    let n_kv = c.count().ok_or_else(|| bad("metadata count"))?;
    cx.format_set("metadata_keys", n_kv);
    let mut kv: BTreeMap<String, Value> = BTreeMap::new();
    let mut complete = true;
    for i in 0..n_kv.min(MAX_KV) {
        if i % 1024 == 0 {
            cx.checkpoint()?;
        }
        let parsed = (|| {
            let key = c.string()?;
            let t = c.u32()?;
            let v = c.value(t, 0)?;
            Some((key, v))
        })();
        let Some((key, v)) = parsed else {
            complete = false;
            break;
        };
        kv.insert(key, v);
    }
    let text = |v: &Value| v.as_str().map_or_else(|| v.to_string(), str::to_string);
    for (key, out) in GENERAL {
        if let Some(v) = kv.get(key) {
            let s = redact_sensitive(&text(v)).into_owned();
            cx.format_set(out, truncate_chars(&s, if out == "description" { 1000 } else { 300 }));
        }
    }
    if let Some(n) = kv.get("general.name").and_then(Value::as_str) {
        cx.content().source("gguf.general.name").title(truncate_chars(n, 200));
    }
    if let Some(a) = kv.get("general.author").and_then(Value::as_str) {
        cx.content().source("gguf.general.author").author(truncate_chars(a, 200));
    }
    if let Some(d) = kv.get("general.description").and_then(Value::as_str) {
        cx.content().source("gguf.general.description").description(truncate_chars(d, 1000));
    }
    let lic = kv.get("general.license").and_then(Value::as_str);
    let link = kv.get("general.license.link").and_then(Value::as_str);
    cx.rights().source("gguf.general.license").license(lic, link);
    if let Some(t) = kv.get("general.file_type").and_then(Value::as_u64) {
        cx.format_set("file_type", file_type(t));
    }
    let arch = kv.get("general.architecture").and_then(Value::as_str).unwrap_or_default().to_string();
    let mut hyper = Map::new();
    for k in ARCH {
        if let Some(v) = kv.get(&format!("{arch}.{k}")) {
            hyper.insert(k.replace('.', "_"), v.clone());
        }
    }
    if !hyper.is_empty() {
        cx.format_set("hyperparameters", Value::Object(hyper));
    }
    if let Some(n) = kv.get("tokenizer.ggml.tokens").and_then(|t| t.get("length")).and_then(Value::as_u64) {
        cx.format_set("vocabulary", n);
    }
    if kv.contains_key("tokenizer.chat_template") {
        cx.format_set("chat_template", true);
    }
    let bases: Vec<String> = (0..kv.get("general.base_model.count").and_then(Value::as_u64).unwrap_or(0).min(20))
        .filter_map(|i| kv.get(&format!("general.base_model.{i}.name")).map(|v| truncate_chars(&text(v), 200)))
        .collect();
    if !bases.is_empty() {
        cx.format_set("base_models", bases);
    }
    if let Some(Value::Object(tags)) = kv.get("general.tags")
        && let Some(Value::Array(first)) = tags.get("first")
    {
        cx.format_set("tags", Value::Array(first.clone()));
    }
    cx.format_set("keys", kv.keys().take(200).map(|k| truncate_chars(k, 100)).collect::<Vec<_>>());
    if !complete {
        if cut {
            cx.warn("metadata continues past the parse limit");
        } else {
            return Err(bad("metadata"));
        }
        return Ok(());
    }
    // Tensor infos.
    let mut params = 0u64;
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut read = 0usize;
    for i in 0..n_tensors.min(MAX_TENSORS) {
        if i % 4096 == 0 {
            cx.checkpoint()?;
        }
        let info = (|| {
            c.string()?;
            let dims = c.u32()?;
            if dims > 8 {
                return None;
            }
            let shape: Vec<u64> = (0..dims).map(|_| c.count()).collect::<Option<_>>()?;
            let t = c.u32()?;
            c.u64()?;
            Some((shape, t))
        })();
        let Some((shape, t)) = info else {
            if cut {
                cx.warn("tensor infos continue past the parse limit");
            }
            break;
        };
        let n = product(&shape);
        params = params.saturating_add(n);
        *types.entry(ggml_type(t)).or_default() += 1;
        read += 1;
    }
    tensors(cx, read, params, types);
    if u64::try_from(read).unwrap_or(0) != n_tensors {
        cx.format_set("declared_tensors", n_tensors);
    }
    Ok(())
}

impl Extractor for Gguf {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        // The metadata and tensor infos come first; the weights follow and
        // are not read (so a large model is not a truncated read).
        let len = usize::try_from(src.len()).unwrap_or(usize::MAX);
        let n = len.min(cx.parse_limit());
        let b = src.read_vec(0, n).map_err(|_| ExtractError::malformed("header"))?;
        gguf(cx, &b, n < len)
    }
}

crate::register_extractor!(Gguf);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_names() {
        assert_eq!(ggml_type(12), "Q4_K");
        assert_eq!(file_type(15), "MOSTLY_Q4_K_M");
        assert_eq!(ggml_type(99), "type 99");
    }

    crate::fixture_tests!("gguf");
}
