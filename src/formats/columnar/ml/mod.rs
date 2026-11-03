//! Machine-learning model files: their structure, never their weights.

pub(crate) mod coreml;
pub(crate) mod gguf;
pub(crate) mod onnx;
pub(crate) mod safetensors;
pub(crate) mod tensorflow;
pub(crate) mod torch;

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::short_count;
use crate::plugin::Context;

/// Report a parameter count and a tensor-type histogram.
pub(crate) fn tensors(cx: &mut Context<'_>, count: usize, params: u64, types: BTreeMap<String, u64>) {
    cx.format_set("tensors", count);
    cx.format_set("parameters", params);
    cx.format_set("parameters_label", short_count(params));
    if !types.is_empty() {
        let m: Map<String, Value> = types.into_iter().map(|(k, v)| (k, v.into())).collect();
        cx.format_set("tensor_types", Value::Object(m));
    }
}

/// Counts by name, most frequent first (operator histograms).
pub(crate) fn histogram(counts: BTreeMap<String, u64>, max: usize) -> Value {
    let mut v: Vec<(String, u64)> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    Value::Object(v.into_iter().take(max).map(|(k, n)| (k, n.into())).collect())
}
