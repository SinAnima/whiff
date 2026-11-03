//! TensorFlow and Keras models:
//! * Keras 3 archives (`.keras`, a ZIP): Keras version, save date, the
//!   model class and name, layers (count, classes, names), the weights file;
//! * TensorFlow Lite (`.tflite`, FlatBuffers `TFL3`): schema version,
//!   description, subgraphs, operators and their histogram, tensors and
//!   their types, inputs and outputs, parameters, signatures and metadata
//!   (the minimum runtime version);
//! * SavedModel (`saved_model.pb`): schema version, meta graphs with their
//!   tags and TensorFlow version, signatures with their inputs and outputs,
//!   graph nodes, functions and the operator histogram.
//!
//! Specifications: Keras `saving/saving_lib.py`; TensorFlow Lite
//! `schema.fbs` (v3); TensorFlow `saved_model.proto`, `meta_graph.proto`,
//! `graph.proto`, `function.proto`.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::super::product;
use super::{histogram, tensors};
use crate::plugin::flatbuf::FlatBuf;
use crate::plugin::protowire::{self, Wire};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, Zip,
    parse_date, truncate_chars, zip_names,
};

/// Extractor for Keras, TensorFlow Lite and SavedModel files.
pub struct TensorFlow;

static META: ExtractorMeta = ExtractorMeta {
    id: "columnar.tensorflow",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "keras",
            name: "Keras model",
            family: "columnar",
            mimes: &[],
            extensions: &["keras"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "tflite",
            name: "TensorFlow Lite model",
            family: "columnar",
            mimes: &[],
            extensions: &["tflite"],
            magic: &[Magic::at(4, b"TFL3")],
            parent: None,
        },
        FormatSpec {
            id: "savedmodel",
            name: "TensorFlow SavedModel",
            family: "columnar",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: None,
        },
    ],
};

/// Layers, signatures and tensors listed.
const MAX_LIST: usize = 100;

/// TensorFlow Lite builtin operators (`BuiltinOperator`).
const TFLITE_OPS: [&str; 162] = [
    "ADD",
    "AVERAGE_POOL_2D",
    "CONCATENATION",
    "CONV_2D",
    "DEPTHWISE_CONV_2D",
    "DEPTH_TO_SPACE",
    "DEQUANTIZE",
    "EMBEDDING_LOOKUP",
    "FLOOR",
    "FULLY_CONNECTED",
    "HASHTABLE_LOOKUP",
    "L2_NORMALIZATION",
    "L2_POOL_2D",
    "LOCAL_RESPONSE_NORMALIZATION",
    "LOGISTIC",
    "LSH_PROJECTION",
    "LSTM",
    "MAX_POOL_2D",
    "MUL",
    "RELU",
    "RELU_N1_TO_1",
    "RELU6",
    "RESHAPE",
    "RESIZE_BILINEAR",
    "RNN",
    "SOFTMAX",
    "SPACE_TO_DEPTH",
    "SVDF",
    "TANH",
    "CONCAT_EMBEDDINGS",
    "SKIP_GRAM",
    "CALL",
    "CUSTOM",
    "EMBEDDING_LOOKUP_SPARSE",
    "PAD",
    "UNIDIRECTIONAL_SEQUENCE_RNN",
    "GATHER",
    "BATCH_TO_SPACE_ND",
    "SPACE_TO_BATCH_ND",
    "TRANSPOSE",
    "MEAN",
    "SUB",
    "DIV",
    "SQUEEZE",
    "UNIDIRECTIONAL_SEQUENCE_LSTM",
    "STRIDED_SLICE",
    "BIDIRECTIONAL_SEQUENCE_RNN",
    "EXP",
    "TOPK_V2",
    "SPLIT",
    "LOG_SOFTMAX",
    "DELEGATE",
    "BIDIRECTIONAL_SEQUENCE_LSTM",
    "CAST",
    "PRELU",
    "MAXIMUM",
    "ARG_MAX",
    "MINIMUM",
    "LESS",
    "NEG",
    "PADV2",
    "GREATER",
    "GREATER_EQUAL",
    "LESS_EQUAL",
    "SELECT",
    "SLICE",
    "SIN",
    "TRANSPOSE_CONV",
    "SPARSE_TO_DENSE",
    "TILE",
    "EXPAND_DIMS",
    "EQUAL",
    "NOT_EQUAL",
    "LOG",
    "SUM",
    "SQRT",
    "RSQRT",
    "SHAPE",
    "POW",
    "ARG_MIN",
    "FAKE_QUANT",
    "REDUCE_PROD",
    "REDUCE_MAX",
    "PACK",
    "LOGICAL_OR",
    "ONE_HOT",
    "LOGICAL_AND",
    "LOGICAL_NOT",
    "UNPACK",
    "REDUCE_MIN",
    "FLOOR_DIV",
    "REDUCE_ANY",
    "SQUARE",
    "ZEROS_LIKE",
    "FILL",
    "FLOOR_MOD",
    "RANGE",
    "RESIZE_NEAREST_NEIGHBOR",
    "LEAKY_RELU",
    "SQUARED_DIFFERENCE",
    "MIRROR_PAD",
    "ABS",
    "SPLIT_V",
    "UNIQUE",
    "CEIL",
    "REVERSE_V2",
    "ADD_N",
    "GATHER_ND",
    "COS",
    "WHERE",
    "RANK",
    "ELU",
    "REVERSE_SEQUENCE",
    "MATRIX_DIAG",
    "QUANTIZE",
    "MATRIX_SET_DIAG",
    "ROUND",
    "HARD_SWISH",
    "IF",
    "WHILE",
    "NON_MAX_SUPPRESSION_V4",
    "NON_MAX_SUPPRESSION_V5",
    "SCATTER_ND",
    "SELECT_V2",
    "DENSIFY",
    "SEGMENT_SUM",
    "BATCH_MATMUL",
    "PLACEHOLDER_FOR_GREATER_OP_CODES",
    "CUMSUM",
    "CALL_ONCE",
    "BROADCAST_TO",
    "RFFT2D",
    "CONV_3D",
    "IMAG",
    "REAL",
    "COMPLEX_ABS",
    "HASHTABLE",
    "HASHTABLE_FIND",
    "HASHTABLE_IMPORT",
    "HASHTABLE_SIZE",
    "REDUCE_ALL",
    "CONV_3D_TRANSPOSE",
    "VAR_HANDLE",
    "READ_VARIABLE",
    "ASSIGN_VARIABLE",
    "BROADCAST_ARGS",
    "RANDOM_STANDARD_NORMAL",
    "BUCKETIZE",
    "RANDOM_UNIFORM",
    "MULTINOMIAL",
    "GELU",
    "DYNAMIC_UPDATE_SLICE",
    "RELU_0_TO_1",
    "UNSORTED_SEGMENT_PROD",
    "UNSORTED_SEGMENT_MAX",
    "UNSORTED_SEGMENT_SUM",
    "ATAN2",
    "UNSORTED_SEGMENT_MIN",
    "SIGN",
    "BITCAST",
    "BITWISE_XOR",
    "RIGHT_SHIFT",
];

fn tflite_type(t: u8) -> String {
    let s = match t {
        0 => "float32",
        1 => "float16",
        2 => "int32",
        3 => "uint8",
        4 => "int64",
        5 => "string",
        6 => "bool",
        7 => "int16",
        8 => "complex64",
        9 => "int8",
        10 => "float64",
        11 => "complex128",
        12 => "uint64",
        13 => "resource",
        14 => "variant",
        15 => "uint32",
        16 => "uint16",
        17 => "int4",
        18 => "bfloat16",
        _ => return format!("type {t}"),
    };
    s.to_string()
}

/// A tensor's shape (`[i32]`) as dimensions.
fn shape(fb: &FlatBuf<'_>, t: usize) -> Vec<i64> {
    let n = fb.vector(t, 0).map_or(0, |(_, n)| n).min(16);
    (0..n)
        .filter_map(|i| fb.element(t, 0, i, 4))
        .map(|b| i64::from(i32::from_le_bytes(b.try_into().unwrap_or_default())))
        .collect()
}

fn tensor_text(fb: &FlatBuf<'_>, t: usize) -> String {
    let dims: Vec<String> = shape(fb, t).iter().map(i64::to_string).collect();
    format!("{}[{}]", tflite_type(fb.u8_field(t, 1).unwrap_or(0)), dims.join(", "))
}

fn tflite(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let fb = FlatBuf(b);
    let root = fb.root().ok_or_else(|| ExtractError::malformed("model"))?;
    cx.format_set("schema_version", fb.u32_field(root, 0).unwrap_or(0));
    if let Some(d) = fb.string(root, 3).filter(|d| !d.is_empty()) {
        cx.format_set("description", truncate_chars(&d, 300));
    }
    // Operator codes: the larger of the deprecated byte and the int code.
    let codes: Vec<String> = fb
        .tables(root, 1)
        .iter()
        .map(|&c| {
            let old = fb.u8_field(c, 0).map_or(0, |v| usize::from(v.cast_signed().max(0).cast_unsigned()));
            let new = fb.u32_field(c, 3).and_then(|v| usize::try_from(v).ok()).unwrap_or(0);
            let code = old.max(new);
            if code == 32 {
                fb.string(c, 1).map_or_else(|| "CUSTOM".into(), |s| format!("CUSTOM:{}", truncate_chars(&s, 60)))
            } else {
                TFLITE_OPS.get(code).map_or_else(|| format!("BUILTIN_{code}"), |s| (*s).to_string())
            }
        })
        .collect();
    let buffers = fb.tables(root, 4);
    let subgraphs = fb.tables(root, 2);
    cx.format_set("subgraphs", subgraphs.len());
    let names: Vec<String> =
        subgraphs.iter().filter_map(|&s| fb.string(s, 4)).take(MAX_LIST).map(|n| truncate_chars(&n, 100)).collect();
    if !names.is_empty() {
        cx.format_set("subgraph_names", names);
    }
    let mut ops: BTreeMap<String, u64> = BTreeMap::new();
    let mut operators = 0u64;
    let (mut count, mut params) = (0usize, 0u64);
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    for &s in &subgraphs {
        for &o in &fb.tables(s, 3) {
            operators += 1;
            let i = fb.u32_field(o, 0).and_then(|v| usize::try_from(v).ok()).unwrap_or(0);
            *ops.entry(codes.get(i).cloned().unwrap_or_else(|| "?".into())).or_default() += 1;
        }
        for &t in &fb.tables(s, 0) {
            count += 1;
            *types.entry(tflite_type(fb.u8_field(t, 1).unwrap_or(0))).or_default() += 1;
            // Constant tensors (weights) have a non-empty buffer.
            let buf = fb.u32_field(t, 2).and_then(|v| usize::try_from(v).ok()).and_then(|i| buffers.get(i).copied());
            let constant = buf.is_some_and(|b| {
                fb.vector(b, 0).is_some_and(|(_, n)| n > 0) || fb.u64_field(b, 2).is_some_and(|n| n > 0)
            });
            if constant {
                let dims: Vec<u64> = shape(&fb, t).iter().map(|&d| d.max(0).cast_unsigned()).collect();
                params = params.saturating_add(product(&dims));
            }
        }
    }
    cx.format_set("operators", operators);
    cx.format_set("operator_types", histogram(ops, 50));
    tensors(cx, count, params, types);
    if let Some(&s) = subgraphs.first() {
        let all = fb.tables(s, 0);
        for (field, key) in [(1, "inputs"), (2, "outputs")] {
            let n = fb.vector(s, field).map_or(0, |(_, n)| n).min(MAX_LIST);
            let io: Map<String, Value> = (0..n)
                .filter_map(|i| fb.element(s, field, i, 4))
                .filter_map(|b| usize::try_from(i32::from_le_bytes(b.try_into().ok()?)).ok())
                .filter_map(|i| all.get(i).copied())
                .map(|t| {
                    (truncate_chars(&fb.string(t, 3).unwrap_or_default(), 200), Value::String(tensor_text(&fb, t)))
                })
                .collect();
            cx.format_set(key, Value::Object(io));
        }
    }
    let sigs: Vec<String> = fb
        .tables(root, 7)
        .iter()
        .filter_map(|&s| fb.string(s, 2))
        .take(MAX_LIST)
        .map(|n| truncate_chars(&n, 100))
        .collect();
    if !sigs.is_empty() {
        cx.format_set("signatures", sigs);
    }
    let mut meta = Map::new();
    for &m in fb.tables(root, 6).iter().take(MAX_LIST) {
        let Some(name) = fb.string(m, 0) else { continue };
        let data = fb
            .u32_field(m, 1)
            .and_then(|v| usize::try_from(v).ok())
            .and_then(|i| buffers.get(i).copied())
            .and_then(|b| fb.bytes(b, 0));
        // Short text values (the runtime version) are shown; others sized.
        let v = match data {
            Some(d) if d.len() <= 64 && d.iter().all(|&c| c == 0 || (0x20..0x7f).contains(&c)) => {
                Value::String(String::from_utf8_lossy(d).trim_end_matches('\0').to_string())
            }
            Some(d) => Value::String(format!("({} bytes)", d.len())),
            None => Value::Null,
        };
        meta.insert(truncate_chars(&name, 100), v);
    }
    if !meta.is_empty() {
        cx.format_set("metadata", Value::Object(meta));
    }
    Ok(())
}

fn keras(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let zip = Zip::open(src, 10_000)?;
    if let Some(Ok(t)) = zip.read_text(src, "metadata.json", cx, 1 << 20)
        && let Ok(m) = serde_json::from_str::<Value>(&t)
    {
        if let Some(v) = m.get("keras_version").and_then(Value::as_str) {
            cx.format_set("keras_version", truncate_chars(v, 50));
        }
        if let Some(d) = m.get("date_saved").and_then(Value::as_str) {
            cx.format_set("date_saved", truncate_chars(d, 50));
            // "2025-10-31@21:04:59" (local time of the writer).
            if let Some((t, tz)) = parse_date(&d.replacen('@', " ", 1)) {
                cx.temporal().source("keras.date_saved").content_date(DateField::Created, t, tz);
            }
        }
    }
    let config = zip
        .read_text(src, "config.json", cx, 16 << 20)
        .and_then(Result::ok)
        .and_then(|t| serde_json::from_str::<Value>(&t).ok());
    if let Some(c) = config {
        if let Some(k) = c.get("class_name").and_then(Value::as_str) {
            cx.format_set("model_class", truncate_chars(k, 100));
        }
        if let Some(n) = c.pointer("/config/name").and_then(Value::as_str) {
            cx.format_set("model_name", truncate_chars(n, 200));
            cx.content().source("keras.config.name").title(truncate_chars(n, 200));
        }
        let layers = c.pointer("/config/layers").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
        cx.format_set("layer_count", layers.len());
        let mut classes: BTreeMap<String, u64> = BTreeMap::new();
        let mut names = Vec::new();
        for l in layers {
            if let Some(k) = l.get("class_name").and_then(Value::as_str) {
                *classes.entry(truncate_chars(k, 100)).or_default() += 1;
            }
            if let Some(n) = l.pointer("/config/name").and_then(Value::as_str)
                && names.len() < MAX_LIST
            {
                names.push(truncate_chars(n, 100));
            }
        }
        cx.format_set("layer_classes", histogram(classes, 50));
        cx.format_set("layers", names);
        if let Some(o) = c.pointer("/compile_config/optimizer/class_name").and_then(Value::as_str) {
            cx.format_set("optimizer", truncate_chars(o, 100));
        }
        if let Some(l) = c.pointer("/compile_config/loss") {
            cx.format_set("loss", truncate_chars(&l.as_str().map_or_else(|| l.to_string(), str::to_string), 200));
        }
    }
    let weights: Vec<String> = zip
        .entries
        .iter()
        .filter(|e| {
            std::path::Path::new(&e.name)
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("h5") || x.eq_ignore_ascii_case("npz"))
        })
        .map(|e| e.name.clone())
        .take(10)
        .collect();
    if let Some(w) = weights.first() {
        cx.format_set("weights_file", truncate_chars(w, 200));
    }
    Ok(())
}

/// A `TensorInfo` as `dtype[shape]`.
fn tensor_info(t: &[u8]) -> String {
    let dtype = protowire::first(t, 2).and_then(Wire::int).unwrap_or(0);
    let dt = match dtype {
        1 => "float32",
        2 => "float64",
        3 => "int32",
        4 => "uint8",
        5 => "int16",
        6 => "int8",
        7 => "string",
        9 => "int64",
        10 => "bool",
        14 => "bfloat16",
        19 => "float16",
        _ => "?",
    };
    let dims: Vec<String> = protowire::first(t, 3)
        .and_then(Wire::bytes)
        .map(|s| {
            protowire::all(s, 2)
                .filter_map(Wire::bytes)
                .take(16)
                .map(|d| {
                    protowire::first(d, 1)
                        .and_then(Wire::int)
                        .map_or_else(|| "?".into(), |n| n.cast_signed().to_string())
                })
                .collect()
        })
        .unwrap_or_default();
    format!("{dt}[{}]", dims.join(", "))
}

fn savedmodel(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    if let Some(v) = protowire::first(b, 1).and_then(Wire::int) {
        cx.format_set("schema_version", v);
    }
    let metas: Vec<&[u8]> = protowire::all(b, 2).filter_map(Wire::bytes).collect();
    if metas.is_empty() {
        return Err(ExtractError::malformed("no meta graph"));
    }
    cx.format_set("meta_graphs", metas.len());
    let mut ops: BTreeMap<String, u64> = BTreeMap::new();
    let (mut nodes, mut functions) = (0u64, 0u64);
    let mut sigs = Map::new();
    for m in &metas {
        if let Some(info) = protowire::first(m, 1).and_then(Wire::bytes) {
            let tags: Vec<String> = protowire::all(info, 4).filter_map(Wire::text).take(20).collect();
            if !tags.is_empty() {
                cx.format_set("tags", tags);
            }
            if let Some(v) = protowire::first(info, 5).and_then(Wire::text) {
                cx.format_set("tensorflow_version", truncate_chars(&v, 50));
            }
            if let Some(v) = protowire::first(info, 6).and_then(Wire::text) {
                cx.format_set("tensorflow_git_version", truncate_chars(&v, 100));
            }
        }
        if let Some(g) = protowire::first(m, 2).and_then(Wire::bytes) {
            for n in protowire::all(g, 1).filter_map(Wire::bytes) {
                nodes += 1;
                if let Some(op) = protowire::first(n, 2).and_then(Wire::text) {
                    *ops.entry(truncate_chars(&op, 100)).or_default() += 1;
                }
            }
            if let Some(lib) = protowire::first(g, 2).and_then(Wire::bytes) {
                for f in protowire::all(lib, 1).filter_map(Wire::bytes) {
                    functions += 1;
                    for n in protowire::all(f, 3).filter_map(Wire::bytes) {
                        if let Some(op) = protowire::first(n, 2).and_then(Wire::text) {
                            *ops.entry(truncate_chars(&op, 100)).or_default() += 1;
                        }
                    }
                }
            }
            if let Some(p) =
                protowire::first(g, 4).and_then(Wire::bytes).and_then(|v| protowire::first(v, 1)).and_then(Wire::int)
            {
                cx.format_set("graph_producer", p);
            }
        }
        for entry in protowire::all(m, 5).filter_map(Wire::bytes).take(MAX_LIST) {
            let Some(key) = protowire::first(entry, 1).and_then(Wire::text) else { continue };
            let Some(sig) = protowire::first(entry, 2).and_then(Wire::bytes) else { continue };
            let side = |n: u32| -> Value {
                Value::Object(
                    protowire::all(sig, n)
                        .filter_map(Wire::bytes)
                        .take(MAX_LIST)
                        .filter_map(|kv| {
                            let k = protowire::first(kv, 1).and_then(Wire::text)?;
                            let t =
                                protowire::first(kv, 2).and_then(Wire::bytes).map_or_else(|| "?".into(), tensor_info);
                            Some((truncate_chars(&k, 100), Value::String(t)))
                        })
                        .collect(),
                )
            };
            let mut s = Map::new();
            s.insert("inputs".into(), side(1));
            s.insert("outputs".into(), side(2));
            if let Some(mn) = protowire::first(sig, 3).and_then(Wire::text) {
                s.insert("method".into(), truncate_chars(&mn, 100).into());
            }
            sigs.insert(truncate_chars(&key, 100), Value::Object(s));
        }
    }
    cx.format_set("graph_nodes", nodes);
    cx.format_set("functions", functions);
    cx.format_set("operator_types", histogram(ops, 50));
    if !sigs.is_empty() {
        cx.format_set("signatures", Value::Object(sigs));
    }
    Ok(())
}

impl Extractor for TensorFlow {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let base = probe.name.map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n));
        if base == Some("saved_model.pb") && probe.head.first() == Some(&0x08) {
            return Some(Sniff { format: "savedmodel", confidence: 0.95 });
        }
        let names = zip_names(probe, 200);
        let keras = names.iter().any(|n| n == "config.json")
            && names.iter().any(|n| n == "metadata.json" || n.ends_with(".weights.h5") || n == "model.weights.npz");
        keras
            .then_some(Sniff { format: "keras", confidence: if probe.extension == Some("keras") { 0.98 } else { 0.9 } })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "keras" => keras(cx, src),
            "tflite" => {
                let (b, cut) = cx.read_bytes(src)?;
                if cut {
                    // Weights follow the model tables; a cut file may still read.
                    cx.warn("model larger than the parse limit");
                }
                tflite(cx, &b)
            }
            _ => {
                let (b, _) = cx.read_bytes(src)?;
                savedmodel(cx, &b)
            }
        }
    }
}

crate::register_extractor!(TensorFlow);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_table() {
        assert_eq!(TFLITE_OPS[9], "FULLY_CONNECTED");
        assert_eq!(TFLITE_OPS[126], "BATCH_MATMUL");
        assert_eq!(TFLITE_OPS[161], "RIGHT_SHIFT");
        assert_eq!(tflite_type(9), "int8");
    }

    crate::fixture_tests!("keras", "tflite", "savedmodel");
}
