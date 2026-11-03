//! ONNX models: IR version, producer and its version, domain, model
//! version, description, operator sets, the graph's name, nodes and their
//! operator histogram, inputs and outputs (element types and shapes),
//! initializers (count, parameters, element types, external data),
//! functions and the metadata properties. The model is walked through the
//! source field by field, so weights stored inline are skipped, not read.
//!
//! Specification: ONNX `onnx.proto` (IR version 10).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::super::product;
use super::{histogram, tensors};
use crate::plugin::protowire::{self, Wire};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, redact_sensitive,
    truncate_chars,
};

/// Extractor for ONNX models.
pub struct Onnx;

static META: ExtractorMeta = ExtractorMeta {
    id: "columnar.onnx",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "onnx",
        name: "ONNX model",
        family: "columnar",
        mimes: &[],
        extensions: &["onnx"],
        magic: &[],
        parent: None,
    }],
};

/// Bytes read of one node or value info.
const MAX_SMALL: u64 = 1 << 20;
/// Bytes read from the start of an initializer (its header, not its data).
const INIT_HEAD: u64 = 64 << 10;
/// Fields walked in the graph.
const MAX_FIELDS: u64 = 5_000_000;
/// Inputs and outputs listed.
const MAX_IO: usize = 100;

/// One field of a message read through the source.
struct Field {
    number: u32,
    wire: u8,
    /// Varint value, or the payload offset for wire type 2.
    value: u64,
    len: u64,
}

fn varint(buf: &[u8], i: &mut usize) -> Option<u64> {
    protowire::varint(buf, i)
}

/// The field at `*at` (before `end`), advancing past it.
fn next(src: &mut dyn Source, at: &mut u64, end: u64) -> Option<Field> {
    if *at >= end {
        return None;
    }
    let n = usize::try_from((end - *at).min(24)).ok()?;
    let buf = src.read_vec(*at, n).ok()?;
    let mut i = 0;
    let key = varint(&buf, &mut i)?;
    let number = u32::try_from(key >> 3).ok().filter(|&n| n > 0)?;
    let wire = u8::try_from(key & 7).ok()?;
    let f = match wire {
        0 => Field { number, wire, value: varint(&buf, &mut i)?, len: 0 },
        1 => {
            i += 8;
            Field { number, wire, value: 0, len: 8 }
        }
        2 => {
            let len = varint(&buf, &mut i)?;
            let start = *at + i as u64;
            if start.checked_add(len)? > end {
                return None;
            }
            *at = start + len;
            return Some(Field { number, wire, value: start, len });
        }
        5 => {
            i += 4;
            Field { number, wire, value: 0, len: 4 }
        }
        _ => return None,
    };
    *at += i as u64;
    Some(f)
}

fn read(src: &mut dyn Source, f: &Field, max: u64) -> Option<Vec<u8>> {
    src.read_vec(f.value, usize::try_from(f.len.min(max)).ok()?).ok()
}

fn elem_type(t: u64) -> String {
    let s = match t {
        1 => "float32",
        2 => "uint8",
        3 => "int8",
        4 => "uint16",
        5 => "int16",
        6 => "int32",
        7 => "int64",
        8 => "string",
        9 => "bool",
        10 => "float16",
        11 => "float64",
        12 => "uint32",
        13 => "uint64",
        14 => "complex64",
        15 => "complex128",
        16 => "bfloat16",
        17 => "float8e4m3fn",
        18 => "float8e4m3fnuz",
        19 => "float8e5m2",
        20 => "float8e5m2fnuz",
        21 => "uint4",
        22 => "int4",
        23 => "float4e2m1",
        _ => return format!("type {t}"),
    };
    s.to_string()
}

/// A `ValueInfoProto` as `name` and `type[shape]`.
fn value_info(v: &[u8]) -> Option<(String, String)> {
    let name = protowire::first(v, 1).and_then(Wire::text)?;
    let t = protowire::first(v, 2).and_then(Wire::bytes);
    let kind = match t.and_then(|t| protowire::fields(t).next()) {
        Some((1, Wire::Bytes(tensor))) => {
            let et = protowire::first(tensor, 1).and_then(Wire::int).map_or_else(|| "?".into(), elem_type);
            let dims: Vec<String> = protowire::first(tensor, 2)
                .and_then(Wire::bytes)
                .map(|shape| {
                    protowire::all(shape, 1)
                        .filter_map(Wire::bytes)
                        .take(16)
                        .map(|d| match protowire::fields(d).next() {
                            Some((1, Wire::Varint(n))) => n.cast_signed().to_string(),
                            Some((2, Wire::Bytes(p))) => String::from_utf8_lossy(p).into_owned(),
                            _ => "?".into(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            format!("{et}[{}]", dims.join(", "))
        }
        Some((4, _)) => "sequence".into(),
        Some((5, _)) => "map".into(),
        Some((9, _)) => "optional".into(),
        Some((8, _)) => "sparse_tensor".into(),
        _ => "?".into(),
    };
    Some((truncate_chars(&name, 200), truncate_chars(&kind, 200)))
}

#[derive(Default)]
struct Graph {
    name: Option<String>,
    ops: BTreeMap<String, u64>,
    nodes: u64,
    inputs: Vec<(String, String)>,
    outputs: Vec<(String, String)>,
    initializers: usize,
    params: u64,
    types: BTreeMap<String, u64>,
    external: u64,
    init_names: std::collections::BTreeSet<String>,
}

fn graph(cx: &mut Context<'_>, src: &mut dyn Source, start: u64, end: u64, g: &mut Graph) -> Result<(), ExtractError> {
    let mut at = start;
    let mut walked = 0u64;
    while let Some(f) = next(src, &mut at, end) {
        walked += 1;
        if walked.is_multiple_of(4096) {
            cx.checkpoint()?;
        }
        if walked > MAX_FIELDS {
            cx.warn("graph field limit reached");
            break;
        }
        if f.wire != 2 {
            continue;
        }
        match f.number {
            1 => {
                g.nodes += 1;
                if let Some(n) = read(src, &f, MAX_SMALL) {
                    let op = protowire::first(&n, 4).and_then(Wire::text).unwrap_or_default();
                    let domain =
                        protowire::first(&n, 7).and_then(Wire::text).filter(|d| !d.is_empty() && d != "ai.onnx");
                    let key = domain.map_or_else(|| op.clone(), |d| format!("{d}.{op}"));
                    *g.ops.entry(truncate_chars(&key, 100)).or_default() += 1;
                }
            }
            2 => g.name = read(src, &f, 4096).map(|b| String::from_utf8_lossy(&b).into_owned()),
            5 => {
                g.initializers += 1;
                let Some(t) = read(src, &f, INIT_HEAD) else { continue };
                let dims: Vec<u64> = protowire::all(&t, 1).flat_map(protowire::packed).collect();
                g.params = g.params.saturating_add(product(&dims));
                let et = protowire::first(&t, 2).and_then(Wire::int).map_or_else(|| "?".into(), elem_type);
                *g.types.entry(et).or_default() += 1;
                if protowire::first(&t, 14).and_then(Wire::int) == Some(1) {
                    g.external += 1;
                }
                if let Some(n) = protowire::first(&t, 8).and_then(Wire::text)
                    && g.init_names.len() < 100_000
                {
                    g.init_names.insert(n);
                }
            }
            11 | 12 => {
                let Some(v) = read(src, &f, MAX_SMALL) else { continue };
                let list = if f.number == 11 { &mut g.inputs } else { &mut g.outputs };
                if list.len() < 10_000
                    && let Some(io) = value_info(&v)
                {
                    list.push(io);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

impl Extractor for Onnx {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // ModelProto starts with ir_version (field 1, varint) and is followed
        // by producer, opsets or the graph.
        let h = probe.head;
        let ok = probe.extension == Some("onnx")
            && h.first() == Some(&0x08)
            && protowire::fields(h.get(..h.len().min(64))?).take(2).count() >= 1;
        ok.then_some(Sniff { format: "onnx", confidence: 0.95 })
    }

    #[allow(clippy::too_many_lines)] // the model fields, then the graph
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let end = src.len();
        let mut at = 0u64;
        let mut g = Graph::default();
        let mut opsets = Map::new();
        let mut props = Map::new();
        let mut functions = 0u64;
        let mut seen = false;
        while let Some(f) = next(src, &mut at, end) {
            seen = true;
            match (f.number, f.wire) {
                (1, 0) => cx.format_set("ir_version", f.value),
                (5, 0) => cx.format_set("model_version", f.value.cast_signed()),
                (2 | 3 | 4 | 6, 2) => {
                    let Some(b) = read(src, &f, 64 << 10) else { continue };
                    let s = String::from_utf8_lossy(&b).into_owned();
                    let key = match f.number {
                        2 => "producer",
                        3 => "producer_version",
                        4 => "domain",
                        _ => "doc_string",
                    };
                    if f.number == 6 {
                        cx.content().source("onnx.doc_string").description(truncate_chars(&s, 1000));
                    }
                    cx.format_set(key, truncate_chars(&s, if f.number == 6 { 1000 } else { 200 }));
                }
                (7, 2) => graph(cx, src, f.value, f.value + f.len, &mut g)?,
                (8, 2) => {
                    let Some(b) = read(src, &f, MAX_SMALL) else { continue };
                    let d = protowire::first(&b, 1)
                        .and_then(Wire::text)
                        .filter(|d| !d.is_empty())
                        .unwrap_or_else(|| "ai.onnx".into());
                    let v = protowire::first(&b, 2).and_then(Wire::int).unwrap_or(0);
                    if opsets.len() < 100 {
                        opsets.insert(truncate_chars(&d, 100), v.into());
                    }
                }
                (14, 2) => {
                    let Some(b) = read(src, &f, MAX_SMALL) else { continue };
                    if let Some(k) = protowire::first(&b, 1).and_then(Wire::text)
                        && props.len() < 100
                    {
                        let v = protowire::first(&b, 2).and_then(Wire::text).unwrap_or_default();
                        props
                            .insert(truncate_chars(&k, 100), Value::String(truncate_chars(&redact_sensitive(&v), 500)));
                    }
                }
                (25, 2) => functions += 1,
                _ => {}
            }
        }
        if !seen {
            return Err(ExtractError::malformed("ModelProto"));
        }
        if !opsets.is_empty() {
            cx.format_set("opsets", Value::Object(opsets));
        }
        if let Some(n) = &g.name {
            cx.format_set("graph", truncate_chars(n, 200));
        }
        cx.format_set("nodes", g.nodes);
        cx.format_set("operators", histogram(g.ops, 50));
        // Graph inputs that are initializers are weights, not inputs.
        let io = |list: &[(String, String)], skip: &std::collections::BTreeSet<String>| -> Value {
            Value::Object(
                list.iter()
                    .filter(|(n, _)| !skip.contains(n))
                    .take(MAX_IO)
                    .map(|(n, t)| (n.clone(), Value::String(t.clone())))
                    .collect(),
            )
        };
        cx.format_set("inputs", io(&g.inputs, &g.init_names));
        cx.format_set("outputs", io(&g.outputs, &std::collections::BTreeSet::new()));
        tensors(cx, g.initializers, g.params, g.types);
        if g.external > 0 {
            cx.format_set("external_tensors", g.external);
        }
        if functions > 0 {
            cx.format_set("functions", functions);
        }
        if !props.is_empty() {
            if let Some(a) = props.get("author").and_then(Value::as_str) {
                cx.content().source("onnx.metadata_props.author").author(a.to_string());
            }
            cx.format_set("metadata", Value::Object(props));
        }
        Ok(())
    }
}

crate::register_extractor!(Onnx);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_infos() {
        // name "x", tensor_type {elem_type 1, shape {dim {dim_param "batch"}, dim {dim_value 4}}}
        let v = [
            0x0a, 1, b'x', 0x12, 19, 0x0a, 17, 0x08, 1, 0x12, 13, 0x0a, 7, 0x12, 5, b'b', b'a', b't', b'c', b'h', 0x0a,
            2, 0x08, 4,
        ];
        assert_eq!(value_info(&v), Some(("x".into(), "float32[batch, 4]".into())));
        assert_eq!(elem_type(16), "bfloat16");
    }

    crate::fixture_tests!("onnx");
}
