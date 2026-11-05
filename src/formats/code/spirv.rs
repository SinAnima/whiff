//! SPIR-V shader modules (`.spv`): version, generator (the tool that wrote
//! the module), ID bound, capabilities, extensions, imported instruction
//! sets, addressing and memory model, entry points (execution model, name,
//! workgroup size), source language, and counts of functions, debug names
//! and instructions. Debug strings (`OpString`, usually source file paths)
//! are counted, never listed.
//!
//! Specification: Khronos "SPIR-V Specification" 1.6, sections 2.3–2.4 and 3.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for SPIR-V modules.
pub struct Spirv;

static META: ExtractorMeta = ExtractorMeta {
    id: "code.spirv",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "spirv",
        name: "SPIR-V binary",
        family: "code.source",
        mimes: &["application/x-spirv"],
        extensions: &["spv", "spirv"],
        magic: &[Magic::prefix(b"\x03\x02\x23\x07"), Magic::prefix(b"\x07\x23\x02\x03")],
        parent: None,
    }],
};

/// Instructions walked at most.
const MAX_INSTRUCTIONS: u64 = 4_000_000;
/// Entries listed per field.
const MAX_LISTED: usize = 100;

impl Extractor for Spirv {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, _) = cx.read_bytes(src)?;
        if data.len() < 20 {
            return Err(ExtractError::Truncated { offset: 0, needed: 20 });
        }
        let big = data.starts_with(b"\x07\x23\x02\x03");
        let words: Vec<u32> = data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| if big { u32::from_be_bytes(*b) } else { u32::from_le_bytes(*b) })
            .collect();
        let (version, generator, bound) = (words[1], words[2], words[3]);
        cx.format_set("version", format!("{}.{}", (version >> 16) & 0xff, (version >> 8) & 0xff));
        cx.format_set("byte_order", if big { "big" } else { "little" });
        let tool = generator >> 16;
        let mut g = Map::new();
        g.insert("tool_id".into(), json!(tool));
        if let Some(name) = generator_name(tool) {
            g.insert("tool".into(), json!(name));
        }
        g.insert("tool_version".into(), json!(generator & 0xffff));
        cx.format_set("generator", Value::Object(g));
        cx.format_set("id_bound", bound);
        if data.len() % 4 != 0 {
            cx.warn("length is not a multiple of 4");
        }
        walk(&words[5..], cx)
    }
}

crate::register_extractor!(Spirv);

#[derive(Default)]
struct Module {
    capabilities: BTreeSet<String>,
    extensions: Vec<String>,
    imports: Vec<String>,
    entry_points: Vec<(u32, Map<String, Value>)>,
    local_sizes: Vec<(u32, [u32; 3])>,
    processed: Vec<String>,
    source_extensions: Vec<String>,
    functions: u64,
    names: u64,
    strings: u64,
    instructions: u64,
}

fn walk(words: &[u32], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut m = Module::default();
    let mut at = 0;
    while at < words.len() {
        let (count, opcode) = ((words[at] >> 16) as usize, words[at] & 0xffff);
        if count == 0 || at + count > words.len() {
            cx.warn(format!("instruction at word {} runs past the end", at + 5));
            break;
        }
        let ops = &words[at + 1..at + count];
        m.instructions += 1;
        if m.instructions > MAX_INSTRUCTIONS {
            cx.warn("instruction limit reached");
            break;
        }
        if m.instructions.is_multiple_of(65_536) {
            cx.checkpoint()?;
        }
        match opcode {
            3 => {
                if let Some(&lang) = ops.first() {
                    cx.format_set("source_language", source_language(lang));
                }
                if let Some(&v) = ops.get(1) {
                    cx.format_set("source_version", v);
                }
            }
            4 => push(&mut m.source_extensions, string(ops)),
            5 => m.names += 1,
            7 => m.strings += 1,
            10 => push(&mut m.extensions, string(ops)),
            11 => push(&mut m.imports, string(ops.get(1..).unwrap_or_default())),
            14 => {
                if let [addressing, memory, ..] = ops {
                    cx.format_set("addressing_model", addressing_model(*addressing));
                    cx.format_set("memory_model", memory_model(*memory));
                }
            }
            15 => {
                if let [model, id, rest @ ..] = ops
                    && m.entry_points.len() < MAX_LISTED
                {
                    let mut e = Map::new();
                    e.insert("name".into(), json!(string(rest)));
                    e.insert("execution_model".into(), json!(execution_model(*model)));
                    m.entry_points.push((*id, e));
                }
            }
            // OpExecutionMode LocalSize.
            16 => {
                if let [id, 17, x, y, z, ..] = ops {
                    m.local_sizes.push((*id, [*x, *y, *z]));
                }
            }
            17 => {
                if let Some(&c) = ops.first()
                    && m.capabilities.len() < MAX_LISTED
                {
                    m.capabilities.insert(capability(c));
                }
            }
            54 => m.functions += 1,
            330 => push(&mut m.processed, string(ops)),
            _ => {}
        }
        at += count;
    }
    report(m, cx);
    Ok(())
}

fn report(m: Module, cx: &mut Context<'_>) {
    let entry_points: Vec<Value> = m
        .entry_points
        .into_iter()
        .map(|(id, mut e)| {
            if let Some((_, size)) = m.local_sizes.iter().find(|(i, _)| *i == id) {
                e.insert("local_size".into(), json!(size));
            }
            Value::Object(e)
        })
        .collect();
    for (key, list) in [
        ("capabilities", m.capabilities.into_iter().collect::<Vec<_>>()),
        ("extensions", m.extensions),
        ("ext_inst_imports", m.imports),
        ("source_extensions", m.source_extensions),
        ("module_processed", m.processed),
    ] {
        if !list.is_empty() {
            cx.format_set(key, json!(list));
        }
    }
    if !entry_points.is_empty() {
        cx.format_set("entry_points", Value::Array(entry_points));
    }
    cx.format_set("functions", m.functions);
    cx.format_set("debug_names", m.names);
    if m.strings > 0 {
        cx.format_set("debug_strings", m.strings);
    }
    cx.format_set("instructions", m.instructions);
}

fn push(list: &mut Vec<String>, s: String) {
    if list.len() < MAX_LISTED && !s.is_empty() && !list.contains(&s) {
        list.push(s);
    }
}

/// A literal string: UTF-8 packed four bytes per word, low byte first, NUL-terminated.
fn string(words: &[u32]) -> String {
    let mut bytes = Vec::new();
    'words: for w in words {
        for b in w.to_le_bytes() {
            if b == 0 {
                break 'words;
            }
            bytes.push(b);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Tools registered in the Khronos SPIR-V registry (`spir-v.xml`).
fn generator_name(id: u32) -> Option<&'static str> {
    Some(match id {
        0 => "Khronos",
        1 => "LunarG",
        2 => "Valve",
        3 => "Codeplay",
        4 => "NVIDIA",
        5 => "ARM",
        6 => "Khronos LLVM/SPIR-V Translator",
        7 => "Khronos SPIR-V Tools Assembler",
        8 => "Khronos Glslang Reference Front End",
        13 => "Google Shaderc over Glslang",
        14 => "Google spiregg",
        15 => "Google rspirv",
        17 => "Khronos SPIR-V Tools Linker",
        21 => "Google Clspv",
        22 => "Google MLIR SPIR-V Serializer",
        23 => "Google Tint Compiler",
        27 => "Embark Studios Rust GPU Compiler Backend",
        28 => "gfx-rs community Naga",
        _ => return None,
    })
}

fn source_language(v: u32) -> Value {
    let name = match v {
        0 => "Unknown",
        1 => "ESSL",
        2 => "GLSL",
        3 => "OpenCL_C",
        4 => "OpenCL_CPP",
        5 => "HLSL",
        6 => "CPP_for_OpenCL",
        7 => "SYCL",
        8 => "HERO_C",
        9 => "NZSL",
        10 => "WGSL",
        11 => "Slang",
        12 => "Zig",
        _ => return json!(v),
    };
    json!(name)
}

fn execution_model(v: u32) -> Value {
    let name = match v {
        0 => "Vertex",
        1 => "TessellationControl",
        2 => "TessellationEvaluation",
        3 => "Geometry",
        4 => "Fragment",
        5 => "GLCompute",
        6 => "Kernel",
        5267 => "TaskNV",
        5268 => "MeshNV",
        5313 => "RayGenerationKHR",
        5314 => "IntersectionKHR",
        5315 => "AnyHitKHR",
        5316 => "ClosestHitKHR",
        5317 => "MissKHR",
        5318 => "CallableKHR",
        5364 => "TaskEXT",
        5365 => "MeshEXT",
        _ => return json!(v),
    };
    json!(name)
}

fn addressing_model(v: u32) -> Value {
    match v {
        0 => json!("Logical"),
        1 => json!("Physical32"),
        2 => json!("Physical64"),
        5348 => json!("PhysicalStorageBuffer64"),
        _ => json!(v),
    }
}

fn memory_model(v: u32) -> Value {
    match v {
        0 => json!("Simple"),
        1 => json!("GLSL450"),
        2 => json!("OpenCL"),
        3 => json!("Vulkan"),
        _ => json!(v),
    }
}

fn capability(v: u32) -> String {
    match v {
        0 => "Matrix",
        1 => "Shader",
        2 => "Geometry",
        3 => "Tessellation",
        4 => "Addresses",
        5 => "Linkage",
        6 => "Kernel",
        9 => "Float16",
        10 => "Float64",
        11 => "Int64",
        22 => "Int16",
        39 => "Int8",
        _ => return v.to_string(),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_unpack() {
        let w = [u32::from_le_bytes(*b"GLSL"), u32::from_le_bytes(*b".std"), u32::from_le_bytes(*b".450"), 0];
        assert_eq!(string(&w), "GLSL.std.450");
        assert_eq!(string(&[u32::from_le_bytes(*b"ab\0\0")]), "ab");
        assert_eq!(string(&[]), "");
    }

    crate::fixture_tests!("spirv");
}
