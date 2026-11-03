//! PyTorch checkpoints (`torch.save`), never unpickled:
//! * the ZIP format (1.6+): archive name, serialisation version, byte
//!   order, tensor storages (count and bytes), TorchScript code, and the
//!   globals of `data.pkl` (what it holds: state dict, module, optimizer
//!   state, storage types);
//! * the legacy format: the magic number and protocol pickles, then the
//!   globals of the object pickle.
//!
//! Globals that run code when loaded report `unsafe_deserialization`, as
//! for plain pickles.
//!
//! Specification: PyTorch `torch/serialization.py` (`_save`,
//! `_legacy_save`) and `torch/csrc/jit/serialization` (TorchScript archives).

use std::collections::BTreeSet;

use super::super::pickle::{imports, is_unsafe};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, Zip, truncate_chars,
    zip_names,
};

/// Extractor for PyTorch checkpoints.
pub struct Torch;

static META: ExtractorMeta = ExtractorMeta {
    id: "columnar.torch",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "pytorch",
        name: "PyTorch checkpoint",
        family: "columnar",
        mimes: &[],
        extensions: &["pt", "pth", "ckpt"],
        magic: &[],
        parent: None,
    }],
};

/// ZIP entries listed.
const MAX_ENTRIES: usize = 200_000;
/// Bytes of `data.pkl` walked.
const MAX_PICKLE: usize = 64 << 20;
/// Globals listed.
const MAX_GLOBALS: usize = 100;

/// The legacy format's first pickle: the magic number as a `LONG1`.
const LEGACY: &[u8] = b"\x80\x02\x8a\x0a\x6c\xfc\x9c\x46\xf9\x20\x6a\xa8\x50\x19";

/// What the globals say a checkpoint holds.
fn holds(globals: &[String]) -> Vec<&'static str> {
    let mut out = BTreeSet::new();
    for g in globals {
        let k = match g.as_str() {
            "collections.OrderedDict" => "state_dict",
            "torch._utils._rebuild_tensor_v2" | "torch._utils._rebuild_tensor" => "tensors",
            "torch._utils._rebuild_parameter" => "parameters",
            "torch.nn.modules.module.Module" => "module",
            s if s.starts_with("torch.nn.modules.") => "module",
            s if s.starts_with("torch.optim.") => "optimizer",
            s if s.starts_with("numpy.") => "numpy_arrays",
            _ => continue,
        };
        out.insert(k);
    }
    out.into_iter().collect()
}

/// Storage types named by the globals (`torch.FloatStorage` → `float32`).
fn dtypes(globals: &[String]) -> Vec<String> {
    globals
        .iter()
        .filter_map(|g| g.strip_prefix("torch.").and_then(|s| s.strip_suffix("Storage")))
        .filter(|s| !s.is_empty() && !s.contains('.') && *s != "Untyped" && *s != "Typed")
        .map(|s| {
            match s {
                "Float" => "float32",
                "Double" => "float64",
                "Half" => "float16",
                "BFloat16" => "bfloat16",
                "Long" => "int64",
                "Int" => "int32",
                "Short" => "int16",
                "Char" => "int8",
                "Byte" => "uint8",
                "Bool" => "bool",
                "ComplexFloat" => "complex64",
                "ComplexDouble" => "complex128",
                other => other,
            }
            .to_string()
        })
        .collect()
}

fn globals(cx: &mut Context<'_>, data: &[u8]) {
    let (protocol, globals) = imports(data);
    if let Some(p) = protocol {
        cx.format_set("pickle_protocol", p);
    }
    let h = holds(&globals);
    if !h.is_empty() {
        cx.format_set("holds", h);
    }
    let d = dtypes(&globals);
    if !d.is_empty() {
        cx.format_set("storage_types", d);
    }
    if !globals.is_empty() {
        cx.format_set("globals", globals.iter().take(MAX_GLOBALS).map(|g| truncate_chars(g, 200)).collect::<Vec<_>>());
    }
    let bad: Vec<&str> = globals.iter().map(String::as_str).filter(|g| is_unsafe(g)).collect();
    if !bad.is_empty() {
        cx.security().risk("unsafe_deserialization", Some(truncate_chars(&bad.join(", "), 300)));
    }
}

fn zipped(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let zip = Zip::open(src, MAX_ENTRIES)?;
    let pkl = zip
        .entries
        .iter()
        .find(|e| e.name.ends_with("/data.pkl") && e.name.matches('/').count() == 1)
        .ok_or_else(|| ExtractError::malformed("no data.pkl"))?
        .clone();
    let archive = pkl.name.trim_end_matches("/data.pkl").to_string();
    cx.format_set("format", "zip");
    cx.format_set("archive", truncate_chars(&archive, 200));
    let prefix = format!("{archive}/");
    for (name, key) in
        [("version", "serialization_version"), (".data/version", "serialization_version"), ("byteorder", "byte_order")]
    {
        if let Some(Ok(t)) = zip.read_text(src, &format!("{prefix}{name}"), cx, 64) {
            cx.format_set(key, truncate_chars(t.trim(), 20));
        }
    }
    let data = format!("{prefix}data/");
    let (mut storages, mut bytes) = (0u64, 0u64);
    for e in zip.under(&data) {
        storages += 1;
        bytes = bytes.saturating_add(e.size);
    }
    cx.format_set("storages", storages);
    cx.format_set("storage_bytes", bytes);
    if zip.entries.iter().any(|e| e.name.starts_with(&format!("{prefix}code/"))) {
        cx.format_set("torchscript", true);
    }
    if zip.find(&format!("{prefix}constants.pkl")).is_some() {
        cx.format_set("constants", true);
    }
    let (p, _) = zip.read_prefix(src, &pkl, cx, MAX_PICKLE.min(cx.parse_limit()))?;
    globals(cx, &p);
    Ok(())
}

impl Extractor for Torch {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if probe.head.starts_with(LEGACY) {
            return Some(Sniff { format: "pytorch", confidence: 0.98 });
        }
        // A ZIP whose first-level `data.pkl` sits next to `version` or `data/`.
        let names = zip_names(probe, 2000);
        let archive = names.iter().find_map(|n| n.strip_suffix("/data.pkl").filter(|a| !a.contains('/')))?;
        let marked = names.iter().any(|n| {
            n.strip_prefix(archive).is_some_and(|r| r == "/version" || r == "/.data/version" || r.starts_with("/data/"))
        });
        marked.then_some(Sniff { format: "pytorch", confidence: 0.98 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if src.head().starts_with(b"PK") {
            return zipped(cx, src);
        }
        // Legacy: magic, protocol version, system info, the object, storage keys, storages.
        let (b, _) = cx.read_bytes(src)?;
        cx.format_set("format", "legacy");
        globals(cx, &b);
        Ok(())
    }
}

crate::register_extractor!(Torch);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_type_names() {
        let g = vec![
            "torch.FloatStorage".to_string(),
            "collections.OrderedDict".to_string(),
            "torch.UntypedStorage".to_string(),
        ];
        assert_eq!(dtypes(&g), vec!["float32"]);
        assert_eq!(holds(&g), vec!["state_dict"]);
    }

    crate::fixture_tests!("pytorch");
}
