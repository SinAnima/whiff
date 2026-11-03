//! HDF5 files and the layouts built on them:
//! * any HDF5 file: superblock version, user block, groups and datasets
//!   (paths, shapes, types, layouts, chunking, filters), the root
//!   attributes, links, and the layout it follows (NetCDF-4, AnnData,
//!   Loom, MATLAB 7.3, Keras, HDF-EOS5, NeXus);
//! * NetCDF-4 (also the classic model): the library versions, then the
//!   NetCDF data model (dimensions, variables, global attributes, CF);
//! * AnnData `.h5ad`: observations and variables, the encoding of `X`, the
//!   annotation columns, layers, `obsm` / `varm` / `obsp` / `varp` / `uns`;
//! * Loom: the matrix shape, row and column attributes, layers, graphs;
//! * MATLAB 7.3 MAT-files: the header text and the variables with their
//!   MATLAB classes and sizes.
//!
//! Specifications: see `h5.rs`; NetCDF-4 "Format Specification" (dimension
//! scales, `_NCProperties`); anndata "On-disk format"; Loom file format
//! specification 3.0; MathWorks "MAT-File Versions".

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::h5::{self, Dataset, File, attr};
use super::netcdf::{self, Dim, Model, Var};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, redact_sensitive,
    truncate_chars,
};

/// Extractor for HDF5 files and their layouts.
pub struct Hdf5;

const SIG: &[u8] = h5::SIGNATURE;

static META: ExtractorMeta = ExtractorMeta {
    id: "science.hdf5",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "hdf5",
            name: "HDF5",
            family: "sci",
            mimes: &["application/x-hdf5"],
            extensions: &["h5", "hdf5", "he5"],
            magic: &[Magic::at(0, SIG), Magic::at(512, SIG), Magic::at(1024, SIG), Magic::at(2048, SIG)],
            parent: None,
        },
        FormatSpec {
            id: "netcdf4",
            name: "NetCDF-4",
            family: "sci",
            mimes: &["application/x-netcdf"],
            extensions: &["nc", "nc4"],
            magic: &[Magic::at(0, SIG)],
            parent: Some("hdf5"),
        },
        FormatSpec {
            id: "h5ad",
            name: "AnnData (h5ad)",
            family: "sci",
            mimes: &[],
            extensions: &["h5ad"],
            magic: &[Magic::at(0, SIG)],
            parent: Some("hdf5"),
        },
        FormatSpec {
            id: "loom",
            name: "Loom",
            family: "sci",
            mimes: &[],
            extensions: &["loom"],
            magic: &[Magic::at(0, SIG)],
            parent: Some("hdf5"),
        },
        FormatSpec {
            id: "mat73",
            name: "MATLAB MAT",
            family: "sci",
            mimes: &["application/x-matlab-data"],
            extensions: &["mat"],
            magic: &[Magic::at(0, b"MATLAB 7.3 MAT-file")],
            parent: Some("hdf5"),
        },
    ],
};

/// Datasets and groups listed.
const MAX_LIST: usize = 200;

fn has(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

fn shown(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(truncate_chars(&redact_sensitive(s), 500)),
        Value::Array(a) if a.len() > 16 => Value::String(format!("({} values)", a.len())),
        other => other.clone(),
    }
}

fn attrs_map(attrs: &[(String, Value)]) -> Value {
    Value::Object(attrs.iter().take(100).map(|(k, v)| (truncate_chars(k, 100), shown(v))).collect())
}

fn text(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Array(a) => a.first().and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

fn strings(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(|s| truncate_chars(s, 200)).collect(),
        Some(Value::String(s)) => vec![truncate_chars(s, 200)],
        _ => Vec::new(),
    }
}

/// The layout a file follows (by its structure), as a format id or name.
fn layout(f: &File) -> Option<&'static str> {
    let root = f.group("/")?;
    let ra = &root.attrs;
    if attr(ra, "_NCProperties").is_some()
        || f.datasets.iter().any(|d| attr(&d.attrs, "CLASS").and_then(Value::as_str) == Some("DIMENSION_SCALE"))
    {
        return Some("netcdf4");
    }
    if text(attr(ra, "encoding-type")).as_deref() == Some("anndata") {
        return Some("h5ad");
    }
    if f.dataset("/matrix").is_some() && f.group("/row_attrs").is_some() && f.group("/col_attrs").is_some() {
        return Some("loom");
    }
    if f.userblock >= 128 && f.datasets.iter().any(|d| attr(&d.attrs, "MATLAB_class").is_some()) {
        return Some("mat73");
    }
    if attr(ra, "keras_version").is_some() || attr(ra, "model_config").is_some() {
        return Some("keras");
    }
    if f.group("/HDFEOS INFORMATION").is_some() {
        return Some("hdf_eos5");
    }
    if f.groups.iter().any(|g| attr(&g.attrs, "NX_class").is_some()) {
        return Some("nexus");
    }
    None
}

fn shape_text(d: &Dataset) -> String {
    if d.shape.is_empty() {
        return "scalar".into();
    }
    d.shape
        .iter()
        .zip(&d.max)
        .map(|(n, m)| if *m == u64::MAX { format!("{n}+") } else { n.to_string() })
        .collect::<Vec<_>>()
        .join("x")
}

fn generic(cx: &mut Context<'_>, f: &File) {
    cx.format_set("superblock_version", f.superblock);
    if f.userblock > 0 {
        cx.format_set("userblock_bytes", f.userblock);
    }
    cx.format_set("groups", f.groups.len());
    cx.format_set("datasets", f.datasets.len());
    if let Some(root) = f.group("/").filter(|r| !r.attrs.is_empty()) {
        cx.format_set("root_attributes", attrs_map(&root.attrs));
    }
    let mut list = Vec::new();
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut filters: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for d in &f.datasets {
        let t = d.dtype.as_ref().map_or_else(|| "?".into(), h5::DType::name);
        *types.entry(t.clone()).or_default() += 1;
        filters.extend(d.filters.iter().cloned());
        if list.len() < MAX_LIST {
            let mut m = Map::new();
            m.insert("path".into(), truncate_chars(&d.path, 300).into());
            m.insert("shape".into(), shape_text(d).into());
            m.insert("type".into(), t.into());
            if !d.layout.is_empty() {
                m.insert("layout".into(), d.layout.into());
            }
            if !d.chunks.is_empty() {
                m.insert("chunks".into(), d.chunks.iter().map(u64::to_string).collect::<Vec<_>>().join("x").into());
            }
            if !d.filters.is_empty() {
                m.insert("filters".into(), d.filters.clone().into());
            }
            list.push(Value::Object(m));
        }
    }
    cx.format_set("dataset_list", list);
    let groups: Vec<String> =
        f.groups.iter().filter(|g| g.path != "/").take(MAX_LIST).map(|g| truncate_chars(&g.path, 300)).collect();
    if !groups.is_empty() {
        cx.format_set("group_list", groups);
    }
    let m: Map<String, Value> = types.into_iter().map(|(k, v)| (k, v.into())).collect();
    cx.format_set("types", Value::Object(m));
    if !filters.is_empty() {
        cx.format_set("filters", filters.into_iter().collect::<Vec<_>>());
    }
    let links: usize = f.groups.iter().map(|g| g.links.len()).sum();
    if links > 0 {
        cx.format_set("soft_links", links);
    }
    if f.skipped > 0 {
        cx.warn(format!("{} objects not read (limits or unreadable headers)", f.skipped));
    }
}

/// CDL type names for HDF5 types (NetCDF-4).
fn cdl(t: Option<&h5::DType>) -> String {
    use h5::DType::{Float, Int, Str, VlenStr};
    match t {
        Some(Int { size: 1, signed: true, .. }) => "byte".into(),
        Some(Int { size: 1, signed: false, .. }) => "ubyte".into(),
        Some(Int { size: 2, signed, .. }) => if *signed { "short" } else { "ushort" }.into(),
        Some(Int { size: 4, signed, .. }) => if *signed { "int" } else { "uint" }.into(),
        Some(Int { size: 8, signed, .. }) => if *signed { "int64" } else { "uint64" }.into(),
        Some(Float { size: 4, .. }) => "float".into(),
        Some(Float { size: 8, .. }) => "double".into(),
        Some(Str { .. }) => "char".into(),
        Some(VlenStr) => "string".into(),
        Some(other) => other.name(),
        None => "?".into(),
    }
}

/// Attributes netCDF-4 uses for its own bookkeeping.
const NC_INTERNAL: [&str; 9] = [
    "CLASS",
    "NAME",
    "REFERENCE_LIST",
    "DIMENSION_LIST",
    "_Netcdf4Dimid",
    "_Netcdf4Coordinates",
    "_NCProperties",
    "_nc3_strict",
    "_SuperblockVersion",
];

fn base(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

fn netcdf4(cx: &mut Context<'_>, f: &File) {
    let root = f.group("/");
    if let Some(p) = root.and_then(|r| text(attr(&r.attrs, "_NCProperties"))) {
        // "version=2,netcdf=4.9.2,hdf5=1.14.3"
        for part in p.split(',') {
            if let Some((k, v)) = part.split_once('=') {
                match k {
                    "netcdf" => cx.format_set("netcdf_version", truncate_chars(v, 50)),
                    "hdf5" => cx.format_set("hdf5_version", truncate_chars(v, 50)),
                    _ => {}
                }
            }
        }
    }
    if root.is_some_and(|r| attr(&r.attrs, "_nc3_strict").is_some()) {
        cx.format_set("classic_model", true);
    }
    let mut m = Model::default();
    let not_var = "This is a netCDF dimension but not a netCDF variable";
    for d in &f.datasets {
        if attr(&d.attrs, "CLASS").and_then(Value::as_str) == Some("DIMENSION_SCALE") {
            m.dims.push(Dim {
                name: base(&d.path),
                len: d.shape.first().copied().unwrap_or(0),
                unlimited: d.max.first() == Some(&u64::MAX),
            });
            if text(attr(&d.attrs, "NAME")).is_some_and(|n| n.starts_with(not_var)) {
                continue;
            }
        }
        // Dimension names from DIMENSION_LIST references; a coordinate
        // variable is its own dimension.
        let dims: Vec<String> = match attr(&d.attrs, "DIMENSION_LIST") {
            Some(Value::Array(list)) => list
                .iter()
                .map(|refs| {
                    let a = refs.as_array().and_then(|r| r.first()).and_then(Value::as_u64).or_else(|| refs.as_u64());
                    a.and_then(|a| f.paths.get(&a)).map_or_else(|| "?".into(), |p| base(p))
                })
                .collect(),
            _ if attr(&d.attrs, "CLASS").and_then(Value::as_str) == Some("DIMENSION_SCALE") => vec![base(&d.path)],
            _ => Vec::new(),
        };
        let attrs = d.attrs.iter().filter(|(n, _)| !NC_INTERNAL.contains(&n.as_str())).cloned().collect();
        m.vars.push(Var { name: d.path.trim_start_matches('/').to_string(), kind: cdl(d.dtype.as_ref()), dims, attrs });
    }
    m.attrs = root
        .map(|r| r.attrs.iter().filter(|(n, _)| !NC_INTERNAL.contains(&n.as_str())).cloned().collect())
        .unwrap_or_default();
    let subgroups = f.groups.iter().filter(|g| g.path != "/").count();
    if subgroups > 0 {
        cx.format_set("netcdf_groups", subgroups);
    }
    netcdf::describe(cx, &m);
}

/// Rows of an AnnData annotation frame (its index length).
fn frame_rows(f: &File, g: &str) -> Option<u64> {
    let group = f.group(g)?;
    let index = text(attr(&group.attrs, "_index")).unwrap_or_else(|| "_index".into());
    f.dataset(&format!("{g}/{index}")).and_then(|d| d.shape.first().copied())
}

fn h5ad(cx: &mut Context<'_>, f: &File) {
    if let Some(v) = f.group("/").and_then(|r| text(attr(&r.attrs, "encoding-version"))) {
        cx.format_set("anndata_encoding", v);
    }
    let (mut obs, mut vars) = (frame_rows(f, "/obs"), frame_rows(f, "/var"));
    if let Some(x) = f.dataset("/X") {
        cx.format_set("x_encoding", "dense");
        cx.format_set("x_type", x.dtype.as_ref().map_or_else(|| "?".into(), h5::DType::name));
        obs = obs.or_else(|| x.shape.first().copied());
        vars = vars.or_else(|| x.shape.get(1).copied());
    } else if let Some(x) = f.group("/X") {
        if let Some(e) = text(attr(&x.attrs, "encoding-type")) {
            cx.format_set("x_encoding", e);
        }
        if let Some(Value::Array(s)) = attr(&x.attrs, "shape") {
            obs = obs.or_else(|| s.first().and_then(Value::as_u64));
            vars = vars.or_else(|| s.get(1).and_then(Value::as_u64));
        }
        if let Some(d) = f.dataset("/X/data") {
            cx.format_set("x_type", d.dtype.as_ref().map_or_else(|| "?".into(), h5::DType::name));
            cx.format_set("x_stored_values", d.shape.first().copied().unwrap_or(0));
        }
    }
    if let Some(n) = obs {
        cx.format_set("observations", n);
    }
    if let Some(n) = vars {
        cx.format_set("variables", n);
    }
    for (g, key) in [("/obs", "obs_columns"), ("/var", "var_columns")] {
        if let Some(group) = f.group(g) {
            let cols = strings(attr(&group.attrs, "column-order"));
            cx.format_set(key, cols);
        }
    }
    for g in ["layers", "obsm", "varm", "obsp", "varp", "uns"] {
        let kids = f.children(&format!("/{g}"));
        if !kids.is_empty() {
            cx.format_set(g, kids.into_iter().take(100).map(|k| truncate_chars(&k, 200)).collect::<Vec<_>>());
        }
    }
}

fn loom(cx: &mut Context<'_>, f: &File) {
    if let Some(m) = f.dataset("/matrix") {
        cx.format_set("rows", m.shape.first().copied().unwrap_or(0));
        cx.format_set("columns", m.shape.get(1).copied().unwrap_or(0));
        cx.format_set("matrix_type", m.dtype.as_ref().map_or_else(|| "?".into(), h5::DType::name));
    }
    for (g, key) in [
        ("/row_attrs", "row_attributes"),
        ("/col_attrs", "column_attributes"),
        ("/layers", "layers"),
        ("/row_graphs", "row_graphs"),
        ("/col_graphs", "column_graphs"),
    ] {
        let kids = f.children(g);
        if !kids.is_empty() {
            cx.format_set(key, kids.into_iter().take(100).map(|k| truncate_chars(&k, 200)).collect::<Vec<_>>());
        }
    }
    // Loom 3 keeps global attributes as datasets under /attrs; 2 as root attributes.
    let global = f.children("/attrs");
    if !global.is_empty() {
        cx.format_set("global_attributes", global.into_iter().take(100).collect::<Vec<_>>());
    }
    if let Some(v) = f.group("/").and_then(|r| text(attr(&r.attrs, "LOOM_SPEC_VERSION"))) {
        cx.format_set("loom_version", v);
    }
}

fn mat73(cx: &mut Context<'_>, f: &File, head: &[u8]) {
    let text = String::from_utf8_lossy(head.get(..116).unwrap_or(head));
    let text = text.trim_end_matches(['\0', ' ']);
    cx.format_set("mat_version", "7.3");
    cx.format_set("header", truncate_chars(text, 116));
    if let Some(p) = text.split("Platform: ").nth(1).and_then(|r| r.split(',').next()) {
        cx.format_set("platform", truncate_chars(p.trim(), 50));
    }
    let mut vars = Map::new();
    for name in f.children("/").into_iter().take(MAX_LIST) {
        let path = format!("/{name}");
        let (class, shape) = if let Some(d) = f.dataset(&path) {
            (text_attr(&d.attrs), d.shape.iter().rev().map(u64::to_string).collect::<Vec<_>>().join("x"))
        } else if let Some(g) = f.group(&path) {
            (text_attr(&g.attrs), String::new())
        } else {
            continue;
        };
        if name.starts_with('#') {
            continue; // #refs#, #subsystem#
        }
        let desc = match (class, shape.is_empty()) {
            (Some(c), false) => format!("{c} {shape}"),
            (Some(c), true) => c,
            (None, _) => shape,
        };
        vars.insert(truncate_chars(&name, 200), Value::String(desc));
    }
    cx.format_set("variables", Value::Object(vars));
}

fn text_attr(a: &[(String, Value)]) -> Option<String> {
    text(attr(a, "MATLAB_class"))
}

fn keras(cx: &mut Context<'_>, f: &File) {
    let Some(r) = f.group("/") else { return };
    for (k, out) in [("keras_version", "keras_version"), ("backend", "keras_backend")] {
        if let Some(v) = text(attr(&r.attrs, k)) {
            cx.format_set(out, truncate_chars(&v, 50));
        }
    }
    if let Some(c) = text(attr(&r.attrs, "model_config")).and_then(|c| serde_json::from_str::<Value>(&c).ok()) {
        if let Some(k) = c.get("class_name").and_then(Value::as_str) {
            cx.format_set("model_class", truncate_chars(k, 100));
        }
        if let Some(n) = c.pointer("/config/name").and_then(Value::as_str) {
            cx.format_set("model_name", truncate_chars(n, 200));
        }
        if let Some(l) = c.pointer("/config/layers").and_then(Value::as_array) {
            cx.format_set("layer_count", l.len());
        }
    }
}

impl Extractor for Hdf5 {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.starts_with(b"MATLAB 7.3 MAT-file") && h.get(512..520) == Some(SIG) {
            return Some(Sniff { format: "mat73", confidence: 0.99 });
        }
        if !h.starts_with(SIG) {
            return None;
        }
        let format = if has(h, b"anndata") && has(h, b"encoding-type") {
            "h5ad"
        } else if has(h, b"LOOM_SPEC_VERSION") || (probe.extension == Some("loom") && has(h, b"row_attrs")) {
            "loom"
        } else if has(h, b"_NCProperties")
            || (matches!(probe.extension, Some("nc" | "nc4")) && has(h, b"DIMENSION_SCALE"))
        {
            "netcdf4"
        } else {
            return None;
        };
        Some(Sniff { format, confidence: 0.98 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.read_vec(0, 128.min(usize::try_from(src.len()).unwrap_or(0))).unwrap_or_default();
        let deadline = std::cell::Cell::new(false);
        let f = {
            let cx_ref = &*cx;
            let mut check = || {
                if cx_ref.checkpoint().is_err() {
                    deadline.set(true);
                }
                deadline.get()
            };
            h5::read(src, &mut check).ok_or_else(|| ExtractError::malformed("HDF5 superblock"))?
        };
        if deadline.get() {
            return Err(ExtractError::Timeout);
        }
        let kind = layout(&f);
        let id = cx.format_id().to_string();
        // A plain HDF5 detection of a known layout: report it as that format.
        if id == "hdf5"
            && let Some(k) = kind.filter(|k| META.formats.iter().any(|s| s.id == *k))
        {
            cx.redirect(k);
            return Ok(());
        }
        if let Some(k) = kind {
            cx.format_set("layout", k);
        }
        generic(cx, &f);
        match kind {
            Some("netcdf4") => netcdf4(cx, &f),
            Some("h5ad") => h5ad(cx, &f),
            Some("loom") => loom(cx, &f),
            Some("mat73") => mat73(cx, &f, &head),
            Some("keras") => keras(cx, &f),
            _ => {}
        }
        if let Some(t) = f.group("/").and_then(|r| text(attr(&r.attrs, "title"))) {
            cx.content().source("hdf5.title").title(truncate_chars(&t, 300));
        }
        Ok(())
    }
}

crate::register_extractor!(Hdf5);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("hdf5", "netcdf4", "h5ad", "loom", "mat73");
}
