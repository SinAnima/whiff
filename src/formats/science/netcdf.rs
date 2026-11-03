//! NetCDF classic files (CDF-1, CDF-2 64-bit offset, CDF-5 64-bit data):
//! dimensions, variables with their types, dimensions and attributes, and
//! the global attributes; the same model describes NetCDF-4 files (read
//! through HDF5).
//!
//! Specification: NetCDF Users Guide, "File Format Specifications" (classic
//! and 64-bit offset; CDF-5); CF Conventions 1.11 for the attribute names.

// Field names follow the format specification.
#![allow(clippy::many_single_char_names)]

use serde_json::{Map, Value};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, redact_sensitive, truncate_chars,
};

/// Extractor for NetCDF classic files.
pub struct NetCdf;

static META: ExtractorMeta = ExtractorMeta {
    id: "science.netcdf",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "netcdf3",
        name: "NetCDF (3 / 4)",
        family: "sci",
        mimes: &["application/x-netcdf"],
        extensions: &["nc", "cdf", "nc3"],
        magic: &[Magic::at(0, b"CDF\x01"), Magic::at(0, b"CDF\x02"), Magic::at(0, b"CDF\x05")],
        parent: None,
    }],
};

/// Variables and attributes listed.
const MAX_ITEMS: usize = 500;

/// A dimension: name, length, unlimited.
pub(crate) struct Dim {
    pub name: String,
    pub len: u64,
    pub unlimited: bool,
}

/// A variable: name, CDL type, dimension names, attributes.
pub(crate) struct Var {
    pub name: String,
    pub kind: String,
    pub dims: Vec<String>,
    pub attrs: Vec<(String, Value)>,
}

/// A NetCDF data model.
#[derive(Default)]
pub(crate) struct Model {
    pub dims: Vec<Dim>,
    pub vars: Vec<Var>,
    pub attrs: Vec<(String, Value)>,
}

/// An attribute value as text (for the normalised fields).
fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Array(a) if a.iter().all(Value::is_string) => {
            Some(a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" "))
        }
        _ => None,
    }
}

fn shown(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(truncate_chars(&redact_sensitive(s), 500)),
        other => other.clone(),
    }
}

/// Describe a NetCDF model in the report.
pub(crate) fn describe(cx: &mut Context<'_>, m: &Model) {
    let dims: Map<String, Value> =
        m.dims.iter().take(MAX_ITEMS).map(|d| (truncate_chars(&d.name, 200), d.len.into())).collect();
    cx.format_set("dimensions", Value::Object(dims));
    let unlimited: Vec<&str> = m.dims.iter().filter(|d| d.unlimited).map(|d| d.name.as_str()).collect();
    if !unlimited.is_empty() {
        cx.format_set("unlimited_dimensions", unlimited);
    }
    let mut vars = Map::new();
    for v in m.vars.iter().take(MAX_ITEMS) {
        let mut e = Map::new();
        e.insert("type".into(), v.kind.clone().into());
        e.insert("dimensions".into(), v.dims.clone().into());
        for key in ["units", "standard_name", "long_name"] {
            if let Some(s) = v.attrs.iter().find(|(n, _)| n == key).and_then(|(_, x)| text(x)) {
                e.insert(key.into(), truncate_chars(&s, 200).into());
            }
        }
        vars.insert(truncate_chars(&v.name, 200), Value::Object(e));
    }
    cx.format_set("variable_count", m.vars.len());
    cx.format_set("variables", Value::Object(vars));
    let globals: Map<String, Value> =
        m.attrs.iter().take(MAX_ITEMS).map(|(k, v)| (truncate_chars(k, 100), shown(v))).collect();
    if !globals.is_empty() {
        cx.format_set("global_attributes", Value::Object(globals));
    }
    let get = |k: &str| m.attrs.iter().find(|(n, _)| n == k).and_then(|(_, v)| text(v));
    if let Some(c) = get("Conventions").or_else(|| get("conventions")) {
        cx.format_set("conventions", truncate_chars(&c, 100));
    }
    if let Some(t) = get("title") {
        cx.content().source("netcdf.title").title(truncate_chars(&t, 300));
    }
    if let Some(d) = get("summary").or_else(|| get("comment")) {
        cx.content().source("netcdf.summary").description(truncate_chars(&d, 1000));
    }
    if let Some(a) = get("creator_name").or_else(|| get("author")) {
        cx.content().source("netcdf.creator_name").author(truncate_chars(&a, 200));
    }
    if let Some(l) = get("license") {
        cx.rights().source("netcdf.license").license(Some(&truncate_chars(&l, 200)), None);
    }
}

/// A CDL type name from a classic `nc_type`.
fn cdl(t: u32) -> &'static str {
    match t {
        1 => "byte",
        2 => "char",
        3 => "short",
        4 => "int",
        5 => "float",
        6 => "double",
        7 => "ubyte",
        8 => "ushort",
        9 => "uint",
        10 => "int64",
        11 => "uint64",
        _ => "?",
    }
}

fn type_size(t: u32) -> usize {
    match t {
        1 | 2 | 7 => 1,
        3 | 8 => 2,
        4 | 5 | 9 => 4,
        6 | 10 | 11 => 8,
        _ => 0,
    }
}

/// A cursor over a classic header (big-endian; counts are 64-bit in CDF-5).
struct Header<'a> {
    b: &'a [u8],
    at: usize,
    wide: bool,
}

impl Header<'_> {
    fn u32(&mut self) -> Option<u32> {
        let v = u32::from_be_bytes(self.b.get(self.at..self.at + 4)?.try_into().ok()?);
        self.at += 4;
        Some(v)
    }

    fn u64(&mut self) -> Option<u64> {
        let v = u64::from_be_bytes(self.b.get(self.at..self.at + 8)?.try_into().ok()?);
        self.at += 8;
        Some(v)
    }

    /// A count (`NON_NEG`): 32-bit, or 64-bit in CDF-5.
    fn count(&mut self) -> Option<u64> {
        if self.wide { self.u64() } else { self.u32().map(u64::from) }
    }

    fn name(&mut self) -> Option<String> {
        let n = usize::try_from(self.count()?).ok()?;
        let s = String::from_utf8_lossy(self.b.get(self.at..self.at.checked_add(n)?)?).into_owned();
        self.at += n.div_ceil(4) * 4;
        Some(s)
    }

    /// A list header: tag and element count (`ABSENT` is zero, zero).
    fn list(&mut self, tag: u32) -> Option<u64> {
        let t = self.u32()?;
        let n = self.count()?;
        if t == 0 && n == 0 {
            return Some(0);
        }
        (t == tag).then_some(n)
    }

    fn attrs(&mut self) -> Option<Vec<(String, Value)>> {
        let n = self.list(0x0C)?;
        let mut out = Vec::new();
        for _ in 0..n.min(10_000) {
            let name = self.name()?;
            let t = self.u32()?;
            let count = usize::try_from(self.count()?).ok()?;
            let size = type_size(t);
            let len = count.checked_mul(size)?;
            let raw = self.b.get(self.at..self.at.checked_add(len)?)?;
            self.at += len.div_ceil(4) * 4;
            let v = if t == 2 {
                Value::String(truncate_chars(String::from_utf8_lossy(raw).trim_end_matches('\0'), 2000))
            } else {
                let vals: Vec<Value> = raw.chunks_exact(size.max(1)).take(64).map(|c| number(c, t)).collect();
                if vals.len() == 1 { vals.into_iter().next().unwrap_or(Value::Null) } else { Value::Array(vals) }
            };
            if out.len() < MAX_ITEMS {
                out.push((name, v));
            }
        }
        Some(out)
    }
}

fn number(c: &[u8], t: u32) -> Value {
    let u = c.iter().fold(0u64, |a, &x| a << 8 | u64::from(x));
    match t {
        1 => Value::from(c[0].cast_signed()),
        3 => Value::from(i16::from_be_bytes([c[0], c[1]])),
        4 => Value::from(i32::from_be_bytes([c[0], c[1], c[2], c[3]])),
        5 => super::number(f64::from(f32::from_bits(u32::try_from(u).unwrap_or(0)))),
        6 => super::number(f64::from_bits(u)),
        10 => Value::from(u.cast_signed()),
        _ => Value::from(u),
    }
}

fn classic(b: &[u8]) -> Option<(u8, u64, Model)> {
    let version = *b.get(3)?;
    let wide = version == 5;
    let mut h = Header { b, at: 4, wide };
    let numrecs = h.count()?;
    let mut m = Model::default();
    let n = h.list(0x0A)?;
    for _ in 0..n.min(10_000) {
        let name = h.name()?;
        let len = h.count()?;
        m.dims.push(Dim { name, len: if len == 0 { numrecs } else { len }, unlimited: len == 0 });
    }
    m.attrs = h.attrs()?;
    let n = h.list(0x0B)?;
    for _ in 0..n.min(100_000) {
        let name = h.name()?;
        let nd = usize::try_from(h.count()?).ok()?;
        let dims: Vec<String> = (0..nd.min(64))
            .map(|_| {
                h.count().map(|i| {
                    m.dims
                        .get(usize::try_from(i).unwrap_or(usize::MAX))
                        .map_or_else(|| format!("dim {i}"), |d| d.name.clone())
                })
            })
            .collect::<Option<_>>()?;
        let attrs = h.attrs()?;
        let t = h.u32()?;
        h.count()?; // vsize
        if version == 1 {
            h.u32()?;
        } else {
            h.u64()?;
        } // begin
        if m.vars.len() < 100_000 {
            m.vars.push(Var { name, kind: cdl(t).into(), dims, attrs });
        }
    }
    Some((version, numrecs, m))
}

impl Extractor for NetCdf {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        // The header precedes the data; read up to the parse limit.
        let len = usize::try_from(src.len()).unwrap_or(usize::MAX);
        let b = src.read_vec(0, len.min(cx.parse_limit())).map_err(|_| ExtractError::malformed("header"))?;
        let (version, records, m) = classic(&b).ok_or_else(|| ExtractError::malformed("NetCDF header"))?;
        cx.format_set(
            "format",
            match version {
                1 => "classic (CDF-1)",
                2 => "64-bit offset (CDF-2)",
                _ => "64-bit data (CDF-5)",
            },
        );
        cx.format_set("records", records);
        describe(cx, &m);
        Ok(())
    }
}

crate::register_extractor!(NetCdf);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_classic_header() {
        // CDF-1, 2 records, one unlimited dimension "t", no attributes, one int variable.
        let mut b = b"CDF\x01".to_vec();
        b.extend(2u32.to_be_bytes());
        b.extend([0, 0, 0, 0x0A, 0, 0, 0, 1, 0, 0, 0, 1, b't', 0, 0, 0, 0, 0, 0, 0]);
        b.extend([0; 8]);
        b.extend([0, 0, 0, 0x0B, 0, 0, 0, 1, 0, 0, 0, 1, b'h', 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
        b.extend([0; 8]);
        b.extend([0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0]);
        let (v, n, m) = classic(&b).unwrap();
        assert_eq!((v, n), (1, 2));
        assert!(m.dims[0].unlimited);
        assert_eq!(m.vars[0].dims, vec!["t"]);
        assert_eq!(m.vars[0].kind, "int");
    }

    crate::fixture_tests!("netcdf3");
}
