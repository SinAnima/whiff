//! An HDF5 reader for metadata: the superblock (versions 0–3, user
//! blocks), object headers (versions 1 and 2, continuation blocks), groups
//! (v1 symbol tables; compact links; dense links through the fractal heap
//! and its v2 B-tree name index), datasets (dataspace, datatype, layout,
//! filters) and attributes (compact and dense, with variable-length
//! strings and references through the global heap). Raw data is never
//! read except attribute values. Everything goes through the source and is
//! bounded; cycles are skipped.
//!
//! Specification: HDF5 File Format Specification version 3.0 (§II
//! superblock, §III.A B-trees v1, §III.B v2, §III.D local heaps, §III.E
//! global heap, §III.G fractal heap, §IV.A object headers and messages).

// `o` / `l` (sizes of offsets and lengths) and the message field names
// follow the specification.
#![allow(clippy::many_single_char_names, clippy::similar_names)]

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::plugin::{Source, truncate_chars};

/// HDF5's file signature.
pub(crate) const SIGNATURE: &[u8; 8] = b"\x89HDF\r\n\x1a\n";
/// Objects (groups and datasets) visited.
const MAX_OBJECTS: usize = 100_000;
/// Group nesting followed.
const MAX_DEPTH: usize = 64;
/// Messages read from one object header.
const MAX_MESSAGES: usize = 10_000;
/// Bytes read for one header chunk, heap block or B-tree node.
const MAX_BLOCK: usize = 4 << 20;
/// Elements of an attribute decoded.
const MAX_VALUES: usize = 64;

/// A datatype.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DType {
    Int { size: usize, signed: bool, big: bool },
    Float { size: usize, big: bool },
    Str { size: usize },
    VlenStr,
    Vlen(Box<DType>),
    Ref { region: bool },
    Compound { size: usize, members: Vec<(String, usize, DType)> },
    Enum(Box<DType>, Vec<String>),
    Array(Vec<u64>, Box<DType>),
    Other { class: u8, size: usize },
}

impl DType {
    pub(crate) fn size(&self, offsets: usize) -> usize {
        match self {
            Self::Int { size, .. }
            | Self::Float { size, .. }
            | Self::Str { size }
            | Self::Compound { size, .. }
            | Self::Other { size, .. } => *size,
            Self::VlenStr | Self::Vlen(_) => 4 + offsets + 4,
            Self::Ref { region } => {
                if *region {
                    offsets + 4
                } else {
                    offsets
                }
            }
            Self::Enum(base, _) => base.size(offsets),
            Self::Array(dims, base) => {
                usize::try_from(dims.iter().product::<u64>()).unwrap_or(0).saturating_mul(base.size(offsets))
            }
        }
    }

    /// A short name: `int32`, `float64`, `string[8]`, `vlen string` …
    pub(crate) fn name(&self) -> String {
        match self {
            Self::Int { size, signed, .. } => format!("{}int{}", if *signed { "" } else { "u" }, size * 8),
            Self::Float { size, .. } => format!("float{}", size * 8),
            Self::Str { size } => format!("string[{size}]"),
            Self::VlenStr => "vlen string".into(),
            Self::Vlen(b) => format!("vlen<{}>", b.name()),
            Self::Ref { region } => {
                if *region {
                    "region reference".into()
                } else {
                    "object reference".into()
                }
            }
            Self::Compound { members, .. } => {
                let m: Vec<String> = members.iter().take(32).map(|(n, _, t)| format!("{n}: {}", t.name())).collect();
                truncate_chars(&format!("compound{{{}}}", m.join(", ")), 300)
            }
            Self::Enum(b, _) => format!("enum<{}>", b.name()),
            Self::Array(d, b) => {
                format!("{}[{}]", b.name(), d.iter().map(u64::to_string).collect::<Vec<_>>().join("x"))
            }
            Self::Other { class, size } => match class {
                2 => format!("time{}", size * 8),
                4 => format!("bitfield{}", size * 8),
                5 => format!("opaque[{size}]"),
                _ => format!("class {class}"),
            },
        }
    }
}

/// A dataset.
#[derive(Debug, Clone, Default)]
pub(crate) struct Dataset {
    pub path: String,
    pub shape: Vec<u64>,
    /// Maximum dimensions (`u64::MAX`: unlimited).
    pub max: Vec<u64>,
    pub dtype: Option<DType>,
    pub layout: &'static str,
    pub chunks: Vec<u64>,
    pub filters: Vec<String>,
    pub attrs: Vec<(String, Value)>,
}

/// A group.
#[derive(Debug, Clone, Default)]
pub(crate) struct Group {
    pub path: String,
    pub attrs: Vec<(String, Value)>,
    /// Soft and external links (name → target).
    pub links: Vec<(String, String)>,
}

/// The file as read.
#[derive(Debug, Default)]
pub(crate) struct File {
    pub superblock: u8,
    pub offsets: usize,
    pub userblock: u64,
    pub groups: Vec<Group>,
    pub datasets: Vec<Dataset>,
    /// Objects past the limits, unreadable headers.
    pub skipped: u64,
    /// Object header address → path (for references).
    pub paths: HashMap<u64, String>,
}

impl File {
    pub(crate) fn group(&self, path: &str) -> Option<&Group> {
        self.groups.iter().find(|g| g.path == path)
    }

    pub(crate) fn dataset(&self, path: &str) -> Option<&Dataset> {
        self.datasets.iter().find(|d| d.path == path)
    }

    /// Children (names) of a group: groups and datasets directly below it.
    pub(crate) fn children(&self, path: &str) -> Vec<String> {
        let prefix = if path == "/" { "/".to_string() } else { format!("{path}/") };
        let direct =
            |p: &str| p.strip_prefix(&prefix).filter(|r| !r.is_empty() && !r.contains('/')).map(str::to_string);
        let mut v: Vec<String> = self
            .groups
            .iter()
            .filter_map(|g| direct(&g.path))
            .chain(self.datasets.iter().filter_map(|d| direct(&d.path)))
            .collect();
        v.sort();
        v
    }
}

pub(crate) fn attr<'a>(attrs: &'a [(String, Value)], name: &str) -> Option<&'a Value> {
    attrs.iter().find(|(n, _)| n == name).map(|(_, v)| v)
}

fn le(b: &[u8], at: usize, n: usize) -> Option<u64> {
    let s = b.get(at..at.checked_add(n)?)?;
    Some(s.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x)))
}

/// A message of an object header.
struct Message {
    kind: u16,
    data: Vec<u8>,
}

struct Reader<'s> {
    src: &'s mut dyn Source,
    base: u64,
    o: usize,
    l: usize,
    gheap: HashMap<u64, Vec<u8>>,
}

impl Reader<'_> {
    fn read(&mut self, addr: u64, n: usize) -> Option<Vec<u8>> {
        let at = self.base.checked_add(addr)?;
        let len = self.src.len();
        if at >= len {
            return None;
        }
        let n = usize::try_from((len - at).min(n as u64)).ok()?;
        self.src.read_vec(at, n).ok()
    }

    fn undefined(&self, a: u64) -> bool {
        a == u64::MAX >> (64 - 8 * self.o.min(8))
    }

    /// The messages of the object header at `addr`.
    fn messages(&mut self, addr: u64) -> Option<Vec<Message>> {
        let head = self.read(addr, 16)?;
        let mut out = Vec::new();
        let mut blocks: Vec<(u64, u64, bool)> = Vec::new();
        if head.starts_with(b"OHDR") {
            let flags = *head.get(5)?;
            let mut at = 6;
            if flags & 0x20 != 0 {
                at += 16;
            }
            if flags & 0x10 != 0 {
                at += 4;
            }
            let width = 1usize << (flags & 3);
            let b = self.read(addr, at + width)?;
            let size = le(&b, at, width)?;
            blocks.push((addr + (at + width) as u64, size, true));
            // Version 2 chunks: type u8, size u16, flags u8, [creation order u16].
            let mut seen = 0;
            while let Some((start, size, first)) = blocks.pop() {
                seen += 1;
                if seen > 1000 {
                    break;
                }
                let mut data = self.read(start, usize::try_from(size).ok()?.min(MAX_BLOCK))?;
                let mut i = 0;
                if !first {
                    if !data.starts_with(b"OCHK") {
                        continue;
                    }
                    i = 4;
                }
                // A continuation block's length includes its checksum (chunk 0's
                // size does not).
                if !first {
                    data.truncate(data.len().saturating_sub(4));
                }
                while i + 4 <= data.len() && out.len() < MAX_MESSAGES {
                    let kind = u16::from(data[i]);
                    let len = usize::from(u16::from_le_bytes([data[i + 1], data[i + 2]]));
                    i += 4 + if flags & 0x04 != 0 { 2 } else { 0 };
                    let Some(body) = data.get(i..i + len) else { break };
                    if kind == 0x10 {
                        let (a, s) = (le(body, 0, self.o)?, le(body, self.o, self.l)?);
                        blocks.push((a, s, false));
                    } else if kind != 0 {
                        out.push(Message { kind, data: body.to_vec() });
                    }
                    i += len;
                }
            }
            return Some(out);
        }
        // Version 1: 16-byte prefix, then 8-byte aligned messages.
        if head.first() != Some(&1) {
            return None;
        }
        let count = usize::try_from(le(&head, 2, 2)?).ok()?;
        let size = le(&head, 8, 4)?;
        blocks.push((addr + 16, size, true));
        let mut seen = 0;
        while let Some((start, size, _)) = blocks.pop() {
            seen += 1;
            if seen > 1000 {
                break;
            }
            let data = self.read(start, usize::try_from(size).ok()?.min(MAX_BLOCK))?;
            let mut i = 0;
            while i + 8 <= data.len() && out.len() < count.min(MAX_MESSAGES) {
                let kind = u16::from_le_bytes([data[i], data[i + 1]]);
                let len = usize::from(u16::from_le_bytes([data[i + 2], data[i + 3]]));
                let Some(body) = data.get(i + 8..i + 8 + len) else { break };
                if kind == 0x10 {
                    let (a, s) = (le(body, 0, self.o)?, le(body, self.o, self.l)?);
                    blocks.push((a, s, false));
                } else {
                    out.push(Message { kind, data: body.to_vec() });
                }
                i += 8 + len;
            }
        }
        Some(out)
    }

    /// A global heap object (variable-length data).
    fn global(&mut self, addr: u64, index: u32) -> Option<Vec<u8>> {
        if !self.gheap.contains_key(&addr) {
            let head = self.read(addr, 8 + self.l)?;
            if !head.starts_with(b"GCOL") || self.gheap.len() > 10_000 {
                return None;
            }
            let size = usize::try_from(le(&head, 8, self.l)?).ok()?.min(MAX_BLOCK);
            let col = self.read(addr, size)?;
            self.gheap.insert(addr, col);
        }
        let col = self.gheap.get(&addr)?;
        let mut at = 8 + self.l;
        while at + 8 + self.l <= col.len() {
            let i = u32::try_from(le(col, at, 2)?).ok()?;
            let size = usize::try_from(le(col, at + 8, self.l)?).ok()?;
            let data_at = at + 8 + self.l;
            if i == index {
                return col.get(data_at..data_at.checked_add(size)?).map(<[u8]>::to_vec);
            }
            if i == 0 {
                return None;
            }
            at = data_at + size.div_ceil(8) * 8;
        }
        None
    }

    fn dtype(b: &[u8], depth: usize) -> Option<DType> {
        if depth > 16 {
            return None;
        }
        let class = b.first()? & 0x0f;
        let version = b.first()? >> 4;
        let bits = [*b.get(1)?, *b.get(2)?, *b.get(3)?];
        let size = usize::try_from(le(b, 4, 4)?).ok()?;
        let props = b.get(8..).unwrap_or_default();
        Some(match class {
            0 => DType::Int { size, signed: bits[0] & 0x08 != 0, big: bits[0] & 1 != 0 },
            1 => DType::Float { size, big: bits[0] & 1 != 0 },
            3 => DType::Str { size },
            6 => {
                let n = usize::from(u16::from_le_bytes([bits[0], bits[1]]));
                let mut members = Vec::new();
                let mut at = 0;
                for _ in 0..n.min(1024) {
                    let rest = props.get(at..)?;
                    let end = rest.iter().position(|&c| c == 0)?;
                    let name = String::from_utf8_lossy(&rest[..end]).into_owned();
                    at += if version < 3 { (end + 1).div_ceil(8) * 8 } else { end + 1 };
                    let off_size =
                        if version >= 3 { (usize::BITS - size.leading_zeros()).div_ceil(8).max(1) as usize } else { 4 };
                    let off = usize::try_from(le(props, at, off_size)?).ok()?;
                    at += off_size;
                    if version == 1 {
                        at += 28; // dimensionality, reserved, permutation, dimension sizes
                    }
                    let t = Self::dtype(props.get(at..)?, depth + 1)?;
                    at += 8 + type_props_len(props.get(at..)?, depth + 1)?;
                    members.push((name, off, t));
                }
                DType::Compound { size, members }
            }
            7 => DType::Ref { region: bits[0] & 0x0f == 1 },
            8 => {
                let base = Self::dtype(props, depth + 1)?;
                let n = usize::from(u16::from_le_bytes([bits[0], bits[1]]));
                let mut at = 8 + type_props_len(props, depth + 1)?;
                let mut names = Vec::new();
                for _ in 0..n.min(256) {
                    let rest = props.get(at..)?;
                    let end = rest.iter().position(|&c| c == 0)?;
                    names.push(String::from_utf8_lossy(&rest[..end]).into_owned());
                    at += if version < 3 { (end + 1).div_ceil(8) * 8 } else { end + 1 };
                }
                DType::Enum(Box::new(base), names)
            }
            9 => {
                if bits[0] & 0x0f == 1 {
                    DType::VlenStr
                } else {
                    DType::Vlen(Box::new(Self::dtype(props, depth + 1)?))
                }
            }
            10 => {
                let rank = usize::from(*props.first()?);
                let at = if version < 3 { 4 } else { 1 };
                let dims: Vec<u64> = (0..rank.min(32)).map(|i| le(props, at + 4 * i, 4)).collect::<Option<_>>()?;
                let mut base_at = at + 4 * rank;
                if version < 3 {
                    base_at += 4 * rank; // permutation indices
                }
                DType::Array(dims, Box::new(Self::dtype(props.get(base_at..)?, depth + 1)?))
            }
            c => DType::Other { class: c, size },
        })
    }

    /// Decode `count` elements of `t` from `raw` (attribute values).
    fn values(&mut self, t: &DType, raw: &[u8], count: usize) -> Value {
        let size = t.size(self.o);
        let mut v = Vec::new();
        for i in 0..count.min(MAX_VALUES) {
            let Some(e) = raw.get(i * size..(i + 1) * size) else { break };
            v.push(self.value(t, e, 0));
        }
        if count == 1 { v.pop().unwrap_or(Value::Null) } else { Value::Array(v) }
    }

    fn value(&mut self, t: &DType, e: &[u8], depth: usize) -> Value {
        let num = |e: &[u8], big: bool| -> u64 {
            let it: Vec<u8> = if big { e.iter().rev().copied().collect() } else { e.to_vec() };
            it.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x))
        };
        match t {
            DType::Int { size, signed, big } if *size <= 8 => {
                let v = num(e, *big);
                if *signed {
                    let shift = 64 - 8 * size;
                    Value::from((v << shift).cast_signed() >> shift)
                } else {
                    Value::from(v)
                }
            }
            DType::Float { size: 4, big } => {
                super::number(f64::from(f32::from_bits(u32::try_from(num(e, *big)).unwrap_or(0))))
            }
            DType::Float { size: 8, big } => super::number(f64::from_bits(num(e, *big))),
            DType::Str { .. } => {
                let s = String::from_utf8_lossy(e);
                Value::String(truncate_chars(s.trim_end_matches(['\0', ' ']), 2000))
            }
            DType::VlenStr | DType::Vlen(_) if depth < 4 => {
                let len = usize::try_from(le(e, 0, 4).unwrap_or(0)).unwrap_or(0);
                let addr = le(e, 4, self.o).unwrap_or(0);
                let idx = u32::try_from(le(e, 4 + self.o, 4).unwrap_or(0)).unwrap_or(0);
                if addr == 0 || self.undefined(addr) {
                    return Value::Null;
                }
                let data = self.global(addr, idx).unwrap_or_default();
                match t {
                    DType::Vlen(base) => {
                        let s = base.size(self.o);
                        let n = len.min(MAX_VALUES);
                        Value::Array(
                            (0..n)
                                .filter_map(|i| data.get(i * s..(i + 1) * s))
                                .map(|x| self.value(base, x, depth + 1))
                                .collect(),
                        )
                    }
                    _ => Value::String(truncate_chars(&String::from_utf8_lossy(&data[..len.min(data.len())]), 2000)),
                }
            }
            DType::Ref { region: false } => Value::from(le(e, 0, self.o).unwrap_or(0)),
            DType::Enum(base, names) => {
                let v = self.value(base, e, depth + 1);
                v.as_u64().and_then(|i| names.get(usize::try_from(i).ok()?)).map_or(v, |n| Value::String(n.clone()))
            }
            DType::Array(dims, base) if depth < 4 => {
                let n = usize::try_from(dims.iter().product::<u64>()).unwrap_or(0).min(MAX_VALUES);
                let s = base.size(self.o);
                Value::Array(
                    (0..n).filter_map(|i| e.get(i * s..(i + 1) * s)).map(|x| self.value(base, x, depth + 1)).collect(),
                )
            }
            _ => Value::Null,
        }
    }

    /// Dataspace: (dimensions, maximum dimensions); scalar → empty.
    fn dataspace(&self, b: &[u8]) -> Option<(Vec<u64>, Vec<u64>)> {
        let version = *b.first()?;
        let rank = usize::from(*b.get(1)?);
        let flags = *b.get(2)?;
        let at = if version == 1 { 8 } else { 4 };
        if version == 2 && *b.get(3)? == 2 {
            return Some((vec![0], vec![0])); // null dataspace
        }
        let dims: Vec<u64> = (0..rank.min(32)).map(|i| le(b, at + self.l * i, self.l)).collect::<Option<_>>()?;
        let max = if flags & 1 != 0 {
            (0..rank.min(32)).map(|i| le(b, at + self.l * (rank + i), self.l)).collect::<Option<_>>()?
        } else {
            dims.clone()
        };
        Some((dims, max))
    }

    fn attribute(&mut self, b: &[u8]) -> Option<(String, Value)> {
        let version = *b.first()?;
        let name_len = usize::try_from(le(b, 2, 2)?).ok()?;
        let dt_len = usize::try_from(le(b, 4, 2)?).ok()?;
        let ds_len = usize::try_from(le(b, 6, 2)?).ok()?;
        let pad = |n: usize| if version == 1 { n.div_ceil(8) * 8 } else { n };
        let mut at = if version == 3 { 9 } else { 8 };
        let name = String::from_utf8_lossy(b.get(at..at + name_len)?).trim_end_matches('\0').to_string();
        at += pad(name_len);
        let dt = Self::dtype(b.get(at..at + dt_len)?, 0);
        at += pad(dt_len);
        let ds = self.dataspace(b.get(at..at + ds_len)?);
        at += pad(ds_len);
        let count = ds.map_or(1, |(d, _)| usize::try_from(d.iter().product::<u64>()).unwrap_or(0));
        let value = match dt {
            Some(t) => {
                let raw = b.get(at..).unwrap_or_default().to_vec();
                self.values(&t, &raw, count)
            }
            None => Value::Null,
        };
        Some((name, value))
    }

    /// The objects of a fractal heap, by heap ID.
    fn heap_object(&mut self, heap: &Heap, id: &[u8]) -> Option<Vec<u8>> {
        let kind = (id.first()? >> 4) & 3;
        if kind == 2 {
            let n = usize::from(id[0] & 0x0f) + 1;
            return id.get(1..1 + n).map(<[u8]>::to_vec);
        }
        if kind != 0 {
            return None; // huge objects are not read
        }
        let off = le(id, 1, heap.offset_bytes)?;
        let len = usize::try_from(le(id, 1 + heap.offset_bytes, heap.length_bytes)?).ok()?;
        let (start, _, addr) = heap.blocks.iter().copied().find(|&(s, n, _)| off >= s && off < s + n)?;
        self.read(addr + (off - start), len.min(MAX_BLOCK))
    }

    fn fractal_heap(&mut self, addr: u64) -> Option<Heap> {
        let h = self.read(addr, 256)?;
        if !h.starts_with(b"FRHP") {
            return None;
        }
        let o = self.o;
        let l = self.l;
        let id_len = usize::try_from(le(&h, 5, 2)?).ok()?;
        let io_len = le(&h, 7, 2)?;
        let max_obj = le(&h, 10, 4)?;
        // Fixed part: through "number of tiny objects".
        let mut at = 14 + l + o + l + o + l + l + l + l + l + l + l + l;
        let width = usize::try_from(le(&h, at, 2)?).ok()?;
        at += 2;
        let start_size = le(&h, at, l)?;
        at += l;
        let max_direct = le(&h, at, l)?;
        at += l;
        let max_heap_bits = usize::try_from(le(&h, at, 2)?).ok()?;
        at += 2;
        at += 2; // starting rows
        let root = le(&h, at, o)?;
        at += o;
        let rows = usize::try_from(le(&h, at, 2)?).ok()?;
        let offset_bytes = max_heap_bits.div_ceil(8);
        let lim = max_direct.min(max_obj);
        let length_bytes = ((u64::BITS - lim.leading_zeros()) as usize).div_ceil(8).max(1);
        let mut heap = Heap { blocks: Vec::new(), offset_bytes, length_bytes, id_len };
        if io_len != 0 || self.undefined(root) {
            return Some(heap); // filtered heaps are not read
        }
        if rows == 0 {
            heap.blocks.push((0, start_size, root));
        } else {
            self.indirect(&mut heap, root, rows, width, start_size, max_direct, 0, 0);
        }
        Some(heap)
    }

    #[allow(clippy::too_many_arguments)] // the heap's geometry
    fn indirect(
        &mut self,
        heap: &mut Heap,
        addr: u64,
        rows: usize,
        width: usize,
        start: u64,
        max_direct: u64,
        base: u64,
        depth: usize,
    ) {
        if depth > 8 || heap.blocks.len() > 10_000 {
            return;
        }
        let header = 4 + 1 + self.o + heap.offset_bytes;
        let entries = rows.saturating_mul(width).min(100_000);
        let Some(b) = self.read(addr, header + entries * self.o) else { return };
        if !b.starts_with(b"FHIB") {
            return;
        }
        let mut off = base;
        for r in 0..rows {
            let size = if r < 2 { start } else { start << (r - 1) };
            for c in 0..width {
                let Some(child) = le(&b, header + (r * width + c) * self.o, self.o) else { return };
                if size <= max_direct {
                    if !self.undefined(child) && child != 0 {
                        heap.blocks.push((off, size, child));
                    }
                } else if !self.undefined(child) && child != 0 {
                    // An indirect child: rows enough for its span.
                    let span_rows = (u64::BITS - (size / start).leading_zeros()) as usize + 1;
                    self.indirect(heap, child, span_rows.min(64), width, start, max_direct, off, depth + 1);
                }
                off = off.saturating_add(size);
            }
        }
    }

    /// Heap IDs of a v2 B-tree whose root is a leaf (depth 0), from records
    /// starting `id_at` bytes in.
    fn btree2_ids(&mut self, addr: u64, id_at: usize, id_len: usize) -> Option<Vec<Vec<u8>>> {
        let h = self.read(addr, 64)?;
        if !h.starts_with(b"BTHD") {
            return None;
        }
        let rec = usize::try_from(le(&h, 10, 2)?).ok()?;
        let depth = le(&h, 12, 2)?;
        let root = le(&h, 16, self.o)?;
        let n = usize::try_from(le(&h, 16 + self.o, 2)?).ok()?;
        if depth != 0 {
            return None;
        }
        let leaf = self.read(root, 6 + n * rec)?;
        if !leaf.starts_with(b"BTLF") {
            return None;
        }
        Some(
            (0..n)
                .filter_map(|i| leaf.get(6 + i * rec + id_at..6 + i * rec + id_at + id_len).map(<[u8]>::to_vec))
                .collect(),
        )
    }

    /// Messages stored in a fractal heap (dense links or attributes): by the
    /// v2 B-tree when its root is a leaf, else by walking the heap blocks.
    fn dense(&mut self, heap_addr: u64, btree: u64, id_at: usize) -> Vec<Vec<u8>> {
        let Some(heap) = self.fractal_heap(heap_addr) else { return Vec::new() };
        if let Some(ids) = self.btree2_ids(btree, id_at, heap.id_len) {
            return ids.iter().filter_map(|id| self.heap_object(&heap, id)).collect();
        }
        Vec::new()
    }

    /// The (name, object header address) links of a v1 symbol-table group.
    fn symbol_table(&mut self, btree: u64, heap: u64) -> Vec<(String, u64)> {
        let mut out = Vec::new();
        let Some(h) = self.read(heap, 8 + 2 * self.l + self.o) else { return out };
        if !h.starts_with(b"HEAP") {
            return out;
        }
        let Some(size) = le(&h, 8, self.l).and_then(|s| usize::try_from(s).ok()) else { return out };
        let Some(data_at) = le(&h, 8 + 2 * self.l, self.o) else { return out };
        let names = self.read(data_at, size.min(MAX_BLOCK)).unwrap_or_default();
        let mut stack = vec![(btree, 0usize)];
        let mut seen = HashSet::new();
        while let Some((node, depth)) = stack.pop() {
            if !seen.insert(node) || depth > 32 || seen.len() > 100_000 {
                continue;
            }
            let Some(b) = self.read(node, 24 + 2 * self.o + 4096 * self.o) else { continue };
            if b.starts_with(b"TREE") {
                let used = usize::try_from(le(&b, 6, 2).unwrap_or(0)).unwrap_or(0);
                // Keys (heap offsets, size `l`) and children alternate after the siblings.
                let mut at = 8 + 2 * self.o + self.l;
                for _ in 0..used.min(4096) {
                    let Some(child) = le(&b, at, self.o) else { break };
                    stack.push((child, depth + 1));
                    at += self.o + self.l;
                }
            } else if b.starts_with(b"SNOD") {
                let n = usize::try_from(le(&b, 6, 2).unwrap_or(0)).unwrap_or(0);
                let entry = 2 * self.o + 24;
                for i in 0..n.min(4096) {
                    let at = 8 + i * entry;
                    let (Some(name_off), Some(obj)) = (le(&b, at, self.o), le(&b, at + self.o, self.o)) else { break };
                    let start = usize::try_from(name_off).unwrap_or(usize::MAX);
                    let Some(rest) = names.get(start..) else { continue };
                    let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
                    out.push((String::from_utf8_lossy(&rest[..end]).into_owned(), obj));
                }
            }
        }
        out
    }

    /// A link message: (name, hard link address or soft / external target).
    fn link(&self, b: &[u8]) -> Option<(String, Result<u64, String>)> {
        let flags = *b.get(1)?;
        let mut at = 2;
        let kind = if flags & 0x08 != 0 {
            at += 1;
            b[2]
        } else {
            0
        };
        if flags & 0x04 != 0 {
            at += 8;
        }
        if flags & 0x10 != 0 {
            at += 1;
        }
        let w = 1usize << (flags & 3);
        let n = usize::try_from(le(b, at, w)?).ok()?;
        at += w;
        let name = String::from_utf8_lossy(b.get(at..at + n)?).into_owned();
        at += n;
        let target = match kind {
            0 => Ok(le(b, at, self.o)?),
            1 => {
                let len = usize::try_from(le(b, at, 2)?).ok()?;
                Err(String::from_utf8_lossy(b.get(at + 2..at + 2 + len)?).into_owned())
            }
            _ => Err(format!("external link {kind}")),
        };
        Some((name, target))
    }
}

/// A fractal heap's direct blocks: (heap offset, size, address).
struct Heap {
    blocks: Vec<(u64, u64, u64)>,
    offset_bytes: usize,
    length_bytes: usize,
    id_len: usize,
}

/// The size of a datatype message's properties (for nested types).
fn type_props_len(b: &[u8], depth: usize) -> Option<usize> {
    if depth > 16 {
        return None;
    }
    let class = b.first()? & 0x0f;
    let version = b.first()? >> 4;
    let props = b.get(8..)?;
    Some(match class {
        0 | 4 => 4,
        1 => 12,
        2 => 2,
        5 => usize::from(b[1]),
        6 => {
            let n = usize::from(u16::from_le_bytes([b[1], b[2]]));
            let size = usize::try_from(le(b, 4, 4)?).ok()?;
            let mut at = 0;
            for _ in 0..n.min(1024) {
                let end = props.get(at..)?.iter().position(|&c| c == 0)?;
                at += if version < 3 { (end + 1).div_ceil(8) * 8 } else { end + 1 };
                at += if version >= 3 { (usize::BITS - size.leading_zeros()).div_ceil(8).max(1) as usize } else { 4 };
                if version == 1 {
                    at += 28;
                }
                at += 8 + type_props_len(props.get(at..)?, depth + 1)?;
            }
            at
        }
        8 => {
            let n = usize::from(u16::from_le_bytes([b[1], b[2]]));
            let base_size = usize::try_from(le(props, 4, 4)?).ok()?;
            let mut at = 8 + type_props_len(props, depth + 1)?;
            for _ in 0..n.min(1024) {
                let end = props.get(at..)?.iter().position(|&c| c == 0)?;
                at += if version < 3 { (end + 1).div_ceil(8) * 8 } else { end + 1 };
            }
            at + n * base_size
        }
        9 => 8 + type_props_len(props, depth + 1)?,
        10 => {
            let rank = usize::from(*props.first()?);
            let mut at = if version < 3 { 4 + 8 * rank } else { 1 + 4 * rank };
            at += 8 + type_props_len(props.get(at..)?, depth + 1)?;
            at
        }
        _ => 0,
    })
}

fn filter_name(id: u64) -> String {
    match id {
        1 => "deflate".into(),
        2 => "shuffle".into(),
        3 => "fletcher32".into(),
        4 => "szip".into(),
        5 => "nbit".into(),
        6 => "scaleoffset".into(),
        307 => "bzip2".into(),
        32000 => "lzf".into(),
        32001 => "blosc".into(),
        32004 => "lz4".into(),
        32008 => "bitshuffle".into(),
        32013 => "zfp".into(),
        32015 => "zstd".into(),
        32017 => "sz".into(),
        32026 => "blosc2".into(),
        n => format!("filter {n}"),
    }
}

fn filters(b: &[u8]) -> Vec<String> {
    let Some(&version) = b.first() else { return Vec::new() };
    let n = usize::from(*b.get(1).unwrap_or(&0));
    let mut at = if version == 1 { 8 } else { 2 };
    let mut out = Vec::new();
    for _ in 0..n.min(32) {
        let Some(id) = le(b, at, 2) else { break };
        let has_name = version == 1 || id >= 256;
        let name_len = if has_name { usize::try_from(le(b, at + 2, 2).unwrap_or(0)).unwrap_or(0) } else { 0 };
        let base = at + if has_name { 4 } else { 2 };
        let values = usize::try_from(le(b, base + 2, 2).unwrap_or(0)).unwrap_or(0);
        at = base + 4;
        at += if version == 1 { name_len.div_ceil(8) * 8 } else { name_len };
        at += 4 * values;
        if version == 1 && values % 2 == 1 {
            at += 4;
        }
        out.push(filter_name(id));
    }
    out
}

/// An object to visit: path, object header address, depth, the symbol table
/// of a v1 root group.
type Pending = (String, u64, usize, Option<(u64, u64)>);

/// Read an HDF5 file's metadata.
#[allow(clippy::too_many_lines)] // superblock, then the walk
pub(crate) fn read(src: &mut dyn Source, deadline: &mut dyn FnMut() -> bool) -> Option<File> {
    // The superblock: at 0, 512, 1024, 2048 …
    let len = src.len();
    let mut at = 0u64;
    let sb = loop {
        let b = src.read_vec(at, 8).ok()?;
        if b == SIGNATURE {
            break at;
        }
        at = if at == 0 { 512 } else { at * 2 };
        if at >= len.min(1 << 24) {
            return None;
        }
    };
    let s = src.read_vec(sb, 128.min(usize::try_from(len - sb).ok()?)).ok()?;
    let version = *s.get(8)?;
    let mut file = File { superblock: version, userblock: sb, ..File::default() };
    let (o, l, base, root_addr, root_scratch) = if version < 2 {
        let o = usize::from(*s.get(13)?);
        let l = usize::from(*s.get(14)?);
        let mut i = 24 + if version == 1 { 4 } else { 0 };
        let base = le(&s, i, o)?;
        i += 4 * o; // base, free space, end of file, driver info
        // Root symbol table entry: name offset, object header, cache type, reserved, scratch.
        let root = le(&s, i + o, o)?;
        let cache = le(&s, i + 2 * o, 4)?;
        let scratch = if cache == 1 { Some((le(&s, i + 2 * o + 8, o)?, le(&s, i + 3 * o + 8, o)?)) } else { None };
        (o, l, base, root, scratch)
    } else {
        let o = usize::from(*s.get(9)?);
        let l = usize::from(*s.get(10)?);
        let base = le(&s, 12, o)?;
        let root = le(&s, 12 + 3 * o, o)?;
        (o, l, base, root, None)
    };
    if !(2..=8).contains(&o) || !(2..=8).contains(&l) {
        return None;
    }
    file.offsets = o;
    // Addresses are relative to the base address, which is the
    // superblock's position when the stored value is 0.
    let base = if base == 0 { sb } else { base };
    let mut r = Reader { src, base, o, l, gheap: HashMap::new() };
    let mut seen: HashSet<u64> = HashSet::new();
    let mut stack: Vec<Pending> = vec![("/".into(), root_addr, 0, root_scratch)];
    while let Some((path, addr, depth, scratch)) = stack.pop() {
        if file.groups.len() + file.datasets.len() >= MAX_OBJECTS || deadline() {
            file.skipped += 1 + stack.len() as u64;
            break;
        }
        if !seen.insert(addr) {
            continue;
        }
        let Some(msgs) = r.messages(addr) else {
            file.skipped += 1;
            continue;
        };
        file.paths.insert(addr, path.clone());
        let mut attrs = Vec::new();
        let mut links: Vec<(String, Result<u64, String>)> = Vec::new();
        let (mut space, mut dtype, mut layout, mut chunks, mut filt) = (None, None, "", Vec::new(), Vec::new());
        let mut is_group = scratch.is_some();
        for m in &msgs {
            match m.kind {
                0x0001 => space = r.dataspace(&m.data),
                0x0003 => dtype = Reader::dtype(&m.data, 0),
                0x0008 => {
                    let v = m.data.first().copied().unwrap_or(0);
                    let class =
                        if v >= 3 { m.data.get(1).copied().unwrap_or(9) } else { m.data.get(2).copied().unwrap_or(9) };
                    layout = match class {
                        0 => "compact",
                        1 => "contiguous",
                        2 => "chunked",
                        3 => "virtual",
                        _ => "?",
                    };
                    if class == 2 && v == 3 {
                        let rank = usize::from(m.data.get(2).copied().unwrap_or(0));
                        chunks = (0..rank.saturating_sub(1)).filter_map(|i| le(&m.data, 3 + o + 4 * i, 4)).collect();
                    } else if class == 2 && v >= 4 {
                        let rank = usize::from(m.data.get(3).copied().unwrap_or(0));
                        let w = usize::from(m.data.get(4).copied().unwrap_or(0));
                        chunks = (0..rank.saturating_sub(1)).filter_map(|i| le(&m.data, 5 + w * i, w)).collect();
                    }
                }
                0x000B => filt = filters(&m.data),
                0x000C => {
                    if let Some(a) = r.attribute(&m.data)
                        && attrs.len() < 500
                    {
                        attrs.push(a);
                    }
                }
                0x0011 => {
                    is_group = true;
                    if let (Some(bt), Some(hp)) = (le(&m.data, 0, o), le(&m.data, o, o)) {
                        links.extend(r.symbol_table(bt, hp).into_iter().map(|(n, a)| (n, Ok(a))));
                    }
                }
                0x0006 => {
                    is_group = true;
                    if let Some(lk) = r.link(&m.data) {
                        links.push(lk);
                    }
                }
                0x0002 => {
                    is_group = true;
                    let flags = m.data.get(1).copied().unwrap_or(0);
                    let at = 2 + if flags & 1 != 0 { 8 } else { 0 };
                    if let (Some(heap), Some(bt)) = (le(&m.data, at, o), le(&m.data, at + o, o))
                        && !r.undefined(heap)
                    {
                        // Link name index records: hash (4), then the heap ID.
                        for msg in r.dense(heap, bt, 4) {
                            if let Some(lk) = r.link(&msg) {
                                links.push(lk);
                            }
                        }
                    }
                }
                0x0015 => {
                    let flags = m.data.get(1).copied().unwrap_or(0);
                    let at = 2 + if flags & 1 != 0 { 2 } else { 0 };
                    if let (Some(heap), Some(bt)) = (le(&m.data, at, o), le(&m.data, at + o, o))
                        && !r.undefined(heap)
                    {
                        // Attribute name index records: the heap ID first.
                        for msg in r.dense(heap, bt, 0) {
                            if let Some(a) = r.attribute(&msg)
                                && attrs.len() < 500
                            {
                                attrs.push(a);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if is_group || (space.is_none() && dtype.is_none()) {
            let mut g = Group { path: path.clone(), attrs, links: Vec::new() };
            for (name, target) in links {
                let child = if path == "/" { format!("/{name}") } else { format!("{path}/{name}") };
                match target {
                    Ok(a) if depth < MAX_DEPTH => stack.push((child, a, depth + 1, None)),
                    Ok(_) => file.skipped += 1,
                    Err(t) => g.links.push((name, truncate_chars(&t, 300))),
                }
            }
            file.groups.push(g);
        } else {
            let (shape, max) = space.unwrap_or_default();
            file.datasets.push(Dataset { path, shape, max, dtype, layout, chunks, filters: filt, attrs });
        }
    }
    // A stable order (the walk is a stack).
    file.groups.sort_by(|a, b| a.path.cmp(&b.path));
    file.datasets.sort_by(|a, b| a.path.cmp(&b.path));
    Some(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_names() {
        assert_eq!(DType::Int { size: 4, signed: true, big: false }.name(), "int32");
        assert_eq!(DType::Float { size: 8, big: false }.name(), "float64");
        assert_eq!(
            DType::Array(vec![2, 3], Box::new(DType::Int { size: 1, signed: false, big: false })).name(),
            "uint8[2x3]"
        );
        assert_eq!(filter_name(32015), "zstd");
    }

    #[test]
    fn filter_pipeline_v2() {
        // version 2, two filters: deflate (1 value), shuffle (no values).
        let b = [2, 2, 1, 0, 0, 0, 1, 0, 6, 0, 0, 0, 2, 0, 0, 0, 0, 0];
        assert_eq!(filters(&b), vec!["deflate", "shuffle"]);
    }
}
