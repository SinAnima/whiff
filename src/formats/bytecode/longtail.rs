//! Bytecode and images of less common virtual machines:
//! * Hermes bytecode (React Native): the bytecode version, execution or
//!   delta form, the source hash, function, string and identifier counts,
//!   regular expressions, CommonJS modules, debug information and the
//!   names of the functions it defines;
//! * Smalltalk images (Squeak, Pharo, Cuis): the image format (word size,
//!   closures, Spur object memory, Sista), byte order, heap size, saved
//!   window size and the VM parameters stored in the header;
//! * Smalltalk change logs (`.changes`): the system that wrote them, the
//!   chunks, snapshots and method definitions they hold, with the classes
//!   touched; author stamps only with `--privacy off`;
//! * ActionScript bytecode (`.abc`, AVM2): the ABC version, the constant
//!   pool, methods, metadata, the classes with their super classes and
//!   packages, scripts and method bodies. SWF files hand their `DoABC`
//!   tags to the same reader.
//!
//! Specifications: Hermes `include/hermes/BCGen/HBC/BytecodeFileFormat.h`
//! (bytecode version 96); the OpenSmalltalk VM image header
//! (`readImageFromFile:HeapSize:StartingAt:`) and the Squeak `ImageFormat`
//! numbers; Squeak's change-log chunk format; Adobe "ActionScript Virtual
//! Machine 2 (AVM2) Overview" (2007), chapter 4.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::hex;
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, truncate_chars,
};

/// Extractor for Hermes bytecode, Smalltalk images and change logs, and
/// ActionScript bytecode.
pub struct Longtail;

static META: ExtractorMeta = ExtractorMeta {
    id: "bytecode.longtail",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "hermes_bytecode",
            name: "Hermes JavaScript bytecode",
            family: "bytecode",
            mimes: &["application/x-hermes-bytecode"],
            extensions: &["hbc"],
            magic: &[
                Magic::prefix(b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f"),
                Magic::prefix(b"\x39\xe0\x43\xfc\x3e\xfc\xe6\xe0"),
            ],
            parent: None,
        },
        FormatSpec {
            id: "smalltalk_image",
            name: "Smalltalk image",
            family: "bytecode",
            mimes: &["application/x-smalltalk-image"],
            // `.image` names disk images too: the header decides.
            extensions: &[],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "smalltalk_changes",
            name: "Smalltalk change log",
            family: "bytecode",
            mimes: &["text/x-smalltalk-changes"],
            // `.changes` is also a Debian upload description.
            extensions: &[],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "flash_abc",
            name: "ActionScript bytecode (ABC)",
            family: "bytecode",
            mimes: &["application/x-actionscript-bytecode"],
            extensions: &[],
            magic: &[Magic::prefix(b"\x10\x00\x2e\x00")],
            parent: None,
        },
    ],
};

/// Function names listed.
const MAX_NAMES: usize = 50;
/// Classes listed.
const MAX_CLASSES: usize = 100;

impl Extractor for Longtail {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if image_header(probe.head).is_some() {
            return Some(Sniff { format: "smalltalk_image", confidence: 0.85 });
        }
        let h = probe.head;
        let changes = h.starts_with(b"'From ") && h.windows(4).take(400).any(|w| w == b" of ")
            || h.starts_with(b"\"----STARTUP----")
            || h.starts_with(b"\"----SNAPSHOT----");
        changes.then_some(Sniff { format: "smalltalk_changes", confidence: 0.85 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "hermes_bytecode" => {
                let (b, _) = cx.read_bytes(src)?;
                hermes(&b, src.len(), cx)
            }
            "smalltalk_image" => {
                let n = usize::try_from(src.len().min(4096)).unwrap_or(0);
                let h = src.read_vec(0, n)?;
                image(&h, src.len(), cx)
            }
            "smalltalk_changes" => {
                let (b, _) = cx.read_bytes(src)?;
                changes(&crate::plugin::latin1_or_utf8(&b), cx);
                Ok(())
            }
            _ => {
                let (b, _) = cx.read_bytes(src)?;
                let abc = abc(&b).ok_or_else(|| ExtractError::malformed("ABC constant pool or tables cut short"))?;
                abc.write(cx);
                Ok(())
            }
        }
    }
}

crate::register_extractor!(Longtail);

fn le32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}

// ---------------------------------------------------------------- Hermes

fn hermes(b: &[u8], size: u64, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    if b.len() < 128 {
        return Err(ExtractError::malformed("Hermes header cut short"));
    }
    let field = |at: usize| le32(b, at).unwrap_or(0);
    let delta = b.starts_with(b"\x39\xe0\x43\xfc");
    let version = field(8);
    cx.format_set("implementation", "Hermes");
    cx.format_set("bytecode_version", version);
    cx.format_set("form", if delta { "delta" } else { "execution" });
    cx.format_set("source_hash", hex(&b[12..32]));
    let length = field(32);
    cx.format_set("file_length", length);
    if u64::from(length) > size {
        cx.warn(format!("header says {length} bytes, the file has {size}"));
    }
    let (functions, kinds, identifiers, strings, overflow) = (field(40), field(44), field(48), field(52), field(56));
    cx.format_set("functions", functions);
    cx.format_set("strings", strings);
    cx.format_set("identifiers", identifiers);
    cx.format_set("string_storage_bytes", field(60));
    // The fields after the string storage size have this layout since
    // bytecode version 87 (BigInt support).
    if version >= 87 {
        let mut counts = Map::new();
        for (name, at) in
            [("bigints", 64), ("regexps", 72), ("commonjs_modules", 96), ("function_sources", 100)]
        {
            let v = field(at);
            if v > 0 {
                counts.insert(name.into(), v.into());
            }
        }
        if !counts.is_empty() {
            cx.format_set("tables", Value::Object(counts));
        }
        cx.format_set("segment", field(92));
        cx.format_set("debug_info", field(104) != 0);
        let opts = b[108];
        let mut options = Vec::new();
        for (bit, name) in [(1, "static_builtins"), (2, "cjs_modules_statically_resolved"), (4, "async")] {
            if opts & bit != 0 {
                options.push(name);
            }
        }
        if !options.is_empty() {
            cx.format_set("options", json!(options));
        }
    }
    if delta {
        return Ok(());
    }
    // Function headers, string kinds, identifier hashes, then the string
    // tables and storage, each a whole number of 32-bit words.
    let (fh, small) = (128usize, 128 + 16 * functions as usize + 4 * kinds as usize + 4 * identifiers as usize);
    let over = small.saturating_add(4 * strings as usize);
    let storage = over.saturating_add(8 * overflow as usize);
    let string = |id: u32| -> Option<String> {
        let e = le32(b, small + 4 * id as usize)?;
        let (utf16, mut off, mut len) = (e & 1 == 1, (e >> 1) & 0x7f_ffff, e >> 24);
        if len == 0xff {
            let entry = over.checked_add(8 * off as usize)?;
            (off, len) = (le32(b, entry)?, le32(b, entry + 4)?);
        }
        let start = storage.checked_add(off as usize)?;
        if utf16 {
            let raw = b.get(start..start.checked_add(2 * len as usize)?)?;
            let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
            Some(String::from_utf16_lossy(&units))
        } else {
            Some(String::from_utf8_lossy(b.get(start..start.checked_add(len as usize)?)?).into_owned())
        }
    };
    if id_in_range(strings, b.len(), small) {
        let mut names: Vec<String> = Vec::new();
        let mut overflowed = 0u64;
        for i in 0..functions.min(100_000) as usize {
            let Some(h) = b.get(fh + 16 * i..fh + 16 * i + 16) else { break };
            if h[15] & 0x20 != 0 {
                overflowed += 1;
                continue;
            }
            let name_id = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) >> 15;
            if let Some(n) = string(name_id).filter(|n| !n.is_empty())
                && names.len() < MAX_NAMES
                && !names.contains(&n)
            {
                names.push(truncate_chars(&n, 120));
            }
        }
        if let Some(g) = b.get(fh + 16 * field(36) as usize..).and_then(|h| h.get(4..8)) {
            let id = u32::from_le_bytes([g[0], g[1], g[2], g[3]]) >> 15;
            if let Some(n) = string(id) {
                cx.format_set("global_function", n);
            }
        }
        if !names.is_empty() {
            cx.format_set("function_names", json!(names));
        }
        if overflowed > 0 {
            cx.format_set("large_function_headers", overflowed);
        }
    }
    Ok(())
}

/// Whether the string table of `count` entries at `at` lies inside the file.
fn id_in_range(count: u32, len: usize, at: usize) -> bool {
    at.checked_add(4 * count as usize).is_some_and(|end| end <= len)
}

// ------------------------------------------------------------- Smalltalk

/// What an image format number says: word size, closures, Spur, Sista.
fn image_format(v: u32) -> Option<(u8, &'static str)> {
    Some(match v {
        6502 => (32, "classic"),
        6504 => (32, "classic, closures"),
        6505 => (32, "classic, closures, native float order"),
        6521 => (32, "Spur"),
        7033 => (32, "Spur, Sista"),
        68000 => (64, "classic"),
        68002 => (64, "classic, closures"),
        68003 => (64, "classic, closures, native float order"),
        68019 => (64, "Spur (preliminary)"),
        68021 => (64, "Spur"),
        68533 => (64, "Spur, Sista"),
        _ => return None,
    })
}

/// `(header offset, little endian, format, word bits, description)`: the
/// header is at 0, or at 512 behind an old Mac resource prefix.
fn image_header(h: &[u8]) -> Option<(usize, bool, u32, u8, &'static str)> {
    for at in [0, 512] {
        let raw: [u8; 4] = h.get(at..at + 4)?.try_into().ok()?;
        for little in [true, false] {
            let v = if little { u32::from_le_bytes(raw) } else { u32::from_be_bytes(raw) };
            if let Some((bits, what)) = image_format(v) {
                let hs = h.get(at + 4..at + 8)?;
                let hs = if little { u32::from_le_bytes(hs.try_into().ok()?) } else { u32::from_be_bytes(hs.try_into().ok()?) };
                if hs == if bits == 32 { 64 } else { 128 } {
                    return Some((at, little, v, bits, what));
                }
            }
        }
    }
    None
}

fn image(h: &[u8], size: u64, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let (at, little, version, bits, what) =
        image_header(h).ok_or_else(|| ExtractError::malformed("no Smalltalk image header"))?;
    let w = usize::from(bits / 8);
    let int = |off: usize, n: usize| -> Option<u64> {
        let s = h.get(at + off..at + off + n)?;
        Some(if little {
            s.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x))
        } else {
            s.iter().fold(0u64, |a, &x| a << 8 | u64::from(x))
        })
    };
    cx.format_set("image_format", version);
    cx.format_set("word_bits", bits);
    cx.format_set("object_memory", what);
    cx.format_set("byte_order", if little { "little_endian" } else { "big_endian" });
    if at > 0 {
        cx.format_set("header_offset", at);
    }
    // Words after the format and header size: data size, old base address,
    // special objects, last hash, window size, flags.
    let word = |i: usize| int(8 + i * w, w);
    if let Some(d) = word(0) {
        cx.format_set("heap_bytes", d);
        if d.saturating_add(if bits == 32 { 64 } else { 128 }) > size {
            cx.warn(format!("header says {d} heap bytes, the file is {size} bytes"));
        }
    }
    if let Some(s) = word(4) {
        let s = s & 0xffff_ffff;
        let (width, height) = (s >> 16, s & 0xffff);
        if width > 0 && height > 0 {
            cx.format_set("window", json!({ "width": width, "height": height }));
        }
    }
    if let Some(f) = word(5) {
        cx.format_set("fullscreen", f & 1 == 1);
    }
    let rest = 8 + 6 * w;
    let mut vm = Map::new();
    for (name, off, n) in [("extra_vm_memory", 0, 4), ("stack_pages", 4, 2), ("jit_code_kib", 6, 2), ("eden_bytes", 8, 4)] {
        if let Some(v) = int(rest + off, n).filter(|&v| v > 0) {
            vm.insert(name.into(), v.into());
        }
    }
    if what.starts_with("Spur")
        && let Some(v) = int(rest + 16, w).filter(|&v| v > 0)
    {
        vm.insert("first_segment_bytes".into(), v.into());
    }
    if !vm.is_empty() {
        cx.format_set("vm_parameters", Value::Object(vm));
    }
    Ok(())
}

/// Method-definition chunks: `!Class methodsFor: 'category' stamp: '…'!`.
fn changes(text: &str, cx: &mut Context<'_>) {
    let mut chunks = 0u64;
    let (mut methods, mut snapshots, mut startups) = (0u64, 0u64, 0u64);
    let mut classes: BTreeMap<String, u64> = BTreeMap::new();
    let mut authors: BTreeMap<String, u64> = BTreeMap::new();
    let mut system: Option<String> = None;
    for chunk in text.split('!') {
        let c = chunk.trim();
        if c.is_empty() {
            continue;
        }
        chunks += 1;
        if system.is_none()
            && let Some(rest) = c.strip_prefix("'From ")
        {
            system = rest.split(" of ").next().map(|s| truncate_chars(s.trim(), 80));
        }
        if c.starts_with("\"----SNAPSHOT----") {
            snapshots += 1;
        } else if c.starts_with("\"----STARTUP----") {
            startups += 1;
        }
        if let Some(i) = c.find(" methodsFor: '") {
            methods += 1;
            let class = c[..i].split_whitespace().next().unwrap_or("");
            if !class.is_empty() && classes.len() < 1000 {
                *classes.entry(truncate_chars(class, 80)).or_default() += 1;
            }
            if let Some(s) = c.find("stamp: '").map(|j| &c[j + 8..])
                && let Some(author) = s.split([' ', '\'']).next().filter(|a| !a.is_empty())
                && authors.len() < 100
            {
                *authors.entry(truncate_chars(author, 40)).or_default() += 1;
            }
        }
    }
    if let Some(s) = system {
        cx.format_set("system", s);
    }
    cx.format_set("chunks", chunks);
    cx.format_set("method_categories", methods);
    if snapshots > 0 {
        cx.format_set("snapshots", snapshots);
    }
    if startups > 0 {
        cx.format_set("startups", startups);
    }
    if !classes.is_empty() {
        cx.format_set("classes", classes.len());
        let mut top: Vec<(String, u64)> = classes.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        cx.format_set("classes_touched", json!(top.iter().take(20).map(|(c, _)| c).collect::<Vec<_>>()));
    }
    // Stamps carry author initials or names.
    if !authors.is_empty() {
        if cx.privacy_strict() {
            cx.format_set("authors", authors.len());
        } else {
            cx.format_set("authors", json!(authors));
        }
    }
}

// ------------------------------------------------------------------- ABC

/// A cursor over AVM2's variable-length integers.
struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cur<'a> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.i)?;
        self.i += 1;
        Some(v)
    }

    /// `u30` / `u32` / `s32`: up to five bytes, seven bits each.
    fn u30(&mut self) -> Option<u32> {
        let mut v = 0u32;
        for shift in [0, 7, 14, 21, 28] {
            let b = self.u8()?;
            v |= u32::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        Some(v)
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.i..self.i.checked_add(n)?)?;
        self.i += n;
        Some(s)
    }

    /// `count` entries of `item`, where entry 0 is implicit (`count - 1` stored).
    fn pool(&mut self, mut item: impl FnMut(&mut Self) -> Option<()>) -> Option<u32> {
        let n = self.u30()?;
        for _ in 1..n {
            item(self)?;
        }
        Some(n.saturating_sub(1))
    }

    /// `count` entries of `item`.
    fn list(&mut self, mut item: impl FnMut(&mut Self) -> Option<()>) -> Option<u32> {
        let n = self.u30()?;
        for _ in 0..n {
            item(self)?;
        }
        Some(n)
    }

    fn traits(&mut self) -> Option<u32> {
        self.list(|c| {
            c.u30()?;
            let kind = c.u8()?;
            match kind & 0x0f {
                0 | 6 => {
                    c.u30()?;
                    c.u30()?;
                    if c.u30()? != 0 {
                        c.u8()?;
                    }
                }
                1..=5 => {
                    c.u30()?;
                    c.u30()?;
                }
                _ => return None,
            }
            if kind & 0x40 != 0 {
                c.list(|c| c.u30().map(drop))?;
            }
            Some(())
        })
    }
}

/// A parsed ABC file.
#[derive(Default)]
pub(crate) struct Abc {
    version: (u16, u16),
    pool: Vec<(&'static str, u32)>,
    methods: u32,
    metadata: BTreeMap<String, u64>,
    /// `(name, super, interface)`.
    pub classes: Vec<(String, String, bool)>,
    scripts: u32,
    bodies: u32,
    code_bytes: u64,
}

/// Parse an ABC file (a standalone `.abc` or the body of a SWF `DoABC` tag).
#[allow(clippy::too_many_lines)] // one pass over the ABC tables, in file order
pub(crate) fn abc(b: &[u8]) -> Option<Abc> {
    let mut c = Cur { b, i: 0 };
    let minor = u16::from_le_bytes(c.bytes(2)?.try_into().ok()?);
    let major = u16::from_le_bytes(c.bytes(2)?.try_into().ok()?);
    let mut out = Abc { version: (major, minor), ..Abc::default() };
    let ints = c.pool(|c| c.u30().map(drop))?;
    let uints = c.pool(|c| c.u30().map(drop))?;
    let doubles = c.pool(|c| c.bytes(8).map(drop))?;
    let mut strings: Vec<&[u8]> = vec![b""];
    let n = c.u30()?;
    for _ in 1..n {
        let len = c.u30()? as usize;
        strings.push(c.bytes(len)?);
    }
    let s = |i: u32| strings.get(i as usize).map_or_else(String::new, |s| String::from_utf8_lossy(s).into_owned());
    let mut namespaces: Vec<(u8, u32)> = vec![(0, 0)];
    let nss = c.pool(|c| {
        namespaces.push((c.u8()?, c.u30()?));
        Some(())
    })?;
    let ns_sets = c.pool(|c| c.list(|c| c.u30().map(drop)).map(drop))?;
    // Multinames: QName `(namespace, name)`; other kinds keep only a name.
    let mut multinames: Vec<(u32, u32)> = vec![(0, 0)];
    let mns = c.pool(|c| {
        let m = match c.u8()? {
            0x07 | 0x0d => (c.u30()?, c.u30()?),
            0x0f | 0x10 => (0, c.u30()?),
            0x11 | 0x12 => (0, 0),
            0x09 | 0x0e => {
                let name = c.u30()?;
                c.u30()?;
                (0, name)
            }
            0x1b | 0x1c => {
                c.u30()?;
                (0, 0)
            }
            0x1d => {
                let q = c.u30()?;
                c.list(|c| c.u30().map(drop))?;
                multinames.get(q as usize).copied().unwrap_or((0, 0))
            }
            _ => return None,
        };
        multinames.push(m);
        Some(())
    })?;
    out.pool = vec![
        ("integers", ints),
        ("unsigned_integers", uints),
        ("doubles", doubles),
        ("strings", n.saturating_sub(1)),
        ("namespaces", nss),
        ("namespace_sets", ns_sets),
        ("multinames", mns),
    ];
    let qname = |i: u32| -> String {
        let (ns, name) = multinames.get(i as usize).copied().unwrap_or((0, 0));
        let pkg = namespaces.get(ns as usize).map(|&(_, n)| s(n)).unwrap_or_default();
        let name = s(name);
        if pkg.is_empty() { name } else { format!("{pkg}.{name}") }
    };
    out.methods = c.list(|c| {
        let params = c.u30()?;
        c.u30()?;
        for _ in 0..params {
            c.u30()?;
        }
        c.u30()?;
        let flags = c.u8()?;
        if flags & 0x08 != 0 {
            c.list(|c| {
                c.u30()?;
                c.u8().map(drop)
            })?;
        }
        if flags & 0x80 != 0 {
            for _ in 0..params {
                c.u30()?;
            }
        }
        Some(())
    })?;
    let mut meta = BTreeMap::new();
    c.list(|c| {
        let name = c.u30()?;
        c.list(|c| {
            c.u30()?;
            c.u30().map(drop)
        })?;
        *meta.entry(truncate_chars(&s(name), 80)).or_default() += 1;
        Some(())
    })?;
    out.metadata = meta;
    let classes = c.u30()?;
    let mut list = Vec::new();
    for _ in 0..classes {
        let (name, sup) = (c.u30()?, c.u30()?);
        let flags = c.u8()?;
        if flags & 0x08 != 0 {
            c.u30()?;
        }
        c.list(|c| c.u30().map(drop))?;
        c.u30()?;
        c.traits()?;
        if list.len() < MAX_CLASSES {
            list.push((truncate_chars(&qname(name), 200), truncate_chars(&qname(sup), 200), flags & 0x04 != 0));
        }
    }
    for _ in 0..classes {
        c.u30()?;
        c.traits()?;
    }
    out.classes = list;
    out.scripts = c.list(|c| {
        c.u30()?;
        c.traits().map(drop)
    })?;
    let mut code = 0u64;
    out.bodies = c.list(|c| {
        for _ in 0..5 {
            c.u30()?;
        }
        let len = c.u30()?;
        c.bytes(len as usize)?;
        code += u64::from(len);
        c.list(|c| {
            for _ in 0..5 {
                c.u30()?;
            }
            Some(())
        })?;
        c.traits().map(drop)
    })?;
    out.code_bytes = code;
    Some(out)
}

impl Abc {
    /// Only classes (what a SWF gathers from its `DoABC` tags).
    pub(crate) fn with_classes(classes: Vec<(String, String, bool)>) -> Self {
        Self { classes, ..Self::default() }
    }

    fn write(&self, cx: &mut Context<'_>) {
        cx.format_set("abc_version", format!("{}.{}", self.version.0, self.version.1));
        let pool: Map<String, Value> = self.pool.iter().map(|(k, v)| ((*k).to_string(), json!(v))).collect();
        cx.format_set("constant_pool", Value::Object(pool));
        cx.format_set("methods", self.methods);
        cx.format_set("method_bodies", self.bodies);
        cx.format_set("code_bytes", self.code_bytes);
        cx.format_set("scripts", self.scripts);
        if !self.metadata.is_empty() {
            cx.format_set("metadata", json!(self.metadata));
        }
        self.write_classes(cx.format());
    }

    /// Classes and their packages, into `out`.
    pub(crate) fn write_classes(&self, out: &mut Map<String, Value>) {
        out.insert("classes".into(), json!(self.classes.len()));
        if self.classes.is_empty() {
            return;
        }
        let list: Vec<Value> = self
            .classes
            .iter()
            .map(|(name, sup, interface)| {
                let mut m = Map::new();
                m.insert("name".into(), json!(name));
                if !sup.is_empty() {
                    m.insert("extends".into(), json!(sup));
                }
                if *interface {
                    m.insert("interface".into(), json!(true));
                }
                Value::Object(m)
            })
            .collect();
        out.insert("class_list".into(), Value::Array(list));
        let mut packages: Vec<&str> =
            self.classes.iter().filter_map(|(n, _, _)| n.rsplit_once('.').map(|(p, _)| p)).collect();
        packages.sort_unstable();
        packages.dedup();
        if !packages.is_empty() {
            out.insert("packages".into(), json!(packages));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("hermes_bytecode", "smalltalk_image", "smalltalk_changes", "flash_abc");

    #[test]
    fn change_log_authors_follow_privacy() {
        let log = b"'From Pharo12.0.0 of 1 May 2024'!\n!Tide methodsFor: 'height' stamp: 'ab 3/4/2024 10:00'!\nheight ^ 3! !\n";
        let strict = crate::plugin::testing::report_for("tides.changes", log);
        assert_eq!(strict.format["smalltalk_changes"]["authors"], json!(1));
        let open = crate::plugin::testing::report_without_privacy("tides.changes", log);
        assert_eq!(open.format["smalltalk_changes"]["authors"], json!({ "ab": 1 }));
    }

    #[test]
    fn truncated_abc_is_rejected() {
        assert!(abc(&[0x10, 0, 0x2e, 0, 5]).is_none());
        assert!(abc(&[0x10, 0, 0x2e, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_some());
    }
}
