//! Debug information kept apart from the program:
//!
//! * Microsoft program databases (`.pdb`, MSF 7.00): the stream directory,
//!   the PDB information stream (version, signature, age, GUID: what an
//!   executable's debug directory points at), the DBI stream (machine,
//!   toolchain, the modules and the object files they came from) and the
//!   type count of the TPI stream;
//! * split DWARF (`.dwo` objects and `.dwp` packages, ELF files holding
//!   `.debug_*.dwo` sections): per compile unit the DWARF version, the
//!   DWO id and, read from the unit's first entry, its producer, language
//!   and source name; a package gives its unit index.
//!
//! Specifications: LLVM's *The PDB File Format* (MSF, PDB info, DBI and TPI
//! streams); DWARF 5 (§7.3 split units, §7.3.5 package index), and the GNU
//! split-DWARF extension for version 4.

use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    latin1_or_utf8, user_path,
};

/// Extractor for PDB files and split DWARF.
pub struct Debug;

const MSF7: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

static META: ExtractorMeta = ExtractorMeta {
    id: "exec.debug",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "ms_pdb",
            name: "Microsoft program database (PDB)",
            family: "exec",
            mimes: &["application/x-ms-pdb"],
            // `.pdb` is also the Protein Data Bank: the magic decides.
            extensions: &[],
            magic: &[Magic::prefix(MSF7)],
            parent: None,
        },
        FormatSpec {
            id: "split_dwarf",
            name: "Split DWARF debug information (DWO / DWP)",
            family: "exec",
            mimes: &["application/x-dwarf"],
            extensions: &["dwo", "dwp"],
            magic: &[],
            parent: Some("elf"),
        },
    ],
};

/// Modules listed.
const MAX_MODULES: usize = 200;
/// Compile units read.
const MAX_UNITS: usize = 10_000;

impl Extractor for Debug {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if !probe.head.starts_with(b"\x7fELF") {
            return None;
        }
        if matches!(probe.extension, Some("dwo" | "dwp")) {
            return Some(Sniff { format: "split_dwarf", confidence: 0.9 });
        }
        // The section names usually sit near the end.
        let has = |b: &[u8], n: &[u8]| b.windows(n.len()).any(|w| w == n);
        let named = |n: &[u8]| has(probe.tail, n) || has(probe.head, n);
        (named(b".debug_info.dwo") && !named(b".text")).then_some(Sniff { format: "split_dwarf", confidence: 0.85 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "ms_pdb" { pdb(src, cx) } else { dwarf(src, cx) }
    }
}

crate::register_extractor!(Debug);

// --- PDB -------------------------------------------------------------------------

/// An MSF file: its block size and every stream's size and blocks.
struct Msf {
    block: u64,
    streams: Vec<(u32, Vec<u32>)>,
}

impl Msf {
    fn open(src: &mut dyn Source) -> Result<Self, ExtractError> {
        let h = src.read_vec(0, 56)?;
        let mut r = ByteReader::new(&h).skip(32)?;
        let block = u64::from(r.le_u32()?);
        if !matches!(block, 512 | 1024 | 2048 | 4096 | 8192 | 16384 | 32768) {
            return Err(ExtractError::malformed("MSF block size"));
        }
        r.le_u32()?;
        let blocks = u64::from(r.le_u32()?);
        let dir_bytes = u64::from(r.le_u32()?);
        r.le_u32()?;
        let map_block = u64::from(r.le_u32()?);
        if blocks.saturating_mul(block) > src.len().saturating_add(block) || dir_bytes > 64 << 20 {
            return Err(ExtractError::malformed("MSF sizes"));
        }
        // The block map lists the directory's blocks; the directory lists
        // the streams' sizes, then each stream's blocks.
        let dir_blocks = dir_bytes.div_ceil(block);
        let map = src.read_vec(map_block * block, usize::try_from(dir_blocks * 4).unwrap_or(0))?;
        let mut dir = Vec::new();
        for c in map.as_chunks::<4>().0 {
            let b = u64::from(u32::from_le_bytes(*c));
            dir.extend(src.read_vec(b * block, usize::try_from(block).unwrap_or(0))?);
        }
        dir.truncate(usize::try_from(dir_bytes).unwrap_or(0));
        let mut r = ByteReader::new(&dir);
        let n = usize::try_from(r.le_u32()?).unwrap_or(0).min(1 << 16);
        let sizes: Vec<u32> = (0..n).map(|_| r.le_u32()).collect::<Result<_, _>>()?;
        let mut streams = Vec::with_capacity(n);
        for size in sizes {
            let count = if size == u32::MAX { 0 } else { u64::from(size).div_ceil(block) };
            let ids: Vec<u32> = (0..count).map(|_| r.le_u32()).collect::<Result<_, _>>()?;
            streams.push((if size == u32::MAX { 0 } else { size }, ids));
        }
        Ok(Self { block, streams })
    }

    /// Stream `i`, up to `max` bytes.
    fn read(&self, src: &mut dyn Source, i: usize, max: usize) -> Result<Vec<u8>, ExtractError> {
        let Some((size, blocks)) = self.streams.get(i) else { return Ok(Vec::new()) };
        let want = usize::try_from(*size).unwrap_or(0).min(max);
        let mut out = Vec::with_capacity(want);
        for &b in blocks {
            if out.len() >= want {
                break;
            }
            let n = usize::try_from(self.block).unwrap_or(0).min(want - out.len());
            out.extend(src.read_vec(u64::from(b) * self.block, n)?);
        }
        Ok(out)
    }
}

/// A GUID as Windows writes it: `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
fn guid(b: &[u8]) -> String {
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    let hex = b[8..16].iter().fold(String::new(), |mut acc, x| {
        use std::fmt::Write;
        let _ = write!(acc, "{x:02X}");
        acc
    });
    format!("{{{d1:08X}-{d2:04X}-{d3:04X}-{}-{}}}", &hex[..4], &hex[4..])
}

fn machine(m: u16) -> String {
    match m {
        0x014c => "x86".into(),
        0x8664 => "x86-64".into(),
        0xaa64 => "ARM64".into(),
        0x01c4 => "ARM (Thumb-2)".into(),
        0x0200 => "IA-64".into(),
        n => format!("0x{n:04x}"),
    }
}

fn pdb(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let msf = Msf::open(src)?;
    cx.format_set("block_bytes", msf.block);
    cx.format_set("streams", msf.streams.len());
    let info = msf.read(src, 1, 1 << 16)?;
    if info.len() >= 28 {
        let mut r = ByteReader::new(&info);
        let version = r.le_u32()?;
        cx.format_set(
            "version",
            match version {
                19_990_604 => "VC6".to_string(),
                20_000_404 => "VC7".to_string(),
                20_030_901 => "VC8".to_string(),
                20_091_201 => "VC14".to_string(),
                n => n.to_string(),
            },
        );
        cx.format_set("signature", r.le_u32()?);
        cx.format_set("age", r.le_u32()?);
        cx.format_set("guid", guid(r.bytes(16)?));
    }
    let tpi = msf.read(src, 2, 64)?;
    if tpi.len() >= 16 {
        let mut r = ByteReader::new(&tpi).skip(8)?;
        let (first, end) = (r.le_u32()?, r.le_u32()?);
        cx.format_set("types", end.saturating_sub(first));
    }
    let dbi = msf.read(src, 3, cx.parse_limit())?;
    if dbi.len() >= 64 && dbi[..4] == [0xff; 4] {
        let mut r = ByteReader::new(&dbi).skip(8)?;
        cx.format_set("dbi_age", r.le_u32()?);
        r.le_u16()?;
        let build = r.le_u16()?;
        if build & 0x8000 != 0 {
            cx.format_set("toolchain", format!("{}.{}", (build >> 8) & 0x7f, build & 0xff));
        }
        let mut f = ByteReader::new(&dbi).skip(24)?;
        let mod_bytes = usize::try_from(f.le_u32()?).unwrap_or(0);
        let mut m = ByteReader::new(&dbi).skip(56)?;
        let flags = m.le_u16()?;
        cx.format_set("machine", machine(m.le_u16()?));
        if flags & 1 != 0 {
            cx.format_set("incrementally_linked", true);
        }
        if flags & 2 != 0 {
            cx.format_set("private_symbols_stripped", true);
        }
        let mods = dbi.get(64..64 + mod_bytes.min(dbi.len() - 64)).unwrap_or(&[]);
        let (list, count) = modules(cx, mods);
        cx.format_set("module_count", count);
        cx.format_set("modules", list);
    }
    Ok(())
}

/// The DBI module list: (module and object file names, module count).
fn modules(cx: &Context<'_>, mut b: &[u8]) -> (Vec<serde_json::Value>, usize) {
    let (mut list, mut count) = (Vec::new(), 0usize);
    while b.len() > 64 {
        let rest = &b[64..];
        let Some(n1) = rest.iter().position(|&c| c == 0) else { break };
        let Some(n2) = rest[n1 + 1..].iter().position(|&c| c == 0) else { break };
        let (module, object) = (latin1_or_utf8(&rest[..n1]), latin1_or_utf8(&rest[n1 + 1..n1 + 1 + n2]));
        count += 1;
        if list.len() < MAX_MODULES {
            let mut m = serde_json::Map::new();
            m.insert("module".into(), user_path(cx, &module).into());
            if !object.is_empty() && object != module {
                m.insert("object".into(), user_path(cx, &object).into());
            }
            list.push(m.into());
        }
        let used = (64 + n1 + 1 + n2 + 1).next_multiple_of(4);
        b = b.get(used..).unwrap_or(&[]);
    }
    (list, count)
}

// --- split DWARF -----------------------------------------------------------------

/// The sections of an ELF file: name → (offset, size).
fn elf_sections(src: &mut dyn Source) -> Result<Vec<(String, u64, u64)>, ExtractError> {
    let h = src.read_vec(0, 64)?;
    let wide = h[4] == 2;
    let le = h[5] != 2;
    let u16_at = |b: &[u8], at: usize| {
        let x = [b[at], b[at + 1]];
        u64::from(if le { u16::from_le_bytes(x) } else { u16::from_be_bytes(x) })
    };
    let u32_at = |b: &[u8], at: usize| {
        let x = [b[at], b[at + 1], b[at + 2], b[at + 3]];
        u64::from(if le { u32::from_le_bytes(x) } else { u32::from_be_bytes(x) })
    };
    let u64_at = |b: &[u8], at: usize| {
        let x: [u8; 8] = b[at..at + 8].try_into().unwrap_or([0; 8]);
        if le { u64::from_le_bytes(x) } else { u64::from_be_bytes(x) }
    };
    let (shoff, shentsize, shnum, shstrndx) = if wide {
        (u64_at(&h, 40), u16_at(&h, 58), u16_at(&h, 60), u16_at(&h, 62))
    } else {
        (u32_at(&h, 32), u16_at(&h, 46), u16_at(&h, 48), u16_at(&h, 50))
    };
    if shnum == 0 || shnum > 4096 || shentsize < if wide { 64 } else { 40 } {
        return Err(ExtractError::malformed("ELF section table"));
    }
    let table = src.read_vec(shoff, usize::try_from(shnum * shentsize).unwrap_or(0))?;
    let entry = |i: u64| {
        let at = usize::try_from(i * shentsize).unwrap_or(0);
        let e = &table[at..];
        if wide { (u32_at(e, 0), u64_at(e, 24), u64_at(e, 32)) } else { (u32_at(e, 0), u32_at(e, 16), u32_at(e, 20)) }
    };
    let (_, str_off, str_size) = entry(shstrndx.min(shnum - 1));
    let names = src.read_vec(str_off, usize::try_from(str_size.min(1 << 20)).unwrap_or(0))?;
    Ok((0..shnum)
        .map(|i| {
            let (name, off, size) = entry(i);
            let n = names.get(usize::try_from(name).unwrap_or(usize::MAX)..).unwrap_or(&[]);
            (latin1_or_utf8(n.split(|&b| b == 0).next().unwrap_or(&[])), off, size)
        })
        .collect())
}

fn language(l: u64) -> Option<&'static str> {
    Some(match l {
        0x01 | 0x02 | 0x0c | 0x1d | 0x2c => "C",
        0x04 | 0x1a | 0x21 | 0x2b => "C++",
        0x0d | 0x22 => "Ada",
        0x0e | 0x07 | 0x08 | 0x22e8 => "Fortran",
        0x16 => "Go",
        0x1c => "Rust",
        0x1e => "Swift",
        0x10 => "Objective-C",
        0x13 => "D",
        0x0b => "Java",
        _ => return None,
    })
}

/// DWARF forms of a fixed size (32-bit DWARF): the bytes to skip, or
/// `None` for the variable-length ones handled apart.
fn fixed_form(form: u64, addr: usize) -> Option<usize> {
    Some(match form {
        // data1, flag, ref1, strx1, addrx1
        0x0b | 0x0c | 0x11 | 0x25 | 0x29 => 1,
        // data2, ref2, strx2, addrx2
        0x05 | 0x12 | 0x26 | 0x2a => 2,
        // strx3, addrx3
        0x27 | 0x2b => 3,
        // data4, ref4, ref_sup4, strx4, addrx4, and the offsets: strp,
        // ref_addr, sec_offset, strp_sup, line_strp
        0x06 | 0x13 | 0x1c | 0x28 | 0x2c | 0x0e | 0x10 | 0x17 | 0x1d | 0x1f => 4,
        // data8, ref8, ref_sig8, ref_sup8
        0x07 | 0x14 | 0x20 | 0x24 => 8,
        0x1e => 16,
        0x01 => addr,
        // flag_present, implicit_const
        0x19 | 0x21 => 0,
        _ => return None,
    })
}

fn uleb(r: &mut ByteReader<'_>) -> Result<u64, ExtractError> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let b = r.u8()?;
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(ExtractError::malformed("LEB128"))
}

/// The attributes (name, form) of abbreviation `code` in `abbrev`.
fn abbreviation(abbrev: &[u8], code: u64) -> Result<Vec<(u64, u64, i64)>, ExtractError> {
    let mut r = ByteReader::new(abbrev);
    while r.remaining() > 0 {
        let c = uleb(&mut r)?;
        if c == 0 {
            break;
        }
        uleb(&mut r)?;
        r.u8()?;
        let mut attrs = Vec::new();
        loop {
            let (name, form) = (uleb(&mut r)?, uleb(&mut r)?);
            if name == 0 && form == 0 {
                break;
            }
            // DW_FORM_implicit_const carries its value here.
            let k = if form == 0x21 { i64::try_from(uleb(&mut r)?).unwrap_or(0) } else { 0 };
            attrs.push((name, form, k));
        }
        if c == code {
            return Ok(attrs);
        }
    }
    Err(ExtractError::malformed("DWARF abbreviation"))
}

/// The strings of a split unit: `.debug_str.dwo` through `.debug_str_offsets.dwo`.
struct Strings {
    str_: Vec<u8>,
    offsets: Vec<u8>,
}

impl Strings {
    fn at(&self, off: usize) -> Option<String> {
        let s = self.str_.get(off..)?;
        Some(latin1_or_utf8(s.split(|&b| b == 0).next()?))
    }

    fn index(&self, i: u64) -> Option<String> {
        // A DWARF 5 offsets table has an 8-byte header; GNU's v4 one none.
        let base = if self.offsets.get(4..6) == Some(&[5, 0]) { 8 } else { 0 };
        let at = base + usize::try_from(i).ok()? * 4;
        let b = self.offsets.get(at..at + 4)?;
        self.at(usize::try_from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok()?)
    }
}

/// The first entry (the compile unit) of a unit: producer, language, name.
fn unit_entry(
    body: &[u8],
    abbrev: &[u8],
    addr: usize,
    strings: &Strings,
) -> Result<serde_json::Map<String, serde_json::Value>, ExtractError> {
    let mut out = serde_json::Map::new();
    let mut r = ByteReader::new(body);
    let code = uleb(&mut r)?;
    for (name, form, _) in abbreviation(abbrev, code)? {
        let value: Option<serde_json::Value> = match form {
            0x08 => Some(latin1_or_utf8(r.cstr()?).into()),
            0x0e => {
                let o = r.le_u32()?;
                strings.at(usize::try_from(o).unwrap_or(usize::MAX)).map(Into::into)
            }
            // strx, and GNU's str_index (DWARF 4 split units)
            0x1a | 0x1f02 => strings.index(uleb(&mut r)?).map(Into::into),
            0x25 => strings.index(u64::from(r.u8()?)).map(Into::into),
            0x26 => strings.index(u64::from(r.le_u16()?)).map(Into::into),
            0x28 => strings.index(u64::from(r.le_u32()?)).map(Into::into),
            0x0b => Some(r.u8()?.into()),
            0x05 => Some(r.le_u16()?.into()),
            0x06 => Some(r.le_u32()?.into()),
            0x0f => Some(uleb(&mut r)?.into()),
            // sdata (the same bytes as LEB128), ref_udata, addrx,
            // loclistx, rnglistx, GNU addr_index
            0x0d | 0x15 | 0x1b | 0x22 | 0x23 | 0x1f01 => {
                uleb(&mut r)?;
                None
            }
            0x0a => {
                let n = usize::from(r.u8()?);
                r.advance(n)?;
                None
            }
            0x03 => {
                let n = usize::from(r.le_u16()?);
                r.advance(n)?;
                None
            }
            0x04 => {
                let n = usize::try_from(r.le_u32()?).unwrap_or(usize::MAX);
                r.advance(n)?;
                None
            }
            0x09 | 0x18 => {
                let n = usize::try_from(uleb(&mut r)?).unwrap_or(usize::MAX);
                r.advance(n)?;
                None
            }
            f => {
                let Some(n) = fixed_form(f, addr) else { break };
                r.advance(n)?;
                None
            }
        };
        let Some(v) = value else { continue };
        match name {
            0x25 => _ = out.insert("producer".into(), v),
            0x03 => _ = out.insert("name".into(), v),
            0x13 => {
                if let Some(l) = v.as_u64().and_then(language) {
                    out.insert("language".into(), l.into());
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

fn dwarf(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let sections = elf_sections(src)?;
    let limit = cx.parse_limit() as u64;
    let mut read = |name: &str| -> Result<Vec<u8>, ExtractError> {
        match sections.iter().find(|(n, ..)| n == name) {
            Some((_, off, size)) => Ok(src.read_vec(*off, usize::try_from((*size).min(limit)).unwrap_or(0))?),
            None => Ok(Vec::new()),
        }
    };
    let names: Vec<&str> = sections.iter().map(|(n, ..)| n.as_str()).filter(|n| n.starts_with(".debug")).collect();
    cx.format_set("debug_sections", names.iter().map(|n| serde_json::Value::from(*n)).collect::<Vec<_>>());
    // A package: its CU index (version, columns, units, hash slots).
    let index = read(".debug_cu_index")?;
    if index.len() >= 16 {
        cx.format_set("package", true);
        let mut r = ByteReader::new(&index);
        let v = r.le_u32()?;
        cx.format_set("index_version", if v & 0xffff == 5 { 5 } else { v });
        r.le_u32()?;
        cx.format_set("units", r.le_u32()?);
        let tu = read(".debug_tu_index")?;
        if tu.len() >= 16 {
            cx.format_set("type_units", ByteReader::new(&tu).skip(8)?.le_u32()?);
        }
        return Ok(());
    }
    let info = read(".debug_info.dwo")?;
    let abbrev = read(".debug_abbrev.dwo")?;
    let strings = Strings { str_: read(".debug_str.dwo")?, offsets: read(".debug_str_offsets.dwo")? };
    let mut units = Vec::new();
    let mut at = 0usize;
    while at + 11 < info.len() && units.len() < MAX_UNITS {
        let mut r = ByteReader::new(&info[at..]);
        let mut len = u64::from(r.le_u32()?);
        let mut off_size = 4;
        if len == 0xffff_ffff {
            len = r.le_u64()?;
            off_size = 8;
        }
        let start = r.position();
        let version = r.le_u16()?;
        let mut unit = serde_json::Map::new();
        unit.insert("dwarf_version".into(), version.into());
        let (abbrev_off, addr) = if version >= 5 {
            let kind = r.u8()?;
            let addr = usize::from(r.u8()?);
            let off = if off_size == 8 { r.le_u64()? } else { u64::from(r.le_u32()?) };
            if matches!(kind, 4 | 5) {
                unit.insert("dwo_id".into(), format!("{:016x}", r.le_u64()?).into());
            }
            (off, addr)
        } else {
            let off = if off_size == 8 { r.le_u64()? } else { u64::from(r.le_u32()?) };
            (off, usize::from(r.u8()?))
        };
        let end = (at + start).saturating_add(usize::try_from(len).unwrap_or(usize::MAX)).min(info.len());
        let body = info.get(at + r.position()..end).unwrap_or(&[]);
        let ab = abbrev.get(usize::try_from(abbrev_off).unwrap_or(usize::MAX)..).unwrap_or(&[]);
        if let Ok(e) = unit_entry(body, ab, addr, &strings) {
            unit.extend(e);
        }
        units.push(serde_json::Value::Object(unit));
        if end <= at {
            break;
        }
        at = end;
    }
    cx.format_set("units", units.len());
    if let Some(p) = units.iter().find_map(|u| u.get("producer").and_then(serde_json::Value::as_str)) {
        cx.format_set("producer", p.to_string());
    }
    cx.format_set("unit_list", units);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("ms_pdb", "split_dwarf");

    #[test]
    fn guids_and_languages() {
        let b = [0x5b, 0xda, 0x55, 0xe6, 0x8f, 0x97, 0x37, 0x81, 0x4c, 0x4c, 0x44, 0x20, 0x50, 0x44, 0x42, 0x2e];
        assert_eq!(guid(&b), "{E655DA5B-978F-8137-4C4C-44205044422E}");
        assert_eq!(language(0x1d), Some("C"));
        assert_eq!(language(0x1c), Some("Rust"));
        assert_eq!(fixed_form(0x01, 8), Some(8));
    }
}
