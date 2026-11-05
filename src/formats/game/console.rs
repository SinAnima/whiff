//! Console packages, from their unencrypted structures:
//! * Nintendo Switch NSP (PFS0): files, the content kinds (NCA, ticket,
//!   certificate, CNMT), title IDs from the ticket names, sizes;
//! * Nintendo Switch XCI (game card): card size, package ID, the root
//!   HFS0 partitions;
//! * Nintendo 3DS CIA: sections, title ID and kind, title version, content
//!   count, and from the SMDH icon in the meta section the short and long
//!   titles and the publisher.
//!
//! Everything encrypted (NCA contents, the secure partition, CIA contents)
//! is left alone. Specifications: `switchbrew` wiki (PFS0, HFS0, XCI),
//! `3dbrew` wiki (CIA, Title metadata, SMDH).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::{bump, hist, member_ext};
use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    truncate_chars,
};

/// Extractor for console packages.
pub struct Console;

static META: ExtractorMeta = ExtractorMeta {
    id: "game.console",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "nsp",
            name: "Nintendo Switch package (NSP)",
            family: "game",
            mimes: &[],
            extensions: &["nsp"],
            magic: &[Magic::prefix(b"PFS0")],
            parent: None,
        },
        FormatSpec {
            id: "xci",
            name: "Nintendo Switch game card image (XCI)",
            family: "game",
            mimes: &[],
            extensions: &["xci"],
            magic: &[Magic::at(0x100, b"HEAD")],
            parent: None,
        },
        // No signature: the header size (0x2020) and the extension.
        FormatSpec {
            id: "cia",
            name: "Nintendo 3DS installable archive (CIA)",
            family: "game",
            mimes: &[],
            extensions: &["cia"],
            magic: &[],
            parent: None,
        },
    ],
};

const MAX_FILES: usize = 10_000;

/// A PFS0 / HFS0 file list: (name, offset, size).
fn partition_fs(b: &[u8], hashed: bool) -> Result<Vec<(String, u64, u64)>, ExtractError> {
    let mut r = ByteReader::new(b);
    let magic = r.bytes(4)?;
    if magic != b"PFS0" && magic != b"HFS0" {
        return Err(ExtractError::Malformed("not a PFS0 / HFS0 header".into()));
    }
    let count = r.le_u32()? as usize;
    let table = r.le_u32()? as usize;
    r.advance(4)?;
    let entry = if hashed { 0x40 } else { 0x18 };
    let entries = r.position() + count.min(MAX_FILES) * entry;
    let strings = b.get(entries..entries.saturating_add(table)).unwrap_or(&[]);
    let mut out = Vec::new();
    for _ in 0..count.min(MAX_FILES) {
        let e = r.bytes(entry)?;
        let mut er = ByteReader::new(e);
        let offset = er.le_u64()?;
        let size = er.le_u64()?;
        let name_at = er.le_u32()? as usize;
        let name = strings.get(name_at..).map_or(&[][..], |s| &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())]);
        out.push((truncate_chars(&String::from_utf8_lossy(name), 300), offset, size));
    }
    Ok(out)
}

fn nsp(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let files = partition_fs(b, false)?;
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let mut titles = BTreeSet::new();
    let mut total = 0u64;
    for (name, _, size) in &files {
        total = total.saturating_add(*size);
        let kind = if name.ends_with(".cnmt.nca") {
            "cnmt.nca".to_string()
        } else if name.ends_with(".cnmt.xml") {
            "cnmt.xml".to_string()
        } else {
            member_ext(name)
        };
        bump(&mut kinds, &kind, 50);
        // Ticket and certificate names are the rights ID: the title ID
        // (16 hex digits) and the key generation.
        if let Some(stem) = name.strip_suffix(".tik").or_else(|| name.strip_suffix(".cert"))
            && stem.len() == 32
            && stem.bytes().all(|c| c.is_ascii_hexdigit())
            && titles.len() < 100
        {
            titles.insert(stem[..16].to_ascii_lowercase());
        }
    }
    cx.format_set("file_count", files.len());
    cx.format_set("file_kinds", hist(kinds));
    if !titles.is_empty() {
        cx.format_set("title_ids", titles.into_iter().collect::<Vec<_>>());
    }
    let names: Vec<Value> = files.iter().take(100).map(|(n, ..)| n.clone().into()).collect();
    cx.format_set("files", names);
    cx.physical().entries(files.len() as u64).uncompressed_bytes(total);
    Ok(())
}

fn xci(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let h = b.get(0x100..0x200).ok_or(ExtractError::Malformed("short XCI header".into()))?;
    let le64 = |i: usize| u64::from_le_bytes(h[i..i + 8].try_into().unwrap_or_default());
    let size = match h[0x0D] {
        0xFA => Some("1 GB"),
        0xF8 => Some("2 GB"),
        0xF0 => Some("4 GB"),
        0xE0 => Some("8 GB"),
        0xE1 => Some("16 GB"),
        0xE2 => Some("32 GB"),
        _ => None,
    };
    if let Some(s) = size {
        cx.format_set("card_size", s);
    }
    cx.format_set("package_id", format!("{:016x}", le64(0x10)));
    // Valid data ends at a page (512 bytes) number.
    cx.format_set("data_bytes", le64(0x18).saturating_add(1).saturating_mul(512));
    let root = usize::try_from(le64(0x30)).unwrap_or(usize::MAX);
    if let Some(r) = b.get(root..) {
        match partition_fs(r, true) {
            Ok(parts) => {
                let names: Vec<Value> = parts.iter().map(|(n, ..)| n.clone().into()).collect();
                cx.format_set("partitions", names);
            }
            Err(_) => cx.warn("the root HFS0 partition could not be read"),
        }
    }
    cx.security().encrypted(true);
    Ok(())
}

fn align64(n: u64) -> u64 {
    n.div_ceil(64) * 64
}

fn title_kind(id: u64) -> Option<&'static str> {
    Some(match id >> 32 {
        0x0004_0000 => "application",
        0x0004_0001 => "download play",
        0x0004_0002 => "demo",
        0x0004_000E => "update",
        0x0004_008C => "add-on content",
        0x0004_0010 | 0x0004_0030 => "system application",
        0x0004_001B | 0x0004_009B | 0x0004_00DB => "system data",
        0x0004_0130 | 0x0004_0138 => "system module",
        0x0004_8004 => "DSiWare",
        _ => return None,
    })
}

/// Size of a signature block (type, signature, padding) by type.
fn sig_len(t: u32) -> Option<usize> {
    Some(match t {
        0x0001_0000 | 0x0001_0003 => 4 + 0x200 + 0x3C,
        0x0001_0001 | 0x0001_0004 => 4 + 0x100 + 0x3C,
        0x0001_0002 | 0x0001_0005 => 4 + 0x3C + 0x40,
        _ => return None,
    })
}

fn utf16_field(b: &[u8]) -> Option<String> {
    let units: Vec<u16> =
        b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    let s = String::from_utf16_lossy(&units).replace('\n', " ");
    let s = s.trim();
    (!s.is_empty()).then(|| truncate_chars(s, 300))
}

fn cia(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let len = src.len();
    let head = src.read_vec(0, 0x20)?;
    let mut r = ByteReader::new(&head);
    let header = u64::from(r.le_u32()?);
    let kind = r.le_u16()?;
    let version = r.le_u16()?;
    let certs = u64::from(r.le_u32()?);
    let ticket = u64::from(r.le_u32()?);
    let tmd = u64::from(r.le_u32()?);
    let meta = u64::from(r.le_u32()?);
    let content = r.le_u64()?;
    // Sections follow the header, each aligned to 64 bytes.
    let tmd_at = align64(header) + align64(certs) + align64(ticket);
    let meta_at = tmd_at.saturating_add(align64(tmd)).saturating_add(align64(content));
    let mut part = |at: u64, n: u64| -> Result<Vec<u8>, ExtractError> {
        if n == 0 || at >= len {
            return Ok(Vec::new());
        }
        let n = usize::try_from(n.min(len - at).min(0x4000)).unwrap_or(0);
        Ok(src.read_vec(at, n)?)
    };
    let tmd_b = part(tmd_at, tmd)?;
    let meta_b = part(meta_at, meta)?;
    let mut m = Map::new();
    m.insert("type".into(), kind.into());
    m.insert("version".into(), version.into());
    m.insert("content_bytes".into(), content.into());
    if !tmd_b.is_empty() {
        let t = &tmd_b;
        let sig = sig_len(u32::from_be_bytes(t.get(..4).unwrap_or(&[0; 4]).try_into().unwrap_or_default()));
        if let Some(h) = sig.and_then(|s| t.get(s..s + 0xC4)) {
            let id = u64::from_be_bytes(h[0x4C..0x54].try_into().unwrap_or_default());
            m.insert("title_id".into(), format!("{id:016x}").into());
            if let Some(k) = title_kind(id) {
                m.insert("title_kind".into(), k.into());
            }
            let tv = u16::from_be_bytes([h[0x9C], h[0x9D]]);
            m.insert("title_version".into(), format!("{}.{}.{}", tv >> 10, (tv >> 4) & 0x3F, tv & 0xF).into());
            m.insert("content_count".into(), u16::from_be_bytes([h[0x9E], h[0x9F]]).into());
            let save = u32::from_le_bytes(h[0x5A..0x5E].try_into().unwrap_or_default());
            if save > 0 {
                m.insert("save_data_bytes".into(), save.into());
            }
        }
    }
    // The meta section: dependencies, core version, then the SMDH icon.
    if meta > 0
        && let Some(s) = meta_b.get(0x400..0x400 + 0x2040)
        && s.starts_with(b"SMDH")
    {
        // Sixteen languages of (short 0x80, long 0x100, publisher 0x80);
        // English is the second.
        let lang = |i: usize| &s[8 + i * 0x200..8 + (i + 1) * 0x200];
        let pick = |field: std::ops::Range<usize>| {
            utf16_field(&lang(1)[field.clone()]).or_else(|| (0..16).find_map(|i| utf16_field(&lang(i)[field.clone()])))
        };
        if let Some(t) = pick(0..0x80) {
            cx.content().title(t.clone());
            m.insert("short_title".into(), t.into());
        }
        if let Some(t) = pick(0x80..0x180) {
            m.insert("long_title".into(), t.into());
        }
        if let Some(p) = pick(0x180..0x200) {
            cx.rights().creator(p.clone());
            m.insert("publisher".into(), p.into());
        }
        let regions = u32::from_le_bytes(s[0x2018..0x201C].try_into().unwrap_or_default());
        let names: Vec<Value> = ["Japan", "North America", "Europe", "Australia", "China", "Korea", "Taiwan"]
            .iter()
            .enumerate()
            .filter(|(i, _)| regions & (1 << i) != 0)
            .map(|(_, r)| (*r).into())
            .collect();
        if regions == 0x7FFF_FFFF {
            m.insert("regions".into(), "region-free".into());
        } else if !names.is_empty() {
            m.insert("regions".into(), names.into());
        }
    }
    for (k, v) in m {
        cx.format_set(&k, v);
    }
    cx.security().encrypted(true);
    Ok(())
}

impl Extractor for Console {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        (probe.extension == Some("cia") && h.get(..4) == Some(&[0x20, 0x20, 0, 0]))
            .then_some(Sniff { format: "cia", confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let id = cx.format_id().to_string();
        if id == "cia" {
            return cia(cx, src);
        }
        // Headers and file tables; contents are skipped.
        let (b, _) = src.read_prefix(cx.parse_limit().min(1 << 20))?;
        match id.as_str() {
            "nsp" => nsp(cx, &b),
            _ => xci(cx, &b),
        }
    }
}

crate::register_extractor!(Console);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("nsp", "xci", "cia");
}
