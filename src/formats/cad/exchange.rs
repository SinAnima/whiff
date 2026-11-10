//! CAD exchange and authoring formats read from their headers:
//!
//! * Parasolid transmit files (`.x_t` text, `.x_b` binary): the PART1 /
//!   PART2 header (application, modeller version, schema, format, date);
//!   the user and site only with `--privacy off`;
//! * ACIS (`.sat` text, `.sab` binary): version, product, ACIS build,
//!   date, units, bodies, and entities by type;
//! * Revit models and families (`.rvt`, `.rfa`, `.rte`): the
//!   `BasicFileInfo` stream (format year, build, worksharing, locale) and
//!   the PartAtom title; the last save path by name and the user only with
//!   `--privacy off`;
//! * JT (ISO 14306): version, byte order, segments by type;
//! * PRC (ISO 14739): versions, file structures;
//! * U3D (ECMA-363): version, profile, declared size, blocks by type;
//! * DWF 6 and DWFx: version, sections, pages, resources.
//!
//! Specifications: Siemens' Parasolid transmit file format; Spatial's
//! ACIS SAT / SAB format; ISO 14306 (JT); ISO 14739-1 (PRC); ECMA-363
//! (U3D); Autodesk's DWF 6 and DWFx (OPC) packaging. Revit's streams are
//! read as Revit writes them.

use std::collections::BTreeMap;

use serde_json::json;

use super::{bump, hist};
use crate::plugin::{
    Cfb, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, Zip, zip_names,
};

/// Extractor for the CAD formats above.
pub struct Exchange;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, [$($ext:literal),*], [$($magic:expr),*]) => {
        FormatSpec { id: $id, name: $name, family: "cad", mimes: &[$mime], extensions: &[$($ext),*], magic: &[$($magic),*], parent: None }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "cad.exchange",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!(
            "parasolid",
            "Parasolid transmit file",
            "application/x-parasolid",
            ["x_t", "x_b", "xmt_txt", "xmt_bin"],
            []
        ),
        spec!("acis", "ACIS solid model", "application/x-acis", ["sat", "sab"], []),
        spec!("revit", "Revit model / family", "application/vnd.autodesk.revit", ["rvt", "rfa", "rte", "rft"], []),
        // No magic: "Version " also starts MapInfo and LTspice files; the
        // sniff wants " JT" in the 80-byte header.
        spec!("jt", "JT", "model/jt", ["jt"], []),
        spec!("prc", "PRC (Product Representation Compact)", "model/prc", [], [Magic::prefix(b"PRC")]),
        spec!("u3d", "U3D (Universal 3D)", "model/u3d", ["u3d"], [Magic::prefix(b"U3D\0")]),
        spec!("dwf", "DWF / DWFx", "model/vnd.dwf", ["dwf", "dwfx"], []),
    ],
};

/// Names listed.
const MAX_LISTED: usize = 100;

impl Extractor for Exchange {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or("").to_ascii_lowercase();
        let pick = |format: &'static str, confidence: f64| Some(Sniff { format, confidence });
        let has = |n: &[u8]| h.windows(n.len()).take(4096).any(|w| w == n);
        // Text and binary variants share these specs, so the binary magic
        // is checked here rather than declared.
        if h.starts_with(b"ACIS BinaryFile") {
            return pick("acis", 0.97);
        }
        if h.starts_with(b"(DWF V") {
            return pick("dwf", 0.97);
        }
        if has(b"**ABCDEFGHIJKLMNOPQRSTUVWXYZ") || has(b"**PART1;") {
            return pick("parasolid", 0.95);
        }
        if h.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") && matches!(ext.as_str(), "rvt" | "rfa" | "rte" | "rft") {
            return pick("revit", 0.95);
        }
        if h.starts_with(b"Version ") && h.len() > 80 && h[8..80].windows(3).any(|w| w == b" JT") {
            return pick("jt", 0.95);
        }
        if h.starts_with(b"PK\x03\x04") {
            let names = zip_names(probe, 2000);
            if names
                .iter()
                .any(|n| n.ends_with(".dwfseq") || n.starts_with("dwf/") || n.contains("DWFDocumentSequence"))
            {
                return pick("dwf", 0.95);
            }
        }
        // ACIS text: "<version> <records> <bodies> <flags>" then the product line.
        let first: Vec<&str> =
            std::str::from_utf8(&h[..h.len().min(200)]).ok()?.lines().next()?.split_whitespace().collect();
        (ext == "sat" && first.len() == 4 && first.iter().all(|w| w.parse::<u64>().is_ok()))
            .then_some(Sniff { format: "acis", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "revit" => return revit(src, cx),
            "dwf" => return dwf(src, cx),
            _ => {}
        }
        let (b, cut) = cx.read_bytes(src)?;
        if cut {
            cx.format_set("truncated", true);
        }
        match cx.format_id() {
            "parasolid" => parasolid(cx, &b),
            "acis" => acis(cx, &b),
            "jt" => jt(cx, &b),
            "prc" => prc(cx, &b),
            _ => u3d(cx, &b),
        }
        Ok(())
    }
}

crate::register_extractor!(Exchange);

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn le64(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8).map_or(0, |s| u64::from_le_bytes(s.try_into().unwrap_or([0; 8])))
}

/// A path as the privacy mode allows: its last component, or whole.
fn path_ref(strict: bool, p: &str) -> String {
    if strict { p.rsplit(['/', '\\']).next().unwrap_or(p).to_string() } else { p.to_string() }
}

// --- Parasolid -----------------------------------------------------------------------------------

fn parasolid(cx: &mut Context<'_>, b: &[u8]) {
    let strict = cx.privacy_strict();
    let Some(p) = b.windows(8).position(|w| w == b"**PART1;") else {
        cx.warn("no PART1 header");
        return;
    };
    cx.format_set("encoding", if b.starts_with(b"PS") { "binary" } else { "text" });
    let end = b[p..].windows(17).position(|w| w == b"**END_OF_HEADER**").map_or(b.len().min(p + 8192), |e| p + e);
    // Header lines are wrapped at 80 columns: join them before splitting.
    let header: String = String::from_utf8_lossy(&b[p..end]).lines().collect::<Vec<_>>().join("");
    let mut fields = serde_json::Map::new();
    for part in header.split("**PART").skip(1) {
        for kv in part.split(';').skip(1) {
            let Some((k, v)) = kv.split_once('=') else { continue };
            let key = match k.trim() {
                "APPL" => "application",
                "FORMAT" => "format",
                "GUISE" => "guise",
                "KEY" => "key",
                "FILE" => "file",
                "DATE" => "date",
                "SCH" => "schema",
                "USFLD_SIZE" => "user_field_size",
                "SITE" if !strict => "site",
                "USER" if !strict => "user",
                _ => continue,
            };
            let v = if key == "file" { path_ref(strict, v.trim()) } else { v.trim().to_string() };
            fields.entry(key).or_insert(json!(v));
        }
    }
    if let Some(s) = fields.get("schema").and_then(|v| v.as_str()) {
        // `SCH_3600274_36001`: the modeller version (36.0) and build.
        if let Some(n) = s.strip_prefix("SCH_").and_then(|r| r.split('_').next()).and_then(|n| n.parse::<u64>().ok()) {
            cx.format_set("parasolid_version", format!("{}.{}", n / 100_000, n / 1000 % 100));
        }
    }
    for (k, v) in fields {
        cx.format_set(&k, v);
    }
}

// --- ACIS ---------------------------------------------------------------------------------------------

fn acis(cx: &mut Context<'_>, b: &[u8]) {
    if b.starts_with(b"ACIS BinaryFile") {
        cx.format_set("encoding", "binary");
        cx.format_set("version", le32(b, 15));
        cx.format_set("bodies", le32(b, 23));
        return;
    }
    let text = String::from_utf8_lossy(b);
    let mut lines = text.lines();
    let first: Vec<u64> = lines.next().unwrap_or("").split_whitespace().filter_map(|w| w.parse().ok()).collect();
    cx.format_set("encoding", "text");
    if let Some(v) = first.first() {
        cx.format_set("version", *v);
    }
    if let Some(n) = first.get(2) {
        cx.format_set("bodies", *n);
    }
    // `<n> <product> <n> <ACIS version> <n> <date>`: length-prefixed strings.
    if let Some(line) = lines.next() {
        let mut rest = line.trim();
        let mut parts = Vec::new();
        while let Some((n, r)) = rest.split_once(' ') {
            let Ok(n) = n.parse::<usize>() else { break };
            let s = r.get(..n).unwrap_or(r);
            parts.push(s.to_string());
            rest = r.get(n..).unwrap_or("").trim_start();
        }
        for (i, key) in ["product", "acis_build", "date"].iter().enumerate() {
            if let Some(p) = parts.get(i) {
                cx.format_set(key, p.clone());
            }
        }
    }
    if let Some(units) = lines.next().and_then(|l| l.split_whitespace().next()).and_then(|u| u.parse::<f64>().ok()) {
        let name = match units {
            u if (u - 1.0).abs() < 1e-9 => "mm".to_string(),
            u if (u - 10.0).abs() < 1e-9 => "cm".to_string(),
            u if (u - 1000.0).abs() < 1e-9 => "m".to_string(),
            u if (u - 25.4).abs() < 1e-9 => "inch".to_string(),
            u => format!("{u} mm"),
        };
        cx.format_set("units", name);
    }
    let mut entities: BTreeMap<String, u64> = BTreeMap::new();
    for line in text.lines().skip(3).take(5_000_000) {
        let t = line.trim_start_matches(|c: char| c == '-' || c.is_ascii_digit()).trim_start();
        if let Some(w) =
            t.split_whitespace().next().filter(|w| w.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        {
            if w == "End-of-ACIS-data" {
                break;
            }
            bump(&mut entities, w, 200);
        }
    }
    cx.format_set("entities", hist(entities));
}

// --- Revit --------------------------------------------------------------------------------------------

/// Text runs in a stream: UTF-16LE at either alignment, else ASCII.
fn text_runs(b: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for start in 0..2 {
        let u: Vec<u16> =
            b.get(start..).unwrap_or_default().as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        let mut cur = String::new();
        for c in char::decode_utf16(u).map(|r| r.unwrap_or('\0')) {
            if c == '\n' || c == '\r' || c == '\0' || (c.is_control() && c != '\t') {
                if cur.trim().len() >= 3 {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
            } else {
                cur.push(c);
            }
        }
        if cur.trim().len() >= 3 {
            out.push(cur.trim().to_string());
        }
    }
    out
}

/// `BasicFileInfo` keys and the report keys they become.
const KEYS: [(&str, &str); 11] = [
    ("Format:", "format"),
    ("Revit Build:", "build"),
    ("Build:", "build"),
    ("Worksharing:", "worksharing"),
    ("Locale when saved:", "locale"),
    ("Unique Document GUID:", "document_guid"),
    ("Unique Document Increments:", "increments"),
    ("Last Save Path:", "last_save_path"),
    ("Central Model Path:", "central_model_path"),
    ("Username:", "user"),
    ("Identity:", "identity"),
];

fn revit(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let strict = cx.privacy_strict();
    let cfb = Cfb::open(src)?;
    let find = |name: &str| cfb.entries.iter().position(|e| e.name == name);
    let streams: Vec<String> = cfb.entries.iter().filter(|e| e.parent == Some(0)).map(|e| e.name.clone()).collect();
    cx.format_set("streams", streams.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    if let Some(i) = find("BasicFileInfo") {
        let data = cfb.read(src, &cfb.entries[i].clone(), 1 << 20)?;
        let mut info = serde_json::Map::new();
        for line in text_runs(&data) {
            // A run may begin with stray bytes: find the key inside it.
            let Some((key, v)) =
                KEYS.iter().find_map(|(k, key)| line.find(k).map(|p| (*key, line[p + k.len()..].trim())))
            else {
                continue;
            };
            if v.is_empty() || (key == "user" && strict) {
                continue;
            }
            let v = if key.ends_with("_path") { path_ref(strict, v) } else { v.to_string() };
            info.entry(key).or_insert(json!(v));
        }
        if let Some(f) = info.get("format").and_then(|v| v.as_str()) {
            cx.format_set("revit_version", format!("Revit {f}"));
        }
        cx.format_set("basic_file_info", serde_json::Value::Object(info));
    }
    if let Some(i) = find("PartAtom") {
        let xml = String::from_utf8_lossy(&cfb.read(src, &cfb.entries[i].clone(), 1 << 20)?).into_owned();
        let tag = |t: &str| {
            xml.find(&format!("<{t}>"))
                .map(|p| &xml[p + t.len() + 2..])
                .and_then(|r| r.split('<').next())
                .map(str::to_string)
        };
        if let Some(t) = tag("title") {
            cx.content().title(t.clone());
            cx.format_set("title", t);
        }
        if let Some(u) = tag("updated") {
            cx.format_set("updated", u);
        }
    }
    if find("RevitPreview4.0").is_some() {
        cx.format_set("preview", true);
    }
    Ok(())
}

// --- JT / PRC / U3D --------------------------------------------------------------------------------------

/// JT segment types.
const KINDS: [(u32, &str); 12] = [
    (1, "logical scene graph"),
    (2, "JT B-Rep"),
    (3, "PMI data"),
    (4, "meta data"),
    (6, "shape"),
    (7, "shape LOD0"),
    (8, "shape LOD1"),
    (16, "shape LOD9"),
    (17, "XT B-Rep"),
    (18, "wireframe"),
    (20, "ULP"),
    (24, "LWPA"),
];

fn jt(cx: &mut Context<'_>, b: &[u8]) {
    let version = String::from_utf8_lossy(b.get(..80).unwrap_or(b)).trim().trim_end_matches('\0').to_string();
    cx.format_set("version_string", version.clone());
    let v = version.split_whitespace().nth(1).unwrap_or("").to_string();
    cx.format_set("version", v.clone());
    let big = b.get(80) == Some(&1);
    cx.format_set("byte_order", if big { "big-endian" } else { "little-endian" });
    let major: u32 = v.split('.').next().and_then(|m| m.parse().ok()).unwrap_or(0);
    let rd32 = |at: usize| {
        b.get(at..at + 4).map_or(0, |s| {
            if big {
                u32::from_be_bytes([s[0], s[1], s[2], s[3]])
            } else {
                u32::from_le_bytes([s[0], s[1], s[2], s[3]])
            }
        })
    };
    // Version 10 widened the TOC offset and entry fields to 64 bits.
    let wide = major >= 10;
    let toc = if wide { usize::try_from(le64(b, 85)).unwrap_or(usize::MAX) } else { rd32(85) as usize };
    let entries = rd32(toc) as usize;
    let entry_size = if wide { 16 + 8 + 4 + 4 } else { 16 + 4 + 4 + 4 };
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    for i in 0..entries.min(100_000) {
        let at = toc + 4 + i * entry_size + entry_size - 4;
        if at + 4 > b.len() {
            break;
        }
        let kind = rd32(at) >> 24;
        let name =
            KINDS.iter().find(|(k, _)| *k == kind).map_or_else(|| format!("type {kind}"), |(_, n)| (*n).to_string());
        bump(&mut kinds, &name, 50);
    }
    cx.format_set("toc_entries", entries);
    cx.format_set("segments", hist(kinds));
}

fn prc(cx: &mut Context<'_>, b: &[u8]) {
    cx.format_set("minimal_version_for_read", le32(b, 3));
    cx.format_set("authoring_version", le32(b, 7));
    // File structure id (UUID), application id (UUID), then the count.
    cx.format_set("file_structures", le32(b, 11 + 16 + 16));
}

fn u3d(cx: &mut Context<'_>, b: &[u8]) {
    let data = le32(b, 4) as usize;
    let h = b.get(12..).unwrap_or_default();
    let (major, minor) = (
        i16::from_le_bytes([h.first().copied().unwrap_or(0), h.get(1).copied().unwrap_or(0)]),
        i16::from_le_bytes([h.get(2).copied().unwrap_or(0), h.get(3).copied().unwrap_or(0)]),
    );
    cx.format_set("version", format!("{major}.{minor}"));
    let profile = le32(h, 4);
    let flags: Vec<&str> = [(2, "extensible"), (4, "no compression"), (8, "defined units")]
        .iter()
        .filter(|(bit, _)| profile & bit != 0)
        .map(|(_, n)| *n)
        .collect();
    cx.format_set("profile", flags);
    cx.format_set("declared_size_bytes", le64(h, 12));
    if le32(h, 20) == 106 {
        cx.format_set("encoding", "UTF-8");
    }
    // Blocks: type, data size, metadata size, then both padded to 4 bytes.
    let mut at = 12 + data.next_multiple_of(4) + (le32(b, 8) as usize).next_multiple_of(4);
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    for _ in 0..1_000_000 {
        if at + 12 > b.len() {
            break;
        }
        let (kind, d, m) = (le32(b, at), le32(b, at + 4) as usize, le32(b, at + 8) as usize);
        let name = match kind {
            0xFFFF_FF12 => "file reference",
            0xFFFF_FF14 => "modifier chain",
            0xFFFF_FF15 => "priority update",
            0xFFFF_FF16 => "new object type",
            0xFFFF_FF21 => "group node",
            0xFFFF_FF22 => "model node",
            0xFFFF_FF23 => "light node",
            0xFFFF_FF24 => "view node",
            0xFFFF_FF31 => "CLOD mesh declaration",
            0xFFFF_FF3B => "CLOD progressive mesh",
            0xFFFF_FF36 => "point set declaration",
            0xFFFF_FF37 => "line set declaration",
            0xFFFF_FF41 => "2D glyph modifier",
            0xFFFF_FF42 => "subdivision modifier",
            0xFFFF_FF43 => "animation modifier",
            0xFFFF_FF44 => "bone weight modifier",
            0xFFFF_FF45 => "shading modifier",
            0xFFFF_FF46 => "CLOD modifier",
            0xFFFF_FF51 => "light resource",
            0xFFFF_FF52 => "view resource",
            0xFFFF_FF53 => "lit texture shader",
            0xFFFF_FF54 => "material resource",
            0xFFFF_FF55 => "texture declaration",
            0xFFFF_FF5C => "texture continuation",
            0xFFFF_FF56 => "motion resource",
            _ => "other",
        };
        bump(&mut kinds, name, 50);
        let Some(next) = at.checked_add(12 + d.next_multiple_of(4) + m.next_multiple_of(4)) else { break };
        at = next;
    }
    cx.format_set("blocks", hist(kinds));
}

// --- DWF / DWFx -----------------------------------------------------------------------------------------

fn dwf(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let head = src.read_vec(0, usize::try_from(src.len().min(16)).unwrap_or(0))?;
    let names: Vec<String> = if head.starts_with(b"(DWF V") {
        let v = String::from_utf8_lossy(&head[6..head.len().min(11)]).to_string();
        cx.format_set("version", v);
        cx.format_set("packaging", "DWF 6 (ZIP)");
        // The ZIP follows the 12-byte version string; walk its local headers.
        let (b, _) = cx.read_bytes(src)?;
        let mut out = Vec::new();
        let mut at = 12;
        while at + 30 <= b.len() && b[at..].starts_with(b"PK\x03\x04") && out.len() < 100_000 {
            let n = usize::from(u16::from_le_bytes([b[at + 26], b[at + 27]]));
            let x = usize::from(u16::from_le_bytes([b[at + 28], b[at + 29]]));
            let size = le32(&b, at + 18) as usize;
            out.push(String::from_utf8_lossy(b.get(at + 30..at + 30 + n).unwrap_or_default()).into_owned());
            at += 30 + n + x + size;
        }
        out
    } else {
        cx.format_set("packaging", "DWFx (OPC)");
        Zip::open(src, 100_000)?.entries.iter().map(|e| e.name.clone()).collect()
    };
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    for n in &names {
        let ext = n.rsplit_once('.').map_or("", |(_, e)| e).to_ascii_lowercase();
        bump(&mut kinds, &ext, 50);
    }
    let pages = names
        .iter()
        .filter(|n| {
            let ext = std::path::Path::new(n.as_str()).extension().and_then(|e| e.to_str()).unwrap_or("");
            ["fpage", "w2d", "dwfseq"].iter().any(|x| ext.eq_ignore_ascii_case(x))
        })
        .count();
    cx.format_set("entries", names.len());
    cx.format_set("pages", pages);
    cx.format_set("by_extension", hist(kinds));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("parasolid", "acis", "revit", "jt", "prc", "u3d", "dwf");

    /// The modeller's user and site appear only with `--privacy off`
    /// (neutral sample).
    #[test]
    fn parasolid_follows_privacy() {
        let x_t = b"**ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz**\n**PART1;APPL=a;SITE=gamma;USER=alpha;FILE=/home/alpha/m.x_t;**PART2;SCH=SCH_1_1;**END_OF_HEADER**\n";
        let strict = serde_json::to_string(&crate::plugin::testing::report_for("m.x_t", x_t)).unwrap();
        assert!(!strict.contains("alpha") && !strict.contains("gamma"), "{strict}");
        let off = serde_json::to_string(&crate::plugin::testing::report_without_privacy("m.x_t", x_t)).unwrap();
        assert!(off.contains("\"user\":\"alpha\"") && off.contains("gamma"));
    }

    #[test]
    fn revit_text() {
        let mut b = vec![0u8, 1, 2];
        b.extend("Format: 2024\r\nUsername: alpha\r\n".encode_utf16().flat_map(u16::to_le_bytes));
        let runs = text_runs(&b);
        assert!(runs.iter().any(|r| r.ends_with("Format: 2024")), "{runs:?}");
    }
}
