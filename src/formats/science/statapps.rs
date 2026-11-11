//! Desktop statistics packages' own files:
//!
//! * JMP data tables (`.jmp`): the JMP version and build that saved the
//!   table, when, its character set, rows, columns and column names,
//!   hidden columns, and whether columns are compressed; tables from
//!   before JMP's current layout give their format only;
//! * Minitab worksheets (`.mtw`) and projects (`.mpj`): the release range
//!   (8–11 by their text signature; 12, 13, 14 and 15 and later by their
//!   compound-file streams), the streams, and the document properties;
//!   portable worksheets (`.mtp`) by their signature line.
//!
//! Data values are not read.
//!
//! Specifications: none published. JMP's layout as read by JMPReader.jl
//! (MIT); Minitab's signatures as registered in PRONOM (fmt/1430 –
//! fmt/1438).

use serde_json::{Value, json};

use crate::plugin::{
    Cfb, CfbKind, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff,
    Source,
};

/// Extractor for the formats above.
pub struct StatApps;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, [$($ext:literal),*], [$($magic:expr),*]) => {
        FormatSpec { id: $id, name: $name, family: "sci", mimes: &[$mime], extensions: &[$($ext),*], magic: &[$($magic),*], parent: None }
    };
}

const JMP_CURRENT: &[u8] = b"\xff\xff\x00\x00\x07\x00\x00\x00\x04\x00\x00\x00";
const JMP_OLD: &[u8] = b"\xff\xff\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00";
const MINITAB_TEXT: &[u8] = b"WORKSHEET STORED BY MINITAB";
const MINITAB_PORTABLE: &[u8] = b"Minitab Portable Worksheet";
const OLE: &[u8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";

static META: ExtractorMeta = ExtractorMeta {
    id: "science.statapps",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!(
            "jmp",
            "JMP data table",
            "application/x-jmp",
            ["jmp"],
            [Magic::prefix(JMP_CURRENT), Magic::prefix(JMP_OLD)]
        ),
        // Text (releases 8 – 11) and compound-file forms share these specs:
        // the sniff tells them apart.
        spec!("minitab_worksheet", "Minitab worksheet", "application/x-minitab-worksheet", ["mtw"], []),
        spec!("minitab_project", "Minitab project", "application/x-minitab-project", ["mpj"], []),
        spec!(
            "minitab_portable",
            "Minitab portable worksheet",
            "application/x-minitab-portable",
            ["mtp"],
            [Magic::prefix(MINITAB_PORTABLE)]
        ),
    ],
};

/// Column names listed.
const MAX_COLUMNS: usize = 200;
/// Streams listed.
const MAX_STREAMS: usize = 100;
/// Seconds from 1904-01-01 (JMP's epoch) to 1970-01-01.
const EPOCH_1904: f64 = 2_082_844_800.0;

impl Extractor for StatApps {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or("").to_ascii_lowercase();
        let pick = |format: &'static str, confidence: f64| Some(Sniff { format, confidence });
        if h.starts_with(MINITAB_TEXT) {
            return pick(if ext == "mpj" { "minitab_project" } else { "minitab_worksheet" }, 0.95);
        }
        // Compound files: the stream names decide (`doc.ole` redirects
        // `WorksheetInfo` / `ProjectInfo`); release 12 / 13 files only by name.
        if h.starts_with(OLE) {
            return match ext.as_str() {
                "mtw" => pick("minitab_worksheet", 0.95),
                "mpj" => pick("minitab_project", 0.95),
                _ => None,
            };
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.read_vec(0, usize::try_from(src.len().min(512)).unwrap_or(0))?;
        match cx.format_id() {
            "jmp" => {
                let (b, cut) = cx.read_bytes(src)?;
                if cut {
                    cx.format_set("truncated", true);
                }
                jmp(cx, &b);
            }
            "minitab_portable" => {
                cx.format_set("release_range", "portable");
                signature_line(cx, &head);
            }
            _ if head.starts_with(OLE) => minitab_ole(src, cx)?,
            _ => {
                cx.format_set("release_range", "8-11");
                signature_line(cx, &head);
            }
        }
        Ok(())
    }
}

crate::register_extractor!(StatApps);

/// The printable first line of a text-signed Minitab file.
fn signature_line(cx: &mut Context<'_>, head: &[u8]) {
    let line: String =
        head.iter().take_while(|&&c| (0x20..0x7f).contains(&c)).take(120).map(|&c| char::from(c)).collect();
    let line = line.trim();
    if !line.is_empty() {
        cx.format_set("signature", line);
    }
}

// --- JMP ------------------------------------------------------------------------------------

fn le16(b: &[u8], at: usize) -> Option<u16> {
    b.get(at..at.checked_add(2)?).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at.checked_add(4)?).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn le64(b: &[u8], at: usize) -> Option<u64> {
    b.get(at..at.checked_add(8)?).map(|s| u64::from_le_bytes(s.try_into().unwrap_or([0; 8])))
}

/// A string with an `n`-byte little-endian length, and the offset after it.
fn lp_string(b: &[u8], at: usize, n: usize) -> Option<(String, usize)> {
    let len = match n {
        2 => usize::try_from(le16(b, at)?.cast_signed()).ok()?,
        _ => usize::try_from(le32(b, at)?.cast_signed()).ok()?,
    };
    let start = at.checked_add(n)?;
    let end = start.checked_add(len)?;
    let s = b.get(start..end)?;
    Some((String::from_utf8_lossy(s).trim_end_matches('\0').to_string(), end))
}

fn find(b: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    b.get(from..)?.windows(needle.len()).position(|w| w == needle).map(|i| from + i)
}

/// What JMP's header gives: rows, columns, the character set, the save
/// time and the build string.
struct JmpInfo {
    rows: u64,
    columns: u32,
    charset: String,
    saved: f64,
    build: String,
}

/// The table information that precedes the `07 00 08 00 00 00` mark.
fn jmp_info(b: &[u8]) -> Option<JmpInfo> {
    let mark = find(b, 0, &[0x07, 0x00, 0x08, 0x00, 0x00, 0x00])?;
    let at = (mark + 6).checked_sub(38)?;
    let rows = le64(b, at)?;
    let columns = le32(b, at + 8)?;
    let (charset, next) = lp_string(b, at + 22, 4)?;
    let saved = f64::from_bits(le64(b, next + 6)?);
    let (build, _) = lp_string(b, next + 16, 4)?;
    Some(JmpInfo { rows, columns, charset, saved, build })
}

/// Column names: after the visible / hidden column index lists, the
/// display widths and a variable-length block, a column count and one
/// offset per column to its length-prefixed name.
#[allow(clippy::many_single_char_names)] // bytes `b`, cursor `p`, counts `n` / `v` / `h`, as in JMPReader.jl
fn jmp_columns(b: &[u8], columns: u32) -> Option<(Vec<String>, u32)> {
    let n = usize::try_from(columns).ok()?;
    if n == 0 || n > 1_000_000 {
        return None;
    }
    // The index lists follow a run of 0xFF bytes, 10 bytes, then the
    // visible and hidden column counts (which add up to the column count).
    let mut at = 2;
    let (visible, hidden, lists) = loop {
        let ff = find(b, at, &[0xff, 0xff])?;
        let mut p = ff + 2;
        while b.get(p) == Some(&0xff) {
            p += 1;
        }
        let (v, h) = (le32(b, p + 10)?, le32(b, p + 14)?);
        if u64::from(v) + u64::from(h) == u64::from(columns) {
            break (v, h, p + 26);
        }
        at = p + 8;
    };
    let mut p = lists + 4 * (visible as usize + hidden as usize) + 2 * n + 28;
    // Blocks introduced by a negative 16-bit marker: a 64-bit length, then data.
    while matches!(b.get(p..p + 2), Some([0xfc..=0xff, 0xff])) {
        let len = usize::try_from(le64(b, p + 2)?).ok().filter(|&l| l <= b.len())?;
        p = p.checked_add(10 + len).filter(|&q| q <= b.len())?;
    }
    if le32(b, p)? != columns {
        return None;
    }
    let mut names = Vec::new();
    for i in 0..n.min(MAX_COLUMNS) {
        let offset = usize::try_from(le64(b, p + 4 + 8 * i)?).ok()?;
        names.push(lp_string(b, offset, 2)?.0);
    }
    Some((names, hidden))
}

fn jmp(cx: &mut Context<'_>, b: &[u8]) {
    if b.starts_with(JMP_OLD) {
        cx.format_set("layout", "legacy");
        return;
    }
    cx.format_set("layout", "current");
    let Some(info) = jmp_info(b) else {
        cx.warn("JMP table information not found");
        return;
    };
    if let Some(v) = info.build.split("Version ").nth(1) {
        cx.format_set("jmp_version", v.trim());
    }
    if !info.build.is_empty() {
        cx.format_set("build", info.build.trim());
    }
    if info.saved.is_finite() && info.saved > 0.0 {
        #[allow(clippy::cast_possible_truncation)] // seconds since 1904, checked finite and positive
        let unix = (info.saved - EPOCH_1904).floor() as i64;
        if let Ok(t) = jiff::Timestamp::from_second(unix) {
            cx.format_set("saved", t.strftime("%Y-%m-%dT%H:%M:%SZ").to_string());
            cx.temporal().source("jmp").content_date(
                DateField::Modified,
                t.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
                true,
            );
        }
    }
    if !info.charset.is_empty() {
        cx.format_set("charset", info.charset);
    }
    cx.format_set("rows", info.rows);
    cx.format_set("columns", info.columns);
    if let Some((names, hidden)) = jmp_columns(b, info.columns) {
        if hidden > 0 {
            cx.format_set("hidden_columns", hidden);
        }
        cx.format_set("column_names", json!(names));
    }
    // Compressed column data starts with the 0xCAFEBEEF mark (little-endian).
    if find(b, 0, &[0xef, 0xbe, 0xfe, 0xca]).is_some() {
        cx.format_set("compressed_columns", true);
    }
}

// --- Minitab compound files -----------------------------------------------------------------

fn minitab_ole(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let cfb = Cfb::open(src)?;
    let top: Vec<&crate::plugin::CfbEntry> =
        cfb.entries.iter().filter(|e| e.parent == Some(0) && e.kind == CfbKind::Stream).collect();
    let read = |src: &mut dyn Source, name: &str, max: usize| -> Option<Vec<u8>> {
        let e = cfb.entries.iter().find(|e| e.name == name)?;
        cfb.read(src, e, max).ok()
    };
    let release = if let Some(d) = read(src, "WorksheetInfo", 64).or_else(|| read(src, "ProjectInfo", 64)) {
        match d.get(..16) {
            Some([0x3b, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]) => Some("14"),
            Some([0x5f, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0]) => Some("15+"),
            _ => None,
        }
    } else if let Some(d) = read(src, "Worksheet", 64) {
        match d.get(16..21) {
            Some(b"MTB12") => Some("12"),
            Some(b"MTB13") => Some("13"),
            _ => None,
        }
    } else if let Some(d) = read(src, "Index", 1 << 20) {
        let tail = &d[d.len().saturating_sub(512)..];
        tail.windows(7).any(|w| w == b"MINITAB").then_some("12-13")
    } else {
        None
    };
    if let Some(r) = release {
        cx.format_set("release_range", r);
    }
    super::ole_common(&cfb, src, cx);
    let names: Vec<Value> = top.iter().take(MAX_STREAMS).map(|e| json!(e.name.trim_start_matches('\u{5}'))).collect();
    cx.format_set("top_level_streams", names);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("jmp", "minitab_worksheet", "minitab_project", "minitab_portable");

    #[test]
    fn jmp_strings() {
        assert_eq!(lp_string(b"\x05\x00tidesX", 0, 2), Some(("tides".to_string(), 7)));
        assert_eq!(find(b"abcabc", 1, b"ca"), Some(2));
        assert!(jmp_info(b"\xff\xff").is_none());
    }

    #[test]
    fn huge_block_length_is_rejected() {
        // Found by fuzzing: a 0xFFFC block whose 64-bit length nearly wraps.
        let mut b = vec![0, 0, 0xff, 0xff];
        b.extend_from_slice(&[0; 10]);
        b.extend_from_slice(&1u32.to_le_bytes()); // visible
        b.extend_from_slice(&0u32.to_le_bytes()); // hidden
        b.resize(64, 0);
        b.extend_from_slice(&[0xfc, 0xff]);
        b.extend_from_slice(&(u64::MAX - 5).to_le_bytes());
        b.resize(96, 0);
        assert!(jmp_columns(&b, 1).is_none());
        assert!(lp_string(&b, usize::MAX - 1, 2).is_none());
    }
}
