//! Older binary documents, help files and print jobs, read from their
//! headers and records:
//!
//! * WordPerfect (the prefix packet: product, file type, version,
//!   encryption);
//! * Lotus 1-2-3 worksheets, WKS / WK1 to WK4 and 1-2-3 97 (version, cells
//!   by kind, sheets, label text) and Quattro WQ1;
//! * ClarisWorks / AppleWorks (version);
//! * Microsoft Write (the text) and Ami Pro (version, sections, text);
//! * Compiled HTML Help (CHM: language, the file directory, topics, and the
//!   `#SYSTEM` title, compiler and default topic);
//! * WinHelp (`.hlp`: version, title, copyright, the internal files);
//! * OneNote revision stores (`.one`, `.onetoc2`: kind, file id, the
//!   versions that wrote it, transactions);
//! * PJL / PCL print jobs (job name, language, copies, paper, resolution,
//!   pages) and Windows spool files (`.spl`: document and port; `.shd`:
//!   job id, document, printer, driver, data type).
//!
//! Specifications: the WordPerfect 5.1 / 6 developer notes (prefix
//! packet); Lotus's WK1 and WK3 file format notes and the libwps sources;
//! Microsoft Write's file format (Microsoft KB); Ami Pro's file format
//! notes; the CHM format notes of Matthew Russotto and chmlib; Manfred
//! Winterhoff's *Windows Help file format*; Microsoft's \[MS-ONESTORE\]; HP's
//! PCL 5 and PJL technical references; the SHD / SPL notes of forensic
//! write-ups (Windows 2000 to 10).

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    TextRole, latin1_or_utf8,
};

/// Extractor for older binary documents, help files and print jobs.
pub struct Legacy;

macro_rules! spec {
    ($id:literal, $name:literal, $family:literal, $mime:literal, [$($ext:literal),*], [$($magic:expr),*]) => {
        FormatSpec {
            id: $id,
            name: $name,
            family: $family,
            mimes: &[$mime],
            extensions: &[$($ext),*],
            magic: &[$($magic),*],
            parent: None,
        }
    };
}

const ONE_SECTION: [u8; 16] = *b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3";
const ONE_TOC: [u8; 16] = *b"\xa1\x2f\xff\x43\xd9\xef\x76\x4c\x9e\xe2\x10\xea\x57\x22\x76\x5f";

static META: ExtractorMeta = ExtractorMeta {
    id: "doc.legacy",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!(
            "wordperfect",
            "WordPerfect document",
            "doc.ole",
            "application/vnd.wordperfect",
            ["wpd", "wp", "wp5", "wp6"],
            [Magic::prefix(b"\xffWPC")]
        ),
        spec!(
            "lotus123",
            "Lotus 1-2-3 / Quattro worksheet",
            "doc.other",
            "application/vnd.lotus-1-2-3",
            ["wk1", "wks", "wk3", "wk4", "123", "wq1"],
            []
        ),
        spec!(
            "clarisworks",
            "ClarisWorks / AppleWorks document",
            "doc.other",
            "application/x-appleworks",
            ["cwk"],
            [Magic::at(4, b"BOBO")]
        ),
        spec!(
            "ms_write",
            "Microsoft Write document",
            "doc.other",
            "application/x-mswrite",
            ["wri"],
            [Magic::prefix(b"\x31\xbe\x00\x00\x00\xab")]
        ),
        spec!(
            "ami_pro",
            "Ami Pro document",
            "doc.other",
            "application/vnd.lotus-wordpro",
            [],
            [Magic::prefix(b"[ver]")]
        ),
        spec!(
            "chm",
            "Compiled HTML Help",
            "doc.other",
            "application/vnd.ms-htmlhelp",
            ["chm"],
            [Magic::prefix(b"ITSF")]
        ),
        spec!(
            "winhelp",
            "Windows Help file",
            "doc.other",
            "application/winhlp",
            ["hlp"],
            [Magic::prefix(b"\x3f\x5f\x03\x00")]
        ),
        spec!(
            "onenote",
            "Microsoft OneNote",
            "doc.other",
            "application/onenote",
            ["one", "onetoc2"],
            [Magic::prefix(&ONE_SECTION), Magic::prefix(&ONE_TOC)]
        ),
        spec!(
            "pcl",
            "PCL / PJL print job",
            "doc.other",
            "application/vnd.hp-pcl",
            ["pcl", "prn", "pjl"],
            [Magic::prefix(b"\x1b%-12345X"), Magic::prefix(b"\x1bE")]
        ),
        // `00 00 01 00` also starts icons and resource forks: `sniff` checks
        // the header.
        spec!("spool_spl", "Windows spool file (SPL)", "doc.other", "application/x-windows-spool", ["spl"], []),
        spec!(
            "spool_shd",
            "Windows spool shadow file (SHD)",
            "doc.other",
            "application/x-windows-spool-shadow",
            ["shd"],
            []
        ),
    ],
};

/// Text kept per document.
const MAX_TEXT: usize = 1 << 20;
/// Names listed.
const MAX_LISTED: usize = 100;

impl Extractor for Legacy {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let pick = |format: &'static str, confidence: f64| Some(Sniff { format, confidence });
        // Lotus: a BOF record (opcode 0, length 2 or 26) with a known version.
        if h.len() >= 6 && h[..2] == [0, 0] {
            let (len, version) = (u16::from_le_bytes([h[2], h[3]]), u16::from_le_bytes([h[4], h[5]]));
            if (len == 2 && matches!(version, 0x0404 | 0x0405 | 0x0406 | 0x5120))
                || (len == 0x1a && (0x1000..=0x1005).contains(&version))
            {
                return pick("lotus123", 0.9);
            }
        }
        // SPL: the signature, a header size, and the document name (UTF-16)
        // where the header says.
        if h.starts_with(b"\x00\x00\x01\x00")
            && let (Some(size), Some(doc)) = (u32le(h, 4), u32le(h, 8))
            && (16..=4096).contains(&size)
            && (16..size).contains(&doc)
            && usize::try_from(doc).ok().and_then(|d| utf16_at(h, d)).is_some()
        {
            return pick("spool_spl", 0.85);
        }
        if h.starts_with(b"@PJL") {
            return pick("pcl", 0.9);
        }
        if probe.extension == Some("shd")
            && h.len() >= 8
            && matches!(u32::from_le_bytes([h[0], h[1], h[2], h[3]]), 0x4966 | 0x5123 | 0x5124)
        {
            return pick("spool_shd", 0.85);
        }
        if h.starts_with(b"[ver]") && matches!(probe.extension, Some("sam") | None) {
            return pick("ami_pro", 0.9);
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let format = cx.format_id().to_string();
        match format.as_str() {
            "wordperfect" => wordperfect(src, cx),
            "clarisworks" => {
                let h = src.read_vec(0, 8)?;
                cx.format_set("version", h[0]);
                if h[0] >= 6 {
                    cx.format_set("application", "AppleWorks");
                } else {
                    cx.format_set("application", "ClarisWorks");
                }
                Ok(())
            }
            "chm" => chm(src, cx),
            "winhelp" => winhelp(src, cx),
            "onenote" => onenote(src, cx),
            "spool_spl" => spl(src, cx),
            "spool_shd" => shd(src, cx),
            _ => {
                let n = src.len().min(cx.parse_limit() as u64);
                let data = src.read_vec(0, usize::try_from(n).unwrap_or(0))?;
                match format.as_str() {
                    "lotus123" => lotus(cx, &data),
                    "ms_write" => write(cx, &data),
                    "ami_pro" => ami_pro(cx, &data),
                    _ => pcl(cx, &data),
                }
            }
        }
    }
}

crate::register_extractor!(Legacy);

fn u16le(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32le(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn cstr(b: &[u8]) -> String {
    latin1_or_utf8(b.split(|&c| c == 0).next().unwrap_or(&[]))
}

/// Windows-1252 text (Write and Lotus labels predate Unicode).
fn ansi(b: &[u8]) -> String {
    encoding_rs::WINDOWS_1252.decode_without_bom_handling(b).0.into_owned()
}

// --- WordPerfect -----------------------------------------------------------------

fn wordperfect(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 16)?;
    let product = match h[8] {
        1 => "WordPerfect".to_string(),
        2 => "Shell".to_string(),
        3 => "Notebook".to_string(),
        4 => "Calculator".to_string(),
        10 => "Presentations".to_string(),
        n => format!("product {n}"),
    };
    cx.format_set("product", product);
    let kind = match (h[8], h[9]) {
        (1, 0x0a) => "document".to_string(),
        (1, 0x0b) => "dictionary".to_string(),
        (1, 0x0c) => "thesaurus".to_string(),
        (1, 0x10) => "graphics".to_string(),
        (_, n) => format!("file type {n}"),
    };
    cx.format_set("file_type", kind);
    let version = match h[10] {
        0 => format!("5.{}", h[11]),
        1 => format!("5.1 / 5.2 (minor {})", h[11]),
        2 => format!("6.0 or later (minor {})", h[11]),
        n => format!("{n}.{}", h[11]),
    };
    cx.format_set("version", version);
    cx.format_set("document_offset", u32le(&h, 4).unwrap_or(0));
    if u16le(&h, 12).unwrap_or(0) != 0 {
        cx.security().encrypted(true);
    }
    Ok(())
}

// --- Lotus 1-2-3 -------------------------------------------------------------------

#[allow(clippy::unnecessary_wraps)] // one signature for every reader
fn lotus(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let version = u16le(b, 4).unwrap_or(0);
    let wk3 = u16le(b, 2) == Some(0x1a);
    cx.format_set(
        "version",
        match version {
            0x0404 | 0x0405 => "1-2-3 1A (WKS)",
            0x0406 => "1-2-3 2 (WK1)",
            0x5120 => "Quattro (WQ1)",
            0x1000 => "1-2-3 3 (WK3)",
            0x1002 => "1-2-3 4 (WK4)",
            0x1003 => "1-2-3 97",
            0x1005 => "1-2-3 Millennium",
            _ => "unknown",
        },
    );
    let (mut at, mut records) = (0usize, 0u64);
    let mut cells: BTreeMap<&str, u64> = BTreeMap::new();
    let (mut sheets, mut labels) = (0u8, String::new());
    while let (Some(op), Some(len)) = (u16le(b, at), u16le(b, at + 2)) {
        let body = b.get(at + 4..at + 4 + usize::from(len)).unwrap_or(&[]);
        records += 1;
        match (wk3, op) {
            (_, 0x0001) => break,
            (false, 0x000d) => *cells.entry("integer").or_default() += 1,
            (false, 0x000e) => *cells.entry("number").or_default() += 1,
            (false, 0x0010) | (true, 0x0019) => *cells.entry("formula").or_default() += 1,
            (false, 0x000f) => {
                *cells.entry("label").or_default() += 1;
                // format, column, row, then the alignment prefix and text.
                if let Some(t) = body.get(5..).filter(|_| labels.len() < MAX_TEXT) {
                    labels.push_str(&ansi(t.split(|&c| c == 0).next().unwrap_or(&[]).get(1..).unwrap_or(&[])));
                    labels.push('\n');
                }
            }
            (true, 0x0016) => {
                *cells.entry("label").or_default() += 1;
                sheets = sheets.max(body.get(2).copied().unwrap_or(0).saturating_add(1));
                if let Some(t) = body.get(4..).filter(|_| labels.len() < MAX_TEXT) {
                    labels.push_str(&ansi(t.split(|&c| c == 0).next().unwrap_or(&[]).get(1..).unwrap_or(&[])));
                    labels.push('\n');
                }
            }
            (true, 0x0017 | 0x0018) => {
                *cells.entry("number").or_default() += 1;
                sheets = sheets.max(body.get(2).copied().unwrap_or(0).saturating_add(1));
            }
            _ => {}
        }
        at += 4 + usize::from(len);
        if records > 10_000_000 {
            break;
        }
    }
    cx.format_set("records", records);
    cx.format_set("cells", json!(cells));
    if wk3 {
        cx.physical().sheets(u64::from(sheets.max(1)));
    }
    cx.emit_text(TextRole::Body, &labels);
    Ok(())
}

// --- Write / Ami Pro -----------------------------------------------------------------

#[allow(clippy::unnecessary_wraps)] // one signature for every reader
fn write(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    // The text runs from 128 to `fcMac`.
    let end = u32le(b, 14).map_or(b.len(), |e| usize::try_from(e).unwrap_or(usize::MAX)).min(b.len());
    let text = ansi(b.get(128..end).unwrap_or(&[]));
    cx.format_set("characters", text.chars().count());
    cx.format_set("paragraphs", text.matches('\r').count().max(usize::from(!text.is_empty())));
    if b.get(1) == Some(&0xbe) && b[0] == 0x32 {
        cx.format_set("ole_objects", true);
    }
    cx.emit_text(TextRole::Body, &text.replace('\r', ""));
    Ok(())
}

#[allow(clippy::unnecessary_wraps)] // one signature for every reader
fn ami_pro(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let text = ansi(b);
    let mut lines = text.lines();
    lines.next();
    if let Some(v) = lines.next() {
        cx.format_set("version", v.trim());
    }
    let mut sections = Vec::new();
    let (mut in_body, mut prose) = (false, String::new());
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') && t.ends_with(']') && !t.contains(' ') {
            let name = t.trim_matches(['[', ']']).to_string();
            in_body = name == "edoc";
            if !sections.contains(&name) && sections.len() < MAX_LISTED {
                sections.push(name);
            }
            continue;
        }
        if in_body && !t.starts_with('<') && prose.len() < MAX_TEXT {
            // Inline codes `<+!>` and the like are dropped.
            let mut clean = String::new();
            let mut depth = 0;
            for c in t.chars() {
                match c {
                    '<' => depth += 1,
                    '>' if depth > 0 => depth -= 1,
                    c if depth == 0 => clean.push(c),
                    _ => {}
                }
            }
            prose.push_str(&clean);
            prose.push('\n');
        }
    }
    cx.format_set("sections", sections);
    cx.emit_text(TextRole::Body, &prose);
    Ok(())
}

// --- CHM -------------------------------------------------------------------------------

/// A CHM ENCINT: big-endian 7-bit groups.
fn encint(r: &mut ByteReader<'_>) -> Option<u64> {
    let mut v = 0u64;
    for _ in 0..9 {
        let b = r.u8().ok()?;
        v = (v << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

fn language(lcid: u32) -> Option<&'static str> {
    Some(match lcid & 0x3ff {
        0x09 => "en",
        0x07 => "de",
        0x0c => "fr",
        0x0a => "es",
        0x10 => "it",
        0x13 => "nl",
        0x16 => "pt",
        0x19 => "ru",
        0x11 => "ja",
        0x04 => "zh",
        0x12 => "ko",
        0x15 => "pl",
        0x1d => "sv",
        _ => return None,
    })
}

fn chm(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    let h = src.read_vec(0, usize::try_from(len.min(0x60)).unwrap_or(0))?;
    let mut r = ByteReader::new(&h).skip(4)?;
    let version = r.le_u32()?;
    cx.format_set("version", version);
    let lcid = u32le(&h, 0x14).unwrap_or(0);
    cx.format_set("lcid", format!("0x{lcid:04x}"));
    if let Some(l) = language(lcid) {
        cx.content().language(l, 0.9);
    }
    let dir_at = u64::from(u32le(&h, 0x48).unwrap_or(0));
    let content0 = if version >= 3 {
        u64::from(u32le(&h, 0x58).unwrap_or(0))
    } else {
        // Version 2: section 0 follows the directory.
        dir_at + u64::from(u32le(&h, 0x50).unwrap_or(0))
    };
    let itsp = src.read_vec(dir_at, usize::try_from(len.saturating_sub(dir_at).min(0x54)).unwrap_or(0))?;
    if itsp.get(..4) != Some(b"ITSP") {
        return Err(ExtractError::malformed("CHM directory"));
    }
    let header = u64::from(u32le(&itsp, 8).unwrap_or(0x54));
    let chunk = u64::from(u32le(&itsp, 0x10).unwrap_or(0x1000)).clamp(512, 1 << 16);
    let chunks = u32le(&itsp, 0x2c).unwrap_or(0).min(100_000);
    let (mut files, mut topics, mut system) = (Vec::new(), Vec::new(), None);
    let mut entries = 0u64;
    for c in 0..u64::from(chunks) {
        if c % 64 == 63 {
            cx.checkpoint()?;
        }
        let at = dir_at + header + c * chunk;
        if at + chunk > len {
            break;
        }
        let buf = src.read_vec(at, usize::try_from(chunk).unwrap_or(0))?;
        if buf.get(..4) != Some(b"PMGL") {
            continue;
        }
        let free = usize::try_from(u32le(&buf, 4).unwrap_or(0)).unwrap_or(0);
        let used = buf.len().saturating_sub(free);
        let mut r = ByteReader::new(buf.get(20..used).unwrap_or(&[]));
        while r.remaining() > 0 {
            let Some(n) = encint(&mut r) else { break };
            let Ok(name) = r.bytes(usize::try_from(n).unwrap_or(usize::MAX)) else { break };
            let name = String::from_utf8_lossy(name).into_owned();
            let (Some(section), Some(offset), Some(length)) = (encint(&mut r), encint(&mut r), encint(&mut r)) else {
                break;
            };
            entries += 1;
            if name == "/#SYSTEM" && section == 0 {
                system = Some((offset, length));
            }
            if !name.starts_with("::") && !name.ends_with('/') && !name.starts_with("/#") && !name.starts_with("/$") {
                let ext = std::path::Path::new(&name).extension();
                if ext.is_some_and(|x| x.eq_ignore_ascii_case("htm") || x.eq_ignore_ascii_case("html")) {
                    topics.push(name.trim_start_matches('/').to_string());
                }
                files.push(name);
            }
        }
    }
    cx.format_set("directory_entries", entries);
    cx.format_set("files", files.len());
    cx.format_set("topics", topics.len());
    cx.format_set("topic_list", topics.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    // `#SYSTEM`: a version, then (code, length, data) records.
    if let Some((off, n)) = system {
        let data = src.read_vec(content0 + off, usize::try_from(n.min(64 * 1024)).unwrap_or(0))?;
        let mut r = ByteReader::new(data.get(4..).unwrap_or(&[]));
        while r.remaining() >= 4 {
            let (code, n) = (r.le_u16()?, usize::from(r.le_u16()?));
            let Ok(v) = r.bytes(n) else { break };
            let text = cstr(v);
            match code {
                0 => cx.format_set("contents_file", text),
                1 => cx.format_set("index_file", text),
                2 => cx.format_set("default_topic", text),
                3 if !text.is_empty() => {
                    cx.content().title(text.clone());
                    cx.format_set("title", text);
                }
                6 => cx.format_set("compiled_file", text),
                9 => cx.format_set("compiler", text),
                _ => {}
            }
        }
    }
    Ok(())
}

// --- WinHelp -------------------------------------------------------------------------------

/// The internal files of a WinHelp file: its directory B+ tree's leaves.
fn hlp_directory(src: &mut dyn Source, at: u64) -> Result<Vec<(String, u64)>, ExtractError> {
    // A file header (9 bytes), then the B+ tree header.
    let h = src.read_vec(at + 9, 38)?;
    if u16le(&h, 0) != Some(0x293b) {
        return Err(ExtractError::malformed("WinHelp directory"));
    }
    let page = u64::from(u16le(&h, 4).unwrap_or(1024)).clamp(256, 1 << 14);
    let root = u64::from(u16le(&h, 26).unwrap_or(0));
    let levels = u16le(&h, 32).unwrap_or(1).clamp(1, 8);
    let pages_at = at + 9 + 38;
    // Down the leftmost path to the first leaf.
    let mut node = root;
    for _ in 1..levels {
        let p = src.read_vec(pages_at + node * page, 6)?;
        node = u64::from(u16le(&p, 4).unwrap_or(0));
    }
    let mut out = Vec::new();
    for _ in 0..10_000 {
        let p = src.read_vec(pages_at + node * page, usize::try_from(page).unwrap_or(0))?;
        let n = u16le(&p, 2).unwrap_or(0);
        let next = i16::from_le_bytes([p[6], p[7]]);
        let mut r = ByteReader::new(&p[8..]);
        for _ in 0..n {
            let Ok(name) = r.cstr() else { break };
            let Ok(off) = r.le_u32() else { break };
            out.push((latin1_or_utf8(name), u64::from(off)));
        }
        if next < 0 || out.len() > 100_000 {
            break;
        }
        node = u64::try_from(next).unwrap_or(0);
    }
    Ok(out)
}

fn winhelp(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let header = src.read_vec(0, 16)?;
    let dir = u64::from(u32le(&header, 4).unwrap_or(0));
    let files = hlp_directory(src, dir)?;
    cx.format_set("internal_files", files.len());
    cx.format_set(
        "internal_file_list",
        files.iter().take(MAX_LISTED).map(|(n, _)| Value::from(n.as_str())).collect::<Vec<_>>(),
    );
    let Some(&(_, sys)) = files.iter().find(|(n, _)| n == "|SYSTEM") else { return Ok(()) };
    let sys_head = src.read_vec(sys, 9 + 12)?;
    let mut r = ByteReader::new(&sys_head).skip(9)?;
    if r.le_u16()? != 0x036c {
        return Err(ExtractError::malformed("WinHelp |SYSTEM"));
    }
    let (minor, major) = (r.le_u16()?, r.le_u16()?);
    let generated = r.le_u32()?;
    cx.format_set(
        "help_version",
        match minor {
            15 => "WinHelp 3.0".to_string(),
            21 => "WinHelp 3.1".to_string(),
            27 | 33 => "WinHelp 4.0".to_string(),
            n => format!("{major}.{n}"),
        },
    );
    if let Some(t) = super::super::archive::unix_time(i64::from(generated)) {
        cx.format_set("generated", t);
    }
    let used = u32le(&src.read_vec(sys, 9)?, 4).unwrap_or(0);
    let body =
        src.read_vec(sys + 9 + 12, usize::try_from(u64::from(used).saturating_sub(12).min(64 * 1024)).unwrap_or(0))?;
    if minor <= 16 {
        let t = cstr(&body);
        if !t.is_empty() {
            cx.content().title(t.clone());
            cx.format_set("title", t);
        }
        return Ok(());
    }
    let mut r = ByteReader::new(&body);
    while r.remaining() >= 4 {
        let (kind, n) = (r.le_u16()?, usize::from(r.le_u16()?));
        let Ok(v) = r.bytes(n) else { break };
        match kind {
            1 => {
                let t = cstr(v);
                cx.content().title(t.clone());
                cx.format_set("title", t);
            }
            2 => cx.format_set("copyright", cstr(v)),
            4 => {
                let m = cstr(v);
                if !m.is_empty() {
                    cx.security().active_content("winhelp_macro");
                }
            }
            _ => {}
        }
    }
    Ok(())
}

// --- OneNote -------------------------------------------------------------------------------

fn guid(b: &[u8]) -> String {
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    let rest = b[8..16].iter().fold(String::new(), |mut acc, x| {
        use std::fmt::Write;
        let _ = write!(acc, "{x:02X}");
        acc
    });
    format!("{{{d1:08X}-{d2:04X}-{d3:04X}-{}-{}}}", &rest[..4], &rest[4..])
}

fn onenote(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, usize::try_from(src.len().min(1024)).unwrap_or(0))?;
    if h.len() < 300 {
        return Err(ExtractError::malformed("OneNote header"));
    }
    cx.format_set("kind", if h[..16] == ONE_SECTION { "section" } else { "table of contents" });
    cx.format_set("file_id", guid(&h[16..32]));
    if guid(&h[48..64]) != "{109ADD3F-911B-49F5-A5D0-1791EDC8AED8}" {
        cx.warn("unexpected OneNote file format GUID");
    }
    let codes = |at| u32le(&h, at).unwrap_or(0);
    let version = |c: u32| match c {
        0x2a => "OneNote 2010".to_string(),
        0x2d | 0x2e => "OneNote 2013 or later".to_string(),
        0 => "unknown".to_string(),
        n => format!("0x{n:x}"),
    };
    cx.format_set("last_written_by", version(codes(64)));
    cx.format_set("oldest_writer", version(codes(68)));
    cx.format_set("newest_writer", version(codes(72)));
    cx.format_set("transactions", codes(96));
    cx.format_set("file_version_generation", u64::from(codes(228)) | (u64::from(codes(232)) << 32));
    let created = codes(280);
    if created != 0 {
        cx.format_set("created_by_build", created);
    }
    Ok(())
}

// --- PCL / PJL -----------------------------------------------------------------------------

fn paper(code: u32) -> Option<&'static str> {
    Some(match code {
        1 => "Executive",
        2 => "Letter",
        3 => "Legal",
        6 => "Ledger",
        25 => "A5",
        26 => "A4",
        27 => "A3",
        45 => "JIS B5",
        80 => "Monarch envelope",
        81 => "Commercial 10 envelope",
        90 => "DL envelope",
        91 => "C5 envelope",
        _ => return None,
    })
}

#[allow(clippy::unnecessary_wraps)] // one signature for every reader
fn pcl(cx: &mut Context<'_>, job: &[u8]) -> Result<(), ExtractError> {
    // PJL: `@PJL …` lines after the Universal Exit Language sequence, up to
    // `ENTER LANGUAGE`.
    let mut at = job.strip_prefix(b"\x1b%-12345X").map_or(0, |_| 9);
    let mut language = None;
    let mut pjl = serde_json::Map::new();
    while job[at..].starts_with(b"@PJL") {
        let end = job[at..].iter().position(|&c| c == b'\n').map_or(job.len(), |e| at + e + 1);
        let line = latin1_or_utf8(&job[at..end]).trim().to_string();
        let upper = line.to_ascii_uppercase();
        if let Some(l) = upper.strip_prefix("@PJL ENTER LANGUAGE") {
            language = Some(l.trim_start_matches([' ', '=']).trim().to_string());
            at = end;
            break;
        }
        let rest = line.get(5..).unwrap_or("").trim();
        if let Some((k, v)) = rest.split_once('=') {
            let key = k.split_whitespace().last().unwrap_or(k).to_ascii_lowercase();
            let v = v.trim().trim_matches('"').to_string();
            let personal = matches!(key.as_str(), "username" | "user" | "computername" | "hostname");
            if !(personal && cx.privacy_strict()) && pjl.len() < MAX_LISTED {
                if key == "name" && upper.starts_with("@PJL JOB") {
                    cx.content().title(v.clone());
                    pjl.insert("job_name".into(), v.into());
                } else {
                    pjl.insert(key, v.into());
                }
            }
        }
        at = end;
    }
    if !pjl.is_empty() {
        cx.format_set("pjl", Value::Object(pjl));
    }
    let body = &job[at.min(job.len())..];
    if body.windows(12).take(4096).any(|w| w == b") HP-PCL XL;") {
        cx.format_set("language", language.unwrap_or_else(|| "PCLXL".into()));
        return Ok(());
    }
    if body.starts_with(b"%!") {
        cx.format_set("language", language.unwrap_or_else(|| "POSTSCRIPT".into()));
        return Ok(());
    }
    cx.format_set("language", language.unwrap_or_else(|| "PCL".into()));
    // PCL 5: escape sequences, some followed by binary data (`…W`, `&p…X`);
    // a form feed outside them ends a page.
    let (mut i, mut pages, mut resets) = (0usize, 0u64, 0u64);
    let (mut copies, mut paper_size, mut resolution, mut landscape) = (None, None, None, None);
    while i < body.len() {
        match body[i] {
            0x0c => {
                pages += 1;
                i += 1;
            }
            0x1b if body.get(i + 1) == Some(&b'E') => {
                resets += 1;
                i += 2;
            }
            0x1b if body.get(i + 1).is_some_and(|c| (0x21..=0x2f).contains(c)) => {
                let (p, g) = (body[i + 1], body.get(i + 2).copied().unwrap_or(0));
                i = (i + 3).min(body.len());
                // Parameter groups: a value, then a lowercase (more follow)
                // or uppercase (last) letter.
                loop {
                    let start = i;
                    while i < body.len() && (body[i].is_ascii_digit() || matches!(body[i], b'+' | b'-' | b'.')) {
                        i += 1;
                    }
                    let value: f64 =
                        std::str::from_utf8(&body[start..i]).ok().and_then(|v| v.parse().ok()).unwrap_or(0.0);
                    let Some(&letter) = body.get(i) else { break };
                    i += 1;
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    let n = value.max(0.0) as u32;
                    match (p, g, letter.to_ascii_uppercase()) {
                        (b'&', b'l', b'X') => copies = Some(n),
                        (b'&', b'l', b'A') => paper_size = paper(n),
                        (b'&', b'l', b'O') => landscape = Some(n == 1 || n == 3),
                        (b'*', b't', b'R') => resolution = Some(n),
                        (_, _, b'W') | (b'&', b'p', b'X') => i = i.saturating_add(n as usize).min(body.len()),
                        _ => {}
                    }
                    if letter.is_ascii_uppercase() || !letter.is_ascii_lowercase() {
                        break;
                    }
                }
            }
            _ => i += 1,
        }
    }
    cx.physical().pages(pages);
    cx.format_set("resets", resets);
    if let Some(c) = copies {
        cx.format_set("copies", c);
    }
    if let Some(p) = paper_size {
        cx.format_set("paper", p);
    }
    if let Some(r) = resolution {
        cx.format_set("resolution_dpi", r);
    }
    if let Some(l) = landscape {
        cx.format_set("orientation", if l { "landscape" } else { "portrait" });
    }
    Ok(())
}

// --- spool files ---------------------------------------------------------------------------

/// A NUL-terminated UTF-16LE string at `at`.
fn utf16_at(b: &[u8], at: usize) -> Option<String> {
    let s = b.get(at..)?;
    let units: Vec<u16> =
        s.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).take_while(|&u| u != 0).take(1024).collect();
    let text = String::from_utf16(&units).ok()?;
    (!text.is_empty() && text.chars().all(|c| !c.is_control())).then_some(text)
}

fn spl(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, usize::try_from(src.len().min(4096)).unwrap_or(0))?;
    // `SPL_HEADER`: signature, size, document name and port offsets.
    let size = u32le(&h, 4).unwrap_or(0);
    cx.format_set("header_bytes", size);
    if let Some(d) = u32le(&h, 8).and_then(|o| utf16_at(&h, usize::try_from(o).ok()?)) {
        cx.content().title(d.clone());
        cx.format_set("document", d);
    }
    if let Some(p) = u32le(&h, 12).and_then(|o| utf16_at(&h, usize::try_from(o).ok()?)) {
        cx.format_set("port", p);
    }
    // The EMF data that follows (`EMRI_METAFILE` records hold each page).
    let emf = h.windows(4).position(|w| w == b" EMF").is_some();
    cx.format_set("emf_data", emf);
    Ok(())
}

fn shd(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, usize::try_from(src.len().min(64 * 1024)).unwrap_or(0))?;
    let signature = u32le(&h, 0).unwrap_or(0);
    cx.format_set(
        "windows",
        match signature {
            0x4966 => "Windows NT 4 / 2000",
            0x5123 | 0x5124 => "Windows XP or later",
            _ => "unknown",
        },
    );
    let header = usize::try_from(u32le(&h, 4).unwrap_or(0)).unwrap_or(0).min(h.len());
    cx.format_set("job_id", u32le(&h, 12).unwrap_or(0));
    // The string fields, in order, as offsets into the file.
    let names = ["user", "notify", "document", "port", "printer", "driver", "devmode", "print_processor", "data_type"];
    let mut at = 20;
    for name in names {
        let Some(off) = u32le(&h, at) else { break };
        at += 4;
        if name == "devmode" {
            continue;
        }
        let Some(v) = usize::try_from(off).ok().filter(|&o| o >= header && o < h.len()).and_then(|o| utf16_at(&h, o))
        else {
            continue;
        };
        let personal = matches!(name, "user" | "notify");
        if personal && cx.privacy_strict() {
            continue;
        }
        if name == "document" {
            cx.content().title(v.clone());
        }
        cx.format_set(name, v);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!(
        "wordperfect",
        "lotus123",
        "clarisworks",
        "ms_write",
        "ami_pro",
        "chm",
        "winhelp",
        "onenote",
        "pcl",
        "spool_spl",
        "spool_shd"
    );

    #[test]
    fn helpers() {
        let mut r = ByteReader::new(&[0x81, 0x00, 0x05]);
        assert_eq!(encint(&mut r), Some(128));
        assert_eq!(encint(&mut r), Some(5));
        assert_eq!(language(0x0809), Some("en"));
        assert_eq!(paper(26), Some("A4"));
        assert_eq!(guid(&ONE_SECTION), "{7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}");
        assert_eq!(utf16_at(b"H\0i\0\0\0", 0).as_deref(), Some("Hi"));
    }

    /// PCL raster data that contains form feeds is skipped, not counted.
    #[test]
    fn pcl_pages_skip_raster_data() {
        let mut job =
            b"\x1b%-12345X@PJL JOB NAME=\"tides\"\r\n@PJL ENTER LANGUAGE=PCL\r\n\x1bE\x1b&l26A\x1b&l2X".to_vec();
        job.extend(b"\x1b*b4W\x0c\x0c\x0c\x0c");
        job.extend(b"\x0c\x1bE");
        let r = crate::plugin::testing::report_for("tides.pcl", &job);
        assert_eq!(r.physical.document.as_ref().and_then(|d| d.pages), Some(1));
        assert_eq!(r.format["pcl"]["paper"], "A4");
        assert_eq!(r.format["pcl"]["copies"], 2);
        assert_eq!(r.format["pcl"]["pjl"]["job_name"], "tides");
    }
}
