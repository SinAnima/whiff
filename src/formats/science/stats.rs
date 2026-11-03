//! Statistics packages' data files:
//! * SPSS `.sav` / `.zsav`: product, compression, cases, variables (long
//!   names) with their labels, the file label and creation time; SPSS
//!   portable `.por`: version, creation time, product, variables;
//! * Stata `.dta` (formats 113–119): release, byte order, variables,
//!   observations, data label, time stamp, variable names and labels;
//! * SAS XPORT (`.xpt`, versions 5 and 8): SAS version, host, creation
//!   time, members with their labels and variables; SAS `.sas7bdat`:
//!   header (dataset name, release, host, encoding, dates, pages), rows,
//!   column count and names from the meta pages' subheaders;
//! * R `.rds` and `.RData` (XDR, ASCII or native serialisation; plain,
//!   gzip, bzip2 or xz): format version, the R version that wrote it, the
//!   object type (ALTREP sequences and wrappers by their logical type),
//!   and for data frames the columns, classes and rows; `.RData`: the
//!   objects saved.
//!
//! Specifications: the ReadStat sources (SPSS, Stata, SAS formats); Stata
//! "dta" documentation (formats 117–119); SAS TS-140 (XPORT); R Internals
//! §1.8 "Serialization Formats".

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::plugin::{
    Codec, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    parse_date, redact_sensitive, truncate_chars,
};

/// Extractor for statistics packages' data files.
pub struct Stats;

static META: ExtractorMeta = ExtractorMeta {
    id: "science.stats",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "sav",
            name: "SPSS data",
            family: "sci",
            mimes: &["application/x-spss-sav"],
            extensions: &["sav", "zsav"],
            magic: &[Magic::at(0, b"$FL2"), Magic::at(0, b"$FL3")],
            parent: None,
        },
        FormatSpec {
            id: "por",
            name: "SPSS portable",
            family: "sci",
            mimes: &[],
            extensions: &["por"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "dta",
            name: "Stata data",
            family: "sci",
            mimes: &[],
            extensions: &["dta"],
            magic: &[Magic::at(0, b"<stata_dta>")],
            parent: None,
        },
        FormatSpec {
            id: "xpt",
            name: "SAS dataset / transport",
            family: "sci",
            mimes: &[],
            extensions: &["xpt"],
            magic: &[
                Magic::at(0, b"HEADER RECORD*******LIBRARY HEADER RECORD!!!!!!!"),
                Magic::at(0, b"HEADER RECORD*******LIBV8   HEADER RECORD!!!!!!!"),
            ],
            parent: None,
        },
        FormatSpec {
            id: "sas7bdat",
            name: "SAS dataset",
            family: "sci",
            mimes: &[],
            extensions: &["sas7bdat"],
            magic: &[Magic::at(
                12,
                b"\xc2\xea\x81\x60\xb3\x14\x11\xcf\xbd\x92\x08\x00\x09\xc7\x31\x8c\x18\x1f\x10\x11",
            )],
            parent: None,
        },
        FormatSpec {
            id: "rds",
            name: "R data",
            family: "sci",
            mimes: &[],
            extensions: &["rds"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "rdata",
            name: "R workspace",
            family: "sci",
            mimes: &[],
            extensions: &["rdata", "rda"],
            magic: &[],
            parent: None,
        },
    ],
};

/// Variables listed.
const MAX_VARS: usize = 500;

fn cstr(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    s.trim_end_matches(['\0', ' ']).trim().to_string()
}

fn vars_map(vars: Vec<(String, String)>) -> Value {
    Value::Object(
        vars.into_iter()
            .take(MAX_VARS)
            .map(|(n, l)| (truncate_chars(&n, 100), Value::String(truncate_chars(&redact_sensitive(&l), 200))))
            .collect(),
    )
}

// ------------------------------------------------------------- SPSS
fn sav(cx: &mut Context<'_>, b: &[u8]) -> Option<()> {
    let i32_at = |at: usize| Some(i32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?));
    cx.format_set("product", truncate_chars(&cstr(b.get(4..64)?), 60));
    cx.format_set(
        "compression",
        match i32_at(72)? {
            0 => "none",
            1 => "bytecode",
            2 => "zlib",
            _ => "other",
        },
    );
    let cases = i32_at(80)?;
    if cases >= 0 {
        cx.format_set("cases", cases);
    }
    let date = cstr(b.get(84 + 8..84 + 17)?);
    let time = cstr(b.get(101..109)?);
    cx.format_set("created", format!("{date} {time}"));
    if let Some((t, tz)) = parse_date(&format!("{date} {time}")) {
        cx.temporal().source("sav.creation_date").content_date(DateField::Created, t, tz);
    }
    let label = cstr(b.get(109..173)?);
    if !label.is_empty() {
        cx.format_set("file_label", truncate_chars(&label, 64));
        cx.content().source("sav.file_label").title(truncate_chars(&label, 64));
    }
    // Variable records (type 2); continuation records (type -1) for long strings.
    let mut at = 176;
    let mut vars = Vec::new();
    while i32_at(at) == Some(2) {
        let kind = i32_at(at + 4)?;
        let has_label = i32_at(at + 8)?;
        let missing = i32_at(at + 12)?;
        let name = cstr(b.get(at + 24..at + 32)?);
        at += 32;
        let mut label = String::new();
        if has_label == 1 {
            let n = usize::try_from(i32_at(at)?).ok()?;
            label = cstr(b.get(at + 4..at + 4 + n)?);
            at += 4 + n.div_ceil(4) * 4;
        }
        at += 8 * usize::try_from(missing.unsigned_abs()).ok()?;
        if kind >= 0 {
            vars.push((name, label));
        }
        if vars.len() > 100_000 {
            break;
        }
    }
    // Long variable names: record 7, subtype 13, `SHORT=Long` separated by tabs.
    let mut long: BTreeMap<String, String> = BTreeMap::new();
    for _ in 0..10_000 {
        match i32_at(at)? {
            3 => {
                // Value labels, then their variable index record (type 4).
                let n = usize::try_from(i32_at(at + 4)?).ok()?;
                at += 8;
                for _ in 0..n.min(1_000_000) {
                    at += 8;
                    at += (usize::from(*b.get(at)?) + 1).div_ceil(8) * 8;
                }
                if i32_at(at)? != 4 {
                    break;
                }
                at += 8 + 4 * usize::try_from(i32_at(at + 4)?).ok()?;
            }
            6 => at += 8 + 80 * usize::try_from(i32_at(at + 4)?).ok()?,
            7 => {
                let (subtype, width, count) = (i32_at(at + 4)?, i32_at(at + 8)?, i32_at(at + 12)?);
                let len = usize::try_from(width).ok()?.checked_mul(usize::try_from(count).ok()?)?;
                let body = b.get(at + 16..at + 16 + len)?;
                if subtype == 13 {
                    for pair in String::from_utf8_lossy(body).split('\t') {
                        if let Some((k, v)) = pair.split_once('=') {
                            long.insert(k.to_string(), v.to_string());
                        }
                    }
                }
                at += 16 + len;
            }
            _ => break, // 999: the dictionary ends
        }
    }
    for (name, _) in &mut vars {
        if let Some(l) = long.get(name.as_str()) {
            name.clone_from(l);
        }
    }
    cx.format_set("variable_count", vars.len());
    cx.format_set("variables", vars_map(vars));
    Some(())
}

/// SPSS portable: base-30 numbers and strings after the `SPSSPORT` tag.
fn por(cx: &mut Context<'_>, b: &[u8]) -> Option<()> {
    // Lines are 80 characters; the reader ignores the line ends.
    let text: Vec<u8> = b.iter().copied().filter(|&c| c != b'\r' && c != b'\n').collect();
    let at = text.windows(8).position(|w| w == b"SPSSPORT")? + 8;
    let mut p = at;
    let num = |p: &mut usize| -> Option<i64> {
        let start = *p;
        if start >= text.len() {
            return None;
        }
        while *p < text.len() && text[*p] != b'/' {
            *p += 1;
        }
        let s = std::str::from_utf8(&text[start..*p]).ok()?.trim();
        *p += 1;
        // Integers only (base 30, digits 0-9 A-T).
        i64::from_str_radix(s.split('.').next()?.trim_start_matches(' '), 30).ok()
    };
    let string = |p: &mut usize| -> Option<String> {
        let n = usize::try_from(num(p)?).ok()?;
        let s = String::from_utf8_lossy(text.get(*p..*p + n)?).into_owned();
        *p += n;
        Some(s)
    };
    let version = *text.get(p)?;
    p += 1;
    cx.format_set("por_version", char::from(version).to_string());
    let date = string(&mut p)?;
    let time = string(&mut p)?;
    cx.format_set("created", format!("{date} {time}"));
    let mut vars = Vec::new();
    let mut text_var = false;
    while let Some(&tag) = text.get(p) {
        p += 1;
        match tag {
            b'1' => cx.format_set("product", truncate_chars(&string(&mut p)?, 200)),
            b'2' => {
                string(&mut p)?;
            }
            b'3' => cx.format_set("subproduct", truncate_chars(&string(&mut p)?, 200)),
            b'4' | b'5' | b'6' => {
                num(&mut p)?;
            }
            b'7' => {
                text_var = num(&mut p)? > 0; // width; 0 is numeric
                let name = string(&mut p)?;
                for _ in 0..6 {
                    num(&mut p)?;
                }
                vars.push((name, String::new()));
            }
            // Missing values: one (`8` value, `9` LO THRU x, `A` x THRU HI)
            // or two (`B` range), strings for a string variable.
            b'8' | b'9' | b'A' | b'B' => {
                for _ in 0..if tag == b'B' { 2 } else { 1 } {
                    if text_var {
                        string(&mut p)?;
                    } else {
                        num(&mut p)?;
                    }
                }
            }
            b'C' => {
                let label = string(&mut p)?;
                if let Some(last) = vars.last_mut() {
                    last.1 = label;
                }
            }
            b'D' => {
                let n = num(&mut p)?;
                for _ in 0..n.clamp(0, 10_000) {
                    num(&mut p)?;
                    string(&mut p)?;
                }
            }
            b'E' => {
                let n = num(&mut p)?;
                for _ in 0..n.clamp(0, 10_000) {
                    string(&mut p)?;
                }
            }
            _ => break, // 'F': the data
        }
        if vars.len() > 100_000 {
            break;
        }
    }
    cx.format_set("variable_count", vars.len());
    cx.format_set("variables", vars_map(vars));
    Some(())
}

// ------------------------------------------------------------- Stata
fn tagged(b: &[u8], open: &[u8], close: &[u8]) -> Option<(usize, usize)> {
    let s = b.windows(open.len()).position(|w| w == open)? + open.len();
    let e = s + b[s..].windows(close.len()).position(|w| w == close)?;
    Some((s, e))
}

fn dta(cx: &mut Context<'_>, b: &[u8]) -> Option<()> {
    if b.starts_with(b"<stata_dta>") {
        let get = |t: &str| tagged(b, format!("<{t}>").as_bytes(), format!("</{t}>").as_bytes()).map(|(s, e)| &b[s..e]);
        let release: u32 = String::from_utf8_lossy(get("release")?).parse().ok()?;
        let little = get("byteorder") == Some(b"LSF");
        cx.format_set("release", release);
        cx.format_set("byte_order", if little { "little-endian" } else { "big-endian" });
        let k = get("K")?;
        let n = get("N")?;
        let le = |s: &[u8]| s.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x));
        let be = |s: &[u8]| s.iter().fold(0u64, |a, &x| a << 8 | u64::from(x));
        let num = |s: &[u8]| if little { le(s) } else { be(s) };
        let nvars = num(k);
        cx.format_set("variable_count", nvars);
        cx.format_set("observations", num(n));
        // <label>: a 1- (117) or 2-byte (118+) length, then the text.
        if let Some(l) = get("label") {
            let w = if release >= 118 { 2 } else { 1 };
            let text = cstr(l.get(w..).unwrap_or_default());
            if !text.is_empty() {
                cx.format_set("data_label", truncate_chars(&text, 200));
                cx.content().source("dta.label").title(truncate_chars(&text, 200));
            }
        }
        if let Some(ts) = get("timestamp").and_then(|t| t.get(1..)) {
            cx.format_set("timestamp", cstr(ts));
        }
        let width = if release >= 118 { 129 } else { 33 };
        let lwidth = if release >= 118 { 321 } else { 81 };
        let names: Vec<String> = get("varnames").map(|v| v.chunks(width).map(cstr).collect()).unwrap_or_default();
        let labels: Vec<String> =
            get("variable_labels").map(|v| v.chunks(lwidth).map(cstr).collect()).unwrap_or_default();
        let vars = names.into_iter().zip(labels.into_iter().chain(std::iter::repeat(String::new()))).collect();
        cx.format_set("variables", vars_map(vars));
        return Some(());
    }
    // Formats 113–115: version, byte order, type, nvar (2), nobs (4), label (81), stamp (18).
    let release = u32::from(*b.first()?);
    if !(102..=115).contains(&release) {
        return None;
    }
    let little = *b.get(1)? == 2;
    let u16_at = |at: usize| -> Option<u16> {
        let r = [*b.get(at)?, *b.get(at + 1)?];
        Some(if little { u16::from_le_bytes(r) } else { u16::from_be_bytes(r) })
    };
    let u32_at = |at: usize| -> Option<u32> {
        let r: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
        Some(if little { u32::from_le_bytes(r) } else { u32::from_be_bytes(r) })
    };
    cx.format_set("release", release);
    cx.format_set("byte_order", if little { "little-endian" } else { "big-endian" });
    let nvar = usize::from(u16_at(4)?);
    cx.format_set("variable_count", nvar);
    cx.format_set("observations", u32_at(6)?);
    let label = cstr(b.get(10..91)?);
    if !label.is_empty() {
        cx.format_set("data_label", truncate_chars(&label, 200));
    }
    cx.format_set("timestamp", cstr(b.get(91..109)?));
    let names_at = 109 + nvar;
    let names: Vec<(String, String)> = (0..nvar.min(MAX_VARS))
        .filter_map(|i| b.get(names_at + 33 * i..names_at + 33 * (i + 1)).map(cstr))
        .map(|n| (n, String::new()))
        .collect();
    cx.format_set("variables", vars_map(names));
    Some(())
}

// ------------------------------------------------------------- SAS
fn xpt(cx: &mut Context<'_>, b: &[u8]) -> Option<()> {
    let rec = |i: usize| b.get(80 * i..80 * (i + 1));
    let r1 = rec(1)?;
    cx.format_set("sas_version", cstr(r1.get(24..32)?));
    cx.format_set("host", cstr(r1.get(32..40)?));
    cx.format_set("created", cstr(r1.get(64..80)?));
    // Members: "MEMBER HEADER" then a descriptor with the name, label and
    // the NAMESTR header giving the variable count, then 140-byte namestrs.
    let mut members = Vec::new();
    let mut at = 3 * 80;
    // Version 5 `MEMBER  HEADER`, version 8 `MEMBV8  HEADER`.
    let member = |w: &[u8]| {
        w == b"HEADER RECORD*******MEMBER  HEADER RECORD!!!!!!!"
            || w == b"HEADER RECORD*******MEMBV8  HEADER RECORD!!!!!!!"
    };
    cx.format_set("xport_version", if b.get(20..25) == Some(b"LIBV8") { 8 } else { 5 });
    while let Some(i) = b.get(at..).and_then(|r| r.windows(48).position(member)) {
        let m = at + i;
        let d1 = b.get(m + 160..m + 240)?;
        let d2 = b.get(m + 240..m + 320)?;
        let name = cstr(d1.get(8..16)?);
        let label = cstr(d2.get(32..72)?);
        let ns = b.get(m + 320..m + 400)?;
        let n: usize = String::from_utf8_lossy(ns.get(54..58)?).trim().parse().unwrap_or(0);
        let mut vars = Vec::new();
        for j in 0..n.min(MAX_VARS) {
            let v = b.get(m + 400 + 140 * j..m + 400 + 140 * (j + 1))?;
            vars.push((cstr(v.get(8..16)?), cstr(v.get(16..56)?)));
        }
        let mut e = Map::new();
        e.insert("name".into(), truncate_chars(&name, 32).into());
        if !label.is_empty() {
            e.insert("label".into(), truncate_chars(&label, 64).into());
        }
        e.insert("variable_count".into(), n.into());
        e.insert("variables".into(), vars_map(vars));
        members.push(Value::Object(e));
        at = m + 400 + 140 * n;
        if members.len() >= 100 {
            break;
        }
    }
    cx.format_set("members", members);
    Some(())
}

fn sas7bdat(cx: &mut Context<'_>, b: &[u8]) -> Option<()> {
    let a2 = if *b.get(32)? == 0x33 { 4 } else { 0 }; // 64-bit offsets
    let a1 = if *b.get(35)? == 0x33 { 4 } else { 0 };
    let little = *b.get(37)? == 0x01;
    cx.format_set("format", if a2 == 4 { "64-bit" } else { "32-bit" });
    cx.format_set("byte_order", if little { "little-endian" } else { "big-endian" });
    cx.format_set(
        "platform",
        match b.get(39) {
            Some(b'1') => "unix",
            Some(b'2') => "windows",
            _ => "unknown",
        },
    );
    cx.format_set(
        "encoding",
        match b.get(70) {
            Some(20) => "UTF-8".to_string(),
            Some(29) => "latin1".to_string(),
            Some(62) => "wlatin1".to_string(),
            Some(c) => format!("code {c}"),
            None => "?".into(),
        },
    );
    let name = cstr(b.get(92..156)?);
    cx.format_set("dataset", truncate_chars(&name, 64));
    cx.format_set("file_type", cstr(b.get(156..164)?));
    let f64_at = |at: usize| -> Option<f64> {
        let r: [u8; 8] = b.get(at..at + 8)?.try_into().ok()?;
        Some(if little { f64::from_le_bytes(r) } else { f64::from_be_bytes(r) })
    };
    let u32_at = |at: usize| -> Option<u32> {
        let r: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
        Some(if little { u32::from_le_bytes(r) } else { u32::from_be_bytes(r) })
    };
    // Dates are seconds since 1960-01-01.
    for (at, key, field) in [(164 + a1, "created", DateField::Created), (172 + a1, "modified", DateField::Modified)] {
        if let Some(s) = f64_at(at).filter(|s| s.is_finite() && *s > 0.0) {
            #[allow(clippy::cast_possible_truncation)] // whole seconds of a date
            let unix = s as i64 - 315_619_200;
            if let Some(t) = super::unix_time(unix) {
                cx.format_set(key, t.clone());
                cx.temporal().source(format!("sas7bdat.{key}")).content_date(field, t, true);
            }
        }
    }
    cx.format_set("header_bytes", u32_at(196 + a1)?);
    cx.format_set("page_size", u32_at(200 + a1)?);
    cx.format_set("pages", u32_at(204 + a1)?);
    let base = 216 + a1 + a2;
    cx.format_set("release", cstr(b.get(base..base + 8)?));
    cx.format_set("host", cstr(b.get(base + 8..base + 24)?));
    let (header, page) = (u32_at(196 + a1)?, u32_at(200 + a1)?);
    sas_pages(cx, b, a2 == 4, little, usize::try_from(header).ok()?, usize::try_from(page).ok()?);
    Some(())
}

/// The meta pages' subheaders: row size (rows), column size (columns),
/// column text and column name (the names).
fn sas_pages(cx: &mut Context<'_>, b: &[u8], wide: bool, little: bool, header: usize, page: usize) {
    let w = if wide { 8 } else { 4 };
    let int = |at: usize| -> Option<u64> {
        let r = b.get(at..at + w)?;
        Some(if wide {
            let r: [u8; 8] = r.try_into().ok()?;
            if little { u64::from_le_bytes(r) } else { u64::from_be_bytes(r) }
        } else {
            let r: [u8; 4] = r.try_into().ok()?;
            u64::from(if little { u32::from_le_bytes(r) } else { u32::from_be_bytes(r) })
        })
    };
    let u16_at = |at: usize| -> Option<usize> {
        let r = [*b.get(at)?, *b.get(at + 1)?];
        Some(usize::from(if little { u16::from_le_bytes(r) } else { u16::from_be_bytes(r) }))
    };
    let (mut rows, mut columns) = (None, None);
    let (mut texts, mut names): (Vec<usize>, Vec<(usize, usize, usize)>) = (Vec::new(), Vec::new());
    let bit = if wide { 32 } else { 16 };
    for n in 0..1000_usize {
        let Some(start) = n.checked_mul(page).and_then(|o| o.checked_add(header)) else { break };
        if page == 0 || start + page > b.len() {
            break;
        }
        let Some(kind) = u16_at(start + bit) else { break };
        if kind & 0x0f00 != 0 && kind != 0x0200 {
            break; // a data page: the meta pages are over
        }
        let count = u16_at(start + bit + 4).unwrap_or(0);
        for i in 0..count.min(4096) {
            let ptr = start + bit + 8 + i * 3 * w;
            let (Some(off), Some(len)) = (int(ptr), int(ptr + w)) else { break };
            let (Ok(off), Ok(len)) = (usize::try_from(off), usize::try_from(len)) else { break };
            let at = start + off;
            if len < w || at + len > b.len() || b.get(ptr + 2 * w) != Some(&0) {
                continue; // empty, truncated or compressed
            }
            // The signature: the first 4 bytes on the wide side of the int.
            let sig = if wide && !little { b.get(at + 4..at + 8) } else { b.get(at..at + 4) };
            match sig {
                Some([0xF7, 0xF7, 0xF7, 0xF7]) => rows = int(at + 6 * w),
                Some([0xF6, 0xF6, 0xF6, 0xF6]) => columns = int(at + w),
                Some([0xFD, 0xFF, 0xFF, 0xFF] | [0xFF, 0xFF, 0xFF, 0xFD]) => texts.push(at),
                Some([0xFF, 0xFF, 0xFF, 0xFF]) => {
                    for c in 0..(len.saturating_sub(2 * w + 12) / 8).min(MAX_VARS) {
                        let e = at + w + 8 + c * 8;
                        if let (Some(t), Some(o), Some(l)) = (u16_at(e), u16_at(e + 2), u16_at(e + 4)) {
                            names.push((t, o, l));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    if let Some(r) = rows {
        cx.format_set("rows", r);
    }
    if let Some(c) = columns {
        cx.format_set("column_count", c);
    }
    // Name offsets count from the text subheader's signature end.
    let list: Vec<String> = names
        .iter()
        .filter_map(|&(t, o, l)| {
            let at = texts.get(t)? + w + o;
            Some(truncate_chars(&cstr(b.get(at..at + l)?), 100))
        })
        .filter(|n| !n.is_empty())
        .collect();
    if !list.is_empty() {
        cx.format_set("columns", list);
    }
}

// ------------------------------------------------------------- R
/// A reader for R's serialisation, XDR (big-endian) or ASCII (one word
/// per item, strings escaped), enough to walk data frames, vectors, lists
/// and pairlists.
struct RSer<'a> {
    b: &'a [u8],
    at: usize,
    steps: usize,
    ascii: bool,
    /// Native binary: the writer's byte order, taken as little-endian.
    little: bool,
    /// The last integer of the last vector read (compact row names).
    last: i32,
    /// The first double of the last vector read (ALTREP sequence lengths).
    first: f64,
    /// The reference table: symbols (by name) and environments.
    refs: Vec<Option<String>>,
}

/// What an object holds, for the report.
#[derive(Default)]
struct RObj {
    kind: &'static str,
    len: u64,
    /// The kind and length of the first element (lists, pairlists).
    first: Option<(&'static str, u64)>,
    names: Vec<String>,
    class: Vec<String>,
    rows: Option<u64>,
    columns: Vec<String>,
}

fn sexp_kind(t: u32) -> &'static str {
    match t {
        0 => "NULL",
        1 => "symbol",
        2 => "pairlist",
        3 => "closure",
        4 => "environment",
        5 => "promise",
        6 => "language",
        9 => "char",
        10 => "logical",
        13 => "integer",
        14 => "double",
        15 => "complex",
        16 => "character",
        19 => "list",
        20 => "expression",
        7 => "special",
        8 => "builtin",
        17 => "...",
        21 => "bytecode",
        22 => "externalptr",
        23 => "weakref",
        24 => "raw",
        25 => "S4",
        _ => "other",
    }
}

impl<'a> RSer<'a> {
    fn new(b: &'a [u8], ascii: bool, little: bool) -> Self {
        RSer { b, at: 0, steps: 0, ascii, little, last: 0, first: 0.0, refs: Vec::new() }
    }

    fn int(&mut self) -> Option<i32> {
        if self.ascii {
            let w = self.word()?;
            return if w == b"NA" { Some(i32::MIN) } else { std::str::from_utf8(w).ok()?.parse().ok() };
        }
        let r: [u8; 4] = self.b.get(self.at..self.at + 4)?.try_into().ok()?;
        self.at += 4;
        Some(if self.little { i32::from_le_bytes(r) } else { i32::from_be_bytes(r) })
    }

    /// The next whitespace-separated word (ASCII).
    fn word(&mut self) -> Option<&[u8]> {
        while self.b.get(self.at)?.is_ascii_whitespace() {
            self.at += 1;
        }
        let start = self.at;
        while self.b.get(self.at).is_some_and(|c| !c.is_ascii_whitespace()) {
            self.at += 1;
        }
        Some(&self.b[start..self.at])
    }

    /// Skip `n` vector items of `width` bytes (ASCII: `words` words each).
    fn items(&mut self, n: u64, width: u64, words: u64) -> Option<()> {
        if self.ascii {
            for i in 0..n.checked_mul(words)? {
                let w = self.word()?;
                if w.is_empty() {
                    return None;
                }
                let text = std::str::from_utf8(w).ok()?;
                if width == 4 {
                    self.last = if w == b"NA" { i32::MIN } else { text.parse().unwrap_or(0) };
                } else if width == 8 && i == 0 {
                    self.first = text.parse().unwrap_or(0.0);
                }
            }
            return Some(());
        }
        let start = self.at;
        self.skip(n.checked_mul(width)?)?;
        if width == 4 && n > 0 {
            let r: [u8; 4] = self.b.get(self.at - 4..self.at)?.try_into().ok()?;
            self.last = if self.little { i32::from_le_bytes(r) } else { i32::from_be_bytes(r) };
        } else if width == 8 && n > 0 {
            let r: [u8; 8] = self.b.get(start..start + 8)?.try_into().ok()?;
            self.first = if self.little { f64::from_le_bytes(r) } else { f64::from_be_bytes(r) };
        }
        Some(())
    }

    /// `n` string bytes: raw (XDR) or an escaped word (ASCII).
    fn string(&mut self, n: usize) -> Option<String> {
        if !self.ascii {
            let s = String::from_utf8_lossy(self.b.get(self.at..self.at + n)?).into_owned();
            self.at += n;
            return Some(s);
        }
        if n == 0 {
            return Some(String::new());
        }
        Some(unescape(self.word()?))
    }

    fn len(&mut self) -> Option<u64> {
        let n = self.int()?;
        if n == -1 {
            let hi = u64::try_from(self.int()?).ok()?;
            let lo = u64::from(self.int()?.cast_unsigned());
            return Some(hi << 32 | lo);
        }
        u64::try_from(n).ok()
    }

    fn skip(&mut self, n: u64) -> Option<()> {
        self.at = self.at.checked_add(usize::try_from(n).ok()?)?;
        (self.at <= self.b.len()).then_some(())
    }

    /// `Some(None)` is `NA`; `None` is a malformed stream.
    #[allow(clippy::option_option)]
    fn charsxp(&mut self) -> Option<Option<String>> {
        let _flags = self.int()?;
        let n = self.int()?;
        if n < 0 {
            return Some(None); // NA_STRING
        }
        self.string(usize::try_from(n).ok()?).map(Some)
    }

    /// Read (and mostly skip) one object; returns what it holds.
    #[allow(clippy::too_many_lines)] // one arm per serialised type
    fn object(&mut self, depth: usize) -> Option<RObj> {
        self.steps += 1;
        if depth > 64 || self.steps > 1_000_000 {
            return None;
        }
        let start = self.at;
        let mut flags = u32::try_from(self.int()?).ok()?;
        let t = flags & 0xff;
        let mut o = RObj { kind: sexp_kind(t), ..RObj::default() };
        let env = || Some(RObj { kind: "environment", ..RObj::default() });
        match t {
            255 => {
                let i = match flags >> 8 {
                    0 => usize::try_from(self.int()?).ok()?,
                    i => usize::try_from(i).ok()?,
                };
                return match self.refs.get(i.checked_sub(1)?)? {
                    Some(name) => Some(RObj { kind: "symbol", names: vec![name.clone()], ..RObj::default() }),
                    None => env(),
                };
            }
            254 => return Some(RObj { kind: "NULL", ..o }),
            253 | 250 | 242 | 241 => return env(), // global, base namespace, empty, base
            251 | 252 => return Some(RObj { kind: "symbol", ..o }), // missing argument, unbound value
            247..=249 => {
                // Persistent, package and namespace references: a string vector.
                self.int()?;
                let n = self.int()?;
                for _ in 0..n.clamp(0, 10_000) {
                    self.object(depth + 1)?;
                }
                self.refs.push(None);
                return env();
            }
            1 => {
                let name = self.object(depth + 1)?.names.into_iter().next().unwrap_or_default();
                self.refs.push(Some(name.clone()));
                o.names = vec![name];
                return Some(o);
            }
            9 => {
                self.at = start;
                o.names = self.charsxp()?.into_iter().collect();
                return Some(o);
            }
            4 => {
                // Locked flag, enclosure, frame, hash table, attributes.
                self.refs.push(None);
                self.int()?;
                for _ in 0..3 {
                    self.object(depth + 1)?;
                }
                self.attributes(&mut o, depth)?;
                return Some(o);
            }
            2 | 3 | 5 | 6 | 17 => {
                // Cells: [attributes] [tag] car, then the cdr (walked as a
                // loop: long calls and pairlists nest deeply).
                loop {
                    if flags & (1 << 9) != 0 {
                        self.attributes(&mut o, depth)?;
                    }
                    if flags & (1 << 10) != 0 {
                        self.object(depth + 1)?;
                    }
                    let car = self.object(depth + 1)?;
                    if o.first.is_none() {
                        o.first = Some((car.kind, car.len));
                    }
                    if car.kind == "symbol" && o.names.len() < 1000 {
                        o.names.extend(car.names.into_iter().take(1));
                    }
                    let cdr = self.at;
                    flags = u32::try_from(self.int()?).ok()?;
                    if !matches!(flags & 0xff, 2 | 6 | 17) {
                        self.at = cdr;
                        self.object(depth + 1)?;
                        return Some(o);
                    }
                    self.steps += 1;
                    if self.steps > 1_000_000 {
                        return None;
                    }
                }
            }
            7 | 8 => {
                let n = usize::try_from(self.int()?).ok()?;
                self.string(n)?;
            }
            10 | 13 => {
                let n = self.len()?;
                o.len = n;
                self.items(n, 4, 1)?;
            }
            14 => {
                let n = self.len()?;
                o.len = n;
                self.items(n, 8, 1)?;
            }
            15 => {
                let n = self.len()?;
                o.len = n;
                self.items(n, 16, 2)?;
            }
            24 => {
                let n = self.len()?;
                o.len = n;
                self.items(n, 1, 1)?;
            }
            16 => {
                let n = self.len()?;
                o.len = n;
                for i in 0..n {
                    let s = self.charsxp()?;
                    if i < 1000 {
                        o.names.push(s.unwrap_or_else(|| "NA".into()));
                    }
                }
            }
            19 | 20 => {
                let n = self.len()?;
                o.len = n;
                for _ in 0..n {
                    let c = self.object(depth + 1)?;
                    if o.first.is_none() {
                        o.first = Some((c.kind, c.len));
                    }
                    if o.columns.len() < 1000 {
                        o.columns.push(c.kind.to_string());
                    }
                }
            }
            21 => {
                self.int()?; // the shared-cell count
                self.bytecode(depth + 1)?;
            }
            22 => {
                // External pointer: protected value and tag.
                self.refs.push(None);
                self.object(depth + 1)?;
                self.object(depth + 1)?;
            }
            23 => self.refs.push(None),
            25 => {}
            238 => {
                // ALTREP: class information (class, package, type), state,
                // attributes.
                let info = self.object(depth + 1)?;
                let state = self.object(depth + 1)?;
                let class = info.names.first().map_or("", String::as_str);
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // a length stored as a double
                let seq = self.first.max(0.0) as u64;
                let wrapped = state.first.map_or(0, |(_, n)| n);
                (o.kind, o.len) = match class {
                    "compact_intseq" => ("integer", seq),
                    "compact_realseq" => ("double", seq),
                    "deferred_string" => ("character", wrapped),
                    c if c.starts_with("wrap_") => (state.first.map_or("other", |(k, _)| k), wrapped),
                    _ => ("other", 0),
                };
                self.attributes(&mut o, depth)?;
                return Some(o);
            }
            _ => return None,
        }
        if flags & (1 << 9) != 0 {
            self.attributes(&mut o, depth)?;
        }
        Some(o)
    }

    /// Byte code: the code vector and the constant pool.
    fn bytecode(&mut self, depth: usize) -> Option<()> {
        if depth > 64 {
            return None;
        }
        self.object(depth + 1)?;
        let n = self.int()?;
        for _ in 0..n.clamp(0, 100_000) {
            match self.int()? {
                21 => self.bytecode(depth + 1)?,
                t @ (2 | 6 | 239 | 240 | 243 | 244) => self.bc_lang(t, depth + 1)?,
                _ => {
                    self.object(depth + 1)?;
                }
            }
        }
        Some(())
    }

    /// A call or pairlist in byte code: shared cells (`BCREPDEF` /
    /// `BCREPREF`) and cells with attributes; the cdr is walked as a loop.
    fn bc_lang(&mut self, mut t: i32, depth: usize) -> Option<()> {
        if depth > 64 {
            return None;
        }
        loop {
            self.steps += 1;
            if self.steps > 1_000_000 {
                return None;
            }
            match t {
                243 => {
                    self.int()?;
                    return Some(());
                }
                2 | 6 | 239 | 240 | 244 => {
                    if t == 244 {
                        self.int()?;
                        t = self.int()?;
                    }
                    if t == 239 || t == 240 {
                        self.object(depth + 1)?;
                    }
                    self.object(depth + 1)?; // tag
                    let car = self.int()?;
                    self.bc_lang(car, depth + 1)?;
                    t = self.int()?;
                }
                _ => {
                    self.object(depth + 1)?;
                    return Some(());
                }
            }
        }
    }

    /// An attribute pairlist: names, class, row.names.
    fn attributes(&mut self, o: &mut RObj, depth: usize) -> Option<()> {
        loop {
            let flags = u32::try_from(self.int()?).ok()?;
            if flags & 0xff == 254 {
                return Some(());
            }
            if flags & 0xff != 2 {
                return None;
            }
            if flags & (1 << 9) != 0 {
                self.attributes(&mut RObj::default(), depth + 1)?;
            }
            // Tag: a symbol (or a reference to one).
            let tag = self.symbol()?;
            let v = self.object(depth + 1)?;
            match tag.as_deref() {
                Some("names") => o.names.clone_from(&v.names),
                Some("class") => o.class.clone_from(&v.names),
                Some("row.names") => o.rows = Some(if v.kind == "integer" && v.len == 2 { 0 } else { v.len }),
                _ => {}
            }
            if tag.as_deref() == Some("row.names") && v.kind == "integer" && v.len == 2 {
                // Compact row names c(NA, -n): re-read n.
                o.rows = Some(u64::from(self.last.unsigned_abs()));
            }
        }
    }

    /// A tag: `Some(name)`, or `Some(None)` for a symbol without one.
    #[allow(clippy::option_option)] // as `charsxp`
    fn symbol(&mut self) -> Option<Option<String>> {
        let o = self.object(1)?;
        (o.kind == "symbol").then(|| o.names.into_iter().next())
    }
}

/// The R version packed as major * 65536 + minor * 256 + patch.
fn r_version(v: i32) -> String {
    format!("{}.{}.{}", v / 65536, (v / 256) % 256, v % 256)
}

/// Decompress an R file (gzip, bzip2, xz or none).
fn r_payload(cx: &mut Context<'_>, b: &[u8]) -> Vec<u8> {
    let codec = match b {
        [0x1f, 0x8b, ..] => Some(Codec::Gzip),
        [b'B', b'Z', b'h', ..] => Some(Codec::Bzip2),
        [0xfd, b'7', b'z', b'X', b'Z', 0, ..] => Some(Codec::Xz),
        _ => None,
    };
    match codec {
        Some(c) => cx.decompress(b, c, cx.parse_limit()).map(|d| d.data).unwrap_or_default(),
        None => b.to_vec(),
    }
}

fn describe(o: &RObj) -> String {
    let class = if o.class.is_empty() { o.kind.to_string() } else { o.class.join("/") };
    match (o.rows, o.columns.len()) {
        (Some(r), c) if c > 0 => format!("{class} ({r} rows, {c} columns)"),
        _ if o.len > 0 => format!("{class} [{}]", o.len),
        _ => class,
    }
}

/// An R ASCII string: `\\n`-style escapes and `\\ooo` octal.
#[allow(clippy::many_single_char_names)] // bytes of an escape
fn unescape(w: &[u8]) -> String {
    let mut out = Vec::with_capacity(w.len());
    let mut i = 0;
    while let Some(&c) = w.get(i) {
        i += 1;
        if c != b'\\' {
            out.push(c);
            continue;
        }
        let Some(&e) = w.get(i) else { break };
        i += 1;
        out.push(match e {
            b'n' => b'\n',
            b't' => b'\t',
            b'v' => 0x0b,
            b'b' => 0x08,
            b'r' => b'\r',
            b'f' => 0x0c,
            b'a' => 0x07,
            b'0'..=b'7' => {
                let mut v = u32::from(e - b'0');
                for _ in 0..2 {
                    match w.get(i) {
                        Some(&d @ b'0'..=b'7') => {
                            v = v * 8 + u32::from(d - b'0');
                            i += 1;
                        }
                        _ => break,
                    }
                }
                u8::try_from(v).unwrap_or(b'?')
            }
            other => other,
        });
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn r_header(cx: &mut Context<'_>, s: &mut RSer<'_>) -> Option<()> {
    let version = s.int()?;
    let writer = s.int()?;
    let _min = s.int()?;
    cx.format_set("serialization_version", version);
    cx.format_set("written_by_r", r_version(writer));
    if version == 3 {
        let n = usize::try_from(s.int()?).ok()?;
        let enc = s.string(n)?;
        cx.format_set("native_encoding", truncate_chars(&enc, 30));
    }
    Some(())
}

fn rds(cx: &mut Context<'_>, b: &[u8]) -> Option<()> {
    let p = r_payload(cx, b);
    cx.format_set(
        "compression",
        match b.first() {
            Some(0x1f) => "gzip",
            Some(b'B') => "bzip2",
            Some(0xfd) => "xz",
            _ => "none",
        },
    );
    let (fmt, body) = match p.get(..2)? {
        b"X\n" => ("xdr", &p[2..]),
        b"A\n" => ("ascii", &p[2..]),
        b"B\n" => ("native", &p[2..]),
        _ => return None,
    };
    cx.format_set("serialization", fmt);
    let mut s = RSer::new(body, fmt == "ascii", fmt == "native");
    r_header(cx, &mut s)?;
    if let Some(o) = s.object(0) {
        cx.format_set("object", describe(&o));
        if o.rows.is_some() && !o.names.is_empty() {
            let cols: Map<String, Value> = o
                .names
                .iter()
                .zip(&o.columns)
                .take(MAX_VARS)
                .map(|(n, k)| (truncate_chars(n, 100), Value::String((*k).clone())))
                .collect();
            cx.format_set("columns", Value::Object(cols));
        } else if !o.names.is_empty() {
            cx.format_set("names", o.names.iter().take(200).map(|n| truncate_chars(n, 100)).collect::<Vec<_>>());
        }
    }
    Some(())
}

fn rdata(cx: &mut Context<'_>, b: &[u8]) -> Option<()> {
    let p = r_payload(cx, b);
    // RDX: XDR, RDA: ASCII, RDB: native binary.
    let (kind, body) = p.get(..7).zip(p.get(7..))?;
    let (ascii, little) = match (&kind[..3], &kind[4..]) {
        (b"RDX", b"\nX\n") => (false, false),
        (b"RDA", b"\nA\n") => (true, false),
        (b"RDB", b"\nB\n") => (false, true),
        _ => return None,
    };
    cx.format_set("workspace_version", if kind[3] == b'3' { 3 } else { 2 });
    cx.format_set(
        "serialization",
        if ascii {
            "ascii"
        } else if little {
            "native"
        } else {
            "xdr"
        },
    );
    let mut s = RSer::new(body, ascii, little);
    r_header(cx, &mut s)?;
    // A pairlist of (symbol → object).
    let mut objects: BTreeMap<String, String> = BTreeMap::new();
    while let Some(flags) = s.int().and_then(|f| u32::try_from(f).ok()) {
        if flags & 0xff != 2 || objects.len() >= MAX_VARS {
            break;
        }
        if flags & (1 << 9) != 0 && s.attributes(&mut RObj::default(), 0).is_none() {
            break;
        }
        let Some(Some(name)) = s.symbol() else { break };
        let Some(o) = s.object(0) else {
            objects.insert(name, "?".into());
            break;
        };
        objects.insert(name, describe(&o));
    }
    cx.format_set("object_count", objects.len());
    cx.format_set(
        "objects",
        Value::Object(objects.into_iter().map(|(k, v)| (truncate_chars(&k, 100), Value::String(v))).collect()),
    );
    Some(())
}

impl Extractor for Stats {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.windows(8).take(600).any(|w| w == b"SPSSPORT") && probe.extension == Some("por") {
            return Some(Sniff { format: "por", confidence: 0.98 });
        }
        if probe.extension == Some("dta") && matches!(h.first(), Some(113..=115)) && matches!(h.get(1), Some(1 | 2)) {
            return Some(Sniff { format: "dta", confidence: 0.9 });
        }
        // R files are usually compressed: the extension and a serialisation inside.
        let compressed = h.starts_with(&[0x1f, 0x8b]) || h.starts_with(b"BZh") || h.starts_with(b"\xfd7zXZ\0");
        match probe.extension {
            Some("rds") if compressed || h.starts_with(b"X\n") || h.starts_with(b"A\n") || h.starts_with(b"B\n") => {
                Some(Sniff { format: "rds", confidence: 0.98 })
            }
            Some("rdata" | "rda") if compressed => Some(Sniff { format: "rdata", confidence: 0.98 }),
            _ if [b"RDX2\nX\n", b"RDX3\nX\n", b"RDA2\nA\n", b"RDA3\nA\n", b"RDB2\nB\n", b"RDB3\nB\n"]
                .iter()
                .any(|m| h.starts_with(*m)) =>
            {
                Some(Sniff { format: "rdata", confidence: 0.98 })
            }
            _ => None,
        }
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, _) = cx.read_bytes(src)?;
        let id = cx.format_id().to_string();
        let ok = match id.as_str() {
            "sav" => sav(cx, &b),
            "por" => por(cx, &b),
            "dta" => dta(cx, &b),
            "xpt" => xpt(cx, &b),
            "sas7bdat" => sas7bdat(cx, &b),
            "rds" => rds(cx, &b),
            _ => rdata(cx, &b),
        };
        ok.ok_or_else(|| ExtractError::malformed(format!("{id} header")))
    }
}

crate::register_extractor!(Stats);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r_ascii_strings() {
        assert_eq!(unescape(br"Saltmere\040harbour\n"), "Saltmere harbour\n");
        assert_eq!(unescape(br#"a\"b\\c"#), "a\"b\\c");
        assert_eq!(unescape(br"\303\251"), "é");
    }

    #[test]
    fn r_versions() {
        assert_eq!(r_version(263_170), "4.4.2");
        assert_eq!(sexp_kind(19), "list");
    }

    crate::fixture_tests!("sav", "por", "dta", "xpt", "sas7bdat", "rds", "rdata");
}
