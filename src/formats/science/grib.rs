//! GRIB editions 1 and 2 (meteorological fields) and CERN ROOT files:
//! * GRIB: the messages (walked through the source), editions, the
//!   originating centres, reference times, parameters (discipline,
//!   category and number, with names for the common ones) and grids;
//! * ROOT: the format version, compression, creation and modification
//!   times, and the keys of the top directory (name, class, title).
//!
//! Specifications: WMO Manual on Codes, FM 92 GRIB edition 1 and 2 (code
//! tables 0, 4.2); ROOT "File Format" (TFile, TDirectory, TKey).

#![allow(clippy::many_single_char_names)] // section field offsets

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, truncate_chars,
};

/// Extractor for GRIB and ROOT files.
pub struct Fields;

static META: ExtractorMeta = ExtractorMeta {
    id: "science.fields",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "grib",
            name: "GRIB 1/2",
            family: "sci",
            mimes: &["application/x-grib"],
            extensions: &["grb", "grib", "grb2", "grib2", "grib1"],
            magic: &[Magic::at(0, b"GRIB")],
            parent: None,
        },
        FormatSpec {
            id: "root",
            name: "ROOT (CERN)",
            family: "sci",
            mimes: &[],
            extensions: &["root"],
            magic: &[Magic::at(0, b"root")],
            parent: None,
        },
    ],
};

/// Messages walked.
const MAX_MESSAGES: u64 = 1_000_000;

fn centre(c: u16) -> String {
    match c {
        7 => "NCEP".into(),
        34 => "JMA".into(),
        54 => "CMC".into(),
        74 => "UK Met Office".into(),
        78 => "DWD".into(),
        80 => "CNMC Rome".into(),
        85 => "Météo-France".into(),
        98 => "ECMWF".into(),
        _ => format!("centre {c}"),
    }
}

/// GRIB 2 parameter names (discipline, category, number), WMO table 4.2.
fn parameter(d: u8, c: u8, n: u8) -> String {
    let name = match (d, c, n) {
        (0, 0, 0) => "temperature",
        (0, 0, 6) => "dew point temperature",
        (0, 1, 1) => "relative humidity",
        (0, 1, 8) => "total precipitation",
        (0, 2, 2) => "u wind",
        (0, 2, 3) => "v wind",
        (0, 3, 0) => "pressure",
        (0, 3, 1) => "mean sea level pressure",
        (0, 3, 5) => "geopotential height",
        (0, 6, 1) => "total cloud cover",
        (10, 0, 3) => "significant wave height",
        (10, 3, 0) => "sea surface temperature",
        _ => return format!("{d}.{c}.{n}"),
    };
    name.to_string()
}

/// GRIB 1 parameter names (WMO table 2).
fn parameter1(p: u8) -> String {
    match p {
        2 => "mean sea level pressure".into(),
        7 => "geopotential height".into(),
        11 => "temperature".into(),
        33 => "u wind".into(),
        34 => "v wind".into(),
        52 => "relative humidity".into(),
        61 => "total precipitation".into(),
        167 => "2 metre temperature".into(),
        _ => format!("parameter {p}"),
    }
}

fn be(b: &[u8], at: usize, n: usize) -> Option<u64> {
    Some(b.get(at..at + n)?.iter().fold(0u64, |a, &x| a << 8 | u64::from(x)))
}

#[allow(clippy::too_many_lines)] // the edition 1 and edition 2 sections
fn grib(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let len = src.len();
    let mut at = 0u64;
    let mut messages = 0u64;
    let (mut editions, mut centres, mut params, mut grids) =
        (BTreeSet::new(), BTreeSet::new(), BTreeMap::<String, u64>::new(), BTreeSet::new());
    let (mut first, mut last): (Option<String>, Option<String>) = (None, None);
    while at.checked_add(16).is_some_and(|e| e <= len) && messages < MAX_MESSAGES {
        if messages.is_multiple_of(1024) {
            cx.checkpoint()?;
        }
        let h = src.read_vec(at, 16).map_err(|_| ExtractError::malformed("indicator"))?;
        if &h[..4] != b"GRIB" {
            break;
        }
        let edition = h[7];
        let size = if edition == 2 { be(&h, 8, 8).unwrap_or(0) } else { be(&h, 4, 3).unwrap_or(0) };
        if size < 16 || at.checked_add(size).is_none_or(|e| e > len) {
            cx.warn("last message truncated");
            break;
        }
        editions.insert(edition);
        let b = src
            .read_vec(at, usize::try_from(size.min(1 << 20)).unwrap_or(0))
            .map_err(|_| ExtractError::malformed("message"))?;
        let time = if edition == 2 {
            // Section 1 (identification), then sections 3 (grid) and 4 (product).
            let mut s = 16;
            let mut t = None;
            let discipline = h[6];
            while s + 5 <= b.len() {
                let n = usize::try_from(be(&b, s, 4).unwrap_or(0)).unwrap_or(0);
                if n < 5 {
                    break;
                }
                match b[s + 4] {
                    1 => {
                        centres.insert(centre(u16::try_from(be(&b, s + 5, 2).unwrap_or(0)).unwrap_or(0)));
                        t = Some(format!(
                            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                            be(&b, s + 12, 2).unwrap_or(0),
                            b.get(s + 14).copied().unwrap_or(0),
                            b.get(s + 15).copied().unwrap_or(0),
                            b.get(s + 16).copied().unwrap_or(0),
                            b.get(s + 17).copied().unwrap_or(0),
                            b.get(s + 18).copied().unwrap_or(0)
                        ));
                    }
                    3 => {
                        let template = be(&b, s + 12, 2).unwrap_or(0);
                        if template == 0 {
                            grids.insert(format!(
                                "lat-lon {}x{}",
                                be(&b, s + 30, 4).unwrap_or(0),
                                be(&b, s + 34, 4).unwrap_or(0)
                            ));
                        } else {
                            grids.insert(format!("template 3.{template}"));
                        }
                    }
                    4 => {
                        let (c, p) = (b.get(s + 9).copied().unwrap_or(0), b.get(s + 10).copied().unwrap_or(0));
                        *params.entry(parameter(discipline, c, p)).or_default() += 1;
                    }
                    _ => {}
                }
                s += n;
            }
            t
        } else {
            // GRIB 1: the PDS follows the 8-byte indicator.
            let p = 8;
            centres.insert(centre(u16::from(b.get(p + 4).copied().unwrap_or(0))));
            *params.entry(parameter1(b.get(p + 8).copied().unwrap_or(0))).or_default() += 1;
            let century = u64::from(b.get(p + 24).copied().unwrap_or(21));
            let yy = u64::from(b.get(p + 12).copied().unwrap_or(0));
            let year = century.saturating_sub(1) * 100 + yy;
            Some(format!(
                "{year:04}-{:02}-{:02}T{:02}:{:02}:00Z",
                b.get(p + 13).copied().unwrap_or(0),
                b.get(p + 14).copied().unwrap_or(0),
                b.get(p + 15).copied().unwrap_or(0),
                b.get(p + 16).copied().unwrap_or(0)
            ))
        };
        if let Some(t) = time {
            if first.as_ref().is_none_or(|f| &t < f) {
                first = Some(t.clone());
            }
            if last.as_ref().is_none_or(|l| &t > l) {
                last = Some(t);
            }
        }
        messages += 1;
        at += size;
    }
    cx.format_set("messages", messages);
    cx.format_set("editions", editions.into_iter().collect::<Vec<_>>());
    cx.format_set("centres", centres.into_iter().collect::<Vec<_>>());
    cx.format_set(
        "parameters",
        Value::Object(params.into_iter().take(200).map(|(k, v)| (k, v.into())).collect::<Map<_, _>>()),
    );
    if !grids.is_empty() {
        cx.format_set("grids", grids.into_iter().take(50).collect::<Vec<_>>());
    }
    if let Some(f) = first {
        cx.format_set("first_reference_time", f.clone());
        cx.temporal().source("grib.reference_time").content_date(DateField::Created, f, true);
    }
    if let Some(l) = last {
        cx.format_set("last_reference_time", l);
    }
    Ok(())
}

/// A ROOT `TDatime` (packed local date and time).
fn datime(d: u32) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        (d >> 26) + 1995,
        (d >> 22) & 0xf,
        (d >> 17) & 0x1f,
        (d >> 12) & 0x1f,
        (d >> 6) & 0x3f,
        d & 0x3f
    )
}

fn pstring(b: &[u8], at: &mut usize) -> Option<String> {
    let mut n = usize::from(*b.get(*at)?);
    *at += 1;
    if n == 255 {
        n = usize::try_from(be(b, *at, 4)?).ok()?;
        *at += 4;
    }
    let s = String::from_utf8_lossy(b.get(*at..*at + n)?).into_owned();
    *at += n;
    Some(s)
}

/// A `TKey` header at the start of `b`: (key length, class, name, title).
fn tkey(b: &[u8]) -> Option<(usize, String, String, String, u32)> {
    let version = be(b, 4, 2)?;
    let datime = u32::try_from(be(b, 10, 4)?).ok()?;
    let keylen = usize::try_from(be(b, 14, 2)?).ok()?;
    let mut at = 18 + if version > 1000 { 16 } else { 8 };
    let class = pstring(b, &mut at)?;
    let name = pstring(b, &mut at)?;
    let title = pstring(b, &mut at)?;
    Some((keylen, class, name, title, datime))
}

fn root(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("ROOT header");
    let h = src.read_vec(0, 64.min(usize::try_from(src.len()).unwrap_or(0))).map_err(|_| bad())?;
    let version = u32::try_from(be(&h, 4, 4).ok_or_else(bad)?).map_err(|_| bad())?;
    let big = version > 1_000_000;
    let v = version % 1_000_000;
    cx.format_set("root_version", format!("{}.{:02}/{:02}", v / 10000, (v / 100) % 100, v % 100));
    let begin = be(&h, 8, 4).ok_or_else(bad)?;
    // fCompress follows fEND, fSeekFree, fNbytesFree, nfree, fNbytesName, fUnits.
    let compress_at = if big { 41 } else { 33 };
    let nbytes_name = be(&h, if big { 36 } else { 28 }, 4).ok_or_else(bad)?;
    if let Some(c) = be(&h, compress_at, 4) {
        let (alg, level) = (c / 100, c % 100);
        let name = match alg {
            0 if level == 0 => "none",
            0 | 1 => "zlib",
            2 => "lzma",
            4 => "lz4",
            5 => "zstd",
            _ => "other",
        };
        cx.format_set("compression", format!("{name} level {level}"));
    }
    // The top directory: its key at fBEGIN, the file's name and title, then
    // the TDirectory record (fNbytesName bytes after fBEGIN).
    let k = src.read_vec(begin, 512).map_err(|_| bad())?;
    let (_, _, _, title, created) = tkey(&k).ok_or_else(bad)?;
    if !title.is_empty() {
        cx.format_set("title", truncate_chars(&title, 200));
    }
    cx.format_set("created", datime(created));
    let d = src.read_vec(begin + nbytes_name, 64).map_err(|_| bad())?;
    let d = d.as_slice();
    let dver = be(d, 0, 2).ok_or_else(bad)?;
    let mtime = u32::try_from(be(d, 6, 4).ok_or_else(bad)?).map_err(|_| bad())?;
    cx.format_set("modified", datime(mtime));
    // fSeekDir, fSeekParent, then fSeekKeys (64-bit from version 1000).
    let seek_keys = if dver > 1000 { be(d, 34, 8) } else { be(d, 26, 4) }.ok_or_else(bad)?;
    // The keys list: a TKey header, the count, then the keys.
    let list = src
        .read_vec(seek_keys, usize::try_from((src.len() - seek_keys.min(src.len())).min(4 << 20)).unwrap_or(0))
        .map_err(|_| bad())?;
    let (lk, ..) = tkey(&list).ok_or_else(bad)?;
    let n = be(&list, lk, 4).ok_or_else(bad)?;
    let mut at = lk + 4;
    let mut keys = Map::new();
    let mut classes: BTreeMap<String, u64> = BTreeMap::new();
    for _ in 0..n.min(100_000) {
        let Some((len, class, name, title, _)) = list.get(at..).and_then(tkey) else { break };
        *classes.entry(truncate_chars(&class, 100)).or_default() += 1;
        if keys.len() < 500 {
            let v = if title.is_empty() { class } else { format!("{class}: {title}") };
            keys.insert(truncate_chars(&name, 200), Value::String(truncate_chars(&v, 300)));
        }
        if len == 0 {
            break;
        }
        at += len;
    }
    cx.format_set("key_count", n);
    cx.format_set("keys", Value::Object(keys));
    cx.format_set("classes", Value::Object(classes.into_iter().map(|(k, v)| (k, v.into())).collect()));
    Ok(())
}

impl Extractor for Fields {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "grib" { grib(cx, src) } else { root(cx, src) }
    }
}

crate::register_extractor!(Fields);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(parameter(0, 0, 0), "temperature");
        assert_eq!(parameter(0, 9, 9), "0.9.9");
        assert_eq!(centre(98), "ECMWF");
        // 2025-09-01 06:12:00 packed.
        let d = (30 << 26) | (9 << 22) | (1 << 17) | (6 << 12) | (12 << 6);
        assert_eq!(datime(d), "2025-09-01T06:12:00");
    }

    crate::fixture_tests!("grib", "root");
}
