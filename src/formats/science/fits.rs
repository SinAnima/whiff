//! FITS files (FITS 4.0): every header-data unit (primary, image, ASCII
//! and binary tables, tile-compressed images) with its type, dimensions,
//! table columns and rows, the observation keywords of the primary header
//! (telescope, instrument, object, observer, dates, exposure, filter), the
//! world coordinate system, and the `CHECKSUM` / `DATASUM` values verified.
//!
//! Specification: IAU FITS Working Group, "Definition of the Flexible Image
//! Transport System (FITS)", version 4.0 (2018) §3–§7, §10 (tiled image
//! compression), Appendix J (checksums); WCS Papers I–II.

use serde_json::{Map, Value};

use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, parse_date,
    redact_sensitive, truncate_chars,
};

/// Extractor for FITS files.
pub struct Fits;

static META: ExtractorMeta = ExtractorMeta {
    id: "science.fits",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "fits",
        name: "FITS",
        family: "sci",
        mimes: &["application/fits", "image/fits"],
        extensions: &["fits", "fit", "fts", "fz"],
        magic: &[Magic::at(0, b"SIMPLE  =")],
        parent: None,
    }],
};

const BLOCK: u64 = 2880;
/// HDUs listed.
const MAX_HDUS: usize = 1000;
/// Header blocks read per HDU.
const MAX_HEADER_BLOCKS: u64 = 1000;
/// Bytes verified per HDU against its checksums.
const MAX_VERIFY: u64 = 64 << 20;

/// A header: (keyword, value) in order.
type Header = Vec<(String, Value)>;

/// One card's value: string, logical, integer or float.
fn card_value(s: &str) -> Value {
    let s = s.trim_start();
    if let Some(rest) = s.strip_prefix('\'') {
        let mut out = String::new();
        let mut chars = rest.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\'' {
                if chars.peek() == Some(&'\'') {
                    out.push('\'');
                    chars.next();
                } else {
                    break;
                }
            } else {
                out.push(c);
            }
        }
        return Value::String(out.trim_end().to_string());
    }
    let v = s.split('/').next().unwrap_or("").trim();
    match v {
        "T" => Value::Bool(true),
        "F" => Value::Bool(false),
        "" => Value::Null,
        _ => v
            .parse::<i64>()
            .map(Value::from)
            .or_else(|_| v.replace('D', "E").parse::<f64>().map(super::number))
            .unwrap_or_else(|_| Value::String(v.to_string())),
    }
}

/// Parse header blocks into cards; `None` until END is seen.
fn cards(b: &[u8], header: &mut Header) -> bool {
    for card in b.chunks(80) {
        let text = String::from_utf8_lossy(card);
        let key = text.get(..8).unwrap_or("").trim_end().to_string();
        if key == "END" {
            return true;
        }
        if text.get(8..10) == Some("= ") {
            let v = card_value(text.get(10..).unwrap_or(""));
            header.push((key, v));
        } else if key == "CONTINUE"
            && let Some((_, Value::String(prev))) = header.last_mut()
            && let Value::String(more) = card_value(text.get(8..).unwrap_or(""))
        {
            // Long strings: a trailing `&` continues on the next card.
            if let Some(p) = prev.strip_suffix('&') {
                *prev = format!("{p}{more}");
            }
        }
    }
    false
}

fn get<'a>(h: &'a Header, k: &str) -> Option<&'a Value> {
    h.iter().find(|(n, _)| n == k).map(|(_, v)| v)
}

fn int(h: &Header, k: &str) -> i64 {
    get(h, k).and_then(Value::as_i64).unwrap_or(0)
}

fn text(h: &Header, k: &str) -> Option<String> {
    get(h, k).and_then(Value::as_str).map(str::to_string).filter(|s| !s.is_empty())
}

/// The data size of an HDU in bytes (before padding).
fn data_bytes(h: &Header) -> u64 {
    let naxis = int(h, "NAXIS");
    if naxis <= 0 {
        return 0;
    }
    let mut n: u64 = 1;
    for i in 1..=naxis.min(999) {
        n = n.saturating_mul(u64::try_from(int(h, &format!("NAXIS{i}"))).unwrap_or(0));
    }
    let bits = int(h, "BITPIX").unsigned_abs() / 8;
    let gcount = u64::try_from(get(h, "GCOUNT").and_then(Value::as_i64).unwrap_or(1)).unwrap_or(1);
    let pcount = u64::try_from(int(h, "PCOUNT")).unwrap_or(0);
    bits.saturating_mul(gcount).saturating_mul(pcount.saturating_add(n))
}

/// The ones' complement sum of 32-bit big-endian words (Appendix J).
fn checksum(sum: &mut u64, b: &[u8]) {
    for w in b.chunks(4) {
        let mut x = [0u8; 4];
        x[..w.len()].copy_from_slice(w);
        *sum += u64::from(u32::from_be_bytes(x));
    }
}

/// `DATASUM`: an unsigned integer written as a string, often space-padded.
fn datasum(h: &Header) -> Option<u64> {
    match get(h, "DATASUM")? {
        Value::String(s) => s.trim().parse().ok(),
        v => v.as_u64(),
    }
}

fn fold(mut sum: u64) -> u32 {
    while sum >> 32 != 0 {
        sum = (sum & 0xffff_ffff) + (sum >> 32);
    }
    u32::try_from(sum).unwrap_or(0)
}

fn dims(h: &Header, prefix: &str) -> String {
    let n = int(h, &format!("{prefix}NAXIS"));
    (1..=n.clamp(0, 999)).map(|i| int(h, &format!("{prefix}NAXIS{i}")).to_string()).collect::<Vec<_>>().join("x")
}

fn bitpix(b: i64) -> &'static str {
    match b {
        8 => "uint8",
        16 => "int16",
        32 => "int32",
        64 => "int64",
        -32 => "float32",
        -64 => "float64",
        _ => "?",
    }
}

/// Observation keywords reported from the primary header.
const OBSERVATION: [(&str, &str); 12] = [
    ("TELESCOP", "telescope"),
    ("INSTRUME", "instrument"),
    ("OBJECT", "object"),
    ("OBSERVER", "observer"),
    ("ORIGIN", "origin"),
    ("DATE-OBS", "date_obs"),
    ("DATE", "date"),
    ("EXPTIME", "exposure_s"),
    ("FILTER", "filter"),
    ("EQUINOX", "equinox"),
    ("RADESYS", "radesys"),
    ("BUNIT", "unit"),
];

#[allow(clippy::too_many_lines)] // one HDU summary, keyword by keyword
fn hdu(cx: &mut Context<'_>, h: &Header, index: usize, verified: Option<(bool, bool)>, observed: &mut bool) -> Value {
    let mut m = Map::new();
    let ext = text(h, "XTENSION");
    let compressed = get(h, "ZIMAGE") == Some(&Value::Bool(true));
    let kind = match ext.as_deref() {
        None => "primary",
        Some("BINTABLE") if compressed => "compressed image",
        Some("BINTABLE") => "binary table",
        Some("TABLE") => "ascii table",
        Some("IMAGE") => "image",
        Some(_) => "other",
    };
    m.insert("index".into(), index.into());
    m.insert("type".into(), kind.into());
    if let Some(n) = text(h, "EXTNAME") {
        m.insert("name".into(), truncate_chars(&n, 100).into());
    }
    if compressed {
        m.insert("dimensions".into(), dims(h, "Z").into());
        m.insert("data_type".into(), bitpix(int(h, "ZBITPIX")).into());
        if let Some(c) = text(h, "ZCMPTYPE") {
            m.insert("compression".into(), c.into());
        }
    } else if kind.ends_with("table") {
        m.insert("rows".into(), int(h, "NAXIS2").into());
        let n = int(h, "TFIELDS").clamp(0, 999);
        let cols: Map<String, Value> = (1..=n)
            .map(|i| {
                let name = text(h, &format!("TTYPE{i}")).unwrap_or_else(|| format!("col{i}"));
                let form = text(h, &format!("TFORM{i}")).unwrap_or_default();
                let unit = text(h, &format!("TUNIT{i}"));
                let desc = unit.map_or_else(|| form.clone(), |u| format!("{form} [{u}]"));
                (truncate_chars(&name, 100), Value::String(desc))
            })
            .take(500)
            .collect();
        m.insert("columns".into(), Value::Object(cols));
    } else if int(h, "NAXIS") > 0 {
        m.insert("dimensions".into(), dims(h, "").into());
        m.insert("data_type".into(), bitpix(int(h, "BITPIX")).into());
    }
    if let Some((header_ok, data_ok)) = verified {
        if get(h, "CHECKSUM").is_some() {
            m.insert("checksum".into(), if header_ok { "valid" } else { "invalid" }.into());
        }
        if get(h, "DATASUM").is_some() {
            m.insert("datasum".into(), if data_ok { "valid" } else { "invalid" }.into());
        }
    }
    if index == 0 && get(h, "SIMPLE") == Some(&Value::Bool(false)) {
        // `SIMPLE = F`: the writer says the file does not conform to the standard.
        m.insert("conforms".into(), false.into());
    }
    if index == 0 || kind == "image" || compressed {
        // The world coordinate system.
        let naxis = int(h, if compressed { "ZNAXIS" } else { "NAXIS" }).clamp(0, 9);
        let ctype: Vec<String> = (1..=naxis).filter_map(|i| text(h, &format!("CTYPE{i}"))).collect();
        if !ctype.is_empty() {
            let mut w = Map::new();
            w.insert("ctype".into(), ctype.into());
            let crval: Vec<Value> = (1..=naxis).filter_map(|i| get(h, &format!("CRVAL{i}")).cloned()).collect();
            w.insert("crval".into(), crval.into());
            if let Some(r) = text(h, "RADESYS") {
                w.insert("radesys".into(), r.into());
            }
            m.insert("wcs".into(), Value::Object(w));
        }
    }
    // The observation keywords: the primary header's, or (tile-compressed
    // files, whose primary is empty) the first header that has them.
    if !*observed && OBSERVATION.iter().any(|(k, _)| get(h, k).is_some() && *k != "DATE") {
        *observed = true;
        for (k, out) in OBSERVATION {
            if let Some(v) = get(h, k) {
                let v = match v {
                    Value::String(s) => Value::String(truncate_chars(&redact_sensitive(s), 200)),
                    other => other.clone(),
                };
                cx.format_set(out, v);
            }
        }
        if let Some(o) = text(h, "OBJECT") {
            cx.content().source("fits.OBJECT").title(truncate_chars(&o, 200));
        }
        if let Some(o) = text(h, "OBSERVER") {
            cx.content().source("fits.OBSERVER").author(truncate_chars(&o, 200));
        }
        if let Some((t, tz)) = text(h, "DATE-OBS").and_then(|d| parse_date(&d)) {
            cx.temporal().source("fits.DATE-OBS").content_date(DateField::Captured, t, tz);
        }
        if let Some((t, tz)) = text(h, "DATE").and_then(|d| parse_date(&d)) {
            cx.temporal().source("fits.DATE").content_date(DateField::Created, t, tz);
        }
    }
    Value::Object(m)
}

impl Extractor for Fits {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let mut at = 0u64;
        let mut hdus = Vec::new();
        let (mut checked, mut bad) = (0u64, 0u64);
        let mut observed = false;
        while at + BLOCK <= len && hdus.len() < MAX_HDUS {
            cx.checkpoint()?;
            let start = at;
            let mut header = Header::new();
            let mut raw = Vec::new();
            let mut done = false;
            for _ in 0..MAX_HEADER_BLOCKS {
                if at + BLOCK > len {
                    break;
                }
                let b = src.read_vec(at, 2880).map_err(|_| ExtractError::malformed("header block"))?;
                at += BLOCK;
                // Every header starts with SIMPLE or XTENSION.
                if raw.is_empty() && !(b.starts_with(b"SIMPLE  =") || b.starts_with(b"XTENSION=")) {
                    break;
                }
                done = cards(&b, &mut header);
                raw.extend_from_slice(&b);
                if done {
                    break;
                }
            }
            if !done {
                if hdus.is_empty() {
                    return Err(ExtractError::malformed("no END card"));
                }
                cx.warn(format!("bytes after HDU {} are not a FITS extension", hdus.len() - 1));
                at = start;
                break;
            }
            let size = data_bytes(&header);
            let padded = size.div_ceil(BLOCK) * BLOCK;
            // Verify CHECKSUM (header + data sum to -0) and DATASUM (data sum).
            let wants = get(&header, "CHECKSUM").is_some() || get(&header, "DATASUM").is_some();
            let verified = if wants && padded <= MAX_VERIFY && at + padded <= len {
                let data = src.read_vec(at, usize::try_from(padded).unwrap_or(0)).unwrap_or_default();
                let mut d = 0u64;
                checksum(&mut d, &data);
                let mut hsum = 0u64;
                checksum(&mut hsum, &raw);
                let data_ok = datasum(&header) == Some(u64::from(fold(d)));
                let header_ok = fold(hsum + u64::from(fold(d))) == u32::MAX;
                checked += 1;
                if !(header_ok && data_ok) {
                    bad += 1;
                }
                Some((header_ok, data_ok))
            } else {
                None
            };
            let v = hdu(cx, &header, hdus.len(), verified, &mut observed);
            hdus.push(v);
            at += padded;
        }
        cx.format_set("hdus", hdus.len());
        cx.format_set("hdu_list", hdus);
        if checked > 0 {
            cx.format_set("checksums_verified", checked);
            if bad > 0 {
                cx.format_set("checksums_failed", bad);
                cx.warn(format!("{bad} HDU checksum(s) do not match: the file was changed or damaged"));
            }
        }
        if at < len {
            cx.format_set("trailing_bytes", len - at);
        }
        Ok(())
    }
}

crate::register_extractor!(Fits);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_values() {
        assert_eq!(card_value(" 'O''Neil '  / name"), Value::from("O'Neil"));
        assert_eq!(card_value("                    T / simple"), Value::Bool(true));
        assert_eq!(card_value("                  -32"), Value::from(-32));
        assert_eq!(card_value("            1.5D2"), Value::from(150.0));
        assert_eq!(fold(0x1_0000_0001), 2);
        // Found by the oracle: DATASUM written as a space-padded string.
        let h: Header = vec![("DATASUM".into(), card_value(" '         0'         / data unit checksum"))];
        assert_eq!(datasum(&h), Some(0));
    }

    crate::fixture_tests!("fits");
}
