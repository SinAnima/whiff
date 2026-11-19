//! IPTC Information Interchange Model (IIM) datasets, records 1 and 2, into
//! `metadata.iptc` under the IIM names (`ObjectName`, `Keywords`, `By-line`,
//! `Caption-Abstract`, `CopyrightNotice`, …). Repeatable datasets are
//! arrays. Text is UTF-8 when `1:90` says so (or is valid UTF-8), Latin-1
//! otherwise.
//!
//! Specification: IPTC IIM 4.2.

use serde_json::{Map, Value, json};

use super::text_value;
use crate::plugin::{BlockDecoder, BlockKind, ByteReader, Context, ExtractError, TextRole};

/// Decoder for IPTC IIM blocks.
pub struct Iptc;

/// `(record, dataset, name, repeatable)`.
const DATASETS: &[(u8, u8, &str, bool)] = &[
    (1, 0, "EnvelopeRecordVersion", false),
    (1, 5, "Destination", true),
    (1, 20, "FileFormat", false),
    (1, 30, "ServiceIdentifier", false),
    (1, 40, "EnvelopeNumber", false),
    (1, 60, "EnvelopePriority", false),
    (1, 70, "DateSent", false),
    (1, 80, "TimeSent", false),
    (1, 90, "CodedCharacterSet", false),
    (1, 100, "UniqueObjectName", false),
    (2, 0, "ApplicationRecordVersion", false),
    (2, 3, "ObjectTypeReference", false),
    (2, 4, "ObjectAttributeReference", true),
    (2, 5, "ObjectName", false),
    (2, 7, "EditStatus", false),
    (2, 10, "Urgency", false),
    (2, 12, "SubjectReference", true),
    (2, 15, "Category", false),
    (2, 20, "SupplementalCategories", true),
    (2, 22, "FixtureIdentifier", false),
    (2, 25, "Keywords", true),
    (2, 26, "ContentLocationCode", true),
    (2, 27, "ContentLocationName", true),
    (2, 30, "ReleaseDate", false),
    (2, 35, "ReleaseTime", false),
    (2, 37, "ExpirationDate", false),
    (2, 38, "ExpirationTime", false),
    (2, 40, "SpecialInstructions", false),
    (2, 42, "ActionAdvised", false),
    (2, 45, "ReferenceService", true),
    (2, 47, "ReferenceDate", true),
    (2, 50, "ReferenceNumber", true),
    (2, 55, "DateCreated", false),
    (2, 60, "TimeCreated", false),
    (2, 62, "DigitalCreationDate", false),
    (2, 63, "DigitalCreationTime", false),
    (2, 65, "OriginatingProgram", false),
    (2, 70, "ProgramVersion", false),
    (2, 75, "ObjectCycle", false),
    (2, 80, "By-line", true),
    (2, 85, "By-lineTitle", true),
    (2, 90, "City", false),
    (2, 92, "Sub-location", false),
    (2, 95, "Province-State", false),
    (2, 100, "Country-PrimaryLocationCode", false),
    (2, 101, "Country-PrimaryLocationName", false),
    (2, 103, "OriginalTransmissionReference", false),
    (2, 105, "Headline", false),
    (2, 110, "Credit", false),
    (2, 115, "Source", false),
    (2, 116, "CopyrightNotice", false),
    (2, 118, "Contact", true),
    (2, 120, "Caption-Abstract", false),
    (2, 121, "LocalCaption", false),
    (2, 122, "Writer-Editor", true),
    (2, 130, "ImageType", false),
    (2, 131, "ImageOrientation", false),
    (2, 135, "LanguageIdentifier", false),
];

/// Datasets beyond this many are ignored.
const MAX_DATASETS: usize = 10_000;

impl BlockDecoder for Iptc {
    fn kind(&self) -> BlockKind {
        BlockKind::IPTC_IIM
    }

    fn id(&self) -> &'static str {
        "meta.iptc"
    }

    fn decode(&self, data: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let raw = datasets(data)?;
        if raw.is_empty() {
            return Err(ExtractError::malformed("no IIM datasets"));
        }
        // ESC % G declares UTF-8.
        let utf8 = raw.iter().any(|(r, d, v)| *r == 1 && *d == 90 && v.windows(3).any(|w| w == b"\x1b%G"));
        let mut map = Map::new();
        for (record, dataset, value) in raw {
            if record != 1 && record != 2 {
                continue;
            }
            let info = DATASETS.iter().find(|(r, d, ..)| *r == record && *d == dataset);
            let (name, repeatable) = match info {
                Some((_, _, n, rep)) => ((*n).to_string(), *rep),
                None => (format!("{record}:{dataset}"), false),
            };
            let v = match (record, dataset) {
                (1, 90) => json!(if utf8 { "UTF-8" } else { "other" }),
                (1 | 2, 0) if value.len() == 2 => json!(u16::from_be_bytes([value[0], value[1]])),
                _ => text_value(&decode_text(&value, utf8)),
            };
            if repeatable {
                let e = map.entry(name).or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(a) = e
                    && a.len() < super::MAX_ARRAY * 4
                {
                    a.push(v);
                }
            } else {
                map.entry(name).or_insert(v);
            }
        }
        for (k, role) in
            [("ObjectName", TextRole::Title), ("Headline", TextRole::Title), ("Caption-Abstract", TextRole::Caption)]
        {
            if let Some(s) = map.get(k).and_then(Value::as_str) {
                cx.emit_text(role, s);
            }
        }
        let target = cx.metadata("iptc");
        for (k, v) in map {
            target.entry(k).or_insert(v);
        }
        Ok(())
    }
}

crate::register_block_decoder!(Iptc);

/// `(record, dataset, value)` triples. Bytes before the first tag marker
/// (padding) are skipped; anything malformed ends the list.
pub fn datasets(data: &[u8]) -> Result<Vec<(u8, u8, Vec<u8>)>, ExtractError> {
    let start = data.iter().position(|&b| b == 0x1c).ok_or_else(|| ExtractError::malformed("no IIM tag marker"))?;
    let mut r = ByteReader::new(&data[start..]);
    let mut out = Vec::new();
    while !r.is_empty() && out.len() < MAX_DATASETS {
        if r.peek(1) != Some(&[0x1c]) {
            break;
        }
        r.advance(1)?;
        let record = r.u8()?;
        let dataset = r.u8()?;
        let len = r.be_u16()?;
        let len = if len & 0x8000 != 0 {
            // Extended dataset: the low bits give the size of the length field.
            let n = usize::from(len & 0x7fff);
            if n == 0 || n > 4 {
                return Err(ExtractError::malformed("IIM extended length"));
            }
            r.bytes(n)?.iter().fold(0usize, |acc, &b| (acc << 8) | usize::from(b))
        } else {
            usize::from(len)
        };
        let Ok(value) = r.bytes(len) else { break };
        out.push((record, dataset, value.to_vec()));
    }
    Ok(out)
}

fn decode_text(b: &[u8], utf8: bool) -> String {
    if utf8 { String::from_utf8_lossy(b).into_owned() } else { super::latin1_or_utf8(b) }
}

/// IIM `CCYYMMDD` + `HHMMSS±HHMM` → RFC 3339 / civil date-time.
pub fn date(m: &Map<String, Value>, date_key: &str, time_key: &str) -> Option<(String, bool)> {
    let d = m.get(date_key)?.as_str()?;
    if d.len() != 8 || !d.bytes().all(|b| b.is_ascii_digit()) || d == "00000000" {
        return None;
    }
    let day = format!("{}-{}-{}", &d[..4], &d[4..6], &d[6..8]);
    let Some(t) = m.get(time_key).and_then(Value::as_str).filter(|t| t.len() >= 6 && t.is_ascii()) else {
        return crate::text::parse_date(&day);
    };
    let clock = format!("{}:{}:{}", &t[..2], &t[2..4], &t[4..6]);
    let zone =
        t.get(6..11).filter(|z| z.starts_with('+') || z.starts_with('-')).map(|z| format!("{}:{}", &z[..3], &z[3..]));
    match zone {
        Some(z) => crate::text::parse_date(&format!("{day}T{clock}{z}")),
        None => crate::text::parse_date(&format!("{day}T{clock}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dataset(r: u8, d: u8, v: &[u8]) -> Vec<u8> {
        let mut out = vec![0x1c, r, d];
        out.extend_from_slice(&u16::try_from(v.len()).unwrap().to_be_bytes());
        out.extend_from_slice(v);
        out
    }

    fn sample() -> Vec<u8> {
        let mut data = dataset(1, 90, b"\x1b%G");
        data.extend(dataset(2, 5, "Harbour at dusk".as_bytes()));
        data.extend(dataset(2, 25, b"harbour"));
        data.extend(dataset(2, 25, b"boats"));
        data.extend(dataset(2, 55, b"20260914"));
        data.extend(dataset(2, 60, b"170322+0200"));
        data.extend(dataset(2, 116, "© Ada".as_bytes()));
        data
    }

    #[test]
    fn parses_datasets() {
        let raw = datasets(&sample()).unwrap();
        let ids: Vec<(u8, u8)> = raw.iter().map(|(r, d, _)| (*r, *d)).collect();
        assert_eq!(ids, [(1, 90), (2, 5), (2, 25), (2, 25), (2, 55), (2, 60), (2, 116)]);
        assert_eq!(raw[1].2, b"Harbour at dusk");
        assert_eq!(raw[6].2, "© Ada".as_bytes());
        // A tag marker with no room for the rest of the dataset header.
        assert!(matches!(datasets(b"\x1c\x02"), Err(ExtractError::Truncated { .. })));
        // A value cut short ends the list after the datasets before it.
        let mut cut = dataset(2, 5, b"Quay");
        cut.extend_from_slice(&dataset(2, 25, b"harbour")[..6]);
        assert_eq!(datasets(&cut).unwrap(), [(2, 5, b"Quay".to_vec())]);
    }

    #[test]
    fn decodes_names_values_and_dates_from_a_jpeg() {
        // JPEG: SOI, APP13 holding a Photoshop resource 0x0404, SOF0 8×8, EOI.
        let iptc = sample();
        let mut irb = b"Photoshop 3.0\0".to_vec();
        irb.extend_from_slice(b"8BIM\x04\x04\0\0");
        irb.extend_from_slice(&u32::try_from(iptc.len()).unwrap().to_be_bytes());
        irb.extend_from_slice(&iptc);
        if iptc.len() % 2 == 1 {
            irb.push(0);
        }
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xED];
        jpeg.extend_from_slice(&u16::try_from(irb.len() + 2).unwrap().to_be_bytes());
        jpeg.extend_from_slice(&irb);
        jpeg.extend_from_slice(&[0xFF, 0xC0, 0, 11, 8, 0, 8, 0, 8, 1, 1, 0x11, 0, 0xFF, 0xD9]);
        let report = crate::plugin::testing::report_for("dusk.jpg", &jpeg);
        let m = &report.metadata["iptc"];
        assert_eq!(m["ObjectName"], json!("Harbour at dusk"));
        assert_eq!(m["Keywords"], json!(["harbour", "boats"]));
        assert_eq!(m["CopyrightNotice"], json!("© Ada"));
        assert_eq!(m["CodedCharacterSet"], json!("UTF-8"));
        let map = m.as_object().unwrap();
        assert_eq!(date(map, "DateCreated", "TimeCreated"), Some(("2026-09-14T17:03:22+02:00".into(), true)));
    }
}
