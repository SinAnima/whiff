//! DICOM files (Part 10): the meta header (transfer syntax,
//! implementation), the SOP class, modality, manufacturer and model,
//! study and series descriptions, dates, body part, image geometry
//! (rows, columns, frames, bits, photometric interpretation, pixel
//! spacing, slice thickness) and the software versions.
//!
//! Patient-identifying attributes (name, ID, birth date, age, sex,
//! institution, referring physician, accession number) are listed by
//! name only; their values are reported only with privacy off.
//!
//! Specification: DICOM PS3.10 (file format), PS3.5 (data structures and
//! encoding: VRs, transfer syntaxes), PS3.6 (data dictionary), PS3.15
//! Annex E (basic de-identification profile, for the identifying set).

use std::fmt::Write as _;

use serde_json::{Map, Value};

use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, truncate_chars,
};

/// Extractor for DICOM files.
pub struct Dicom;

static META: ExtractorMeta = ExtractorMeta {
    id: "medical.dicom",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "dicom",
        name: "DICOM",
        family: "medical",
        mimes: &["application/dicom"],
        extensions: &["dcm", "dicom", "dic"],
        magic: &[Magic::at(128, b"DICM")],
        parent: None,
    }],
};

/// VRs with a reserved field and a 32-bit length (explicit VR).
const LONG: [&[u8; 2]; 13] =
    [b"OB", b"OD", b"OF", b"OL", b"OV", b"OW", b"SQ", b"SV", b"UC", b"UN", b"UR", b"UT", b"UV"];

/// Attributes reported: (tag, key, identifying).
const TAGS: [(u32, &str, bool); 32] = [
    (0x0008_0016, "sop_class", false),
    (0x0008_0020, "study_date", false),
    (0x0008_0021, "series_date", false),
    (0x0008_0022, "acquisition_date", false),
    (0x0008_0030, "study_time", false),
    (0x0008_0050, "accession_number", true),
    (0x0008_0060, "modality", false),
    (0x0008_0070, "manufacturer", false),
    (0x0008_0080, "institution", true),
    (0x0008_0090, "referring_physician", true),
    (0x0008_1030, "study_description", false),
    (0x0008_103E, "series_description", false),
    (0x0008_1090, "model", false),
    (0x0010_0010, "patient_name", true),
    (0x0010_0020, "patient_id", true),
    (0x0010_0030, "patient_birth_date", true),
    (0x0010_0040, "patient_sex", true),
    (0x0010_1010, "patient_age", true),
    (0x0018_0015, "body_part", false),
    (0x0018_0050, "slice_thickness_mm", false),
    (0x0018_0087, "magnetic_field_tesla", false),
    (0x0018_1020, "software_versions", false),
    (0x0020_0011, "series_number", false),
    (0x0020_0013, "instance_number", false),
    (0x0028_0002, "samples_per_pixel", false),
    (0x0028_0004, "photometric", false),
    (0x0028_0008, "frames", false),
    (0x0028_0010, "rows", false),
    (0x0028_0011, "columns", false),
    (0x0028_0030, "pixel_spacing_mm", false),
    (0x0028_0100, "bits_allocated", false),
    (0x0028_0101, "bits_stored", false),
];

fn sop_name(uid: &str) -> Option<&'static str> {
    Some(match uid {
        "1.2.840.10008.5.1.4.1.1.1" => "CR Image Storage",
        "1.2.840.10008.5.1.4.1.1.1.1" => "Digital X-Ray Image Storage",
        "1.2.840.10008.5.1.4.1.1.1.2" => "Digital Mammography X-Ray Image Storage",
        "1.2.840.10008.5.1.4.1.1.2" => "CT Image Storage",
        "1.2.840.10008.5.1.4.1.1.2.1" => "Enhanced CT Image Storage",
        "1.2.840.10008.5.1.4.1.1.3.1" => "Ultrasound Multi-frame Image Storage",
        "1.2.840.10008.5.1.4.1.1.4" => "MR Image Storage",
        "1.2.840.10008.5.1.4.1.1.4.1" => "Enhanced MR Image Storage",
        "1.2.840.10008.5.1.4.1.1.6.1" => "Ultrasound Image Storage",
        "1.2.840.10008.5.1.4.1.1.7" => "Secondary Capture Image Storage",
        "1.2.840.10008.5.1.4.1.1.12.1" => "X-Ray Angiographic Image Storage",
        "1.2.840.10008.5.1.4.1.1.20" => "Nuclear Medicine Image Storage",
        "1.2.840.10008.5.1.4.1.1.128" => "PET Image Storage",
        "1.2.840.10008.5.1.4.1.1.481.1" => "RT Image Storage",
        "1.2.840.10008.5.1.4.1.1.481.2" => "RT Dose Storage",
        "1.2.840.10008.5.1.4.1.1.481.3" => "RT Structure Set Storage",
        "1.2.840.10008.5.1.4.1.1.88.11" => "Basic Text SR Storage",
        "1.2.840.10008.5.1.4.1.1.104.1" => "Encapsulated PDF Storage",
        "1.2.840.10008.5.1.4.1.1.77.1.6" => "VL Whole Slide Microscopy Image Storage",
        "1.2.840.10008.1.3.10" => "Media Storage Directory Storage",
        _ => return None,
    })
}

fn syntax_name(uid: &str) -> Option<&'static str> {
    Some(match uid {
        "1.2.840.10008.1.2" => "Implicit VR Little Endian",
        "1.2.840.10008.1.2.1" => "Explicit VR Little Endian",
        "1.2.840.10008.1.2.1.99" => "Deflated Explicit VR Little Endian",
        "1.2.840.10008.1.2.2" => "Explicit VR Big Endian",
        "1.2.840.10008.1.2.4.50" => "JPEG Baseline",
        "1.2.840.10008.1.2.4.57" | "1.2.840.10008.1.2.4.70" => "JPEG Lossless",
        "1.2.840.10008.1.2.4.80" => "JPEG-LS Lossless",
        "1.2.840.10008.1.2.4.81" => "JPEG-LS Near-lossless",
        "1.2.840.10008.1.2.4.90" => "JPEG 2000 Lossless",
        "1.2.840.10008.1.2.4.91" => "JPEG 2000",
        "1.2.840.10008.1.2.4.201" => "HTJ2K Lossless",
        "1.2.840.10008.1.2.5" => "RLE Lossless",
        _ => return None,
    })
}

/// A dataset reader: explicit or implicit VR, little or big endian.
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
    explicit: bool,
    big: bool,
}

impl Reader<'_> {
    fn u16(&self, at: usize) -> Option<u16> {
        let r = [*self.b.get(at)?, *self.b.get(at + 1)?];
        Some(if self.big { u16::from_be_bytes(r) } else { u16::from_le_bytes(r) })
    }

    fn u32(&self, at: usize) -> Option<u32> {
        let r: [u8; 4] = self.b.get(at..at + 4)?.try_into().ok()?;
        Some(if self.big { u32::from_be_bytes(r) } else { u32::from_le_bytes(r) })
    }

    /// The next element: (tag, VR, value); `None` at the end. Sequences and
    /// items of undefined length are skipped to their delimiters.
    fn next(&mut self) -> Option<(u32, [u8; 2], &[u8])> {
        let group = self.u16(self.at)?;
        let elem = self.u16(self.at + 2)?;
        let tag = u32::from(group) << 16 | u32::from(elem);
        let (vr, len, head) = if self.explicit && group != 0xFFFE {
            let vr: [u8; 2] = self.b.get(self.at + 4..self.at + 6)?.try_into().ok()?;
            if LONG.contains(&&vr) {
                (vr, self.u32(self.at + 8)?, 12)
            } else {
                (vr, u32::from(self.u16(self.at + 6)?), 8)
            }
        } else {
            (*b"??", self.u32(self.at + 4)?, 8)
        };
        let start = self.at + head;
        if len == 0xFFFF_FFFF {
            // Undefined length: skip to the matching sequence delimiter.
            self.at = start;
            self.skip_undefined(0)?;
            return Some((tag, vr, &[]));
        }
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        let v = self.b.get(start..end.min(self.b.len()))?;
        self.at = end;
        Some((tag, vr, v))
    }

    fn skip_undefined(&mut self, depth: usize) -> Option<()> {
        if depth > 32 {
            return None;
        }
        loop {
            let group = self.u16(self.at)?;
            let elem = self.u16(self.at + 2)?;
            let len = self.u32(self.at + 4)?;
            match (group, elem) {
                (0xFFFE, 0xE0DD) => {
                    self.at += 8;
                    return Some(());
                }
                (0xFFFE, 0xE000) if len == 0xFFFF_FFFF => {
                    self.at += 8;
                    // An item of undefined length: elements until the item delimiter.
                    loop {
                        if self.u16(self.at)? == 0xFFFE && self.u16(self.at + 2)? == 0xE00D {
                            self.at += 8;
                            break;
                        }
                        self.next()?;
                    }
                }
                (0xFFFE, _) => self.at += 8 + usize::try_from(len).ok()?,
                _ => {
                    self.next()?;
                }
            }
        }
    }
}

fn text(v: &[u8]) -> String {
    String::from_utf8_lossy(v).trim_matches(['\0', ' ']).to_string()
}

fn value(vr: [u8; 2], v: &[u8], big: bool, tag: u32) -> Value {
    let us = |v: &[u8]| {
        v.get(..2).map(|s| if big { u16::from_be_bytes([s[0], s[1]]) } else { u16::from_le_bytes([s[0], s[1]]) })
    };
    // US attributes (implicit VR has none): rows, columns, bits, samples.
    let numeric = matches!(tag, 0x0028_0002 | 0x0028_0010 | 0x0028_0011 | 0x0028_0100 | 0x0028_0101);
    if &vr == b"US" || (numeric && &vr == b"??") {
        return us(v).map_or(Value::Null, Value::from);
    }
    let s = text(v);
    // Numbers only for numeric VRs (or, implicit VR, numeric attributes):
    // dates, times and UIDs are digits too.
    let numeric_tag = matches!(tag, 0x0018_0050 | 0x0018_0087 | 0x0020_0011 | 0x0020_0013 | 0x0028_0008);
    let numeric = matches!(&vr, b"IS" | b"DS") || (&vr == b"??" && numeric_tag);
    if numeric && !s.contains('\\') {
        if let Ok(n) = s.parse::<i64>() {
            return n.into();
        }
        if let Ok(f) = s.parse::<f64>() {
            return super::number(f);
        }
    }
    Value::String(truncate_chars(&s, 300))
}

fn date(d: &str, t: Option<&str>) -> Option<String> {
    let d = d.trim();
    if d.len() != 8 || !d.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut s = format!("{}-{}-{}", &d[..4], &d[4..6], &d[6..8]);
    if let Some(t) = t.map(str::trim).filter(|t| t.len() >= 6 && t.as_bytes()[..6].iter().all(u8::is_ascii_digit)) {
        let _ = write!(s, "T{}:{}:{}", &t[..2], &t[2..4], &t[4..6]);
    }
    Some(s)
}

impl Extractor for Dicom {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    #[allow(clippy::too_many_lines)] // meta header, then the dataset
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (raw, _) = cx.read_bytes(src)?;
        // The meta group: explicit VR little endian after the preamble.
        let mut meta = Reader { b: &raw, at: 132, explicit: true, big: false };
        let mut syntax = String::new();
        while meta.u16(meta.at) == Some(0x0002) {
            let Some((tag, _, v)) = meta.next() else { break };
            match tag {
                0x0002_0010 => syntax = text(v),
                0x0002_0012 => cx.format_set("implementation_uid", truncate_chars(&text(v), 64)),
                0x0002_0013 => cx.format_set("implementation", truncate_chars(&text(v), 64)),
                0x0002_0016 => cx.format_set("source_application", truncate_chars(&text(v), 64)),
                _ => {}
            }
        }
        cx.format_set("transfer_syntax", syntax_name(&syntax).map_or_else(|| syntax.clone(), str::to_string));
        let start = meta.at;
        let inflated;
        let (b, at) = if syntax == "1.2.840.10008.1.2.1.99" {
            inflated = cx
                .inflate_prefix(
                    raw.get(start..).unwrap_or_default(),
                    crate::plugin::Compression::Deflate,
                    cx.parse_limit(),
                )
                .unwrap_or_default();
            (&inflated[..], 0)
        } else {
            (&raw[..], start)
        };
        let mut r = Reader { b, at, explicit: syntax != "1.2.840.10008.1.2", big: syntax == "1.2.840.10008.1.2.2" };
        // Some writers encode the dataset in implicit VR whatever the syntax
        // says: no VR letters in the first element.
        if r.explicit
            && !b.get(at + 4..at + 6).is_some_and(|v| v.iter().all(u8::is_ascii_uppercase))
            && b.len() > at + 8
        {
            r.explicit = false;
            cx.warn("the dataset is implicit VR, not the transfer syntax's explicit VR");
        }
        let big = r.big;
        let mut found: Map<String, Value> = Map::new();
        let mut identifying = Vec::new();
        let mut elements = 0u64;
        while let Some((tag, vr, v)) = r.next() {
            elements += 1;
            if tag == 0x7FE0_0010 {
                found.insert("pixel_data_bytes".into(), Value::from(v.len()));
                break;
            }
            if elements > 1_000_000 {
                break;
            }
            let Some(&(_, key, ident)) = TAGS.iter().find(|(t, _, _)| *t == tag) else { continue };
            let val = value(vr, v, big, tag);
            if ident {
                identifying.push(key);
                if cx.privacy_strict() {
                    continue;
                }
            }
            found.insert(key.into(), val);
        }
        cx.format_set("elements_read", elements);
        if let Some(uid) = found.get("sop_class").and_then(Value::as_str).map(str::to_string) {
            cx.format_set("sop_class_uid", truncate_chars(&uid, 64));
            if let Some(n) = sop_name(&uid) {
                found.insert("sop_class".into(), n.into());
            }
        }
        let get = |k: &str| {
            found.get(k).and_then(|v| v.as_str().map(str::to_string).or_else(|| v.as_i64().map(|n| n.to_string())))
        };
        if let Some(d) = get("study_date").and_then(|d| date(&d, get("study_time").as_deref())) {
            cx.temporal().source("dicom.StudyDate").content_date(DateField::Captured, d, false);
        }
        if let Some(d) = get("acquisition_date").and_then(|d| date(&d, None)) {
            cx.temporal().source("dicom.AcquisitionDate").content_date(DateField::Created, d, false);
        }
        if let Some(t) = get("study_description").or_else(|| get("series_description")) {
            cx.content().source("dicom.StudyDescription").title(truncate_chars(&t, 200));
        }
        let rows = found.get("rows").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok());
        let cols = found.get("columns").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok());
        if let (Some(rw), Some(c)) = (rows, cols) {
            let mut img = cx.physical().image(c, rw);
            if let Some(bits) = found.get("bits_stored").and_then(Value::as_u64).and_then(|n| u8::try_from(n).ok()) {
                img.bit_depth(bits);
            }
            if let Some(p) = found.get("photometric").and_then(Value::as_str) {
                img.color_space(p.to_string());
            }
        }
        for (k, v) in found {
            cx.format_set(&k, v);
        }
        if !identifying.is_empty() {
            cx.format_set("identifying_attributes", identifying);
            if cx.privacy_strict() {
                cx.format_set("identifying_values", "withheld (privacy)");
            }
        }
        Ok(())
    }
}

crate::register_extractor!(Dicom);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dicom_values() {
        assert_eq!(date("20250901", Some("061200")).as_deref(), Some("2025-09-01T06:12:00"));
        // Not digits (fuzz): the time is dropped, not sliced mid-character.
        assert_eq!(date("20250901", Some("06\u{fffd}00")).as_deref(), Some("2025-09-01"));
        assert_eq!(sop_name("1.2.840.10008.5.1.4.1.1.2"), Some("CT Image Storage"));
        assert_eq!(value(*b"US", &[16, 0], false, 0x0028_0010), Value::from(16));
        assert_eq!(value(*b"DS", b"5 ", false, 0x0018_0050), Value::from(5));
        assert_eq!(value(*b"DA", b"20250901", false, 0x0008_0020), Value::from("20250901"));
    }

    crate::fixture_tests!("dicom");
}
