//! Medical image volumes:
//! * NIfTI-1 and NIfTI-2 (`.nii`, `.hdr` + `.img`): dimensions, voxel
//!   sizes and units, data type, time step, the description, intent and
//!   the qform / sform coordinate frames;
//! * Analyze 7.5 headers: dimensions, voxel sizes, data type,
//!   description;
//! * NRRD: type, dimension, sizes, space, spacings, kinds, encoding,
//!   endianness, content, data file;
//! * MetaImage (`.mha`, `.mhd`): object type, dimensions, element type and
//!   spacing, orientation, compression, the data file.
//!
//! Specifications: NIfTI-1 (`nifti1.h`, 2004) and NIfTI-2 (2011);
//! Mayo Clinic Analyze 7.5; Teem "NRRD file format" 5; ITK MetaIO.

#![allow(clippy::many_single_char_names)] // header field offsets

use serde_json::{Map, Value};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, truncate_chars,
};

/// Extractor for medical image volumes.
pub struct Volumes;

static META: ExtractorMeta = ExtractorMeta {
    id: "medical.volumes",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "nifti",
            name: "NIfTI-1 / NIfTI-2",
            family: "medical",
            mimes: &[],
            extensions: &["nii"],
            magic: &[Magic::at(344, b"n+1\0"), Magic::at(4, b"n+2\0\r\n\x1a\n")],
            parent: None,
        },
        FormatSpec {
            id: "analyze",
            name: "Analyze 7.5",
            family: "medical",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "nrrd",
            name: "NRRD volume",
            family: "medical",
            mimes: &[],
            extensions: &["nrrd", "nhdr"],
            magic: &[Magic::at(0, b"NRRD000")],
            parent: None,
        },
        FormatSpec {
            id: "metaimage",
            name: "MetaImage",
            family: "medical",
            mimes: &[],
            extensions: &["mha", "mhd"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

fn datatype(t: i64) -> &'static str {
    match t {
        2 => "uint8",
        4 => "int16",
        8 => "int32",
        16 => "float32",
        32 => "complex64",
        64 => "float64",
        128 => "rgb24",
        256 => "int8",
        512 => "uint16",
        768 => "uint32",
        1024 => "int64",
        1280 => "uint64",
        1536 => "float128",
        1792 => "complex128",
        2304 => "rgba32",
        _ => "unknown",
    }
}

fn xform(code: i64) -> &'static str {
    match code {
        0 => "unknown",
        1 => "scanner",
        2 => "aligned",
        3 => "talairach",
        4 => "mni_152",
        5 => "template",
        _ => "other",
    }
}

fn space_unit(u: u8) -> &'static str {
    match u & 0x07 {
        1 => "m",
        2 => "mm",
        3 => "µm",
        _ => "unknown",
    }
}

fn time_unit(u: u8) -> &'static str {
    match u & 0x38 {
        8 => "s",
        16 => "ms",
        24 => "µs",
        32 => "Hz",
        40 => "ppm",
        48 => "rad/s",
        _ => "unknown",
    }
}

/// A header reader in the file's byte order.
struct H<'a> {
    b: &'a [u8],
    big: bool,
}

impl H<'_> {
    fn i16(&self, at: usize) -> Option<i64> {
        let r = [*self.b.get(at)?, *self.b.get(at + 1)?];
        Some(i64::from(if self.big { i16::from_be_bytes(r) } else { i16::from_le_bytes(r) }))
    }

    fn i32(&self, at: usize) -> Option<i64> {
        let r: [u8; 4] = self.b.get(at..at + 4)?.try_into().ok()?;
        Some(i64::from(if self.big { i32::from_be_bytes(r) } else { i32::from_le_bytes(r) }))
    }

    fn i64(&self, at: usize) -> Option<i64> {
        let r: [u8; 8] = self.b.get(at..at + 8)?.try_into().ok()?;
        Some(if self.big { i64::from_be_bytes(r) } else { i64::from_le_bytes(r) })
    }

    fn f32(&self, at: usize) -> Option<f64> {
        let r: [u8; 4] = self.b.get(at..at + 4)?.try_into().ok()?;
        Some(f64::from(if self.big { f32::from_be_bytes(r) } else { f32::from_le_bytes(r) }))
    }

    fn f64(&self, at: usize) -> Option<f64> {
        let r: [u8; 8] = self.b.get(at..at + 8)?.try_into().ok()?;
        Some(if self.big { f64::from_be_bytes(r) } else { f64::from_le_bytes(r) })
    }

    fn text(&self, at: usize, n: usize) -> String {
        String::from_utf8_lossy(self.b.get(at..at + n).unwrap_or_default()).trim_matches(['\0', ' ']).to_string()
    }
}

fn round(v: f64) -> Value {
    super::number((v * 10_000.0).round() / 10_000.0)
}

/// NIfTI-1 / Analyze (348-byte header) or NIfTI-2 (540).
fn nifti(cx: &mut Context<'_>, b: &[u8], analyze: bool) -> Option<()> {
    let le = i32::from_le_bytes(b.get(..4)?.try_into().ok()?);
    let (size, big) =
        if le == 348 || le == 540 { (le, false) } else { (i32::from_be_bytes(b.get(..4)?.try_into().ok()?), true) };
    let h = H { b, big };
    let v2 = size == 540;
    cx.format_set("byte_order", if big { "big-endian" } else { "little-endian" });
    let (ndim, dims, pixdim): (i64, Vec<i64>, Vec<f64>) = if v2 {
        let n = h.i64(16)?;
        let d = (1..=n.clamp(0, 7)).filter_map(|i| h.i64(16 + 8 * usize::try_from(i).ok()?)).collect();
        let p = (1..=n.clamp(0, 7)).filter_map(|i| h.f64(104 + 8 * usize::try_from(i).ok()?)).collect();
        (n, d, p)
    } else {
        let n = h.i16(40)?;
        let d = (1..=n.clamp(0, 7)).filter_map(|i| h.i16(40 + 2 * usize::try_from(i).ok()?)).collect();
        let p = (1..=n.clamp(0, 7)).filter_map(|i| h.f32(76 + 4 * usize::try_from(i).ok()?)).collect();
        (n, d, p)
    };
    if !analyze {
        cx.format_set("nifti_version", if v2 { 2 } else { 1 });
        let magic = if v2 { h.text(4, 4) } else { h.text(344, 4) };
        cx.format_set("storage", if magic.starts_with("n+") { "single file" } else { "header and image pair" });
    }
    cx.format_set("dimensions", ndim);
    cx.format_set("shape", dims.iter().map(i64::to_string).collect::<Vec<_>>().join("x"));
    let dt = if v2 { h.i16(12)? } else { h.i16(70)? };
    cx.format_set("datatype", datatype(dt));
    let units = if v2 { u8::try_from(h.i32(500)? & 0xff).ok()? } else { *b.get(123)? };
    let space = space_unit(units);
    let spacing: Vec<Value> = pixdim.iter().take(3).map(|&p| round(p)).collect();
    cx.format_set("voxel_size", spacing);
    if !analyze {
        cx.format_set("spatial_unit", space);
        if ndim >= 4
            && let Some(step) = pixdim.get(3)
        {
            cx.format_set("time_step", round(*step));
            cx.format_set("time_unit", time_unit(units));
        }
        let (intent, q, s) =
            if v2 { (h.i32(504)?, h.i32(344)?, h.i32(348)?) } else { (h.i16(68)?, h.i16(252)?, h.i16(254)?) };
        if intent != 0 {
            cx.format_set("intent_code", intent);
        }
        cx.format_set("qform", xform(q));
        cx.format_set("sform", xform(s));
    }
    let descrip = if v2 { h.text(240, 80) } else { h.text(148, 80) };
    if !descrip.is_empty() {
        cx.format_set("description", truncate_chars(&descrip, 80));
        cx.content().source("nifti.descrip").description(truncate_chars(&descrip, 80));
    }
    if analyze {
        let db = h.text(4, 18);
        if !db.is_empty() {
            cx.format_set("db_name", truncate_chars(&db, 18));
        }
    }
    let (Some(&w), Some(&hh)) = (dims.first(), dims.get(1)) else { return Some(()) };
    if let (Ok(w), Ok(hh)) = (u32::try_from(w), u32::try_from(hh)) {
        cx.physical().image(w, hh);
    }
    Some(())
}

/// `key: value` (NRRD) or `key = value` (MetaImage) header lines.
fn header_fields(text: &str, sep: &str) -> Vec<(String, String)> {
    text.lines()
        .take_while(|l| !l.trim().is_empty())
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once(sep).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .take(1000)
        .collect()
}

fn nrrd(cx: &mut Context<'_>, text: &str) {
    if let Some(v) = text.lines().next().and_then(|l| l.strip_prefix("NRRD")) {
        cx.format_set("nrrd_version", v.trim().trim_start_matches('0'));
    }
    for (k, v) in header_fields(&text[text.find('\n').map_or(0, |i| i + 1)..], ":") {
        let key = match k.as_str() {
            "type" | "dimension" | "sizes" | "space" | "space directions" | "spacings" | "kinds" | "encoding"
            | "endian" | "content" | "space origin" | "space units" | "data file" | "datafile"
            | "measurement frame" => k.replace(' ', "_").replace("datafile", "data_file"),
            _ => continue,
        };
        cx.format_set(&key, truncate_chars(&v, 300));
        if key == "content" {
            cx.content().source("nrrd.content").description(truncate_chars(&v, 300));
        }
    }
}

fn metaimage(cx: &mut Context<'_>, text: &str) {
    let mut m = Map::new();
    for (k, v) in header_fields(text, "=") {
        let key = match k.as_str() {
            "ObjectType" => "object_type",
            "NDims" => "dimensions",
            "DimSize" => "shape",
            "ElementType" => "element_type",
            "ElementSpacing" | "ElementSize" => "element_spacing",
            "AnatomicalOrientation" => "orientation",
            "CompressedData" => "compressed",
            "BinaryDataByteOrderMSB" | "ElementByteOrderMSB" => "big_endian",
            "Modality" => "modality",
            "ElementDataFile" => "data_file",
            "Offset" | "Origin" | "Position" => "origin",
            _ => continue,
        };
        let v = match key {
            "shape" => v.split_whitespace().collect::<Vec<_>>().join("x"),
            _ => v,
        };
        m.insert(
            key.into(),
            match v.as_str() {
                "True" => Value::Bool(true),
                "False" => Value::Bool(false),
                _ => v.parse::<i64>().map_or_else(|_| Value::String(truncate_chars(&v, 300)), Value::from),
            },
        );
    }
    if m.get("data_file").and_then(Value::as_str) == Some("LOCAL") {
        m.insert("storage".into(), "single file (.mha)".into());
    }
    for (k, v) in m {
        cx.format_set(&k, v);
    }
}

impl Extractor for Volumes {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let size = h.get(..4).map(|s| {
            (i32::from_le_bytes(s.try_into().unwrap_or_default()), i32::from_be_bytes(s.try_into().unwrap_or_default()))
        });
        let is348 = size.is_some_and(|(l, b)| l == 348 || b == 348);
        let is540 = size.is_some_and(|(l, b)| l == 540 || b == 540);
        if (is348 && h.get(344..348) == Some(b"ni1\0")) || (is540 && h.get(4..8) == Some(b"ni2\0")) {
            return Some(Sniff { format: "nifti", confidence: 0.98 });
        }
        // Analyze 7.5: a 348-byte header without the NIfTI magic, `.hdr`.
        if is348 && probe.extension == Some("hdr") && h.get(344..347).is_none_or(|m| m != b"ni1" && m != b"n+1") {
            return Some(Sniff { format: "analyze", confidence: 0.95 });
        }
        let meta =
            matches!(probe.extension, Some("mha" | "mhd")) && (h.starts_with(b"ObjectType") || h.starts_with(b"NDims"));
        meta.then_some(Sniff { format: "metaimage", confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id().to_string().as_str() {
            id @ ("nifti" | "analyze") => {
                let b = src
                    .read_vec(0, usize::try_from(src.len()).unwrap_or(0).min(1024))
                    .map_err(|_| ExtractError::malformed("header"))?;
                nifti(cx, &b, id == "analyze").ok_or_else(|| ExtractError::malformed("header"))
            }
            id => {
                // The text header (an attached .mha / .nrrd holds data after it).
                let head = src
                    .read_vec(0, usize::try_from(src.len()).unwrap_or(0).min(64 << 10))
                    .map_err(|_| ExtractError::malformed("header"))?;
                let text = String::from_utf8_lossy(&head).into_owned();
                if id == "nrrd" {
                    nrrd(cx, &text);
                } else {
                    metaimage(cx, &text);
                }
                Ok(())
            }
        }
    }
}

crate::register_extractor!(Volumes);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nifti_codes() {
        assert_eq!(datatype(16), "float32");
        assert_eq!(xform(4), "mni_152");
        assert_eq!(space_unit(10), "mm");
        assert_eq!(time_unit(10), "s");
    }

    crate::fixture_tests!("nifti", "analyze", "nrrd", "metaimage");
}
