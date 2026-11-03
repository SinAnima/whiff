//! OME-TIFF microscopy images: the OME-XML in the first image's
//! description — images, pixel type, sizes (X, Y, Z, C, T) and dimension
//! order, physical pixel sizes, channel names, instrument, objective and
//! acquisition date, and the TIFF pages.
//!
//! Specification: Open Microscopy Environment OME-TIFF and OME-XML schema
//! 2016-06.

use serde_json::{Map, Value};

use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, parse_date,
    truncate_chars,
};

/// Extractor for OME-TIFF files.
pub struct OmeTiff;

static META: ExtractorMeta = ExtractorMeta {
    id: "science.ome",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "ome_tiff",
        name: "OME-TIFF microscopy image",
        family: "sci",
        mimes: &[],
        extensions: &["ome.tif", "ome.tiff"],
        magic: &[],
        parent: Some("tiff"),
    }],
};

fn has(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

/// TIFF integers in the file's byte order.
struct Tiff {
    big: bool,
}

impl Tiff {
    fn u16(&self, b: &[u8], at: usize) -> Option<u16> {
        let r = [*b.get(at)?, *b.get(at + 1)?];
        Some(if self.big { u16::from_be_bytes(r) } else { u16::from_le_bytes(r) })
    }

    fn u32(&self, b: &[u8], at: usize) -> Option<u32> {
        let r: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
        Some(if self.big { u32::from_be_bytes(r) } else { u32::from_le_bytes(r) })
    }
}

/// The ImageDescription of the first IFD, and the number of IFDs (pages).
fn description(src: &mut dyn Source) -> Option<(String, u64)> {
    let h = src.read_vec(0, 8).ok()?;
    let t = Tiff { big: h.starts_with(b"MM") };
    if t.u16(&h, 2)? != 42 {
        return None; // BigTIFF descriptions are not read
    }
    let mut ifd = u64::from(t.u32(&h, 4)?);
    let mut desc = None;
    let mut pages = 0u64;
    let mut seen = std::collections::HashSet::new();
    while ifd != 0 && pages < 100_000 && seen.insert(ifd) {
        let n = src.read_vec(ifd, 2).ok()?;
        let count = usize::from(t.u16(&n, 0)?);
        let e = src.read_vec(ifd + 2, 12 * count + 4).ok()?;
        if pages == 0 {
            for i in 0..count {
                let at = 12 * i;
                if t.u16(&e, at)? == 270 {
                    let len = usize::try_from(t.u32(&e, at + 4)?).ok()?.min(16 << 20);
                    let raw = if len <= 4 {
                        e.get(at + 8..at + 8 + len)?.to_vec()
                    } else {
                        src.read_vec(u64::from(t.u32(&e, at + 8)?), len).ok()?
                    };
                    desc = Some(String::from_utf8_lossy(&raw).trim_end_matches('\0').to_string());
                }
            }
        }
        pages += 1;
        ifd = u64::from(t.u32(&e, 12 * count)?);
    }
    Some((desc?, pages))
}

fn attr(tag: &str, name: &str) -> Option<String> {
    let k = tag.find(&format!(" {name}=\""))? + name.len() + 3;
    Some(tag[k..].split('"').next()?.to_string())
}

/// The opening tags `<el ...>` of an element.
fn tags<'a>(xml: &'a str, el: &str) -> Vec<&'a str> {
    let open = format!("<{el} ");
    let alt = format!("<{el}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(&open).or_else(|| rest.find(&alt)) {
        let end = rest[i..].find('>').map_or(rest.len(), |e| i + e);
        out.push(&rest[i..end]);
        rest = &rest[end..];
        if out.len() > 10_000 {
            break;
        }
    }
    out
}

impl Extractor for OmeTiff {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let tiff = h.starts_with(b"II*\0") || h.starts_with(b"MM\0*");
        (tiff && has(h, b"<OME") && has(h, b"openmicroscopy.org"))
            .then_some(Sniff { format: "ome_tiff", confidence: 0.99 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (xml, pages) = description(src).ok_or_else(|| ExtractError::malformed("OME-XML description"))?;
        cx.format_set("pages", pages);
        if let Some(c) = tags(&xml, "OME").first().and_then(|t| attr(t, "Creator")) {
            cx.format_set("creator", truncate_chars(&c, 100));
        }
        let images = tags(&xml, "Image");
        cx.format_set("images", images.len());
        let mut list = Vec::new();
        for (i, p) in tags(&xml, "Pixels").into_iter().enumerate().take(100) {
            let mut m = Map::new();
            if let Some(n) = images.get(i).and_then(|t| attr(t, "Name")) {
                m.insert("name".into(), truncate_chars(&n, 100).into());
            }
            for (a, out) in [("Type", "pixel_type"), ("DimensionOrder", "dimension_order")] {
                if let Some(v) = attr(p, a) {
                    m.insert(out.into(), v.into());
                }
            }
            let size: Vec<String> = ["X", "Y", "Z", "C", "T"]
                .iter()
                .map(|d| attr(p, &format!("Size{d}")).unwrap_or_else(|| "1".into()))
                .collect();
            m.insert("size_xyzct".into(), size.join("x").into());
            for d in ["X", "Y", "Z"] {
                if let Some(v) = attr(p, &format!("PhysicalSize{d}")).and_then(|v| v.parse::<f64>().ok()) {
                    let unit = attr(p, &format!("PhysicalSize{d}Unit")).unwrap_or_else(|| "µm".into());
                    m.insert(format!("physical_size_{}", d.to_ascii_lowercase()), format!("{v} {unit}").into());
                }
            }
            list.push(Value::Object(m));
        }
        cx.format_set("image_list", list);
        let channels: Vec<String> = tags(&xml, "Channel")
            .iter()
            .filter_map(|t| attr(t, "Name"))
            .take(100)
            .map(|n| truncate_chars(&n, 100))
            .collect();
        if !channels.is_empty() {
            cx.format_set("channels", channels);
        }
        for (el, a, out) in [
            ("Microscope", "Model", "microscope"),
            ("Objective", "Model", "objective"),
            ("Objective", "NominalMagnification", "magnification"),
        ] {
            if let Some(v) = tags(&xml, el).first().and_then(|t| attr(t, a)) {
                cx.format_set(out, truncate_chars(&v, 100));
            }
        }
        if let Some(d) = xml.split("<AcquisitionDate>").nth(1).and_then(|r| r.split('<').next())
            && let Some((t, tz)) = parse_date(d)
        {
            cx.format_set("acquired", t.clone());
            cx.temporal().source("ome.AcquisitionDate").content_date(DateField::Captured, t, tz);
        }
        Ok(())
    }
}

crate::register_extractor!(OmeTiff);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("ome_tiff");
}
