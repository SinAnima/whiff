//! Whole-slide microscopy images:
//! * Aperio SVS: scanner, magnification, microns per pixel, scan date,
//!   the pyramid levels and the label / macro / thumbnail images, from
//!   the TIFF structure and its `ImageDescription`;
//! * Hamamatsu NDPI: magnification (source lens), focal offset, scanner
//!   serial, the pyramid, from the NDPI private tags;
//! * Leica SCN: device, objective, collection and image sizes, from the
//!   XML description;
//! * Hamamatsu VMS (the text index of a tiled JPEG slide): layers, tile
//!   grid, source lens, the image, map and macro file names.
//!
//! Pixel data and tiles are never read.
//!
//! References: Aperio "Digital Slides and Third-Party Data Interchange"
//! (MP-0018); `OpenSlide` format notes for Hamamatsu (NDPI tags 65420–
//! 65449, VMS keys) and Leica (SCN schema).

use serde_json::{Map, Value, json};

use super::tiff::{Entry, find, ifd_chain, layout};
use crate::plugin::xmlwalk::{Ev, attr, walk};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, truncate_chars,
};

/// Extractor for whole-slide images.
pub struct Slide;

const fn slide(
    id: &'static str,
    name: &'static str,
    ext: &'static [&'static str],
    parent: Option<&'static str>,
) -> FormatSpec {
    FormatSpec { id, name, family: "image.raster", mimes: &[], extensions: ext, magic: &[], parent }
}

static META: ExtractorMeta = ExtractorMeta {
    id: "image.slide",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        slide("svs", "Aperio SVS slide", &["svs"], Some("tiff")),
        slide("ndpi", "Hamamatsu NDPI slide", &["ndpi"], Some("tiff")),
        slide("scn", "Leica SCN slide", &["scn"], Some("tiff")),
        slide("vms", "Hamamatsu VMS slide index", &["vms"], Some("ini")),
    ],
};

const MAX_LEVELS: usize = 64;

impl Extractor for Slide {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.starts_with(b"[Virtual Microscope Specimen]") {
            return Some(Sniff { format: "vms", confidence: 0.97 });
        }
        layout(h)?;
        let text = String::from_utf8_lossy(&h[..h.len().min(16_384)]);
        let format = match probe.extension {
            Some("svs") => "svs",
            Some("ndpi") => "ndpi",
            Some("scn") => "scn",
            _ if text.contains("Aperio Image Library") || text.contains("Aperio Leica Biosystems") => "svs",
            _ if text.contains("leica-microsystems.com/scn") => "scn",
            _ => return None,
        };
        Some(Sniff { format, confidence: 0.96 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "vms" {
            let n = usize::try_from(src.len().min(1 << 20)).unwrap_or(0);
            return vms(&String::from_utf8_lossy(&src.read_vec(0, n)?), cx);
        }
        let l = layout(src.head()).ok_or_else(|| ExtractError::malformed("no TIFF header"))?;
        let pages = ifd_chain(src, &l, cx)?;
        let u = |e: &[Entry], t: u16| find(e, t).and_then(|x| x.uint(l.le));
        let s = |e: &[Entry], t: u16| find(e, t).map(Entry::string).filter(|s| !s.is_empty());
        let mut levels = Vec::new();
        let mut associated = Vec::new();
        for p in &pages {
            let (w, h) = (u(p, 256).unwrap_or(0), u(p, 257).unwrap_or(0));
            let desc = s(p, 270).unwrap_or_default();
            let tiled = find(p, 322).is_some();
            let kind = if desc.starts_with("label") || desc.contains("\nlabel") {
                Some("label")
            } else if desc.starts_with("macro") || desc.contains("\nmacro") {
                Some("macro")
            } else if !tiled && !levels.is_empty() && cx.format_id() == "svs" {
                Some("thumbnail")
            } else {
                None
            };
            match kind {
                Some(k) => associated.push(json!({ "kind": k, "width": w, "height": h })),
                None if levels.len() < MAX_LEVELS => {
                    levels.push(json!({ "width": w, "height": h, "tiled": tiled, "compression": u(p, 259) }));
                }
                None => {}
            }
        }
        let first = pages.first().ok_or_else(|| ExtractError::malformed("no IFD"))?;
        let (w, h) = (u(first, 256).unwrap_or(0), u(first, 257).unwrap_or(0));
        cx.physical()
            .image(u32::try_from(w).unwrap_or(0), u32::try_from(h).unwrap_or(0))
            .frames(u32::try_from(levels.len()).unwrap_or(0));
        let mut slide = Map::new();
        if let Some(m) = s(first, 271) {
            slide.insert("make".into(), json!(m));
        }
        if let Some(m) = s(first, 272) {
            slide.insert("model".into(), json!(m));
        }
        match cx.format_id() {
            "svs" => svs(&s(first, 270).unwrap_or_default(), &mut slide, cx),
            "ndpi" => ndpi(first, l.le, &mut slide),
            _ => scn(&s(first, 270).unwrap_or_default(), &mut slide, cx)?,
        }
        slide.insert("levels".into(), Value::Array(levels));
        slide.insert("associated_images".into(), Value::Array(associated));
        cx.format_set("slide", Value::Object(slide));
        Ok(())
    }
}

crate::register_extractor!(Slide);

/// Aperio keys reported from the `|`-separated description.
const SVS_KEYS: &[(&str, &str)] = &[
    ("AppMag", "magnification"),
    ("MPP", "microns_per_pixel"),
    ("ScanScope ID", "scanner_id"),
    ("Filename", "slide_name"),
    ("ImageID", "image_id"),
    ("Exposure Time", "exposure_time"),
    ("Focus Offset", "focus_offset"),
    ("StripeWidth", "stripe_width"),
];

fn svs(desc: &str, slide: &mut Map<String, Value>, cx: &mut Context<'_>) {
    let mut parts = desc.split('|');
    let head = parts.next().unwrap_or("");
    if let Some(lib) = head.lines().next() {
        slide.insert("software".into(), json!(lib.trim()));
    }
    if let Some(geom) = head.lines().nth(1) {
        slide.insert("scan".into(), json!(geom.trim()));
    }
    let mut date = None;
    let mut time = None;
    for p in parts {
        let Some((k, v)) = p.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        if let Some((_, out)) = SVS_KEYS.iter().find(|(key, _)| *key == k) {
            slide.insert((*out).into(), v.parse::<f64>().map_or_else(|_| json!(truncate_chars(v, 200)), |n| json!(n)));
        }
        match k {
            "Date" => date = Some(v.to_string()),
            "Time" => time = Some(v.to_string()),
            _ => {}
        }
    }
    // Aperio dates are MM/DD/YY.
    if let Some(d) = date
        && let [m, dd, y] = d.split('/').collect::<Vec<_>>()[..]
    {
        let year = if y.len() == 2 { format!("20{y}") } else { y.to_string() };
        let mut iso = format!("{year}-{m:0>2}-{dd:0>2}");
        if let Some(t) = time {
            iso.push('T');
            iso.push_str(t.split_whitespace().next().unwrap_or(""));
        }
        cx.temporal().source("svs.Date").content_date(DateField::Captured, iso, false);
    }
}

fn ndpi(first: &[Entry], le: bool, slide: &mut Map<String, Value>) {
    let float = |t: u16| {
        find(first, t).and_then(|e| {
            (e.typ == 11 && e.data.len() >= 4).then(|| {
                let b = [e.data[0], e.data[1], e.data[2], e.data[3]];
                f64::from(if le { f32::from_le_bytes(b) } else { f32::from_be_bytes(b) })
            })
        })
    };
    let int = |t: u16| find(first, t).and_then(|e| e.uint(le));
    if let Some(m) = float(65421) {
        slide.insert("magnification".into(), json!(m));
    }
    for (t, k) in [(65422, "x_offset_nm"), (65423, "y_offset_nm"), (65424, "focal_plane_nm")] {
        if let Some(v) = find(first, t).and_then(|e| {
            let b: [u8; 4] = e.data.get(..4)?.try_into().ok()?;
            Some(if le { i32::from_le_bytes(b) } else { i32::from_be_bytes(b) })
        }) {
            slide.insert(k.into(), json!(v));
        }
    }
    if let Some(serial) = find(first, 65442).map(Entry::string).filter(|s| !s.is_empty()) {
        slide.insert("scanner_serial".into(), json!(serial));
    }
    if let Some(v) = int(65420) {
        slide.insert("ndpi_format_flag".into(), json!(v));
    }
}

fn scn(desc: &str, slide: &mut Map<String, Value>, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut path: Vec<String> = Vec::new();
    let mut images = 0u64;
    walk(desc, cx, 100_000, |cx, ev| match ev {
        Ev::Start(name, a) => {
            match name {
                "collection" => {
                    if let Some(n) = attr(a, "name") {
                        slide.insert("collection".into(), json!(n));
                    }
                    if let (Some(x), Some(y)) = (attr(a, "sizeX"), attr(a, "sizeY")) {
                        slide.insert("collection_size_nm".into(), json!([x, y]));
                    }
                }
                "image" => images += 1,
                "device" => {
                    if let Some(m) = attr(a, "model") {
                        slide.insert("device".into(), json!(m));
                    }
                    if let Some(v) = attr(a, "version") {
                        slide.insert("device_version".into(), json!(v));
                    }
                }
                _ => {}
            }
            path.push(name.to_string());
        }
        Ev::End(_) => {
            path.pop();
        }
        Ev::Text(t) => match path.last().map(String::as_str) {
            Some("objective") => {
                slide.insert("magnification".into(), t.parse::<f64>().map_or_else(|_| json!(t), |n| json!(n)));
            }
            Some("illuminationSource") => {
                slide.insert("illumination".into(), json!(t));
            }
            Some("numericalAperture") => {
                slide.insert("numerical_aperture".into(), t.parse::<f64>().map_or_else(|_| json!(t), |n| json!(n)));
            }
            Some("creationDate") => {
                cx.temporal().source("scn.creationDate").content_date(DateField::Captured, t, t.ends_with('Z'));
            }
            _ => {}
        },
    })?;
    slide.insert("images".into(), json!(images));
    Ok(())
}

const VMS_KEYS: &[(&str, &str)] = &[
    ("NoLayers", "layers"),
    ("NoJpegColumns", "tile_columns"),
    ("NoJpegRows", "tile_rows"),
    ("SourceLens", "magnification"),
    ("PhysicalWidth", "physical_width_nm"),
    ("PhysicalHeight", "physical_height_nm"),
    ("ImageFile", "image_file"),
    ("MapFile", "map_file"),
    ("MacroImage", "macro_image"),
    ("OptimisationFile", "optimisation_file"),
];

fn vms(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut slide = Map::new();
    let mut tiles = 0u64;
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        if k.starts_with("ImageFile(") {
            tiles += 1;
            continue;
        }
        if let Some((_, out)) = VMS_KEYS.iter().find(|(key, _)| *key == k) {
            slide.insert((*out).into(), v.parse::<f64>().map_or_else(|_| json!(truncate_chars(v, 300)), |n| json!(n)));
        }
    }
    if slide.is_empty() {
        return Err(ExtractError::malformed("no VMS keys"));
    }
    slide.insert("extra_image_files".into(), json!(tiles));
    cx.format_set("slide", Value::Object(slide));
    Ok(())
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("svs", "ndpi", "scn", "vms");
}
