//! Film, grading and astronomy images:
//! * Kodak Cineon and SMPTE DPX film scans: version, creation time,
//!   creator, project, copyright, original file name, image elements
//!   (descriptor, transfer, bit depth, packing), input device, and the
//!   film (format, frame, frame rate, shutter angle, slate) and television
//!   (SMPTE time code, frame rate, interlace) headers;
//! * colour look-up tables: Adobe / Resolve `.cube` (title, 1D / 3D, size,
//!   domain) and Autodesk `.3dl` (mesh size, input and output bit depth);
//! * PixInsight XISF: version, images (geometry, sample format, colour
//!   space, compression), FITS keywords and XISF properties such as the
//!   observed object and the creating application.
//!
//! References: SMPTE ST 268:2014 (DPX 2.0); Kodak "4.5 DRAFT – Image File
//! Format Proposal for Digital Pictures" (Cineon); Adobe "Cube LUT
//! Specification" 1.0; Autodesk Lustre / Flame 3D LUT notes; PixInsight
//! "XISF Version 1.0 Specification".

use serde_json::{Map, Value, json};

use crate::plugin::xmlwalk::{Ev, attr, walk};
use crate::plugin::{
    ByteReader, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff,
    Source, latin1_or_utf8, truncate_chars,
};

/// Extractor for film scans, LUTs and XISF.
pub struct Film;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.film",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "dpx",
            name: "DPX film / video frame",
            family: "image.raster",
            mimes: &["image/x-dpx"],
            extensions: &["dpx"],
            magic: &[Magic::prefix(b"SDPX"), Magic::prefix(b"XPDS")],
            parent: None,
        },
        FormatSpec {
            id: "cineon",
            name: "Kodak Cineon film scan",
            family: "image.raster",
            mimes: &["image/cineon"],
            extensions: &["cin"],
            magic: &[Magic::prefix(b"\x80\x2a\x5f\xd7"), Magic::prefix(b"\xd7\x5f\x2a\x80")],
            parent: None,
        },
        FormatSpec {
            id: "cube_lut",
            name: "Cube colour look-up table",
            family: "image.raster",
            mimes: &[],
            extensions: &["cube"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "lut_3dl",
            name: "Autodesk 3DL colour look-up table",
            family: "image.raster",
            mimes: &[],
            extensions: &["3dl"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "xisf",
            name: "XISF astronomy image",
            family: "image.raster",
            mimes: &["image/x-xisf"],
            extensions: &["xisf"],
            magic: &[Magic::prefix(b"XISF0100")],
            parent: None,
        },
    ],
};

const MAX_LISTED: usize = 100;
/// LUT text read at most (a 65³ cube is about 7 MB).
const MAX_LUT: usize = 64 << 20;
/// XISF header bytes read at most.
const MAX_XISF_HEADER: u32 = 16 << 20;

impl Extractor for Film {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let t = String::from_utf8_lossy(&probe.head[..probe.head.len().min(8192)]);
        if t.lines().any(|l| l.starts_with("LUT_3D_SIZE") || l.starts_with("LUT_1D_SIZE")) {
            return Some(Sniff { format: "cube_lut", confidence: 0.95 });
        }
        if probe.extension == Some("3dl") && mesh_line(&t).is_some() {
            return Some(Sniff { format: "lut_3dl", confidence: 0.95 });
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "dpx" => {
                let mut h = vec![0u8; 2048.min(usize::try_from(src.len()).unwrap_or(0))];
                src.read_exact_at(0, &mut h)?;
                dpx(&h, cx)
            }
            "cineon" => {
                let mut h = vec![0u8; 1024 + 384.min(usize::try_from(src.len()).unwrap_or(0).saturating_sub(1024))];
                src.read_exact_at(0, &mut h)?;
                cineon(&h, cx)
            }
            "cube_lut" | "lut_3dl" => {
                let n = usize::try_from(src.len()).unwrap_or(usize::MAX).min(MAX_LUT);
                let text = latin1_or_utf8(&src.read_vec(0, n)?);
                if cx.format_id() == "cube_lut" { cube(&text, cx) } else { lut3dl(&text, cx) }
            }
            "xisf" => xisf(src, cx),
            other => Err(ExtractError::Unsupported(format!("format {other}"))),
        }
    }
}

crate::register_extractor!(Film);

/// A fixed-size text field, trimmed; `None` when empty or unset (all 0xFF).
fn field(h: &[u8], at: usize, len: usize) -> Option<String> {
    let b = h.get(at..at + len)?;
    let b = &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())];
    if b.is_empty() || b.iter().all(|&c| c == 0xff) {
        return None;
    }
    let s = truncate_chars(latin1_or_utf8(b).trim(), 500);
    (!s.is_empty()).then_some(s)
}

struct Endian<'a> {
    h: &'a [u8],
    le: bool,
}

impl Endian<'_> {
    fn u32(&self, at: usize) -> Option<u32> {
        let b: [u8; 4] = self.h.get(at..at + 4)?.try_into().ok()?;
        let v = if self.le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) };
        (v != u32::MAX).then_some(v)
    }
    fn u16(&self, at: usize) -> Option<u16> {
        let b: [u8; 2] = self.h.get(at..at + 2)?.try_into().ok()?;
        let v = if self.le { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) };
        (v != u16::MAX).then_some(v)
    }
    fn f32(&self, at: usize) -> Option<f64> {
        let bits = self.u32(at)?;
        let v = f64::from(f32::from_bits(bits));
        v.is_finite().then_some(v)
    }
    fn u8(&self, at: usize) -> Option<u8> {
        self.h.get(at).copied().filter(|&v| v != u8::MAX)
    }
}

/// `YYYY:MM:DD:HH:MM:SS[:LTZ]` (DPX) as an ISO 8601 date-time.
fn dpx_time(s: &str) -> Option<(String, bool)> {
    let p: Vec<&str> = s.splitn(7, ':').collect();
    if p.len() < 6 || !p[..6].iter().all(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    let mut out = format!("{}-{}-{}T{}:{}:{}", p[0], p[1], p[2], p[3], p[4], &p[5][..p[5].len().min(2)]);
    let tz = p.get(6).map(|z| z.trim()).filter(|z| !z.is_empty());
    if let Some(z) = tz {
        out.push_str(z);
    }
    Some((out, tz.is_some()))
}

/// A SMPTE time code (BCD `HHMMSSFF`).
fn timecode(v: u32) -> Option<String> {
    let d = |s: u32| {
        let b = (v >> s) & 0xff;
        ((b >> 4) <= 9 && (b & 15) <= 9).then_some((b >> 4) * 10 + (b & 15))
    };
    Some(format!("{:02}:{:02}:{:02}:{:02}", d(24)?, d(16)?, d(8)?, d(0)?))
}

#[allow(clippy::too_many_lines)] // one pass over the fixed header
fn dpx(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    if h.len() < 1664 {
        return Err(ExtractError::Truncated { offset: h.len() as u64, needed: 1664 });
    }
    let e = Endian { h, le: h.starts_with(b"XPDS") };
    cx.format_set("byte_order", if e.le { "little" } else { "big" });
    if let Some(v) = field(h, 8, 8) {
        cx.format_set("version", v);
    }
    if let Some(n) = field(h, 36, 100) {
        cx.format_set("original_file_name", n);
    }
    if let Some((t, tz)) = field(h, 136, 24).as_deref().and_then(dpx_time) {
        cx.temporal().source("dpx.creation_time").content_date(DateField::Created, t, tz);
    }
    if let Some(c) = field(h, 160, 100) {
        cx.format_set("creator", c);
    }
    if let Some(p) = field(h, 260, 200) {
        cx.format_set("project", p);
    }
    if let Some(c) = field(h, 460, 200) {
        cx.rights().source("dpx.copyright").copyright(c);
    }
    cx.format_set("encrypted", e.u32(660).is_some());
    let elements = e.u16(770).unwrap_or(0).min(8);
    let (w, hh) = (e.u32(772).unwrap_or(0), e.u32(776).unwrap_or(0));
    let mut list = Vec::new();
    for i in 0..usize::from(elements) {
        let at = 780 + 72 * i;
        let mut m = Map::new();
        if let Some(d) = e.u8(at + 20) {
            m.insert("descriptor".into(), json!(dpx_descriptor(d)));
        }
        if let Some(t) = e.u8(at + 21) {
            m.insert("transfer".into(), json!(dpx_transfer(t)));
        }
        if let Some(c) = e.u8(at + 22) {
            m.insert("colorimetric".into(), json!(dpx_transfer(c)));
        }
        if let Some(b) = e.u8(at + 23) {
            m.insert("bit_depth".into(), json!(b));
        }
        if let Some(p) = e.u16(at + 24) {
            m.insert("packing".into(), json!(p));
        }
        if let Some(enc) = e.u16(at + 26) {
            m.insert("encoding".into(), json!(if enc == 1 { "RLE" } else { "none" }));
        }
        if let Some(d) = field(h, at + 40, 32) {
            m.insert("description".into(), json!(d));
        }
        list.push(Value::Object(m));
    }
    let first = list.first().and_then(Value::as_object);
    let bits = first.and_then(|m| m.get("bit_depth")?.as_u64()).and_then(|b| u8::try_from(b).ok());
    let channels = first.and_then(|m| m.get("descriptor")?.as_str()).map(|d| match d {
        "RGBA" | "ABGR" | "CbYaCrYa" | "CbYCrA" => 4,
        "RGB" | "CbYCr" | "CbYCrY" => 3,
        _ => 1,
    });
    let mut img = cx.physical().image(w, hh);
    if let Some(b) = bits {
        img.bit_depth(b);
    }
    if let Some(c) = channels {
        img.channels(c);
    }
    if let (Some(a), Some(b)) = (e.u32(1628), e.u32(1632))
        && a > 0
        && b > 0
    {
        cx.format_set("pixel_aspect", json!([a, b]));
    }
    cx.format_set("elements", Value::Array(list));
    if let Some(d) = field(h, 1556, 32) {
        cx.format_set("input_device", d);
    }
    // Film header.
    let mut film = Map::new();
    for (k, at, len) in [
        ("manufacturer_id", 1664, 2),
        ("film_type", 1666, 2),
        ("format", 1680, 32),
        ("frame_id", 1732, 32),
        ("slate", 1764, 100),
    ] {
        if let Some(v) = field(h, at, len) {
            film.insert(k.into(), json!(v));
        }
    }
    if let Some(v) = e.u32(1712) {
        film.insert("frame_position".into(), json!(v));
    }
    if let Some(v) = e.u32(1716) {
        film.insert("sequence_length".into(), json!(v));
    }
    if let Some(v) = e.f32(1724).filter(|v| *v > 0.0) {
        film.insert("frame_rate".into(), json!(v));
    }
    if let Some(v) = e.f32(1728) {
        film.insert("shutter_angle".into(), json!(v));
    }
    if !film.is_empty() {
        cx.format_set("film", Value::Object(film));
    }
    // Television header.
    if h.len() >= 1984 {
        let mut tv = Map::new();
        if let Some(tc) = e.u32(1920).and_then(timecode) {
            tv.insert("timecode".into(), json!(tc));
        }
        if let Some(i) = e.u8(1928) {
            tv.insert("interlaced".into(), json!(i == 1));
        }
        if let Some(v) = e.f32(1940).filter(|v| *v > 0.0) {
            tv.insert("frame_rate".into(), json!(v));
        }
        if let Some(v) = e.f32(1948).filter(|v| *v > 0.0) {
            tv.insert("gamma".into(), json!(v));
        }
        if !tv.is_empty() {
            cx.format_set("television", Value::Object(tv));
        }
    }
    Ok(())
}

fn dpx_descriptor(d: u8) -> Value {
    json!(match d {
        0 => "user-defined",
        1 => "R",
        2 => "G",
        3 => "B",
        4 => "A",
        6 => "Y",
        7 => "CbCr",
        8 => "Z",
        9 => "composite",
        50 => "RGB",
        51 => "RGBA",
        52 => "ABGR",
        100 => "CbYCrY",
        101 => "CbYaCrYa",
        102 => "CbYCr",
        103 => "CbYCrA",
        _ => return json!(d),
    })
}

fn dpx_transfer(t: u8) -> Value {
    json!(match t {
        0 => "user-defined",
        1 => "printing density",
        2 => "linear",
        3 => "logarithmic",
        4 => "unspecified video",
        5 => "SMPTE 274M",
        6 => "ITU-R 709-4",
        7 => "ITU-R 601-5 B/G",
        8 => "ITU-R 601-5 M",
        9 => "NTSC composite",
        10 => "PAL composite",
        11 => "Z linear",
        12 => "Z homogeneous",
        13 => "SMPTE ST 2065-3 (ADX)",
        14 => "ITU-R BT.2020 NCL",
        15 => "ITU-R BT.2020 CL",
        16 => "IEC 61966-2-4 xvYCC",
        17 => "ITU-R BT.2100 PQ / HLG",
        _ => return json!(t),
    })
}

fn cineon(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    if h.len() < 1024 {
        return Err(ExtractError::Truncated { offset: h.len() as u64, needed: 1024 });
    }
    let e = Endian { h, le: h.starts_with(b"\xd7\x5f\x2a\x80") };
    if let Some(v) = field(h, 24, 8) {
        cx.format_set("version", v);
    }
    if let Some(n) = field(h, 32, 100) {
        cx.format_set("original_file_name", n);
    }
    if let (Some(d), t) = (field(h, 132, 12), field(h, 144, 12)) {
        let date = d.replace(':', "-");
        let when = match t.as_deref().map(|t| t.get(..8).unwrap_or(t)) {
            Some(t) => format!("{date}T{t}"),
            None => date,
        };
        cx.temporal().source("cineon.creation_date").content_date(DateField::Created, when, false);
    }
    let channels = h[193].min(8);
    let (bits, w, hh) = (h[198], e.u32(200).unwrap_or(0), e.u32(204).unwrap_or(0));
    cx.physical().image(w, hh).channels(channels).bit_depth(bits);
    let designators: Vec<Value> = (0..usize::from(channels))
        .map(|i| {
            json!(match h[196 + 28 * i + 1] {
                0 => "B&W",
                1 => "red",
                2 => "green",
                3 => "blue",
                _ => "other",
            })
        })
        .collect();
    cx.format_set("channels", Value::Array(designators));
    if let Some(l) = field(h, 452, 200) {
        cx.format_set("label", l);
    }
    for (k, at, len) in [("input_device", 844, 64), ("device_model", 908, 32), ("device_serial", 940, 32)] {
        if let Some(v) = field(h, at, len) {
            cx.format_set(k, v);
        }
    }
    if h.len() >= 1308 {
        let mut film = Map::new();
        if let Some(f) = field(h, 1036, 32) {
            film.insert("format".into(), json!(f));
        }
        if let Some(v) = e.u32(1068) {
            film.insert("frame_position".into(), json!(v));
        }
        if let Some(v) = e.f32(1072).filter(|v| *v > 0.0) {
            film.insert("frame_rate".into(), json!(v));
        }
        if let Some(v) = field(h, 1076, 32) {
            film.insert("frame_id".into(), json!(v));
        }
        if let Some(v) = field(h, 1108, 200) {
            film.insert("slate".into(), json!(v));
        }
        if !film.is_empty() {
            cx.format_set("film", Value::Object(film));
        }
    }
    Ok(())
}

// ---- LUTs -----------------------------------------------------------------------

fn floats(l: &str) -> Option<Vec<f64>> {
    l.split_whitespace().map(|v| v.parse::<f64>().ok().filter(|f| f.is_finite())).collect()
}

fn cube(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let (mut kind, mut size, mut entries) = (None, 0u64, 0u64);
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let (key, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let rest = rest.trim();
        match key {
            "TITLE" => cx.format_set("title", truncate_chars(rest.trim_matches('"'), 300)),
            "LUT_1D_SIZE" | "LUT_3D_SIZE" => {
                kind = Some(if key == "LUT_1D_SIZE" { "1D" } else { "3D" });
                size = rest.parse().map_err(|_| ExtractError::malformed(format!("{key} {rest}")))?;
            }
            "DOMAIN_MIN" | "DOMAIN_MAX" | "LUT_1D_INPUT_RANGE" | "LUT_3D_INPUT_RANGE" => {
                if let Some(v) = floats(rest) {
                    cx.format_set(&key.to_ascii_lowercase(), json!(v));
                }
            }
            _ if floats(line).is_some_and(|v| v.len() == 3) => entries += 1,
            _ => {}
        }
    }
    let kind = kind.ok_or_else(|| ExtractError::malformed("no LUT_1D_SIZE / LUT_3D_SIZE"))?;
    cx.format_set("kind", kind);
    cx.format_set("size", size);
    cx.format_set("entries", entries);
    let expected = if kind == "3D" { size.saturating_pow(3) } else { size };
    if entries != expected {
        cx.warn(format!("{entries} entries, {kind} size {size} needs {expected}"));
    }
    Ok(())
}

/// The input mesh line of a 3DL LUT: increasing integers starting at 0.
fn mesh_line(text: &str) -> Option<Vec<u64>> {
    let l = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("3DMESH") && !l.starts_with("Mesh"))?;
    let v: Vec<u64> = l.split_whitespace().map(|x| x.parse().ok()).collect::<Option<_>>()?;
    (v.len() >= 2 && v[0] == 0 && v.windows(2).all(|w| w[0] < w[1])).then_some(v)
}

fn bits_for(max: u64) -> u64 {
    u64::from(64 - max.leading_zeros())
}

fn lut3dl(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mesh = mesh_line(text).ok_or_else(|| ExtractError::malformed("no input mesh line"))?;
    let mut entries = 0u64;
    let mut max = 0u64;
    let mut seen_mesh = false;
    for l in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        if let Some(rest) = l.strip_prefix("Mesh") {
            cx.format_set("lustre_mesh", rest.trim());
            continue;
        }
        let v: Option<Vec<u64>> = l.split_whitespace().map(|x| x.parse().ok()).collect();
        match v {
            Some(v) if v.len() == 3 && seen_mesh => {
                entries += 1;
                max = max.max(v.into_iter().max().unwrap_or(0));
            }
            Some(v) if v.len() == mesh.len() && !seen_mesh => seen_mesh = true,
            _ => {}
        }
    }
    let n = mesh.len() as u64;
    cx.format_set("size", n);
    cx.format_set("input_bit_depth", bits_for(*mesh.last().unwrap_or(&0)));
    cx.format_set("output_bit_depth", bits_for(max));
    cx.format_set("entries", entries);
    if entries != n.saturating_pow(3) {
        cx.warn(format!("{entries} entries, mesh {n} needs {}", n.saturating_pow(3)));
    }
    Ok(())
}

// ---- XISF -------------------------------------------------------------------------

/// FITS keywords reported (the rest are counted).
const FITS_KEYS: &[&str] = &[
    "OBJECT", "TELESCOP", "INSTRUME", "OBSERVER", "DATE-OBS", "EXPTIME", "EXPOSURE", "FILTER", "RA", "DEC", "OBJCTRA",
    "OBJCTDEC", "FOCALLEN", "XBINNING", "YBINNING", "CCD-TEMP", "IMAGETYP", "GAIN",
];

fn xisf(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.head();
    let mut r = ByteReader::new(h).skip(8)?;
    let len = r.le_u32()?;
    if len > MAX_XISF_HEADER {
        return Err(ExtractError::LimitExceeded(format!("XISF header of {len} bytes")));
    }
    let xml = src.read_vec(16, len as usize)?;
    let text = String::from_utf8_lossy(&xml);
    let text = text.trim_end_matches('\0');
    let mut images: Vec<Map<String, Value>> = Vec::new();
    let mut fits = Map::new();
    let mut fits_count = 0u64;
    let mut props = Map::new();
    let mut version = None;
    walk(text, cx, 200_000, |_, ev| {
        let Ev::Start(name, a) = ev else { return };
        match name {
            "xisf" => version = attr(a, "version").map(str::to_string),
            "Image" if images.len() < MAX_LISTED => {
                let mut m = Map::new();
                for k in ["geometry", "sampleFormat", "colorSpace", "compression", "pixelStorage", "imageType", "id"] {
                    if let Some(v) = attr(a, k) {
                        m.insert(k.into(), json!(v));
                    }
                }
                images.push(m);
            }
            "FITSKeyword" => {
                fits_count += 1;
                if let (Some(k), Some(v)) = (attr(a, "name"), attr(a, "value"))
                    && FITS_KEYS.contains(&k)
                {
                    fits.insert(k.into(), json!(v.trim().trim_matches('\'').trim()));
                }
            }
            "Property" if props.len() < MAX_LISTED => {
                if let (Some(id), Some(v)) = (attr(a, "id"), attr(a, "value")) {
                    props.insert(id.into(), json!(truncate_chars(v, 500)));
                }
            }
            _ => {}
        }
    })?;
    if let Some(v) = version {
        cx.format_set("version", v);
    }
    if let Some(g) = images.first().and_then(|m| m.get("geometry")?.as_str()) {
        let d: Vec<u32> = g.split(':').filter_map(|x| x.parse().ok()).collect();
        if let [w, hh, ref rest @ ..] = d[..] {
            let mut img = cx.physical().image(w, hh);
            if let Some(&c) = rest.last() {
                img.channels(u8::try_from(c).unwrap_or(u8::MAX));
            }
            let bits = match images[0].get("sampleFormat").and_then(Value::as_str) {
                Some("UInt8") => 8,
                Some("UInt16") => 16,
                Some("UInt32" | "Float32") => 32,
                Some("Float64" | "UInt64") => 64,
                _ => 0,
            };
            if bits > 0 {
                img.bit_depth(bits);
            }
        }
    }
    let object =
        fits.get("OBJECT").or_else(|| props.get("Observation:Object:Name")).and_then(Value::as_str).map(str::to_string);
    if let Some(o) = object {
        cx.content().source("xisf.object").title(o);
    }
    if let Some(d) = fits.get("DATE-OBS").or_else(|| props.get("Observation:Time:Start")).and_then(Value::as_str) {
        let tz = d.ends_with('Z');
        cx.temporal().source("xisf.observation").content_date(DateField::Created, d, tz);
    }
    cx.format_set("images", Value::Array(images.into_iter().map(Value::Object).collect()));
    if !fits.is_empty() {
        cx.format_set("fits_keywords", Value::Object(fits));
    }
    cx.format_set("fits_keyword_count", fits_count);
    if !props.is_empty() {
        cx.format_set("properties", Value::Object(props));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpx_fields() {
        assert_eq!(dpx_time("2024:05:01:19:42:10:+02"), Some(("2024-05-01T19:42:10+02".into(), true)));
        assert_eq!(dpx_time("2024:05:01:19:42:10"), Some(("2024-05-01T19:42:10".into(), false)));
        assert_eq!(dpx_time("garbage"), None);
        assert_eq!(timecode(0x0102_0304).as_deref(), Some("01:02:03:04"));
        assert_eq!(timecode(0xffff_ffff), None);
    }

    #[test]
    fn lut_mesh() {
        assert_eq!(mesh_line("# c\n0 64 128 1023\n0 0 0\n"), Some(vec![0, 64, 128, 1023]));
        assert_eq!(mesh_line("1 2 3\n"), None);
        assert_eq!(bits_for(1023), 10);
        assert_eq!(bits_for(4095), 12);
    }

    crate::fixture_tests!("dpx", "cineon", "cube_lut", "lut_3dl", "xisf");
}
