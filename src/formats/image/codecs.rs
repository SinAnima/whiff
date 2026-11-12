//! Less common still-image codecs, header only:
//! * FLIF: size, channels, bit depth, interlacing, animation frames, and
//!   the metadata chunks (ICC, EXIF, XMP: inflated and decoded);
//! * BPG: size, pixel format, bit depth, colour space, alpha, animation
//!   (loops, frame period) and the EXIF / ICC / XMP extensions;
//! * JPEG XR / HD Photo / Windows Media Photo: size, pixel format,
//!   resolution, the descriptive tags (make, model, software, dates,
//!   artist, copyright) and the XMP / ICC / IPTC / Photoshop blocks;
//! * Kodak Photo CD image packs: orientation, highest resolution, scan
//!   time, film medium, scanner and photofinisher.
//!
//! References: FLIF format specification (flif.info, 2016); Fabrice
//! Bellard's "BPG Specification" 0.9.5; ITU-T T.832 Annex A (JPEG XR
//! container) and the WIC pixel format GUIDs; Kodak "Photo CD Image Pac"
//! layout as used by Pillow and ImageMagick.

use serde_json::{Map, Value, json};

use crate::plugin::{
    BlockKind, ByteReader, Compression, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec,
    Magic, Source, latin1_or_utf8, truncate_chars,
};

/// Extractor for FLIF, BPG, JPEG XR and Photo CD.
pub struct Codecs;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.codecs",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "flif",
            name: "FLIF image",
            family: "image.raster",
            mimes: &["image/flif"],
            extensions: &["flif"],
            magic: &[Magic::prefix(b"FLIF")],
            parent: None,
        },
        FormatSpec {
            id: "bpg",
            name: "BPG image",
            family: "image.raster",
            mimes: &["image/bpg"],
            extensions: &["bpg"],
            magic: &[Magic::prefix(b"BPG\xfb")],
            parent: None,
        },
        FormatSpec {
            id: "jxr",
            name: "JPEG XR image",
            family: "image.raster",
            mimes: &["image/jxr", "image/vnd.ms-photo"],
            extensions: &["jxr", "wdp", "hdp", "wmp"],
            magic: &[Magic::prefix(b"II\xbc\x01"), Magic::prefix(b"II\xbc\x00")],
            parent: None,
        },
        FormatSpec {
            id: "photo_cd",
            name: "Kodak Photo CD image",
            family: "image.raster",
            mimes: &["image/x-photo-cd"],
            extensions: &["pcd"],
            magic: &[Magic::at(2048, b"PCD_IPI"), Magic::prefix(b"PCD_OPA")],
            parent: None,
        },
    ],
};

/// Inflated metadata chunk size at most.
const MAX_META: usize = 16 << 20;

impl Extractor for Codecs {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "flif" => flif(src, cx),
            "bpg" => bpg(src, cx),
            "jxr" => jxr(src, cx),
            "photo_cd" => photo_cd(src, cx),
            other => Err(ExtractError::Unsupported(format!("format {other}"))),
        }
    }
}

crate::register_extractor!(Codecs);

/// A big-endian base-128 varint (FLIF, BPG `ue7`): 7 bits per byte, high bit = more.
fn varint(r: &mut ByteReader<'_>) -> Result<u64, ExtractError> {
    let mut v = 0u64;
    for _ in 0..9 {
        let b = r.u8()?;
        v = (v << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(ExtractError::malformed("varint too long"))
}

fn u32_of(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// Read up to `n` bytes from `at` (clamped to the file).
fn read_at(src: &mut dyn Source, at: u64, n: usize) -> Result<Vec<u8>, ExtractError> {
    let n = usize::try_from(src.len().saturating_sub(at)).unwrap_or(usize::MAX).min(n);
    Ok(src.read_vec(at, n)?)
}

// ---- FLIF -----------------------------------------------------------------------

fn flif(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let d = read_at(src, 0, MAX_META)?;
    let mut r = ByteReader::new(&d).skip(4)?;
    let kind = r.u8()?;
    let (mode, channels) = (kind >> 4, kind & 15);
    if !(3..=6).contains(&mode) || !matches!(channels, 1 | 3 | 4) {
        return Err(ExtractError::malformed(format!("header byte {kind:#04x}")));
    }
    let depth = match r.u8()? {
        b'1' => Some(8),
        b'2' => Some(16),
        _ => None,
    };
    let (w, h) = (varint(&mut r)? + 1, varint(&mut r)? + 1);
    let animated = mode >= 5;
    let frames = if animated { varint(&mut r)? + 2 } else { 1 };
    let mut img = cx.physical().image(u32_of(w), u32_of(h));
    img.channels(channels).frames(u32_of(frames));
    if let Some(d) = depth {
        img.bit_depth(d);
    }
    cx.format_set("interlaced", mode == 4 || mode == 6);
    cx.format_set("animated", animated);
    if depth.is_none() {
        cx.format_set("bit_depth", "custom per channel");
    }
    // Metadata chunks: a four-letter name (first letter not 0), a varint length, deflate data.
    let mut chunks = Vec::new();
    while let Some(name) = r.peek(4).filter(|n| n[0] >= b' ' && n.iter().all(u8::is_ascii_alphabetic)) {
        let name = String::from_utf8_lossy(name).into_owned();
        r.advance(4)?;
        let len = usize::try_from(varint(&mut r)?).unwrap_or(usize::MAX);
        let body = r.bytes(len.min(r.remaining()))?;
        let kind = match name.as_str() {
            "iCCP" => Some(BlockKind::ICC),
            "eXif" => Some(BlockKind::EXIF),
            "eXmp" => Some(BlockKind::XMP),
            _ => None,
        };
        if let Some(k) = kind {
            match cx.inflate(body, Compression::Deflate, MAX_META) {
                Ok(data) => cx.emit_block(k, data),
                Err(e) => cx.warn(format!("{name}: {e}")),
            }
        }
        chunks.push(json!(name));
    }
    if !chunks.is_empty() {
        cx.format_set("metadata_chunks", Value::Array(chunks));
    }
    Ok(())
}

// ---- BPG --------------------------------------------------------------------------

fn bpg(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let d = read_at(src, 0, MAX_META)?;
    let mut r = ByteReader::new(&d).skip(4)?;
    let (a, b) = (r.u8()?, r.u8()?);
    let (format, alpha1, depth) = (a >> 5, a & 0x10 != 0, (a & 15) + 8);
    let (space, ext_present, alpha2, limited, animated) = (b >> 4, b & 8 != 0, b & 4 != 0, b & 2 != 0, b & 1 != 0);
    let (w, h) = (varint(&mut r)?, varint(&mut r)?);
    let _picture_len = varint(&mut r)?;
    let alpha = alpha1 || alpha2;
    let pixel_format = match format {
        0 => "grayscale",
        1 => "4:2:0 (JPEG)",
        2 => "4:2:2 (JPEG)",
        3 => "4:4:4",
        4 => "4:2:0 (MPEG-2)",
        5 => "4:2:2 (MPEG-2)",
        _ => "reserved",
    };
    let color = match space {
        0 => "YCbCr (BT.601)",
        1 => "RGB",
        2 => "YCgCo",
        3 => "YCbCr (BT.709)",
        4 => "YCbCr (BT.2020 NCL)",
        5 => "YCbCr (BT.2020 CL)",
        _ => "reserved",
    };
    let channels = u8::from(format != 0) * 2 + 1 + u8::from(alpha);
    cx.physical().image(u32_of(w), u32_of(h)).bit_depth(depth).channels(channels).color_space(color);
    cx.format_set("pixel_format", pixel_format);
    cx.format_set(
        "alpha",
        if !alpha {
            "none"
        } else if alpha1 && alpha2 {
            "premultiplied"
        } else {
            "straight"
        },
    );
    cx.format_set("limited_range", limited);
    cx.format_set("animated", animated);
    if ext_present {
        let len = usize::try_from(varint(&mut r)?).unwrap_or(usize::MAX);
        let mut e = ByteReader::new(r.bytes(len.min(r.remaining()))?);
        let mut exts = Vec::new();
        while !e.is_empty() {
            let tag = varint(&mut e)?;
            let n = usize::try_from(varint(&mut e)?).unwrap_or(usize::MAX);
            let body = e.bytes(n.min(e.remaining()))?;
            let name = match tag {
                1 => {
                    cx.emit_block(BlockKind::EXIF, body.to_vec());
                    "EXIF"
                }
                2 => {
                    cx.emit_block(BlockKind::ICC, body.to_vec());
                    "ICC"
                }
                3 => {
                    cx.emit_block(BlockKind::XMP, body.to_vec());
                    "XMP"
                }
                4 => "thumbnail",
                5 => {
                    let mut a = ByteReader::new(body);
                    let (loops, num, den) = (varint(&mut a)?, varint(&mut a)?, varint(&mut a)?);
                    cx.format_set("loops", loops);
                    if den > 0 {
                        #[allow(clippy::cast_precision_loss)] // frame periods are small
                        cx.format_set("frame_period_s", num as f64 / den as f64);
                    }
                    "animation control"
                }
                _ => "other",
            };
            exts.push(json!(name));
        }
        cx.format_set("extensions", Value::Array(exts));
    }
    Ok(())
}

// ---- JPEG XR ------------------------------------------------------------------------

/// The WIC pixel format named by the last byte of `24C3DD6F-034E-FE4B-B185-3D77768DC9xx`.
fn wic_pixel_format(last: u8) -> Option<(&'static str, u8, u8)> {
    Some(match last {
        0x05 => ("BlackWhite", 1, 1),
        0x08 => ("8bppGray", 1, 8),
        0x09 => ("16bppBGR555", 3, 5),
        0x0a => ("16bppBGR565", 3, 5),
        0x0b => ("16bppGray", 1, 16),
        0x0c => ("24bppBGR", 3, 8),
        0x0d => ("24bppRGB", 3, 8),
        0x0e => ("32bppBGR", 3, 8),
        0x0f => ("32bppBGRA", 4, 8),
        0x10 => ("32bppPBGRA", 4, 8),
        0x11 => ("32bppGrayFloat", 1, 32),
        0x15 => ("48bppRGB", 3, 16),
        0x16 => ("64bppRGBA", 4, 16),
        0x17 => ("64bppPRGBA", 4, 16),
        0x19 => ("128bppRGBAFloat", 4, 32),
        0x1c => ("32bppCMYK", 4, 8),
        0x3a => ("64bppRGBAHalf", 4, 16),
        0x3b => ("48bppRGBHalf", 3, 16),
        0x3e => ("16bppGrayHalf", 1, 16),
        _ => return None,
    })
}

#[allow(clippy::too_many_lines)] // one pass over the IFD tags
fn jxr(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.head().to_vec();
    let first = u64::from(ByteReader::new(&h).skip(4)?.le_u32()?);
    let mut n = [0u8; 2];
    src.read_exact_at(first, &mut n)?;
    let count = usize::from(u16::from_le_bytes(n)).min(1024);
    let ifd = src.read_vec(first + 2, count * 12)?;
    let (mut w, mut hh) = (None, None);
    let mut texts = Map::new();
    for e in ifd.as_chunks::<12>().0 {
        let tag = u16::from_le_bytes([e[0], e[1]]);
        let typ = u16::from_le_bytes([e[2], e[3]]);
        let cnt = u32::from_le_bytes([e[4], e[5], e[6], e[7]]) as usize;
        let val = [e[8], e[9], e[10], e[11]];
        let size = cnt.saturating_mul(match typ {
            3 | 8 => 2,
            4 | 9 | 11 => 4,
            5 | 10 | 12 => 8,
            _ => 1,
        });
        let inline = size <= 4;
        let off = u64::from(u32::from_le_bytes(val));
        let data = |src: &mut dyn Source, max: usize| -> Option<Vec<u8>> {
            if size > max {
                return None;
            }
            if inline { Some(val[..size].to_vec()) } else { src.read_vec(off, size).ok() }
        };
        let int = || match typ {
            3 => u32::from(u16::from_le_bytes([val[0], val[1]])),
            1 => u32::from(val[0]),
            _ => u32::from_le_bytes(val),
        };
        match tag {
            0xbc01 => {
                if let Some(g) = data(src, 16)
                    && g.len() == 16
                {
                    if let Some((name, ch, bits)) = wic_pixel_format(g[15]) {
                        cx.format_set("pixel_format", name);
                        texts.insert("_channels".into(), json!(ch));
                        texts.insert("_bits".into(), json!(bits));
                    } else {
                        cx.format_set("pixel_format", format!("GUID ending {:02x}", g[15]));
                    }
                }
            }
            0xbc80 => w = Some(int()),
            0xbc81 => hh = Some(int()),
            0xbc82 | 0xbc83 if typ == 11 => {
                let k = if tag == 0xbc82 { "_xres" } else { "_yres" };
                texts.insert(k.into(), json!(f32::from_le_bytes(val)));
            }
            0x02bc => {
                if let Some(b) = data(src, MAX_META) {
                    cx.emit_block(BlockKind::XMP, b);
                }
            }
            0x8773 => {
                if let Some(b) = data(src, MAX_META) {
                    cx.emit_block(BlockKind::ICC, b);
                }
            }
            0x83bb => {
                if let Some(b) = data(src, MAX_META) {
                    cx.emit_block(BlockKind::IPTC_IIM, b);
                }
            }
            0x8649 => {
                if let Some(b) = data(src, MAX_META) {
                    cx.emit_block(BlockKind::PHOTOSHOP_IRB, b);
                }
            }
            0x010d | 0x010e | 0x010f | 0x0110 | 0x011d | 0x0131 | 0x0132 | 0x013b | 0x013c | 0x8298 if typ == 2 => {
                if let Some(b) = data(src, 64 << 10) {
                    let s = truncate_chars(latin1_or_utf8(&b).trim_matches(['\0', ' ']), 2000);
                    if !s.is_empty() {
                        texts.insert(jxr_tag_name(tag).into(), json!(s));
                    }
                }
            }
            0xbcc4 => cx.format_set("image_type", int()),
            _ => {}
        }
    }
    let (Some(w), Some(hh)) = (w, hh) else {
        return Err(ExtractError::malformed("no image width / height tags"));
    };
    let mut img = cx.physical().image(w, hh);
    if let Some(c) = texts.remove("_channels").and_then(|v| v.as_u64()) {
        img.channels(u8::try_from(c).unwrap_or(0));
    }
    if let Some(b) = texts.remove("_bits").and_then(|v| v.as_u64()) {
        img.bit_depth(u8::try_from(b).unwrap_or(0));
    }
    if let (Some(x), Some(y)) =
        (texts.remove("_xres").and_then(|v| v.as_f64()), texts.remove("_yres").and_then(|v| v.as_f64()))
        && x > 0.0
        && y > 0.0
    {
        img.dpi(x, y);
    }
    if let Some(a) = texts.get("artist").and_then(Value::as_str) {
        cx.content().source("jxr.artist").author(a);
    }
    if let Some(c) = texts.get("copyright").and_then(Value::as_str) {
        cx.rights().source("jxr.copyright").copyright(c);
    }
    if let Some(d) = texts.get("image_description").and_then(Value::as_str) {
        cx.content().source("jxr.image_description").description(d);
    }
    if !texts.is_empty() {
        cx.format_set("tags", Value::Object(texts));
    }
    cx.format_set("version", if h[3] == 0 { "HD Photo 0" } else { "1" });
    Ok(())
}

fn jxr_tag_name(tag: u16) -> &'static str {
    match tag {
        0x010d => "document_name",
        0x010e => "image_description",
        0x010f => "make",
        0x0110 => "model",
        0x011d => "page_name",
        0x0131 => "software",
        0x0132 => "date_time",
        0x013b => "artist",
        0x013c => "host_computer",
        _ => "copyright",
    }
}

// ---- Photo CD -----------------------------------------------------------------------

fn photo_cd(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    if src.head().starts_with(b"PCD_OPA") {
        cx.format_set("kind", "overview pack");
        let h = src.head();
        if h.len() >= 12 {
            cx.format_set("images", u16::from_be_bytes([h[10], h[11]]));
        }
        return Ok(());
    }
    let h = read_at(src, 2048, 2048)?;
    if !h.starts_with(b"PCD_IPI") || h.len() < 1540 {
        return Err(ExtractError::malformed("no image pack information"));
    }
    cx.format_set("kind", "image pack");
    let s = |at: usize, n: usize| {
        let t = truncate_chars(latin1_or_utf8(&h[at..at + n]).trim_matches(['\0', ' ']), 200);
        (!t.is_empty()).then_some(t)
    };
    let be32 = |at: usize| u32::from_be_bytes([h[at], h[at + 1], h[at + 2], h[at + 3]]);
    cx.format_set("version", format!("{}.{}", h[7], h[8]));
    let scanned = be32(0x0b);
    if scanned > 0
        && let Some(t) = super::super::archive::unix_time(i64::from(scanned))
    {
        cx.temporal().source("pcd.scan_time").content_date(DateField::Digitized, t, true);
    }
    cx.format_set(
        "medium",
        match h[0x13] {
            0 => "colour negative",
            1 => "colour reversal",
            2 => "colour hard copy",
            3 => "thermal hard copy",
            4 => "black-and-white negative",
            5 => "black-and-white reversal",
            6 => "black-and-white hard copy",
            7 => "internegative",
            8 => "synthetic image",
            _ => "unknown",
        },
    );
    for (k, at, n) in [
        ("product_type", 0x14, 20),
        ("scanner_vendor", 0x28, 20),
        ("scanner_product", 0x3c, 16),
        ("photofinisher", 0xa3, 60),
    ] {
        if let Some(v) = s(at, n) {
            cx.format_set(k, v);
        }
    }
    // Image attributes (offset 0x602): rotation in bits 0–1, highest resolution in bits 2–3.
    let attr = h[0x602];
    let rotation = u32::from(attr & 3) * 90;
    let (base_w, base_h) = (768u32, 512u32);
    let scale = match (attr >> 2) & 3 {
        0 => 1,
        1 => 2,
        _ => 4,
    };
    let (w, hh) = if rotation % 180 == 0 { (base_w * scale, base_h * scale) } else { (base_h * scale, base_w * scale) };
    cx.physical().image(w, hh).channels(3).bit_depth(8).color_space("PhotoYCC");
    cx.format_set("rotation", rotation);
    cx.format_set(
        "max_resolution",
        match scale {
            1 => "Base",
            2 => "4Base",
            _ => "16Base",
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        let mut r = ByteReader::new(&[0x81, 0x00, 0x7f]);
        assert_eq!(varint(&mut r).unwrap(), 128);
        assert_eq!(varint(&mut r).unwrap(), 127);
        assert!(varint(&mut ByteReader::new(&[0xff; 10])).is_err());
        assert_eq!(wic_pixel_format(0x0d).map(|p| p.0), Some("24bppRGB"));
    }

    crate::fixture_tests!("flif", "bpg", "jxr", "photo_cd");
}
