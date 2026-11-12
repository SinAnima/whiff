//! GPU texture containers, header only:
//! * ASTC (`.astc`, ARM's container): block footprint and size;
//! * Basis Universal (`.basis`): codec (ETC1S / UASTC), texture type,
//!   images, slices, mip levels, the first image's size, alpha, Y flip,
//!   video frame rate;
//! * `PowerVR` (`.pvr`, versions 2 and 3): pixel format (compressed codec or
//!   channel layout), colour space, channel type, size, depth, surfaces,
//!   faces, mip levels and the metadata keys;
//! * Valve VTF (`.vtf`, versions 7.0–7.5): size, frames, format of the
//!   high- and low-resolution images, mip levels, flags (cube map,
//!   normal map, alpha), depth, reflectivity, resources.
//!
//! References: ARM `astc-encoder` "File format" (`.astc` header); Binomial
//! `basisu_file_headers.h`; Imagination "PVR File Format Specification"
//! (v3, and the legacy v2 header); Valve Developer Community "VTF (Valve
//! Texture Format)".

use serde_json::{Value, json};

use crate::plugin::{ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for ASTC, Basis, PVR and VTF textures.
pub struct Textures;

const fn texture(
    id: &'static str,
    name: &'static str,
    ext: &'static [&'static str],
    magic: &'static [Magic],
) -> FormatSpec {
    FormatSpec { id, name, family: "image.texture", mimes: &[], extensions: ext, magic, parent: None }
}

static META: ExtractorMeta = ExtractorMeta {
    id: "image.textures",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            mimes: &["image/astc"],
            ..texture("astc", "ASTC texture", &["astc"], &[Magic::prefix(b"\x13\xab\xa1\x5c")])
        },
        texture(
            "basis",
            "Basis Universal texture",
            &["basis"],
            &[Magic::masked(0, b"sB\0\0\x4d\0", b"\xff\xff\0\0\xff\xff")],
        ),
        texture(
            "pvr",
            "PowerVR texture",
            &["pvr"],
            &[Magic::prefix(b"PVR\x03"), Magic::prefix(b"\x03RVP"), Magic::at(44, b"PVR!")],
        ),
        FormatSpec {
            mimes: &["image/vnd.valve.source.texture"],
            ..texture("vtf", "Valve texture (VTF)", &["vtf"], &[Magic::prefix(b"VTF\0")])
        },
    ],
};

impl Extractor for Textures {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let h = src.head().to_vec();
        match cx.format_id() {
            "astc" => astc(&h, cx),
            "basis" => basis(src, &h, cx),
            "pvr" => pvr(&h, cx),
            "vtf" => vtf(&h, cx),
            other => Err(ExtractError::Unsupported(format!("format {other}"))),
        }
    }
}

crate::register_extractor!(Textures);

fn u24(b: &[u8]) -> u32 {
    u32::from(b[0]) | u32::from(b[1]) << 8 | u32::from(b[2]) << 16
}

fn astc(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let b = h.get(4..16).ok_or(ExtractError::Truncated { offset: 4, needed: 12 })?;
    let (bx, by, bz) = (b[0], b[1], b[2]);
    let (w, hh, d) = (u24(&b[3..6]), u24(&b[6..9]), u24(&b[9..12]));
    if bx == 0 || by == 0 || bz == 0 {
        return Err(ExtractError::malformed("zero block size"));
    }
    cx.physical().image(w, hh);
    cx.format_set("block", if bz > 1 { format!("{bx}x{by}x{bz}") } else { format!("{bx}x{by}") });
    cx.format_set("depth", d);
    #[allow(clippy::cast_precision_loss)]
    cx.format_set("bits_per_pixel", 128.0 / f64::from(u32::from(bx) * u32::from(by) * u32::from(bz)));
    Ok(())
}

fn basis(src: &mut dyn Source, h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(h).skip(2)?;
    let version = r.le_u16()?;
    let header_size = r.le_u16()?;
    if header_size < 77 {
        return Err(ExtractError::malformed(format!("header size {header_size}")));
    }
    r.advance(2 + 4 + 2)?;
    let slices = u24(r.bytes(3)?);
    let images = u24(r.bytes(3)?);
    let codec = r.u8()?;
    let flags = r.le_u16()?;
    let kind = r.u8()?;
    let us_per_frame = u24(r.bytes(3)?);
    r.seek(65)?;
    let slice_desc = u64::from(r.le_u32()?);
    cx.format_set("version", format!("{version:#x}"));
    cx.format_set(
        "codec",
        match codec {
            0 => "ETC1S",
            1 => "UASTC 4x4",
            2 => "UASTC HDR 4x4",
            _ => "unknown",
        },
    );
    cx.format_set(
        "texture_type",
        match kind {
            0 => "2D",
            1 => "2D array",
            2 => "cube map array",
            3 => "video frames",
            4 => "volume",
            _ => "unknown",
        },
    );
    cx.format_set("images", images);
    cx.format_set("slices", slices);
    cx.format_set("alpha", flags & 4 != 0);
    cx.format_set("y_flipped", flags & 2 != 0);
    if kind == 3 && us_per_frame > 0 {
        cx.format_set("frame_rate", 1e6 / f64::from(us_per_frame));
    }
    // Slice descriptors: 23 bytes each; the first gives the base image's size.
    let n = usize::try_from(slices.min(4096)).unwrap_or(0);
    let descs = src.read_vec(slice_desc, n * 23).unwrap_or_default();
    let mut levels = 0u32;
    for d in descs.as_chunks::<23>().0 {
        levels = levels.max(u32::from(d[3]) + 1);
    }
    if let Some(d) = descs.get(..23) {
        let (w, hh) = (u16::from_le_bytes([d[5], d[6]]), u16::from_le_bytes([d[7], d[8]]));
        let mut img = cx.physical().image(u32::from(w), u32::from(hh));
        img.frames(images);
    }
    cx.format_set("mip_levels", levels);
    Ok(())
}

fn pvr_compressed(v: u32) -> Option<&'static str> {
    Some(match v {
        0 => "PVRTC 2bpp RGB",
        1 => "PVRTC 2bpp RGBA",
        2 => "PVRTC 4bpp RGB",
        3 => "PVRTC 4bpp RGBA",
        4 => "PVRTC-II 2bpp",
        5 => "PVRTC-II 4bpp",
        6 => "ETC1",
        7 => "BC1 (DXT1)",
        8 => "DXT2",
        9 => "BC2 (DXT3)",
        10 => "DXT4",
        11 => "BC3 (DXT5)",
        12 => "BC4",
        13 => "BC5",
        14 => "BC6",
        15 => "BC7",
        16 => "UYVY",
        17 => "YUY2",
        18 => "BW 1bpp",
        19 => "R9G9B9E5",
        20 => "RGBG8888",
        21 => "GRGB8888",
        22 => "ETC2 RGB",
        23 => "ETC2 RGBA",
        24 => "ETC2 RGB A1",
        25 => "EAC R11",
        26 => "EAC RG11",
        27 => "ASTC 4x4",
        28 => "ASTC 5x4",
        29 => "ASTC 5x5",
        30 => "ASTC 6x5",
        31 => "ASTC 6x6",
        32 => "ASTC 8x5",
        33 => "ASTC 8x6",
        34 => "ASTC 8x8",
        35 => "ASTC 10x5",
        36 => "ASTC 10x6",
        37 => "ASTC 10x8",
        38 => "ASTC 10x10",
        39 => "ASTC 12x10",
        40 => "ASTC 12x12",
        _ => return None,
    })
}

fn pvr(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    if h.get(44..48) == Some(b"PVR!") {
        return pvr2(h, cx);
    }
    let big = h.starts_with(b"\x03RVP");
    let mut v = [0u32; 12];
    for (i, b) in
        h.get(4..52).ok_or(ExtractError::Truncated { offset: 4, needed: 48 })?.as_chunks::<4>().0.iter().enumerate()
    {
        v[i] = if big { u32::from_be_bytes(*b) } else { u32::from_le_bytes(*b) };
    }
    let [flags, lo, hi, space, channel_type, hh, w, depth, surfaces, faces, mips, meta_len] = v;
    let mut img = cx.physical().image(w, hh);
    if hi == 0 {
        cx.format_set("pixel_format", pvr_compressed(lo).map_or_else(|| json!(lo), |n| json!(n)));
    } else {
        // Uncompressed: channel names (low 4 bytes) and bits per channel (high 4 bytes).
        let names: String = lo.to_le_bytes().iter().filter(|&&c| c != 0).map(|&c| char::from(c)).collect();
        let bits: Vec<u8> = hi.to_le_bytes().into_iter().filter(|&b| b != 0).collect();
        img.channels(u8::try_from(names.len()).unwrap_or(0));
        if let Some(&b) = bits.iter().max() {
            img.bit_depth(b);
        }
        let layout = names.chars().zip(&bits).fold(String::new(), |mut s, (c, b)| {
            use std::fmt::Write;
            let _ = write!(s, "{c}{b}");
            s
        });
        cx.format_set("pixel_format", layout);
    }
    cx.format_set("color_space", if space == 1 { "sRGB" } else { "linear" });
    cx.format_set(
        "channel_type",
        match channel_type {
            0 => "unsigned byte normalised",
            1 => "signed byte normalised",
            2 => "unsigned byte",
            3 => "signed byte",
            4 => "unsigned short normalised",
            5 => "signed short normalised",
            6 => "unsigned short",
            7 => "signed short",
            8 => "unsigned int normalised",
            9 => "signed int normalised",
            10 => "unsigned int",
            11 => "signed int",
            12 => "float",
            _ => "unknown",
        },
    );
    cx.format_set("premultiplied", flags & 2 != 0);
    cx.format_set("depth", depth);
    cx.format_set("surfaces", surfaces);
    cx.format_set("faces", faces);
    cx.format_set("mip_levels", mips);
    // Metadata blocks: FourCC, key, size, data.
    let meta = h.get(52..52 + meta_len as usize).unwrap_or_default();
    let mut m = ByteReader::new(meta);
    let mut keys = Vec::new();
    while m.remaining() >= 12 && keys.len() < 64 {
        let cc = m.array::<4>()?;
        let key = if big { m.be_u32()? } else { m.le_u32()? };
        let size = if big { m.be_u32()? } else { m.le_u32()? } as usize;
        m.advance(size.min(m.remaining()))?;
        let name = match (&cc, key) {
            (b"PVR\x03", 0) => "texture atlas".to_string(),
            (b"PVR\x03", 1) => "bump data".to_string(),
            (b"PVR\x03", 2) => "cube map order".to_string(),
            (b"PVR\x03", 3) => "orientation".to_string(),
            (b"PVR\x03", 4) => "border".to_string(),
            (b"PVR\x03", 5) => "padding".to_string(),
            _ => format!("{}:{key}", String::from_utf8_lossy(&cc).trim_end_matches('\0')),
        };
        keys.push(json!(name));
    }
    if !keys.is_empty() {
        cx.format_set("metadata", Value::Array(keys));
    }
    cx.format_set("version", 3);
    Ok(())
}

fn pvr2(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(h);
    let (_size, hh, w, mips, flags, _data, bpp) =
        (r.le_u32()?, r.le_u32()?, r.le_u32()?, r.le_u32()?, r.le_u32()?, r.le_u32()?, r.le_u32()?);
    r.seek(48)?;
    let surfaces = r.le_u32()?;
    let kind = flags & 0xff;
    cx.physical().image(w, hh);
    cx.format_set("version", 2);
    cx.format_set(
        "pixel_format",
        match kind {
            0x10 => json!("ARGB4444"),
            0x11 => json!("ARGB1555"),
            0x12 => json!("RGB565"),
            0x13 => json!("RGB555"),
            0x14 => json!("RGB888"),
            0x15 => json!("ARGB8888"),
            0x18 => json!("PVRTC 2bpp"),
            0x19 => json!("PVRTC 4bpp"),
            0x1a => json!("BGRA8888"),
            0x20 => json!("BC1 (DXT1)"),
            0x22 => json!("BC2 (DXT3)"),
            0x24 => json!("BC3 (DXT5)"),
            0x36 => json!("ETC1"),
            _ => json!(kind),
        },
    );
    cx.format_set("bits_per_pixel", bpp);
    cx.format_set("mip_levels", mips + 1);
    cx.format_set("surfaces", surfaces);
    cx.format_set("cube_map", flags & 0x1000 != 0);
    Ok(())
}

fn vtf_format(v: i32) -> Value {
    json!(match v {
        -1 => "none",
        0 => "RGBA8888",
        1 => "ABGR8888",
        2 => "RGB888",
        3 => "BGR888",
        4 => "RGB565",
        5 => "I8",
        6 => "IA88",
        7 => "P8",
        8 => "A8",
        9 => "RGB888 bluescreen",
        10 => "BGR888 bluescreen",
        11 => "ARGB8888",
        12 => "BGRA8888",
        13 => "DXT1",
        14 => "DXT3",
        15 => "DXT5",
        16 => "BGRX8888",
        17 => "BGR565",
        18 => "BGRX5551",
        19 => "BGRA4444",
        20 => "DXT1 one-bit alpha",
        21 => "BGRA5551",
        22 => "UV88",
        23 => "UVWQ8888",
        24 => "RGBA16161616F",
        25 => "RGBA16161616",
        26 => "UVLX8888",
        _ => return json!(v),
    })
}

fn vtf(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(h).skip(4)?;
    let (major, minor) = (r.le_u32()?, r.le_u32()?);
    let _header = r.le_u32()?;
    let (w, hh) = (r.le_u16()?, r.le_u16()?);
    let flags = r.le_u32()?;
    let (frames, _first) = (r.le_u16()?, r.le_u16()?);
    r.advance(4)?;
    let refl = [r.le_u32()?, r.le_u32()?, r.le_u32()?].map(|b| f64::from(f32::from_bits(b)));
    r.advance(4)?;
    let _bump = r.le_u32()?;
    let hi = r.le_i32()?;
    let mips = r.u8()?;
    let lo = r.le_i32()?;
    let (lw, lh) = (r.u8()?, r.u8()?);
    let mut img = cx.physical().image(u32::from(w), u32::from(hh));
    img.frames(u32::from(frames));
    cx.format_set("version", format!("{major}.{minor}"));
    cx.format_set("format", vtf_format(hi));
    cx.format_set("low_res_format", vtf_format(lo));
    if lo != -1 {
        cx.format_set("low_res_size", json!([lw, lh]));
    }
    cx.format_set("mip_levels", mips);
    if refl.iter().all(|v| v.is_finite()) {
        cx.format_set("reflectivity", json!(refl));
    }
    let mut names = Vec::new();
    for (bit, name) in [
        (0x4000u32, "cube map"),
        (0x80, "normal map"),
        (0x100, "no mipmaps"),
        (0x1000, "one-bit alpha"),
        (0x2000, "eight-bit alpha"),
        (0x4, "clamp S"),
        (0x8, "clamp T"),
        (0x0080_0000, "SRGB"),
    ] {
        if flags & bit != 0 {
            names.push(name);
        }
    }
    cx.format_set("flags", json!(names));
    if major == 7 && minor >= 2 {
        cx.format_set("depth", r.le_u16()?);
    }
    if major == 7 && minor >= 3 {
        r.advance(3)?;
        let n = r.le_u32()?.min(32);
        r.advance(8)?;
        let mut res = Vec::new();
        for _ in 0..n {
            let tag = r.bytes(3)?;
            r.advance(5)?;
            res.push(json!(match tag {
                b"\x01\0\0" => "low-res image".to_string(),
                b"\x30\0\0" => "high-res image".to_string(),
                b"\x10\0\0" => "particle sheet".to_string(),
                _ => String::from_utf8_lossy(tag).trim_end_matches('\0').to_string(),
            }));
        }
        cx.format_set("resources", Value::Array(res));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("astc", "basis", "pvr", "vtf");
}
