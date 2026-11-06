//! Legacy and minor raster formats, header only:
//! * Amiga IFF ILBM / PBM (and ANIM sequences): size, planes, masking,
//!   compression, aspect, page size, palette, display mode (HAM, EHB),
//!   and the `NAME` / `AUTH` / `(c) ` / `ANNO` text chunks;
//! * `MacPaint` (bare or `MacBinary`-wrapped): version, the original name;
//! * `CompuServe` RLE and Utah RLE;
//! * Sun Raster, SGI image (with its name field), X11 XBM and XPM,
//!   WAP WBMP, farbfeld;
//! * Apple PICT (version 1 / 2 / extended 2: frame and resolution);
//! * DCX multi-page PCX: page count and the first page;
//! * Apple ICNS: every icon element with its pixel size and encoding;
//! * Windows animated cursors (`.ani`): frames, steps, rate, title, artist.
//!
//! References: EA IFF 85 and the ILBM specification (Commodore-Amiga);
//! Apple Technical Note PT24 (`MacPaint`), Inside Macintosh: Imaging With
//! `QuickDraw` (PICT); `CompuServe` "RLE" (1985); Utah Raster Toolkit
//! `rle(5)`; Sun `rasterfile(5)`; SGI "The SGI Image File Format" 1.00;
//! X11 Xlib §16.9 (XBM), XPM 3.4i manual; WAP-237 WBMP; suckless farbfeld;
//! ZSoft DCX; the `IconFamily` resource (`icns`) as documented by Apple's
//! `IconServices` headers; Microsoft "ANI file format" (RIFF `ACON`).

use serde_json::{Map, Value, json};

use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    latin1_or_utf8, truncate_chars,
};

/// Extractor for legacy raster formats.
pub struct Retro;

const fn raster(
    id: &'static str,
    name: &'static str,
    mimes: &'static [&'static str],
    extensions: &'static [&'static str],
    magic: &'static [Magic],
) -> FormatSpec {
    FormatSpec { id, name, family: "image.raster", mimes, extensions, magic, parent: None }
}

static META: ExtractorMeta = ExtractorMeta {
    id: "image.retro",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        raster(
            "ilbm",
            "Amiga IFF ILBM image",
            &["image/x-ilbm", "image/x-iff"],
            &["iff", "ilbm", "lbm"],
            &[Magic::at(8, b"ILBM"), Magic::at(8, b"PBM "), Magic::at(8, b"ACBM"), Magic::at(8, b"ANIM")],
        ),
        // Bare files have no signature and MacBinary ones a type code: both found by `sniff`.
        raster("macpaint", "MacPaint image", &["image/x-macpaint"], &["mac", "pntg", "pnt"], &[]),
        raster("compuserve_rle", "CompuServe RLE image", &[], &["rle"], &[]),
        raster("utah_rle", "Utah RLE image", &["image/x-rle"], &["rle", "urt"], &[Magic::prefix(b"\x52\xcc")]),
        raster(
            "sun_raster",
            "Sun Raster image",
            &["image/x-sun-raster"],
            &["ras", "sun", "rs", "im1", "im8", "im24", "im32"],
            &[Magic::prefix(b"\x59\xa6\x6a\x95")],
        ),
        raster(
            "sgi",
            "SGI image",
            &["image/x-sgi", "image/x-rgb"],
            &["sgi", "rgb", "rgba", "bw", "int", "inta"],
            &[Magic::masked(0, b"\x01\xda\x00\x01", b"\xff\xff\xfe\xfc")],
        ),
        raster("xbm", "X11 bitmap (XBM)", &["image/x-xbitmap"], &["xbm"], &[]),
        raster("xpm", "X11 pixmap (XPM)", &["image/x-xpixmap"], &["xpm"], &[Magic::prefix(b"/* XPM */")]),
        raster("wbmp", "WAP bitmap (WBMP)", &["image/vnd.wap.wbmp"], &["wbmp"], &[]),
        raster("farbfeld", "farbfeld image", &["image/x-farbfeld"], &["ff"], &[Magic::prefix(b"farbfeld")]),
        raster("pict", "Apple PICT image", &["image/x-pict"], &["pict", "pct", "pic"], &[]),
        raster("dcx", "DCX multi-page PCX", &["image/x-dcx"], &["dcx"], &[Magic::prefix(b"\xb1\x68\xde\x3a")]),
        raster("icns", "Apple icon image (ICNS)", &["image/x-icns"], &["icns"], &[Magic::prefix(b"icns")]),
        raster(
            "ani",
            "Windows animated cursor",
            &["application/x-navi-animation"],
            &["ani"],
            &[Magic::masked(0, b"RIFF\0\0\0\0ACON", b"\xff\xff\xff\xff\0\0\0\0\xff\xff\xff\xff")],
        ),
    ],
};

const MAX_LISTED: usize = 100;
/// IFF / RIFF / ICNS chunks walked at most.
const MAX_CHUNKS: usize = 10_000;
/// Bytes of chunk structure read at most (text chunks, palettes, ICNS directory).
const MAX_READ: u64 = 4 << 20;

impl Extractor for Retro {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or("");
        let hit = |format| Some(Sniff { format, confidence: 0.9 });
        if h.starts_with(b"\x1bG") && matches!(h.get(2), Some(b'H' | b'M')) && ext == "rle" {
            return hit("compuserve_rle");
        }
        if text_start(h).starts_with("#define ") && text_start(h).contains("_width ") {
            return hit("xbm");
        }
        if matches!(ext, "wbmp") && h.len() >= 4 && h[0] == 0 && h[1] == 0 {
            return hit("wbmp");
        }
        if matches!(ext, "pict" | "pct" | "pic") && pict_version_at(h).is_some() {
            return hit("pict");
        }
        if h.len() >= 128 && h[0] == 0 && h.get(65..69) == Some(b"PNTG") {
            return Some(Sniff { format: "macpaint", confidence: 0.95 });
        }
        if matches!(ext, "mac" | "pntg" | "pnt") && h.len() >= 512 && matches!(h[..4], [0, 0, 0, 0 | 2 | 3]) {
            return hit("macpaint");
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.head().to_vec();
        match cx.format_id() {
            "ilbm" => ilbm(src, cx),
            "macpaint" => macpaint(&head, cx),
            "compuserve_rle" => compuserve(&head, cx),
            "utah_rle" => utah(&head, cx),
            "sun_raster" => sun(&head, cx),
            "sgi" => sgi(&head, cx),
            "xbm" => xbm(&head, cx),
            "xpm" => xpm(&head, cx),
            "wbmp" => wbmp(&head, cx),
            "farbfeld" => farbfeld(&head, cx),
            "pict" => pict(&head, cx),
            "dcx" => dcx(src, cx),
            "icns" => icns(src, cx),
            "ani" => ani(src, cx),
            other => Err(ExtractError::Unsupported(format!("format {other}"))),
        }
    }
}

crate::register_extractor!(Retro);

fn text_start(h: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(&h[..h.len().min(2048)])
}

fn text(b: &[u8]) -> String {
    truncate_chars(latin1_or_utf8(b).trim_matches(|c: char| c == '\0' || c.is_whitespace()), 2000)
}

/// Read an IFF / RIFF chunk walk's bytes: the whole file up to `MAX_READ`.
fn read_capped(src: &mut dyn Source) -> Result<Vec<u8>, ExtractError> {
    let n = src.len().min(MAX_READ);
    Ok(src.read_vec(0, usize::try_from(n).unwrap_or(0))?)
}

// ---- IFF ILBM -----------------------------------------------------------------

/// The chunks of an IFF `FORM` body (big-endian sizes, padded to even).
fn iff_chunks(d: &[u8]) -> impl Iterator<Item = ([u8; 4], &[u8])> {
    let mut at = 0usize;
    std::iter::from_fn(move || {
        let id: [u8; 4] = d.get(at..at + 4)?.try_into().ok()?;
        let len = u32::from_be_bytes(d.get(at + 4..at + 8)?.try_into().ok()?) as usize;
        let body = d.get(at + 8..at + 8 + len).unwrap_or_else(|| &d[(at + 8).min(d.len())..]);
        at = at.saturating_add(8 + len + (len & 1));
        Some((id, body))
    })
    .take(MAX_CHUNKS)
}

fn ilbm(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let d = read_capped(src)?;
    if !d.starts_with(b"FORM") || d.len() < 12 {
        return Err(ExtractError::malformed("no IFF FORM header"));
    }
    let form = &d[8..12];
    cx.format_set("form", String::from_utf8_lossy(form).trim_end().to_string());
    if form == b"ANIM" {
        // A sequence of FORM ILBM frames: the first carries the header.
        let frames: Vec<&[u8]> =
            iff_chunks(&d[12..]).filter(|(id, b)| id == b"FORM" && b.starts_with(b"ILBM")).map(|(_, b)| b).collect();
        let first = frames.first().ok_or_else(|| ExtractError::malformed("ANIM without ILBM frames"))?;
        ilbm_body(&first[4..], cx)?;
        if let Some(mut img) = cx.physical().existing_image() {
            img.frames(u32::try_from(frames.len()).unwrap_or(u32::MAX));
        }
        return Ok(());
    }
    ilbm_body(&d[12..], cx)
}

fn ilbm_body(body: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut seen_header = false;
    for (id, b) in iff_chunks(body) {
        match &id {
            b"BMHD" => {
                let mut r = ByteReader::new(b);
                let (w, h) = (r.be_u16()?, r.be_u16()?);
                r.advance(4)?;
                let (planes, masking, compression) = (r.u8()?, r.u8()?, r.u8()?);
                r.advance(1)?;
                let transparent = r.be_u16()?;
                let (xa, ya) = (r.u8()?, r.u8()?);
                let (pw, ph) = (r.be_i16()?, r.be_i16()?);
                let mut img = cx.physical().image(u32::from(w), u32::from(h));
                // 24 / 32 planes are true colour (8 bits per channel); fewer index a palette.
                match planes {
                    24 | 32 => img.channels(planes / 8).bit_depth(8),
                    p => img.channels(1).bit_depth(p),
                };
                cx.format_set("planes", planes);
                cx.format_set(
                    "masking",
                    match masking {
                        0 => "none",
                        1 => "mask plane",
                        2 => "transparent colour",
                        3 => "lasso",
                        _ => "unknown",
                    },
                );
                if masking == 2 {
                    cx.format_set("transparent_color", transparent);
                }
                cx.format_set(
                    "compression",
                    match compression {
                        0 => "none",
                        1 => "ByteRun1",
                        2 => "VDAT",
                        _ => "unknown",
                    },
                );
                if xa > 0 && ya > 0 {
                    cx.format_set("pixel_aspect", json!([xa, ya]));
                }
                if pw > 0 && ph > 0 {
                    cx.format_set("page_size", json!([pw, ph]));
                }
                seen_header = true;
            }
            b"CMAP" => cx.format_set("palette_colors", b.len() / 3),
            b"CAMG" if b.len() >= 4 => {
                let mode = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                let mut flags = Vec::new();
                for (bit, name) in [(0x800, "HAM"), (0x80, "EHB"), (0x8000, "hires"), (0x4, "interlace")] {
                    if mode & bit != 0 {
                        flags.push(name);
                    }
                }
                cx.format_set("display_mode", json!({ "id": mode, "flags": flags }));
            }
            b"NAME" => {
                cx.content().source("iff.NAME").title(text(b));
            }
            b"AUTH" => {
                cx.content().source("iff.AUTH").author(text(b));
            }
            b"(c) " => {
                cx.rights().source("iff.(c)").copyright(text(b));
            }
            b"ANNO" => {
                cx.content().source("iff.ANNO").description(text(b));
            }
            _ => {}
        }
    }
    if !seen_header {
        return Err(ExtractError::malformed("no BMHD chunk"));
    }
    Ok(())
}

// ---- MacPaint ------------------------------------------------------------------

fn macpaint(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut at = 0;
    if h.len() >= 128 && h[0] == 0 && h.get(65..69) == Some(b"PNTG") {
        let n = usize::from(h[1]).min(63);
        cx.format_set("macbinary_name", text(&h[2..2 + n]));
        at = 128;
    }
    let v = h.get(at..at + 4).ok_or(ExtractError::Truncated { offset: at as u64, needed: 4 })?;
    let version = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
    if version > 3 {
        return Err(ExtractError::malformed(format!("version {version}")));
    }
    cx.format_set("version", version);
    cx.format_set("macbinary", at > 0);
    cx.physical().image(576, 720).bit_depth(1).channels(1);
    Ok(())
}

// ---- RLE -----------------------------------------------------------------------

fn compuserve(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let (w, hh, res) = match h.get(2) {
        Some(b'H') => (256, 192, "high"),
        Some(b'M') => (128, 96, "medium"),
        _ => return Err(ExtractError::malformed("no ESC G H / ESC G M header")),
    };
    cx.format_set("resolution", res);
    cx.physical().image(w, hh).bit_depth(1).channels(1);
    Ok(())
}

fn utah(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(h).skip(2)?;
    let (x, y, w, hh) = (r.le_i16()?, r.le_i16()?, r.le_u16()?, r.le_u16()?);
    let (flags, channels, bits, cmaps, cmap_len) = (r.u8()?, r.u8()?, r.u8()?, r.u8()?, r.u8()?);
    // Flags: 1 clear first, 2 no background, 4 alpha channel, 8 comments.
    let alpha = flags & 4 != 0;
    cx.physical().image(u32::from(w), u32::from(hh)).channels(channels + u8::from(alpha)).bit_depth(bits);
    cx.format_set("origin", json!([x, y]));
    cx.format_set("alpha", alpha);
    if cmaps > 0 {
        cx.format_set("colour_maps", json!({ "count": cmaps, "length": 1u32 << cmap_len.min(16) }));
    }
    Ok(())
}

// ---- Sun Raster, SGI, farbfeld, WBMP ------------------------------------------------

fn sun(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(h).skip(4)?;
    let (w, hh, depth, _len, kind, map_kind, map_len) =
        (r.be_u32()?, r.be_u32()?, r.be_u32()?, r.be_u32()?, r.be_u32()?, r.be_u32()?, r.be_u32()?);
    let mut img = cx.physical().image(w, hh);
    match depth {
        24 | 32 => img.channels(if depth == 32 { 4 } else { 3 }).bit_depth(8),
        d => img.channels(1).bit_depth(u8::try_from(d).unwrap_or(0)),
    };
    cx.format_set(
        "type",
        match kind {
            0 => "old",
            1 => "standard",
            2 => "byte-encoded",
            3 => "RGB",
            4 => "TIFF",
            5 => "IFF",
            0xffff => "experimental",
            _ => "unknown",
        },
    );
    if map_kind > 0 {
        cx.format_set("colour_map", json!({ "type": if map_kind == 1 { "RGB" } else { "raw" }, "bytes": map_len }));
    }
    Ok(())
}

fn sgi(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(h).skip(2)?;
    let (storage, bpc, dimension) = (r.u8()?, r.u8()?, r.be_u16()?);
    let (w, hh, z) = (r.be_u16()?, r.be_u16()?, r.be_u16()?);
    let (_min, _max) = (r.be_u32()?, r.be_u32()?);
    r.advance(4)?;
    let name = text(r.bytes(80)?);
    let colormap = r.be_u32()?;
    let channels = if dimension < 3 { 1 } else { z };
    cx.physical()
        .image(u32::from(w), if dimension == 1 { 1 } else { u32::from(hh) })
        .channels(u8::try_from(channels).unwrap_or(u8::MAX))
        .bit_depth(bpc.saturating_mul(8));
    cx.format_set("compression", if storage == 1 { "RLE" } else { "none" });
    cx.format_set("dimension", dimension);
    if !name.is_empty() {
        cx.format_set("name", name);
    }
    if colormap != 0 {
        cx.format_set(
            "colormap",
            match colormap {
                1 => "dithered",
                2 => "screen",
                3 => "colormap",
                _ => "unknown",
            },
        );
    }
    Ok(())
}

fn farbfeld(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(h).skip(8)?;
    let (w, hh) = (r.be_u32()?, r.be_u32()?);
    cx.physical().image(w, hh).channels(4).bit_depth(16).color_space("sRGB");
    Ok(())
}

/// A WBMP multi-byte integer: 7 bits per byte, high bit = more.
fn mb_int(r: &mut ByteReader<'_>) -> Result<u32, ExtractError> {
    let mut v = 0u32;
    for _ in 0..5 {
        let b = r.u8()?;
        v = (v << 7) | u32::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(ExtractError::malformed("multi-byte integer too long"))
}

fn wbmp(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(h);
    let kind = mb_int(&mut r)?;
    let fix = r.u8()?;
    if kind != 0 || fix & 0x9f != 0 {
        return Err(ExtractError::malformed(format!("type {kind}, header {fix:#x}")));
    }
    let (w, hh) = (mb_int(&mut r)?, mb_int(&mut r)?);
    if w == 0 || hh == 0 {
        return Err(ExtractError::malformed("zero size"));
    }
    cx.physical().image(w, hh).bit_depth(1).channels(1);
    cx.format_set("type", kind);
    Ok(())
}

// ---- XBM / XPM -----------------------------------------------------------------------

fn xbm(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let t = text_start(h);
    let mut vals = Map::new();
    let mut name = None;
    for line in t.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("#define") {
            continue;
        }
        let (Some(key), Some(v)) = (parts.next(), parts.next().and_then(|v| v.parse::<u32>().ok())) else { continue };
        for suffix in ["_width", "_height", "_x_hot", "_y_hot"] {
            if let Some(n) = key.strip_suffix(suffix) {
                name.get_or_insert_with(|| n.to_string());
                vals.insert(suffix[1..].to_string(), json!(v));
            }
        }
    }
    let get = |k: &str| vals.get(k).and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok());
    let (Some(w), Some(hh)) = (get("width"), get("height")) else {
        return Err(ExtractError::malformed("no _width / _height defines"));
    };
    cx.physical().image(w, hh).bit_depth(1).channels(1);
    if let Some(n) = name {
        cx.format_set("name", n);
    }
    if let (Some(x), Some(y)) = (get("x_hot"), get("y_hot")) {
        cx.format_set("hotspot", json!([x, y]));
    }
    cx.format_set("version", if t.contains(" short ") { "X10" } else { "X11" });
    Ok(())
}

fn xpm(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let t = text_start(h);
    if let Some(decl) = t.find("static").map(|i| &t[i..])
        && let Some(star) = decl.find('*')
    {
        let name: String =
            decl[star + 1..].trim_start().chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        if !name.is_empty() {
            cx.format_set("name", name);
        }
    }
    // The values string: the first quoted string after the declaration.
    let brace = t.find('{').ok_or_else(|| ExtractError::malformed("no array"))?;
    let rest = &t[brace..];
    let q = rest.find('"').ok_or_else(|| ExtractError::malformed("no values string"))?;
    let end = rest[q + 1..].find('"').ok_or_else(|| ExtractError::malformed("unterminated values string"))?;
    let nums: Vec<u32> = rest[q + 1..q + 1 + end].split_whitespace().filter_map(|v| v.parse().ok()).collect();
    let [w, hh, colors, cpp, ..] = nums[..] else {
        return Err(ExtractError::malformed("values string needs width, height, colours, chars per pixel"));
    };
    cx.physical().image(w, hh);
    cx.format_set("colors", colors);
    cx.format_set("chars_per_pixel", cpp);
    if let [_, _, _, _, x, y, ..] = nums[..] {
        cx.format_set("hotspot", json!([x, y]));
    }
    cx.format_set("extensions", rest[q + 1..q + 1 + end].contains("XPMEXT"));
    Ok(())
}

// ---- PICT ------------------------------------------------------------------------------

/// The PICT version and where the picture starts (after the optional 512-byte header).
fn pict_version_at(h: &[u8]) -> Option<(u8, usize)> {
    for at in [512, 0] {
        let Some(v) = h.get(at + 10..at + 14) else { continue };
        if v[..2] == [0x11, 0x01] {
            return Some((1, at));
        }
        if v == [0x00, 0x11, 0x02, 0xff] {
            return Some((2, at));
        }
    }
    None
}

fn pict(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let (version, at) = pict_version_at(h).ok_or_else(|| ExtractError::malformed("no version opcode"))?;
    let mut r = ByteReader::new(h).skip(at + 2)?;
    let (top, left, bottom, right) = (r.be_i16()?, r.be_i16()?, r.be_i16()?, r.be_i16()?);
    let w = u32::try_from(i32::from(right) - i32::from(left)).unwrap_or(0);
    let hh = u32::try_from(i32::from(bottom) - i32::from(top)).unwrap_or(0);
    let mut img = cx.physical().image(w, hh);
    let mut label = if version == 1 { "1" } else { "2" };
    if version == 2 {
        // Header opcode 0x0C00: version -1 (fixed-point bounds at 72 dpi) or -2 (resolution given).
        r.advance(4)?;
        if r.be_u16()? == 0x0c00 && r.be_i16()? == -2 {
            label = "2 extended";
            r.advance(2)?;
            let (hres, vres) = (r.be_u32()?, r.be_u32()?);
            img.dpi(f64::from(hres) / 65536.0, f64::from(vres) / 65536.0);
        }
    }
    cx.format_set("version", label);
    cx.format_set("header_512", at == 512);
    Ok(())
}

// ---- DCX ----------------------------------------------------------------------------------

fn dcx(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.head().to_vec();
    let mut r = ByteReader::new(&h).skip(4)?;
    let mut pages = Vec::new();
    for _ in 0..1023 {
        let o = r.le_u32()?;
        if o == 0 {
            break;
        }
        pages.push(o);
    }
    let first = *pages.first().ok_or_else(|| ExtractError::malformed("no pages"))?;
    let mut p = [0u8; 70];
    src.read_exact_at(u64::from(first), &mut p)?;
    if p[0] != 0x0a {
        return Err(ExtractError::malformed("first page is not a PCX image"));
    }
    let mut r = ByteReader::new(&p).skip(3)?;
    let bits = r.u8()?;
    let (x0, y0, x1, y1) = (r.le_u16()?, r.le_u16()?, r.le_u16()?, r.le_u16()?);
    r.seek(65)?;
    let planes = r.u8()?;
    let mut img = cx.physical().image(u32::from(x1.saturating_sub(x0)) + 1, u32::from(y1.saturating_sub(y0)) + 1);
    img.bit_depth(bits).channels(planes).frames(u32::try_from(pages.len()).unwrap_or(u32::MAX));
    cx.physical().pages(pages.len() as u64);
    Ok(())
}

// ---- ICNS ----------------------------------------------------------------------------------

/// Pixel size (square) and kind of an ICNS element type.
fn icns_type(t: &[u8]) -> Option<(u32, &'static str)> {
    Some(match t {
        b"ICON" | b"ICN#" => (32, "1-bit"),
        b"icm#" | b"ics#" => (16, "1-bit"),
        b"icl4" => (32, "4-bit"),
        b"icl8" => (32, "8-bit"),
        b"ics4" => (16, "4-bit"),
        b"ics8" => (16, "8-bit"),
        b"is32" => (16, "RGB"),
        b"il32" => (32, "RGB"),
        b"ih32" => (48, "RGB"),
        b"it32" => (128, "RGB"),
        b"s8mk" => (16, "mask"),
        b"l8mk" => (32, "mask"),
        b"h8mk" => (48, "mask"),
        b"t8mk" => (128, "mask"),
        b"icp4" => (16, "compressed"),
        b"icp5" | b"ic11" => (32, "compressed"),
        b"icp6" | b"ic12" => (64, "compressed"),
        b"ic07" => (128, "compressed"),
        b"ic08" | b"ic13" => (256, "compressed"),
        b"ic09" | b"ic14" => (512, "compressed"),
        b"ic10" => (1024, "compressed"),
        b"icsb" => (18, "compressed"),
        b"icsB" => (36, "compressed"),
        b"sb24" => (24, "compressed"),
        b"SB24" => (48, "compressed"),
        _ => return None,
    })
}

fn icns(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let d = read_capped(src)?;
    let total = d.get(4..8).map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    if u64::from(total) != src.len() {
        cx.warn(format!("header says {total} bytes, file has {}", src.len()));
    }
    let mut at = 8usize;
    let mut icons = Vec::new();
    let mut largest = 0;
    while at + 8 <= d.len() && icons.len() < MAX_LISTED {
        let kind = &d[at..at + 4];
        let len = u32::from_be_bytes([d[at + 4], d[at + 5], d[at + 6], d[at + 7]]) as usize;
        if len < 8 {
            cx.warn(format!("element at {at} has length {len}"));
            break;
        }
        let body = &d[(at + 8).min(d.len())..(at + len).min(d.len())];
        let name = String::from_utf8_lossy(kind).to_string();
        match kind {
            b"TOC " | b"icnV" | b"name" | b"info" => {
                if kind == b"icnV" && body.len() >= 4 {
                    cx.format_set("version", f64::from(f32::from_be_bytes([body[0], body[1], body[2], body[3]])));
                }
            }
            _ => {
                let mut e = Map::new();
                e.insert("type".into(), json!(name));
                if let Some((px, k)) = icns_type(kind) {
                    let enc = if body.starts_with(b"\x89PNG") {
                        "PNG"
                    } else if body.starts_with(b"\0\0\0\x0cjP  ") || body.starts_with(b"\xff\x4f\xff\x51") {
                        "JPEG 2000"
                    } else if body.starts_with(b"ARGB") {
                        "ARGB"
                    } else {
                        k
                    };
                    e.insert("size".into(), json!(px));
                    e.insert("encoding".into(), json!(enc));
                    if k != "mask" {
                        largest = largest.max(px);
                    }
                }
                e.insert("bytes".into(), json!(len - 8));
                icons.push(Value::Object(e));
            }
        }
        at = at.saturating_add(len);
    }
    if icons.is_empty() {
        return Err(ExtractError::malformed("no icon elements"));
    }
    if largest > 0 {
        cx.physical().image(largest, largest);
    }
    cx.format_set("icons", Value::Array(icons));
    Ok(())
}

// ---- ANI -------------------------------------------------------------------------------------

/// The chunks of a RIFF body (little-endian sizes, padded to even).
fn riff_chunks(d: &[u8]) -> impl Iterator<Item = ([u8; 4], &[u8])> {
    let mut at = 0usize;
    std::iter::from_fn(move || {
        let id: [u8; 4] = d.get(at..at + 4)?.try_into().ok()?;
        let len = u32::from_le_bytes(d.get(at + 4..at + 8)?.try_into().ok()?) as usize;
        let body = d.get(at + 8..at + 8 + len).unwrap_or_else(|| &d[(at + 8).min(d.len())..]);
        at = at.saturating_add(8 + len + (len & 1));
        Some((id, body))
    })
    .take(MAX_CHUNKS)
}

fn ani(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let d = read_capped(src)?;
    let mut header = None;
    let mut icons = 0u32;
    let mut first_icon = None;
    let mut has_rate = false;
    let mut has_seq = false;
    for (id, b) in riff_chunks(d.get(12..).unwrap_or_default()) {
        match &id {
            b"anih" => header = Some(b),
            b"rate" => has_rate = true,
            b"seq " => has_seq = true,
            b"LIST" if b.starts_with(b"INFO") => {
                for (k, v) in riff_chunks(&b[4..]) {
                    match &k {
                        b"INAM" => {
                            cx.content().source("ani.INAM").title(text(v));
                        }
                        b"IART" => {
                            cx.content().source("ani.IART").author(text(v));
                        }
                        b"ICOP" => {
                            cx.rights().source("ani.ICOP").copyright(text(v));
                        }
                        _ => {}
                    }
                }
            }
            b"LIST" if b.starts_with(b"fram") => {
                for (k, v) in riff_chunks(&b[4..]) {
                    if &k == b"icon" {
                        icons += 1;
                        first_icon.get_or_insert(v);
                    }
                }
            }
            _ => {}
        }
    }
    let h = header.ok_or_else(|| ExtractError::malformed("no anih chunk"))?;
    let mut r = ByteReader::new(h).skip(4)?;
    let (frames, steps, w, hh, bits, _planes, rate, flags) =
        (r.le_u32()?, r.le_u32()?, r.le_u32()?, r.le_u32()?, r.le_u32()?, r.le_u32()?, r.le_u32()?, r.le_u32()?);
    // With the icon flag set, size and depth come from each frame's icon directory.
    let (mut w, mut hh, mut bits) = (w, hh, bits);
    if let Some(icon) = first_icon
        && icon.len() >= 22
        && icon[..4] == [0, 0, 2, 0]
    {
        let side = |b: u8| if b == 0 { 256 } else { u32::from(b) };
        (w, hh) = (side(icon[6]), side(icon[7]));
        if bits == 0 {
            bits = u32::from(u16::from_le_bytes([icon[12], icon[13]]));
        }
    }
    if w > 0 && hh > 0 {
        let mut img = cx.physical().image(w, hh);
        img.frames(frames);
        if bits > 0 {
            img.bit_depth(u8::try_from(bits).unwrap_or(u8::MAX));
        }
    }
    cx.format_set("frames", frames);
    cx.format_set("steps", steps);
    cx.format_set("icon_frames", icons);
    cx.format_set("default_rate_jiffies", rate);
    cx.format_set("per_step_rates", has_rate);
    cx.format_set("sequence", has_seq);
    cx.format_set("icon_flag", flags & 1 != 0);
    if !has_rate && rate > 0 {
        cx.physical().duration_s(f64::from(steps) * f64::from(rate) / 60.0);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wbmp_integers() {
        let mut r = ByteReader::new(&[0x81, 0x00, 0x05]);
        assert_eq!(mb_int(&mut r).unwrap(), 128);
        assert_eq!(mb_int(&mut r).unwrap(), 5);
        assert!(mb_int(&mut ByteReader::new(&[0xff; 6])).is_err());
    }

    #[test]
    fn pict_versions() {
        let mut h = vec![0u8; 512];
        h.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 10, 0, 20, 0x00, 0x11, 0x02, 0xff]);
        assert_eq!(pict_version_at(&h), Some((2, 512)));
        let v1 = [0u8, 0, 0, 0, 0, 0, 0, 10, 0, 20, 0x11, 0x01, 0, 0];
        assert_eq!(pict_version_at(&v1), Some((1, 0)));
    }

    crate::fixture_tests!(
        "ilbm",
        "macpaint",
        "compuserve_rle",
        "utah_rle",
        "sun_raster",
        "sgi",
        "xbm",
        "xpm",
        "wbmp",
        "farbfeld",
        "pict",
        "dcx",
        "icns",
        "ani"
    );
}
