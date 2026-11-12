//! JPEG / JFIF / EXIF JPEG / MPO: frame header (size, precision,
//! components, process, chroma subsampling), quality estimate from the
//! quantisation tables, JFIF and Adobe markers, comments, and the embedded
//! blocks: EXIF (APP1), XMP with extended XMP reassembled by GUID (APP1),
//! ICC reassembled from its chunks (APP2), MPF multi-picture index (APP2),
//! Photoshop resources (APP13) and C2PA Content Credentials (APP11 JUMBF).
//! Ultra HDR gain maps are recognised from the XMP and MPF. JPEG-LS files
//! (SOF55 frame header) are a format of their own with the same report.
//!
//! Specifications: ITU-T T.81, T.87 (JPEG-LS), JFIF 1.02, CIPA DC-007 (MPF), ISO 21496-1 gain maps.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::plugin::{
    BlockKind, ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff,
    Source, TextRole, squash_whitespace, truncate_chars,
};

/// Extractor for JPEG.
pub struct Jpeg;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.jpeg",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "jpeg",
            name: "JPEG image",
            family: "image.raster",
            mimes: &["image/jpeg"],
            extensions: &["jpg", "jpeg", "jpe", "jfif", "jif", "mpo"],
            magic: &[Magic::prefix(b"\xFF\xD8\xFF")],
            parent: None,
        },
        // Told apart from JPEG by its SOF55 frame header (`sniff`).
        FormatSpec {
            id: "jls",
            name: "JPEG-LS image",
            family: "image.raster",
            mimes: &["image/jls"],
            extensions: &["jls"],
            magic: &[],
            parent: Some("jpeg"),
        },
    ],
};

/// Segments examined before the scan starts.
const MAX_SEGMENTS: usize = 1024;
/// Bytes read for one segment (`APPn` segments are at most 64 KiB).
const MAX_SEGMENT: usize = 65_535;

impl Extractor for Jpeg {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        (frame_marker(probe.head)? == 0xF7).then_some(Sniff { format: "jls", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if !src.head().starts_with(b"\xFF\xD8") {
            return Err(ExtractError::Unsupported("JPEG".into()));
        }
        let mut s = Scan::default();
        let len = src.len();
        let mut pos = 2u64;
        for _ in 0..MAX_SEGMENTS {
            let Ok(head) = src.read_vec(pos, 4) else { break };
            if head[0] != 0xFF {
                s.warnings.push(format!("no marker at offset {pos}"));
                break;
            }
            let marker = head[1];
            match marker {
                0xFF => {
                    pos += 1; // fill byte
                    continue;
                }
                0x01 | 0xD0..=0xD7 => {
                    pos += 2;
                    continue;
                }
                0xD9 => break,
                _ => {}
            }
            let seg_len = u64::from(u16::from_be_bytes([head[2], head[3]]));
            if seg_len < 2 || pos + 2 + seg_len > len {
                s.warnings.push(format!("segment 0x{marker:02X} runs past the end"));
                break;
            }
            let body = src.read_vec(pos + 4, usize::try_from(seg_len - 2).unwrap_or(0).min(MAX_SEGMENT))?;
            s.segment(marker, &body);
            if marker == 0xDA {
                break;
            }
            pos += 2 + seg_len;
        }
        s.finish(cx);
        Ok(())
    }
}

crate::register_extractor!(Jpeg);

/// The first frame-header marker (`SOFn` or JPEG-LS `SOF55`) in the head window.
fn frame_marker(h: &[u8]) -> Option<u8> {
    if !h.starts_with(b"\xFF\xD8\xFF") {
        return None;
    }
    let mut at = 2;
    for _ in 0..MAX_SEGMENTS {
        let m = *h.get(at + 1)?;
        if h[at] != 0xFF {
            return None;
        }
        if matches!(m, 0xC0..=0xCF | 0xF7) && !matches!(m, 0xC4 | 0xC8 | 0xCC) {
            return Some(m);
        }
        if m == 0xDA || m == 0xD9 {
            return None;
        }
        at += 2 + usize::from(u16::from_be_bytes([*h.get(at + 2)?, *h.get(at + 3)?]));
    }
    None
}

/// Start of frame: marker, width, height, (sampling h, v) per component, precision.
type Sof = (u8, u16, u16, Vec<(u8, u8)>, u8);

#[derive(Default)]
struct Scan {
    segments: Vec<String>,
    sof: Option<Sof>,
    luma_table: Option<Vec<u16>>,
    jfif: Option<Value>,
    adobe_transform: Option<u8>,
    comments: Vec<String>,
    icc: BTreeMap<u8, Vec<u8>>,
    ext_xmp: BTreeMap<String, (u32, BTreeMap<u32, Vec<u8>>)>,
    xmp_ultra_hdr: bool,
    irb: Vec<u8>,
    mpf: Option<Value>,
    c2pa: bool,
    restart_interval: Option<u16>,
    huffman_tables: u32,
    /// Blocks in file order, emitted once the walk is done.
    pending: Vec<(BlockKind, Vec<u8>)>,
    warnings: Vec<String>,
}

impl Scan {
    fn segment(&mut self, marker: u8, b: &[u8]) {
        if self.segments.len() < 64 {
            self.segments.push(segment_name(marker, b));
        }
        match marker {
            0xC0..=0xCF | 0xF7 if !matches!(marker, 0xC4 | 0xC8 | 0xCC) => self.sof(marker, b),
            0xC4 => self.huffman_tables += 1,
            0xDB => self.dqt(b),
            0xDD if b.len() >= 2 => self.restart_interval = Some(u16::from_be_bytes([b[0], b[1]])),
            0xFE => {
                let c = squash_whitespace(&crate::plugin::decode_text(b).text);
                if !c.is_empty() && self.comments.len() < 16 {
                    self.comments.push(truncate_chars(&c, 1000));
                }
            }
            0xE0 if b.starts_with(b"JFIF\0") && b.len() >= 12 => {
                let units = b[7];
                let (x, y) = (u16::from_be_bytes([b[8], b[9]]), u16::from_be_bytes([b[10], b[11]]));
                self.jfif =
                    Some(json!({ "version": format!("{}.{:02}", b[5], b[6]), "units": units, "density": [x, y] }));
            }
            0xE1 => self.app1(b),
            0xE2 if b.starts_with(b"ICC_PROFILE\0") && b.len() > 14 => {
                self.icc.insert(b[12], b[14..].to_vec());
            }
            0xE2 if b.starts_with(b"MPF\0") => self.mpf = mpf(&b[4..]),
            0xEB if b.windows(4).any(|w| w == b"c2pa") => self.c2pa = true,
            0xED if b.starts_with(b"Photoshop 3.0\0") => self.irb.extend_from_slice(&b[14..]),
            0xED if !self.irb.is_empty() => self.irb.extend_from_slice(b),
            0xEE if b.starts_with(b"Adobe") && b.len() >= 12 => self.adobe_transform = Some(b[11]),
            _ => {}
        }
    }

    fn sof(&mut self, marker: u8, b: &[u8]) {
        if self.sof.is_some() || b.len() < 6 {
            return;
        }
        let precision = b[0];
        let h = u16::from_be_bytes([b[1], b[2]]);
        let w = u16::from_be_bytes([b[3], b[4]]);
        let n = usize::from(b[5]);
        let comps: Vec<(u8, u8)> = b[6..].as_chunks::<3>().0.iter().take(n).map(|c| (c[1] >> 4, c[1] & 0x0f)).collect();
        self.sof = Some((marker, w, h, comps, precision));
    }

    fn dqt(&mut self, b: &[u8]) {
        let mut r = ByteReader::new(b);
        while let Ok(pq_tq) = r.u8() {
            let (precision, id) = (pq_tq >> 4, pq_tq & 0x0f);
            let values: Vec<u16> = if precision == 0 {
                match r.bytes(64) {
                    Ok(v) => v.iter().map(|&x| u16::from(x)).collect(),
                    Err(_) => return,
                }
            } else {
                match r.bytes(128) {
                    Ok(v) => v.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect(),
                    Err(_) => return,
                }
            };
            if id == 0 && self.luma_table.is_none() {
                self.luma_table = Some(values);
            }
        }
    }

    fn app1(&mut self, b: &[u8]) {
        const XMP: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
        const EXT: &[u8] = b"http://ns.adobe.com/xmp/extension/\0";
        if b.starts_with(b"Exif\0") {
            self.pending.push((BlockKind::EXIF, b.to_vec()));
        } else if let Some(x) = b.strip_prefix(XMP) {
            let text = String::from_utf8_lossy(x);
            self.xmp_ultra_hdr |= text.contains("hdrgm:Version") || text.contains("Item:Semantic=\"GainMap\"");
            self.pending.push((BlockKind::XMP, x.to_vec()));
        } else if let Some(x) = b.strip_prefix(EXT)
            && x.len() > 40
        {
            let guid = String::from_utf8_lossy(&x[..32]).into_owned();
            let full = u32::from_be_bytes([x[32], x[33], x[34], x[35]]);
            let offset = u32::from_be_bytes([x[36], x[37], x[38], x[39]]);
            if self.ext_xmp.len() < 4 {
                let entry = self.ext_xmp.entry(guid).or_insert_with(|| (full, BTreeMap::new()));
                entry.1.insert(offset, x[40..].to_vec());
            }
        }
    }

    fn finish(mut self, cx: &mut Context<'_>) {
        for (kind, data) in std::mem::take(&mut self.pending) {
            cx.emit_block(kind, data);
        }
        if !self.icc.is_empty() {
            cx.emit_block(BlockKind::ICC, self.icc.values().flatten().copied().collect::<Vec<u8>>());
        }
        for (full, parts) in self.ext_xmp.values() {
            let joined: Vec<u8> = parts.values().flatten().copied().collect();
            if joined.len() as u64 == u64::from(*full) {
                cx.emit_block(BlockKind::XMP, joined);
                cx.format_set("extended_xmp", true);
            } else {
                cx.warn("extended XMP is incomplete");
            }
        }
        if !self.irb.is_empty() {
            cx.emit_block(BlockKind::PHOTOSHOP_IRB, std::mem::take(&mut self.irb));
        }

        if let Some((marker, w, h, comps, precision)) = &self.sof {
            let n = comps.len();
            let color = match (n, self.adobe_transform) {
                (1, _) => "Gray",
                (3, Some(0)) => "RGB",
                (3, _) => "YCbCr",
                (4, Some(2)) => "YCCK",
                (4, _) => "CMYK",
                _ => "unknown",
            };
            cx.physical()
                .image(u32::from(*w), u32::from(*h))
                .bit_depth(*precision)
                .channels(u8::try_from(n).unwrap_or(u8::MAX))
                .color_space(color);
            cx.format_set("process", process(*marker));
            cx.format_set("progressive", matches!(marker, 0xC2 | 0xC6 | 0xCA | 0xCE));
            if n == 3
                && let Some(s) = subsampling(comps)
            {
                cx.format_set("chroma_subsampling", s);
            }
        } else {
            cx.warn("no frame header (SOF) before the scan");
        }
        if let Some(q) = self.luma_table.as_deref().and_then(quality) {
            cx.format_set("quality_estimate", q);
        }
        if let Some(j) = self.jfif.take() {
            if let Some([x, y]) = j["density"].as_array().map(|a| [a[0].as_f64(), a[1].as_f64()])
                && let (Some(x), Some(y)) = (x, y)
                && x > 1.0
            {
                let k = match j["units"].as_u64() {
                    Some(1) => Some(1.0),
                    Some(2) => Some(2.54),
                    _ => None,
                };
                if let (Some(k), Some(mut img)) = (k, cx.physical().existing_image()) {
                    img.dpi(x * k, y * k);
                }
            }
            cx.format_set("jfif", j);
        }
        if let Some(t) = self.adobe_transform {
            cx.format_set("adobe_transform", t);
        }
        if let Some(r) = self.restart_interval {
            cx.format_set("restart_interval", r);
        }
        cx.format_set("huffman_tables", self.huffman_tables);
        if !self.comments.is_empty() {
            for c in &self.comments {
                cx.emit_text(TextRole::Comment, c);
            }
            cx.format_set("comments", json!(self.comments));
        }
        let gain_map = self.mpf.as_ref().is_some_and(|m| m["gain_map"].as_bool() == Some(true));
        if let Some(m) = self.mpf.take() {
            if let (Some(n), Some(mut img)) = (m["images"].as_u64(), cx.physical().existing_image()) {
                img.frames(u32::try_from(n).unwrap_or(1));
            }
            cx.format_set("mpf", m);
        }
        if self.xmp_ultra_hdr || gain_map {
            cx.format_set("ultra_hdr", true);
        }
        if self.c2pa {
            cx.format_set("c2pa", true);
            cx.security().signed(true);
        }
        cx.format_set("segments", json!(self.segments));
        for w in self.warnings {
            cx.warn(w);
        }
    }
}

fn segment_name(marker: u8, b: &[u8]) -> String {
    match marker {
        0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => format!("SOF{}", marker - 0xC0),
        0xC4 => "DHT".into(),
        0xF7 => "SOF55".into(),
        0xF8 => "LSE".into(),
        0xDA => "SOS".into(),
        0xDB => "DQT".into(),
        0xDD => "DRI".into(),
        0xFE => "COM".into(),
        0xE0..=0xEF => {
            let id: String =
                b.iter().take(16).take_while(|&&c| c != 0 && c.is_ascii_graphic()).map(|&c| char::from(c)).collect();
            if id.is_empty() { format!("APP{}", marker - 0xE0) } else { format!("APP{} {id}", marker - 0xE0) }
        }
        m => format!("0x{m:02X}"),
    }
}

fn process(marker: u8) -> &'static str {
    match marker {
        0xC0 => "baseline",
        0xC1 => "extended sequential",
        0xC2 => "progressive",
        0xC3 => "lossless",
        0xC5..=0xC7 => "hierarchical",
        0xC9..=0xCB => "arithmetic",
        0xF7 => "JPEG-LS",
        _ => "other",
    }
}

/// `4:2:0`, `4:2:2`, `4:4:4`, … from the luma and chroma sampling factors.
fn subsampling(c: &[(u8, u8)]) -> Option<&'static str> {
    let (yh, yv) = c[0];
    if c[1..].iter().any(|&(h, v)| (h, v) != c[1]) {
        return None;
    }
    let (ch, cv) = c[1];
    Some(match (yh / ch.max(1), yv / cv.max(1)) {
        (1, 1) => "4:4:4",
        (2, 1) => "4:2:2",
        (2, 2) => "4:2:0",
        (4, 1) => "4:1:1",
        (1, 2) => "4:4:0",
        _ => return None,
    })
}

/// IJG standard luminance table (zig-zag order as stored in DQT).
const STD_LUMA: [u16; 64] = [
    16, 11, 12, 14, 12, 10, 16, 14, 13, 14, 18, 17, 16, 19, 24, 40, 26, 24, 22, 22, 24, 49, 35, 37, 29, 40, 58, 51, 61,
    60, 57, 51, 56, 55, 64, 72, 92, 78, 64, 68, 87, 69, 55, 56, 80, 109, 81, 87, 95, 98, 103, 104, 103, 62, 77, 113,
    121, 112, 100, 120, 92, 101, 103, 99,
];

/// IJG quality (1–100) that best explains the luminance table.
fn quality(table: &[u16]) -> Option<u32> {
    if table.len() != 64 {
        return None;
    }
    let sum: f64 = table.iter().map(|&v| f64::from(v)).sum();
    let std: f64 = STD_LUMA.iter().map(|&v| f64::from(v)).sum();
    let scale = sum / std * 100.0;
    let q = if scale <= 100.0 { (200.0 - scale) / 2.0 } else { 5000.0 / scale };
    Some(super::px(q.clamp(1.0, 100.0)))
}

/// The MPF index: image count and the role of each image.
fn mpf(b: &[u8]) -> Option<Value> {
    let l = super::tiff::layout(b)?;
    let rd16 = |o: usize| -> Option<u16> {
        let x = b.get(o..o + 2)?;
        Some(if l.le { u16::from_le_bytes([x[0], x[1]]) } else { u16::from_be_bytes([x[0], x[1]]) })
    };
    let rd32 = |o: usize| -> Option<u32> {
        let x = b.get(o..o + 4)?;
        Some(if l.le { u32::from_le_bytes(x.try_into().ok()?) } else { u32::from_be_bytes(x.try_into().ok()?) })
    };
    let ifd = usize::try_from(l.first).ok()?;
    let n = usize::from(rd16(ifd)?).min(64);
    let (mut count, mut entries_at) = (None, None);
    for i in 0..n {
        let e = ifd + 2 + 12 * i;
        match rd16(e)? {
            0xB001 => count = rd32(e + 8),
            0xB002 => entries_at = rd32(e + 8),
            _ => {}
        }
    }
    let count = count?;
    let mut types = Vec::new();
    let mut gain_map = false;
    if let Some(at) = entries_at {
        for i in 0..count.min(32) as usize {
            let Some(attr) = rd32(at as usize + 16 * i) else { break };
            let kind = match attr & 0x00ff_ffff {
                0x03_0000 => "primary",
                0x01_0001 => "large thumbnail (VGA)",
                0x01_0002 => "large thumbnail (full HD)",
                0x02_0001 => "panorama",
                0x02_0002 => "disparity",
                0x02_0003 => "multi-angle",
                0x00_0000 => "undefined",
                _ => "other",
            };
            gain_map |= i > 0 && kind == "undefined";
            types.push(json!(kind));
        }
    }
    Some(json!({ "images": count, "types": types, "gain_map": gain_map }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_and_subsampling() {
        assert_eq!(quality(&STD_LUMA), Some(50));
        let q90: Vec<u16> =
            STD_LUMA.iter().map(|&v| u16::try_from(((u32::from(v) * 20 + 50) / 100).max(1)).unwrap()).collect();
        assert_eq!(quality(&q90), Some(90));
        assert_eq!(subsampling(&[(2, 2), (1, 1), (1, 1)]), Some("4:2:0"));
        assert_eq!(subsampling(&[(1, 1), (1, 1), (1, 1)]), Some("4:4:4"));
    }

    crate::fixture_tests!("jpeg", "jls");
}
