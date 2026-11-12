//! `video` extractors (feature `common`): MP4 / QuickTime / 3GP, Matroska /
//! WebM, AVI, MPEG transport and program streams, Flash Video, Windows Media
//! Video, RealMedia, and elementary streams (H.264, HEVC, AV1, VP8 / VP9 in
//! IVF, YUV4MPEG2, MPEG video).
//!
//! Extractors read container headers, indexes and the first bytes of each
//! stream (for the codec configuration) only; no picture or sound is
//! decoded. Every stream goes to `physical.media.streams[]` with `type`
//! `video`, `audio`, `subtitle` or `data`; the first video stream's size
//! also fills `physical.image`. Tags reuse the audio normalisation
//! (`format.tags`), and camera make, model and location go to
//! `format.device` and `content.location`.

// Header parsers follow their specifications' field names and keep a reader
// `r`, data `d` and stream `v` in scope: short names are clearer here.
#![allow(clippy::many_single_char_names, clippy::similar_names)]
pub(crate) mod asf;
pub(crate) mod avi;
pub(crate) mod broadcast;
pub(crate) mod codec;
pub(crate) mod edit;
pub(crate) mod elementary;
pub(crate) mod flv;
pub(crate) mod matroska;
pub(crate) mod mp4;
pub(crate) mod mpegps;
pub(crate) mod mpegts;
pub(crate) mod pes;
pub(crate) mod realmedia;

use serde_json::{Map, Value, json};

use self::codec::{Colour, matrix_name, primaries_name, transfer_name};
use super::audio::{self, round_s};
use crate::plugin::Context;

/// One video stream, as `physical.media.streams[]` describes it.
#[derive(Debug, Clone, Default)]
pub(crate) struct Video {
    /// ffprobe's codec name: `h264`, `hevc`, `av1`, `vp9`, `mpeg4`, `prores`…
    pub codec: String,
    /// The container's codec tag (`avc1`, `XVID`, `V_MPEG4/ISO/AVC`).
    pub codec_tag: Option<String>,
    pub profile: Option<String>,
    pub level: Option<String>,
    pub tier: Option<&'static str>,
    /// Coded size, after cropping.
    pub width: Option<u32>,
    pub height: Option<u32>,
    /// Sample (pixel) aspect ratio.
    pub sar: Option<(u32, u32)>,
    /// Display aspect ratio, when the stream gives it directly (MPEG-2).
    pub dar: Option<(u32, u32)>,
    /// Display size, when the container gives one that differs.
    pub display: Option<(u32, u32)>,
    pub fps: Option<f64>,
    /// Variable frame rate (MP4 sample durations differ).
    pub vfr: Option<bool>,
    pub frames: Option<u64>,
    pub bit_depth: Option<u8>,
    pub chroma: Option<&'static str>,
    pub colour: Colour,
    pub interlaced: Option<bool>,
    pub field_order: Option<&'static str>,
    pub rotation: Option<u16>,
    pub stereo_mode: Option<String>,
    pub alpha: Option<bool>,
    pub dolby_vision: Option<Value>,
    /// Mastering display luminance (max, min) in cd/m².
    pub mastering: Option<(f64, f64)>,
    /// Content light level (MaxCLL, MaxFALL) in cd/m².
    pub light_level: Option<(u32, u32)>,
    pub bitrate_bps: Option<u64>,
    pub max_bitrate_bps: Option<u64>,
    pub duration_s: Option<f64>,
    pub language: Option<String>,
    pub title: Option<String>,
    pub default: Option<bool>,
    pub forced: Option<bool>,
    pub encrypted: bool,
    /// The H.264 parameter set crops the left or top edge.
    pub crop_origin: bool,
}

impl Video {
    pub(crate) fn new(codec: impl Into<String>) -> Self {
        Self { codec: codec.into(), ..Self::default() }
    }

    /// Take what a codec configuration (`c`) knows over what the container
    /// said: the profile, level, size, depth and chroma come from the
    /// bitstream; the aspect ratio, frame rate and colour only fill gaps.
    /// As in decoders, an H.264 container size no larger than the parameter
    /// set's, on the same 16-pixel macroblock grid and without a left / top
    /// crop, is kept: it can say what 4:2:0 cropping cannot (an odd size).
    pub(crate) fn absorb(&mut self, c: Self) {
        let grid = |a: u32, b: u32| a.div_ceil(16) == b.div_ceil(16);
        match (self.width.zip(self.height), c.width.zip(c.height)) {
            (Some((w, h)), Some((cw, ch)))
                if c.codec == "h264" && !c.crop_origin && w <= cw && h <= ch && grid(w, cw) && grid(h, ch) => {}
            (_, Some((cw, ch))) => (self.width, self.height) = (Some(cw), Some(ch)),
            _ => {}
        }
        if self.codec.is_empty() || self.codec == "unknown" {
            self.codec = c.codec;
        }
        self.profile = c.profile.or(self.profile.take());
        self.level = c.level.or(self.level.take());
        self.tier = c.tier.or(self.tier);
        self.bit_depth = c.bit_depth.or(self.bit_depth);
        self.chroma = c.chroma.or(self.chroma);
        self.sar = self.sar.or(c.sar);
        self.dar = self.dar.or(c.dar);
        self.fps = self.fps.or(c.fps);
        self.interlaced = c.interlaced.or(self.interlaced);
        self.bitrate_bps = self.bitrate_bps.or(c.bitrate_bps);
        let k = &mut self.colour;
        k.primaries = k.primaries.or(c.colour.primaries);
        k.transfer = k.transfer.or(c.colour.transfer);
        k.matrix = k.matrix.or(c.colour.matrix);
        k.full_range = k.full_range.or(c.colour.full_range);
    }

    /// The display aspect ratio, reduced (`16:9`).
    fn display_aspect(&self) -> Option<(u64, u64)> {
        if let Some((a, b)) = self.dar {
            return Some(reduce(u64::from(a), u64::from(b)));
        }
        let (w, h) = self.display.or(self.width.zip(self.height))?;
        let (sw, sh) = if self.display.is_some() { (1, 1) } else { self.sar.unwrap_or((1, 1)) };
        (w > 0 && h > 0 && sw > 0 && sh > 0).then(|| reduce(u64::from(w) * u64::from(sw), u64::from(h) * u64::from(sh)))
    }

    /// The stream map.
    #[allow(clippy::too_many_lines)] // one optional field after another
    pub(crate) fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        let mut put = |k: &str, v: Value| {
            m.insert(k.into(), v);
        };
        put("type", json!("video"));
        put("codec", json!(self.codec));
        if let Some(t) = &self.codec_tag {
            put("codec_tag", json!(t));
        }
        if let Some(p) = &self.profile {
            put("profile", json!(p));
        }
        if let Some(l) = &self.level {
            put("level", json!(l));
        }
        if let Some(t) = self.tier {
            put("tier", json!(t));
        }
        if let (Some(w), Some(h)) = (self.width, self.height) {
            put("width", json!(w));
            put("height", json!(h));
        }
        if let Some((w, h)) = self.display.filter(|d| Some(*d) != self.width.zip(self.height)) {
            put("display_width", json!(w));
            put("display_height", json!(h));
        }
        if let Some((a, b)) = self.sar {
            let (a, b) = reduce(u64::from(a), u64::from(b));
            put("sample_aspect_ratio", json!(format!("{a}:{b}")));
        }
        if let Some((a, b)) = self.display_aspect() {
            put("display_aspect_ratio", json!(format!("{a}:{b}")));
        }
        if let Some(f) = self.fps.filter(|f| f.is_finite() && *f > 0.0 && *f < 1e6) {
            put("frame_rate", json!((f * 1000.0).round() / 1000.0));
        }
        if let Some(v) = self.vfr {
            put("frame_rate_mode", json!(if v { "vfr" } else { "cfr" }));
        }
        if let Some(n) = self.frames.filter(|n| *n > 0) {
            put("frames", json!(n));
        }
        if let Some(b) = self.bit_depth.filter(|b| *b > 0) {
            put("bit_depth", json!(b));
        }
        if let Some(c) = self.chroma {
            put("chroma_subsampling", json!(c));
        }
        let k = self.colour;
        if let Some(n) = k.primaries.and_then(primaries_name) {
            put("color_primaries", json!(n));
        }
        if let Some(n) = k.transfer.and_then(transfer_name) {
            put("color_transfer", json!(n));
        }
        if let Some(n) = k.matrix.and_then(matrix_name) {
            put("color_matrix", json!(n));
        }
        if let Some(f) = k.full_range {
            put("color_range", json!(if f { "full" } else { "limited" }));
        }
        if let Some(h) = self.hdr_format() {
            put("hdr_format", json!(h));
        }
        if let Some(d) = &self.dolby_vision {
            put("dolby_vision", d.clone());
        }
        if let Some((max, min)) = self.mastering {
            put("mastering_display", json!({ "max_luminance_cd_m2": max, "min_luminance_cd_m2": min }));
        }
        if let Some((cll, fall)) = self.light_level {
            put("content_light_level", json!({ "max_cll": cll, "max_fall": fall }));
        }
        if let Some(i) = self.interlaced {
            put("scan_type", json!(if i { "interlaced" } else { "progressive" }));
        }
        if let Some(f) = self.field_order {
            put("field_order", json!(f));
        }
        if let Some(r) = self.rotation.filter(|r| *r != 0) {
            put("rotation_deg", json!(r));
        }
        if let Some(s) = &self.stereo_mode {
            put("stereo_mode", json!(s));
        }
        if let Some(a) = self.alpha.filter(|a| *a) {
            put("alpha", json!(a));
        }
        if let Some(b) = self.bitrate_bps.filter(|b| *b > 0) {
            put("bitrate_bps", json!(b));
        }
        if let Some(b) = self.max_bitrate_bps.filter(|b| *b > 0) {
            put("max_bitrate_bps", json!(b));
        }
        if let Some(d) = self.duration_s.filter(|d| d.is_finite() && *d > 0.0) {
            put("duration_s", json!(round_s(d)));
        }
        if self.encrypted {
            put("encrypted", json!(true));
        }
        labels(&mut m, self.language.as_deref(), self.title.as_deref(), self.default, self.forced);
        m
    }

    /// `hdr10` for PQ, `hlg`, or `dolby_vision`.
    fn hdr_format(&self) -> Option<&'static str> {
        if self.dolby_vision.is_some() {
            return Some("dolby_vision");
        }
        match self.colour.transfer? {
            16 => Some("hdr10"),
            18 => Some("hlg"),
            _ => None,
        }
    }
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

fn reduce(a: u64, b: u64) -> (u64, u64) {
    let g = gcd(a, b).max(1);
    (a / g, b / g)
}

/// Add a stream's language, title and default / forced flags.
pub(crate) fn labels(
    m: &mut Map<String, Value>,
    language: Option<&str>,
    title: Option<&str>,
    default: Option<bool>,
    forced: Option<bool>,
) {
    if let Some(l) = language.map(str::trim).filter(|l| !l.is_empty() && *l != "und") {
        m.insert("language".into(), json!(l));
    }
    if let Some(t) = title.map(str::trim).filter(|t| !t.is_empty()) {
        m.insert("title".into(), json!(crate::plugin::truncate_chars(t, 200)));
    }
    if let Some(d) = default {
        m.insert("default".into(), json!(d));
    }
    if forced == Some(true) {
        m.insert("forced".into(), json!(true));
    }
}

/// An audio stream's map.
pub(crate) fn audio_map(s: &audio::Stream) -> Map<String, Value> {
    s.to_map()
}

/// A subtitle or data stream's map.
pub(crate) fn other_map(kind: &str, codec: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("type".into(), json!(kind));
    m.insert("codec".into(), json!(codec));
    m
}

/// Write the streams, the duration, the overall bitrate (from the file size)
/// and `physical.image` from the first sized video stream.
pub(crate) fn finish(cx: &mut Context<'_>, streams: Vec<Map<String, Value>>, duration: Option<f64>, file_len: u64) {
    let size = streams.iter().find(|s| s["type"] == "video").and_then(|s| {
        let dim = |k: &str| s.get(k).and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok());
        Some((dim("width")?, dim("height")?, s.get("frames").and_then(Value::as_u64)))
    });
    let duration = duration.filter(|d| d.is_finite() && *d > 0.0);
    {
        let mut p = cx.physical();
        for s in streams {
            p.stream(s);
        }
        if let Some(d) = duration {
            p.duration_s(round_s(d));
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, far below u64::MAX
            let overall = (file_len as f64 * 8.0 / d).round() as u64;
            p.bitrate_bps(overall);
        }
    }
    if let Some((w, h, frames)) = size {
        let mut img = cx.physical().image(w, h);
        if let Some(n) = frames.and_then(|n| u32::try_from(n).ok()) {
            img.frames(n);
        }
    }
}

/// Camera or phone details found in a container's metadata.
#[derive(Default)]
pub(crate) struct Device {
    pub make: Option<String>,
    pub model: Option<String>,
    pub software: Option<String>,
    pub location: Option<(f64, f64, Option<f64>)>,
    pub location_source: String,
}

impl Device {
    pub(crate) fn report(self, cx: &mut Context<'_>) {
        let mut m = Map::new();
        for (k, v) in [("make", &self.make), ("model", &self.model), ("software", &self.software)] {
            if let Some(v) = v.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
                m.insert(k.into(), json!(v));
            }
        }
        if !m.is_empty() {
            cx.format_set("device", Value::Object(m));
        }
        if let Some((lat, lon, alt)) = self.location {
            cx.content().source(self.location_source).location(lat, lon, alt);
        }
    }
}

/// An ISO 6709 point (`+37.3349-122.0090+010.000/`), with degrees given as
/// `±DD.D`, `±DDMM.M` or `±DDMMSS.S`.
pub(crate) fn iso6709(s: &str) -> Option<(f64, f64, Option<f64>)> {
    let s = s.trim().trim_end_matches('/');
    let mut parts = Vec::new();
    let mut start = 0;
    for (i, c) in s.char_indices().skip(1) {
        if c == '+' || c == '-' {
            parts.push(&s[start..i]);
            start = i;
        }
        if c == 'C' || c == 'R' {
            break; // a CRS suffix
        }
    }
    parts.push(s[start..].split(['C', 'R']).next().unwrap_or(""));
    let coord = |p: &str, deg_digits: usize| -> Option<f64> {
        let (sign, body) = match p.as_bytes().first()? {
            b'+' => (1.0, &p[1..]),
            b'-' => (-1.0, &p[1..]),
            _ => return None,
        };
        let int_len = body.find('.').unwrap_or(body.len());
        let v: f64 = body.parse().ok()?;
        let deg = match int_len - deg_digits {
            0 => v,
            2 => (v / 100.0).trunc() + (v % 100.0) / 60.0,
            4 => (v / 10000.0).trunc() + ((v / 100.0).trunc() % 100.0) / 60.0 + (v % 100.0) / 3600.0,
            _ => return None,
        };
        Some(sign * deg)
    };
    let lat = coord(parts.first()?, 2)?;
    let lon = coord(parts.get(1)?, 3)?;
    let alt = parts.get(2).and_then(|a| a.parse::<f64>().ok());
    ((-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)).then_some((lat, lon, alt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations_and_aspect() {
        assert_eq!(iso6709("+37.3349-122.0090+010.000/"), Some((37.3349, -122.009, Some(10.0))));
        assert_eq!(iso6709("+40.7128-074.0060/"), Some((40.7128, -74.006, None)));
        let (lat, lon, _) = iso6709("+4042.77-07400.36/").unwrap();
        assert!((lat - 40.7128).abs() < 1e-3 && (lon + 74.006).abs() < 1e-3);
        assert_eq!(iso6709("nowhere"), None);
        let mut v = Video::new("h264");
        (v.width, v.height, v.sar) = (Some(720), Some(576), Some((64, 45)));
        assert_eq!(v.display_aspect(), Some((16, 9)));
        let m = v.to_map();
        assert_eq!((&m["sample_aspect_ratio"], &m["display_aspect_ratio"]), (&json!("64:45"), &json!("16:9")));
    }
}
