//! Broadcast, game and camera video files read from their headers:
//!
//! * DV (IEC 61834 / SMPTE 314M DIF streams): 525/60 or 625/50, frame
//!   count, aspect ratio, recording date and time, audio rate and depth;
//! * MXF (SMPTE 377M): partition pack (version, operational pattern,
//!   essence containers), the Identification set (company, product,
//!   version, platform, date), picture and sound descriptors (coding,
//!   stored size, aspect ratio, edit rate, duration, sampling rate,
//!   channels, depth), the material package name and start timecode;
//! * AMV (the RIFF variant of cheap MP4 players), FLIC (`.fli` / `.flc`),
//!   Bink and Smacker (RAD Game Tools) and Nullsoft NSV: size, frame rate,
//!   frames and audio tracks;
//! * RED R3D and ARRIRAW frames: the header version and, for ARRIRAW,
//!   the image size.
//!
//! Specifications: IEC 61834-4 (DV packs); SMPTE 377M-1 (MXF), 379M,
//! 381M, 382M; the Autodesk FLIC format; RAD's Bink and Smacker layouts
//! and Nullsoft's NSV notes (as FFmpeg reads them).

use std::collections::BTreeMap;

use serde_json::json;

use super::super::audio::Stream;
use super::{Video, audio_map, finish};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source};

/// Extractor for broadcast, game and camera video.
pub struct Broadcast;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, [$($ext:literal),*], [$($magic:expr),*]) => {
        FormatSpec { id: $id, name: $name, family: "video", mimes: &[$mime], extensions: &[$($ext),*], magic: &[$($magic),*], parent: None }
    };
}

const MXF_PARTITION: &[u8] = b"\x06\x0e\x2b\x34\x02\x05\x01\x01\x0d\x01\x02\x01\x01";

static META: ExtractorMeta = ExtractorMeta {
    id: "video.broadcast",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!("dv", "DV video", "video/dv", ["dv", "dif"], []),
        spec!("mxf", "MXF (Material Exchange Format)", "application/mxf", ["mxf"], []),
        spec!(
            "amv",
            "AMV video",
            "video/x-amv",
            ["amv"],
            [Magic::masked(0, b"RIFF\0\0\0\0AMV ", b"\xff\xff\xff\xff\0\0\0\0\xff\xff\xff\xff")]
        ),
        spec!("flic", "FLIC animation", "video/x-flic", ["fli", "flc", "flh", "flx"], []),
        spec!("bink", "Bink video", "video/x-bink", ["bik", "bk2"], []),
        spec!("smacker", "Smacker video", "video/x-smacker", ["smk"], [Magic::prefix(b"SMK2"), Magic::prefix(b"SMK4")]),
        spec!(
            "nsv",
            "Nullsoft Streaming Video",
            "video/x-nsv",
            ["nsv"],
            [Magic::prefix(b"NSVf"), Magic::prefix(b"NSVs")]
        ),
        spec!("r3d", "RED R3D", "video/x-red-r3d", ["r3d"], [Magic::at(4, b"RED1"), Magic::at(4, b"RED2")]),
        spec!(
            "arriraw",
            "ARRIRAW",
            "image/x-arriraw",
            ["ari"],
            [Magic::prefix(b"ARRI\x12\x34\x56\x78"), Magic::prefix(b"ARRI\x78\x56\x34\x12")]
        ),
    ],
};

impl Extractor for Broadcast {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let pick = |format: &'static str| Some(Sniff { format, confidence: 0.95 });
        // MXF may start with a run-in of up to 64 KiB; the header partition key follows.
        if h.windows(MXF_PARTITION.len()).take(65_536).any(|w| w == MXF_PARTITION)
            && h.windows(4).any(|w| w == b"\x06\x0e\x2b\x34")
        {
            let at = h.windows(MXF_PARTITION.len()).position(|w| w == MXF_PARTITION)?;
            if h.get(at + 13) == Some(&0x02) {
                return pick("mxf");
            }
        }
        // DV: a header DIF block (section type 0, sequence 0, block 0).
        if h.len() >= 80 * 6 && h[0] >> 5 == 0 && h[1] & 0xf0 == 0 && h[2] == 0 && h[80] >> 5 == 1 && h[240] >> 5 == 2 {
            return pick("dv");
        }
        if (h.starts_with(b"BIK") || h.starts_with(b"KB2")) && h.len() > 44 && h[3].is_ascii_alphabetic() {
            return pick("bink");
        }
        if h.len() >= 128 && matches!(u16::from_le_bytes([h[4], h[5]]), 0xaf11 | 0xaf12 | 0xaf44 | 0xaf30 | 0xaf31) {
            let size = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
            let frames = u16::from_le_bytes([h[6], h[7]]);
            if size >= 128 && frames > 0 {
                return pick("flic");
            }
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let head = |src: &mut dyn Source, n: u64| src.read_vec(0, usize::try_from(len.min(n)).unwrap_or(0));
        match cx.format_id() {
            "dv" => {
                let b = head(src, 144_000 * 2)?;
                dv(cx, &b, len);
            }
            "mxf" => {
                let (b, _) = cx.read_bytes(src)?;
                mxf(cx, &b, len);
            }
            "amv" => amv(cx, &head(src, 4096)?, len),
            "flic" => flic(cx, &head(src, 4096)?, len),
            "bink" => bink(cx, &head(src, 4096)?, len),
            "smacker" => smacker(cx, &head(src, 4096)?, len),
            "nsv" => nsv(cx, &head(src, 1 << 20)?, len),
            "r3d" => {
                let b = head(src, 4096)?;
                cx.format_set("version", String::from_utf8_lossy(b.get(4..8).unwrap_or_default()).to_string());
                cx.format_set("header_bytes", be32(&b, 0));
            }
            _ => arriraw(cx, &head(src, 4096)?),
        }
        Ok(())
    }
}

crate::register_extractor!(Broadcast);

fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn be16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2).map_or(0, |s| u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be64(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8).map_or(0, |s| u64::from_be_bytes(s.try_into().unwrap_or([0; 8])))
}

// --- DV ------------------------------------------------------------------------------------------

/// A BCD byte's value, with `mask` keeping the meaningful bits.
fn bcd(b: u8, mask: u8) -> u32 {
    let v = b & mask;
    u32::from(v >> 4) * 10 + u32::from(v & 0x0f)
}

fn dv(cx: &mut Context<'_>, b: &[u8], len: u64) {
    let pal = b.get(3).is_some_and(|x| x & 0x80 != 0);
    let frame_bytes: u64 = if pal { 144_000 } else { 120_000 };
    let frames = len / frame_bytes;
    let mut v = Video::new("dvvideo");
    (v.width, v.height) = (Some(720), Some(if pal { 576 } else { 480 }));
    v.fps = Some(if pal { 25.0 } else { 30_000.0 / 1001.0 });
    v.frames = Some(frames);
    v.interlaced = Some(true);
    cx.format_set("system", if pal { "625/50 (PAL)" } else { "525/60 (NTSC)" });
    // Packs in the first frame: VAUX blocks hold 15, audio blocks one.
    let mut packs: BTreeMap<u8, [u8; 5]> = BTreeMap::new();
    let first = b.get(..usize::try_from(frame_bytes).unwrap_or(usize::MAX)).unwrap_or(b);
    for block in first.as_chunks::<80>().0 {
        match block[0] >> 5 {
            2 => {
                for p in block[3..78].as_chunks::<5>().0 {
                    packs.entry(p[0]).or_insert([p[0], p[1], p[2], p[3], p[4]]);
                }
            }
            3 => {
                packs.entry(block[3]).or_insert([block[3], block[4], block[5], block[6], block[7]]);
            }
            _ => {}
        }
    }
    if let Some(p) = packs.get(&0x61) {
        // VAUX source control: the display mode.
        let wide = matches!(p[2] & 0x07, 2 | 7);
        v.dar = Some(if wide { (16, 9) } else { (4, 3) });
    }
    let mut streams = vec![v.to_map()];
    if let Some(p) = packs.get(&0x50) {
        let rate = [48_000, 44_100, 32_000].get(usize::from((p[4] >> 3) & 7)).copied();
        let bits = match p[4] & 7 {
            0 => Some(16),
            1 => Some(12),
            _ => None,
        };
        let mut s = Stream::new("pcm_s16le");
        s.sample_rate_hz = rate;
        s.bits_per_sample = bits;
        s.channels = Some(2);
        streams.push(audio_map(&s));
    }
    if let (Some(d), Some(t)) = (packs.get(&0x62), packs.get(&0x63))
        && d[1..] != [0xff; 4]
    {
        let (day, month, year) = (bcd(d[2], 0x3f), bcd(d[3], 0x1f), bcd(d[4], 0xff));
        let (sec, min, hour) = (bcd(t[2], 0x7f), bcd(t[3], 0x7f), bcd(t[4], 0x3f));
        if (1..=31).contains(&day) && (1..=12).contains(&month) && hour < 24 && min < 60 && sec < 60 {
            let year = if year < 75 { 2000 + year } else { 1900 + year };
            cx.format_set("recorded", format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}"));
        }
    }
    #[allow(clippy::cast_precision_loss)]
    let duration = Some(frames as f64 / if pal { 25.0 } else { 30_000.0 / 1001.0 });
    finish(cx, streams, duration, len);
}

// --- MXF ------------------------------------------------------------------------------------------

/// A BER length at `b[at]`: (length, bytes used).
fn ber(b: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = *b.get(at)?;
    if first < 0x80 {
        return Some((usize::from(first), 1));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 || n > 8 {
        return None;
    }
    let v = b.get(at + 1..at + 1 + n)?.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x));
    Some((usize::try_from(v).ok()?, 1 + n))
}

fn utf16be(b: &[u8]) -> String {
    let u: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
    String::from_utf16_lossy(&u).trim_end_matches('\0').trim().to_string()
}

/// The operational pattern a UL names.
fn operational_pattern(ul: &[u8]) -> String {
    if ul.len() < 16 {
        return "unknown".into();
    }
    if ul[12] == 0x10 {
        return "OP-Atom".into();
    }
    match (ul[12], ul[13]) {
        (1..=3, 1..=3) => format!("OP{}{}", ul[12], ["a", "b", "c"][usize::from(ul[13] - 1)]),
        _ => format!("unknown ({})", hex(ul)),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        use std::fmt::Write as _;
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// The essence mapping an essence-container UL names.
fn essence_container(ul: &[u8]) -> Option<&'static str> {
    if ul.len() < 16 || ul[8..12] != [0x0d, 0x01, 0x03, 0x01] {
        return None;
    }
    Some(match ul[13] {
        0x01 => "D-10 (MPEG IMX)",
        0x02 => "DV",
        0x03 => "D-11 (HDCAM)",
        0x04 => "MPEG elementary stream",
        0x05 => "uncompressed picture",
        0x06 => "AES3 / BWF audio",
        0x07 => "MPEG PES",
        0x08 => "MPEG PS",
        0x09 => "MPEG TS",
        0x0a => "A-law audio",
        0x0b => "encrypted",
        0x0c => "JPEG 2000",
        0x10 => "AVC (H.264)",
        0x11 => "VC-3 (DNxHD)",
        0x13 => "timed text",
        0x1c => "ProRes",
        0x7f => "generic (multiple)",
        _ => "other",
    })
}

/// The picture coding a UL names.
fn picture_coding(ul: &[u8]) -> &'static str {
    match ul.get(8..14) {
        Some([0x04, 0x01, 0x02, 0x02, 0x01, x]) if *x >= 0x30 => "h264",
        Some([0x04, 0x01, 0x02, 0x02, 0x01, _]) => "mpeg2video",
        Some([0x04, 0x01, 0x02, 0x02, 0x02, _]) => "dvvideo",
        Some([0x04, 0x01, 0x02, 0x02, 0x03, 0x01]) => "jpeg2000",
        Some([0x04, 0x01, 0x02, 0x02, 0x03, 0x02]) => "dnxhd",
        Some([0x04, 0x01, 0x02, 0x02, 0x03, 0x06]) => "prores",
        Some([0x04, 0x01, 0x02, 0x01, ..]) => "rawvideo",
        _ => "unknown",
    }
}

fn rational(v: &[u8]) -> Option<f64> {
    let (n, d) = (be32(v, 0), be32(v, 4));
    (d > 0 && v.len() >= 8).then(|| f64::from(n) / f64::from(d))
}

#[allow(clippy::too_many_lines)] // one set after another
fn mxf(cx: &mut Context<'_>, b: &[u8], len: u64) {
    let Some(mut at) = b.windows(MXF_PARTITION.len()).take(65_536).position(|w| w == MXF_PARTITION) else {
        cx.warn("no MXF partition pack");
        return;
    };
    if at > 0 {
        cx.format_set("run_in_bytes", at);
    }
    let (mut partitions, mut sets, mut containers) = (0u64, BTreeMap::<String, u64>::new(), Vec::new());
    let (mut pictures, mut sounds, mut identification, mut package) =
        (Vec::new(), Vec::new(), serde_json::Map::new(), None);
    let mut timecode = None;
    let (mut edit_rate, mut sequence_duration) = (None::<f64>, 0u64);
    let mut klvs = 0usize;
    while at + 17 <= b.len() && klvs < 1_000_000 {
        klvs += 1;
        let key = &b[at..at + 16];
        let Some((n, used)) = ber(b, at + 16) else { break };
        let start = at + 16 + used;
        let Some(v) = b.get(start..start.saturating_add(n).min(b.len())) else { break };
        if key.starts_with(MXF_PARTITION) {
            partitions += 1;
            if partitions == 1 && v.len() >= 88 {
                cx.format_set("version", format!("{}.{}", be16(v, 0), be16(v, 2)));
                cx.format_set("kag_size", be32(v, 4));
                cx.format_set("operational_pattern", operational_pattern(&v[64..80]));
                let (count, size) = (be32(v, 80) as usize, be32(v, 84) as usize);
                for i in 0..count.min(32) {
                    if let Some(ul) = v.get(88 + i * size..88 + (i + 1) * size) {
                        containers.push(essence_container(ul).map_or_else(|| hex(ul), str::to_string));
                    }
                }
                let status = ["open, incomplete", "closed, incomplete", "open, complete", "closed, complete"];
                cx.format_set(
                    "header_partition",
                    status.get(usize::from(key[14]).saturating_sub(1)).copied().unwrap_or("unknown"),
                );
            }
        } else if key.starts_with(b"\x06\x0e\x2b\x34\x02\x53\x01\x01\x0d\x01\x01\x01\x01\x01") {
            // A header metadata local set: 2-byte tags, 2-byte lengths.
            let kind = key[14];
            let name = match kind {
                0x2f => "preface",
                0x30 => "identification",
                0x18 => "content_storage",
                0x36 => "material_package",
                0x37 => "source_package",
                0x3b | 0x3a => "track",
                0x0f => "sequence",
                0x11 => "source_clip",
                0x14 => "timecode",
                0x28 => "cdci_descriptor",
                0x29 => "rgba_descriptor",
                0x42 => "sound_descriptor",
                0x44 => "multiple_descriptor",
                0x47 => "aes3_descriptor",
                0x48 => "wave_descriptor",
                0x51 => "mpeg2_descriptor",
                _ => "other",
            };
            *sets.entry(name.to_string()).or_default() += 1;
            let mut tags: BTreeMap<u16, &[u8]> = BTreeMap::new();
            let mut p = 0;
            while p + 4 <= v.len() {
                let (tag, l) = (be16(v, p), usize::from(be16(v, p + 2)));
                let Some(val) = v.get(p + 4..p + 4 + l) else { break };
                tags.insert(tag, val);
                p += 4 + l;
            }
            match kind {
                0x30 => {
                    for (tag, key) in [
                        (0x3c01, "company"),
                        (0x3c02, "product"),
                        (0x3c04, "version"),
                        (0x3c08, "platform"),
                        (0x3c07, "toolkit_version"),
                    ] {
                        if let Some(t) = tags.get(&tag) {
                            let text = if tag == 0x3c07 {
                                (0..5).map(|i| be16(t, i * 2).to_string()).collect::<Vec<_>>().join(".")
                            } else {
                                utf16be(t)
                            };
                            identification.entry(key).or_insert(json!(text));
                        }
                    }
                    if let Some(d) = tags.get(&0x3c06).filter(|d| d.len() >= 8 && d[..2] != [0, 0]) {
                        identification.entry("modified").or_insert(json!(format!(
                            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
                            be16(d, 0),
                            d[2],
                            d[3],
                            d[4],
                            d[5],
                            d[6]
                        )));
                    }
                }
                0x36 => {
                    if let Some(n) = tags.get(&0x4402).map(|t| utf16be(t)).filter(|n| !n.is_empty()) {
                        package = Some(n);
                    }
                }
                0x3b | 0x3a => {
                    if edit_rate.is_none() {
                        edit_rate = tags.get(&0x4b01).and_then(|v| rational(v)).filter(|r| *r > 0.0);
                    }
                }
                0x0f => {
                    if let Some(d) = tags.get(&0x0202) {
                        sequence_duration = sequence_duration.max(be64(d, 0));
                    }
                }
                0x14 => {
                    if timecode.is_none()
                        && let (Some(s), Some(base)) = (tags.get(&0x1501), tags.get(&0x1502))
                    {
                        let (frames, base) = (be64(s, 0), u64::from(be16(base, 0)));
                        if let Some(secs) = frames.checked_div(base) {
                            let (h, m, sec, f) = (secs / 3600, secs / 60 % 60, secs % 60, frames % base);
                            let drop = tags.get(&0x1503).is_some_and(|d| d.first() == Some(&1));
                            timecode = Some(format!("{h:02}:{m:02}:{sec:02}{}{f:02}", if drop { ';' } else { ':' }));
                        }
                    }
                }
                0x28 | 0x29 | 0x51 => {
                    let mut p = Video::new(tags.get(&0x3201).map_or("unknown", |u| picture_coding(u)));
                    p.width = tags.get(&0x3203).map(|v| be32(v, 0));
                    p.height = tags.get(&0x3202).map(|v| be32(v, 0));
                    let rate = tags.get(&0x3001).and_then(|v| rational(v));
                    p.fps = rate;
                    if let Some(a) = tags.get(&0x320e)
                        && be32(a, 4) > 0
                    {
                        p.dar = Some((be32(a, 0), be32(a, 4)));
                    }
                    p.frames = tags.get(&0x3002).map(|v| be64(v, 0));
                    p.bit_depth = tags.get(&0x3301).and_then(|v| u8::try_from(be32(v, 0)).ok());
                    if let Some(l) = tags.get(&0x320c).and_then(|v| v.first()) {
                        p.interlaced = Some(*l != 0);
                    }
                    if let (Some(n), Some(r)) = (p.frames, rate.filter(|r| *r > 0.0)) {
                        #[allow(clippy::cast_precision_loss)]
                        let d = n as f64 / r;
                        p.duration_s = Some(d);
                    }
                    pictures.push(p);
                }
                0x42 | 0x47 | 0x48 => {
                    let mut s = Stream::new(if kind == 0x42 { "pcm" } else { "pcm_s24le" });
                    if let Some(bits) = tags.get(&0x3d01).map(|v| be32(v, 0)) {
                        s.bits_per_sample = u16::try_from(bits).ok();
                        s.codec = format!("pcm_s{bits}le");
                    }
                    s.sample_rate_hz =
                        tags.get(&0x3d03).and_then(|v| rational(v)).and_then(super::super::audio::whole_u32);
                    s.channels = tags.get(&0x3d07).and_then(|v| u16::try_from(be32(v, 0)).ok());
                    sounds.push(s);
                }
                _ => {}
            }
        } else if key.starts_with(b"\x06\x0e\x2b\x34\x01\x02\x01\x01\x0d\x01\x03\x01") {
            // Essence: the header is read, the body is not walked.
            break;
        }
        at = start.saturating_add(n);
    }
    cx.format_set("essence_containers", containers);
    if !identification.is_empty() {
        cx.format_set("identification", serde_json::Value::Object(identification));
    }
    if let Some(p) = package {
        cx.content().title(p.clone());
        cx.format_set("material_package", p);
    }
    if let Some(t) = timecode {
        cx.format_set("start_timecode", t);
    }
    cx.format_set("partitions_read", partitions);
    cx.format_set("metadata_sets", json!(sets));
    // The descriptors' container duration, else the longest sequence at the
    // first track's edit rate.
    #[allow(clippy::cast_precision_loss)]
    let from_sequence = edit_rate
        .filter(|_| sequence_duration > 0 && sequence_duration < 1 << 48)
        .map(|r| sequence_duration as f64 / r);
    let longest =
        pictures.iter().filter_map(|p| p.duration_s).fold(None, |a: Option<f64>, d| Some(a.map_or(d, |a| a.max(d))));
    let duration = longest.or(from_sequence);
    if let (Some(r), Some(d)) = (edit_rate, from_sequence) {
        for p in pictures.iter_mut().filter(|p| p.frames.is_none()) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let frames = (d * r).round() as u64;
            p.frames = Some(frames);
        }
    }
    let mut streams: Vec<_> = pictures.iter().map(Video::to_map).collect();
    streams.extend(sounds.iter().map(audio_map));
    finish(cx, streams, duration, len);
}

// --- AMV, FLIC, Bink, Smacker, NSV ---------------------------------------------------------------

fn amv(cx: &mut Context<'_>, b: &[u8], len: u64) {
    let Some(p) = b.windows(4).position(|w| w == b"amvh") else {
        cx.warn("no amvh header");
        return;
    };
    let h = b.get(p + 8..).unwrap_or_default();
    let mut v = Video::new("amv");
    let us = le32(h, 0);
    v.width = Some(le32(h, 32)).filter(|w| *w > 0);
    v.height = Some(le32(h, 36)).filter(|w| *w > 0);
    let fps = le32(h, 40);
    v.fps = if fps > 0 { Some(f64::from(fps)) } else { (us > 0).then(|| 1e6 / f64::from(us)) };
    let (sec, min, hour) = (
        u32::from(h.get(52).copied().unwrap_or(0)),
        u32::from(h.get(53).copied().unwrap_or(0)),
        u32::from(le16(h, 54)),
    );
    let duration = (sec + min + hour > 0 && sec < 60 && min < 60).then(|| f64::from(hour * 3600 + min * 60 + sec));
    let mut a = Stream::new("adpcm_ima_amv");
    a.channels = Some(1);
    if let Some(f) = b
        .windows(4)
        .position(|w| w == b"strf")
        .and_then(|p| b.windows(4).skip(p + 4).position(|w| w == b"strf").map(|q| p + 4 + q))
    {
        // The second `strf` is the audio WAVEFORMATEX.
        let wf = b.get(f + 8..).unwrap_or_default();
        a.channels = Some(le16(wf, 2)).filter(|c| *c > 0);
        a.sample_rate_hz = Some(le32(wf, 4)).filter(|r| *r > 0);
    }
    finish(cx, vec![v.to_map(), audio_map(&a)], duration, len);
}

fn flic(cx: &mut Context<'_>, h: &[u8], len: u64) {
    let kind = le16(h, 4);
    cx.format_set(
        "variant",
        match kind {
            0xaf11 => "FLI (Animator)",
            0xaf12 => "FLC (Animator Pro)",
            0xaf44 => "FLX / FLH (high colour)",
            _ => "FLIC (other)",
        },
    );
    let frames = u64::from(le16(h, 6));
    let mut v = Video::new("flic");
    v.width = Some(u32::from(le16(h, 8)));
    v.height = Some(u32::from(le16(h, 10)));
    v.bit_depth = u8::try_from(le16(h, 12)).ok().filter(|d| *d > 0);
    v.frames = Some(frames);
    let speed = le32(h, 16);
    // FLI counts 1/70 s jiffies, FLC milliseconds.
    let frame_s = if kind == 0xaf11 { f64::from(speed) / 70.0 } else { f64::from(speed) / 1000.0 };
    v.fps = (frame_s > 0.0).then(|| 1.0 / frame_s);
    #[allow(clippy::cast_precision_loss)]
    let duration = (frame_s > 0.0).then_some(frames as f64 * frame_s);
    if kind != 0xaf11 {
        // After the speed: a reserved word, then created / creator.
        if let Some(c) = dos_datetime(le32(h, 22)) {
            cx.format_set("created", c);
        }
        let creator = le32(h, 26);
        if creator != 0 {
            cx.format_set("creator_id", format!("{creator:08x}"));
        }
    }
    finish(cx, vec![v.to_map()], duration, len);
}

/// An MS-DOS date (high word) and time (low word).
fn dos_datetime(v: u32) -> Option<String> {
    let (date, time) = (v >> 16, v & 0xffff);
    let (year, month, day) = (1980 + (date >> 9), (date >> 5) & 15, date & 31);
    let (hour, min, sec) = (time >> 11, (time >> 5) & 63, (time & 31) * 2);
    ((1..=12).contains(&month) && (1..=31).contains(&day) && hour < 24 && min < 60 && sec < 60)
        .then(|| format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}"))
}

fn bink(cx: &mut Context<'_>, h: &[u8], len: u64) {
    let tag = String::from_utf8_lossy(h.get(..4).unwrap_or_default()).to_string();
    cx.format_set("revision", tag.clone());
    let frames = u64::from(le32(h, 8));
    let mut v = Video::new(if tag.starts_with("KB2") { "bink2" } else { "binkvideo" });
    v.width = Some(le32(h, 20));
    v.height = Some(le32(h, 24));
    let (num, den) = (le32(h, 28), le32(h, 32));
    v.fps = (den > 0).then(|| f64::from(num) / f64::from(den));
    v.frames = Some(frames);
    let mut streams = vec![v.to_map()];
    let tracks = le32(h, 40).min(16) as usize;
    for i in 0..tracks {
        let at = 44 + tracks * 4 + i * 4;
        let (rate, flags) = (le16(h, at), le16(h, at + 2));
        let mut s = Stream::new(if flags & 0x1000 != 0 { "binkaudio_dct" } else { "binkaudio_rdft" });
        s.sample_rate_hz = Some(u32::from(rate)).filter(|r| *r > 0);
        s.channels = Some(if flags & 0x2000 != 0 { 2 } else { 1 });
        streams.push(audio_map(&s));
    }
    cx.format_set("audio_tracks", tracks);
    #[allow(clippy::cast_precision_loss)]
    let duration = (num > 0 && den > 0).then(|| frames as f64 * f64::from(den) / f64::from(num));
    finish(cx, streams, duration, len);
}

fn smacker(cx: &mut Context<'_>, h: &[u8], len: u64) {
    cx.format_set("version", String::from_utf8_lossy(h.get(..4).unwrap_or_default()).to_string());
    let frames = u64::from(le32(h, 12));
    let rate = le32(h, 16).cast_signed();
    let frame_s = match rate {
        r if r > 0 => f64::from(r) / 1000.0,
        r if r < 0 => f64::from(-r) / 100_000.0,
        _ => 0.1,
    };
    let flags = le32(h, 20);
    let mut v = Video::new("smackvideo");
    v.width = Some(le32(h, 4));
    v.height = Some(le32(h, 8));
    v.fps = Some(1.0 / frame_s);
    v.frames = Some(frames);
    if flags & 6 != 0 {
        cx.format_set("y_scaling", if flags & 2 != 0 { "interlaced" } else { "doubled" });
    }
    let mut streams = vec![v.to_map()];
    for i in 0..7 {
        let at = 72 + i * 4;
        let r = le32(h, at) & 0x00ff_ffff;
        let f = h.get(at + 3).copied().unwrap_or(0);
        if r == 0 {
            continue;
        }
        let codec = if f & 0x08 != 0 {
            if f & 0x04 != 0 { "binkaudio_dct" } else { "binkaudio_rdft" }
        } else if f & 0x80 != 0 {
            "smackaudio"
        } else if f & 0x20 != 0 {
            "pcm_s16le"
        } else {
            "pcm_u8"
        };
        let mut s = Stream::new(codec);
        s.sample_rate_hz = Some(r);
        s.channels = Some(if f & 0x10 != 0 { 2 } else { 1 });
        s.bits_per_sample = Some(if f & 0x20 != 0 { 16 } else { 8 });
        streams.push(audio_map(&s));
    }
    #[allow(clippy::cast_precision_loss)]
    finish(cx, streams, Some(frames as f64 * frame_s), len);
}

fn nsv(cx: &mut Context<'_>, b: &[u8], len: u64) {
    let mut duration = None;
    let mut sync = 0usize;
    if b.starts_with(b"NSVf") {
        let header = le32(b, 4) as usize;
        let ms = le32(b, 12);
        if ms != u32::MAX && ms > 0 {
            duration = Some(f64::from(ms) / 1000.0);
        }
        let meta_len = le32(b, 16) as usize;
        if let Some(meta) = b.get(28..28 + meta_len) {
            // `Key="value"` pairs.
            let text = String::from_utf8_lossy(meta);
            let mut rest = text.as_ref();
            while let Some(eq) = rest.find('=') {
                let key = rest[..eq].trim();
                let after = &rest[eq + 1..];
                let Some(q) = after.chars().next() else { break };
                let Some(end) = after[1..].find(q) else { break };
                let value = &after[1..=end];
                match key.to_ascii_lowercase().as_str() {
                    "title" => {
                        cx.content().title(value.to_string());
                        cx.format_set("title", value);
                    }
                    "url" => cx.format_set("url", value),
                    "creator" => cx.format_set("creator", value),
                    "aspect" => cx.format_set("aspect", value),
                    _ => {}
                }
                rest = &after[end + 2..];
            }
        }
        sync = header;
    }
    let Some(p) = b.get(sync..).and_then(|r| r.windows(4).position(|w| w == b"NSVs")).map(|p| p + sync) else {
        cx.warn("no NSVs frame");
        return;
    };
    let h = &b[p..];
    let (vtag, atag) = (tag(h.get(4..8)), tag(h.get(8..12)));
    let mut v = Video::new(match vtag.as_str() {
        "VP3" | "VP31" => "vp3",
        "VP5" => "vp5",
        "VP6" | "VP60" | "VP61" | "VP62" => "vp6",
        "H264" => "h264",
        "MPG4" | "XVID" => "mpeg4",
        "NONE" => "none",
        _ => "unknown",
    });
    v.codec_tag = Some(vtag);
    v.width = Some(u32::from(le16(h, 12)));
    v.height = Some(u32::from(le16(h, 14)));
    let code = h.get(16).copied().unwrap_or(0);
    v.fps = Some(if code & 0x80 == 0 {
        f64::from(code)
    } else {
        let t = f64::from((code & 0x7f) >> 2);
        let mut f = if t < 16.0 { 1.0 / (t + 1.0) } else { t - 15.0 };
        if code & 1 == 1 {
            f *= 1000.0 / 1001.0;
        }
        f * match code & 3 {
            3 => 24.0,
            2 => 25.0,
            _ => 30.0,
        }
    });
    let mut streams = vec![v.to_map()];
    if atag != "NONE" {
        let mut s = Stream::new(match atag.as_str() {
            "MP3" => "mp3",
            "AAC" | "AACP" => "aac",
            "PCM" => "pcm",
            "SPX" => "speex",
            _ => "unknown",
        });
        s.channels = None;
        streams.push(audio_map(&s));
        streams.last_mut().map(|m| m.insert("codec_tag".into(), json!(atag)));
    }
    finish(cx, streams, duration, len);
}

/// A four-character code, trimmed.
fn tag(b: Option<&[u8]>) -> String {
    String::from_utf8_lossy(b.unwrap_or_default()).trim().to_string()
}

fn arriraw(cx: &mut Context<'_>, h: &[u8]) {
    let little = h.get(4..8) == Some(b"\x12\x34\x56\x78");
    let rd = |at: usize| if little { le32(h, at) } else { be32(h, at) };
    cx.format_set("byte_order", if little { "little-endian" } else { "big-endian" });
    cx.format_set("version", rd(12));
    let (w, hgt) = (rd(20), rd(24));
    if w > 0 && hgt > 0 && w < 65_536 && hgt < 65_536 {
        cx.physical().image(w, hgt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("dv", "mxf", "amv", "flic", "bink", "smacker", "nsv", "r3d", "arriraw");

    #[test]
    fn mxf_helpers() {
        assert_eq!(ber(&[0x83, 0, 1, 0], 0), Some((256, 4)));
        assert_eq!(ber(&[0x10], 0), Some((16, 1)));
        let op1a = [6, 0x0e, 0x2b, 0x34, 4, 1, 1, 1, 0x0d, 1, 2, 1, 1, 1, 9, 0];
        assert_eq!(operational_pattern(&op1a), "OP1a");
        assert_eq!(bcd(0x59, 0x7f), 59);
    }
}
