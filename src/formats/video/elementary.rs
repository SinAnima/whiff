//! Elementary video streams: H.264 and HEVC Annex B byte streams (their
//! sequence parameter sets), MPEG-1 / MPEG-2 video (the sequence header),
//! AV1 in the low-overhead OBU format (the sequence header), IVF (VP8 /
//! VP9 / AV1 frames: header, frame count, time stamps, first key frame),
//! and YUV4MPEG2 (header parameters, frame count).
//!
//! Specifications: ITU-T H.264 / H.265 Annex B, ISO/IEC 13818-2 §6.2.2,
//! AV1 Bitstream §5.2 and Annex B, the IVF header used by libvpx and
//! libaom, and the YUV4MPEG2 description (mjpegtools).

use super::codec;
use super::{Video, finish};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source};

/// Extractor for elementary video streams.
pub struct Elementary;

static META: ExtractorMeta = ExtractorMeta {
    id: "video.elementary",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "h264",
            name: "H.264 elementary stream",
            family: "video",
            mimes: &["video/h264"],
            extensions: &["h264", "264"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "hevc",
            name: "HEVC elementary stream",
            family: "video",
            mimes: &["video/h265"],
            extensions: &["hevc", "h265", "265"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "m2v",
            name: "MPEG video elementary stream",
            family: "video",
            mimes: &["video/mpv"],
            extensions: &["m2v", "m1v", "mpv"],
            magic: &[Magic::prefix(&[0, 0, 1, 0xb3])],
            parent: None,
        },
        FormatSpec {
            id: "ivf",
            name: "IVF video",
            family: "video",
            mimes: &["video/x-ivf"],
            extensions: &["ivf"],
            magic: &[Magic::prefix(b"DKIF")],
            parent: None,
        },
        FormatSpec {
            id: "obu",
            name: "AV1 OBU stream",
            family: "video",
            mimes: &["video/av1"],
            extensions: &["obu", "av1"],
            magic: &[Magic::prefix(&[0x12, 0x00, 0x0a])],
            parent: None,
        },
        FormatSpec {
            id: "y4m",
            name: "YUV4MPEG2 video",
            family: "video",
            mimes: &["video/x-yuv4mpeg"],
            extensions: &["y4m"],
            magic: &[Magic::prefix(b"YUV4MPEG2 ")],
            parent: None,
        },
    ],
};

/// Bytes read for parameter sets and sequence headers.
const HEAD: usize = 1 << 20;
/// IVF frames walked for the time stamps.
const MAX_IVF_FRAMES: u64 = 1 << 20;

/// `h264` or `hevc` from the first NAL unit after a start code.
fn annexb(head: &[u8]) -> Option<&'static str> {
    let at = match head {
        [0, 0, 0, 1, ..] => 4,
        [0, 0, 1, ..] => 3,
        _ => return None,
    };
    let (a, b) = (*head.get(at)?, *head.get(at + 1)?);
    if a & 0x80 != 0 {
        return None;
    }
    // HEVC: VPS, SPS, PPS, AUD or SEI with layer 0 and temporal id 1.
    if matches!((a >> 1) & 0x3f, 32..=35 | 39) && b == 1 {
        return Some("hevc");
    }
    matches!(a & 0x1f, 7 | 9 | 6).then_some("h264")
}

impl Extractor for Elementary {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let format = annexb(probe.head)?;
        Some(Sniff { format, confidence: 0.6 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let (head, _) = src.read_prefix(HEAD)?;
        let format = cx.format_id().to_string();
        let mut duration = None;
        let v = match format.as_str() {
            "h264" | "hevc" => {
                let nals = codec::annexb_nals(&head, 256);
                let parse = if format == "h264" { codec::h264_sps } else { codec::hevc_sps };
                let v = nals.into_iter().find_map(parse);
                if v.is_none() {
                    cx.warn("no sequence parameter set in the first MiB");
                }
                v.unwrap_or_else(|| Video::new(format.clone()))
            }
            "m2v" => codec::mpeg_sequence(&head).ok_or_else(|| ExtractError::malformed("no sequence header"))?,
            "obu" => codec::av1_obus(&head).unwrap_or_else(|| Video::new("av1")),
            "ivf" => {
                let (v, d) = ivf(src, &head, cx)?;
                duration = d;
                v
            }
            "y4m" => {
                let (v, d) = y4m(&head, len).ok_or_else(|| ExtractError::malformed("YUV4MPEG2 header"))?;
                duration = d;
                v
            }
            _ => return Err(ExtractError::malformed("unknown elementary stream")),
        };
        finish(cx, vec![v.to_map()], duration, len);
        Ok(())
    }
}

crate::register_extractor!(Elementary);

fn ivf(src: &mut dyn Source, head: &[u8], cx: &mut Context<'_>) -> Result<(Video, Option<f64>), ExtractError> {
    let h = head.get(..32).ok_or_else(|| ExtractError::malformed("IVF header"))?;
    let u16le = |i: usize| u16::from_le_bytes([h[i], h[i + 1]]);
    let u32le = |i: usize| u32::from_le_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]);
    let header_len = u64::from(u16le(6)).max(32);
    let fourcc = String::from_utf8_lossy(&h[8..12]).into_owned();
    let (rate, scale, frames) = (u32le(16), u32le(20), u32le(24));
    let mut v = Video::new(match fourcc.as_str() {
        "VP80" => "vp8",
        "VP90" => "vp9",
        "AV01" => "av1",
        other => return Ok((Video::new(other.to_ascii_lowercase()), None)),
    });
    v.codec_tag = Some(fourcc);
    (v.width, v.height) = (Some(u32::from(u16le(12))), Some(u32::from(u16le(14))));
    // Walk the frame headers for the count and the time stamps.
    let (mut pos, mut count, mut first_pts, mut last_pts) = (header_len, 0u64, None, None);
    let len = src.len();
    while pos + 12 <= len && count < MAX_IVF_FRAMES {
        if count % 4096 == 0 {
            cx.checkpoint()?;
        }
        let f = src.read_vec(pos, 12)?;
        let size = u64::from(u32::from_le_bytes([f[0], f[1], f[2], f[3]]));
        let pts = u64::from_le_bytes(f[4..12].try_into().unwrap_or_default());
        if pos + 12 + size > len {
            break;
        }
        if count == 0 {
            let data = src.read_vec(pos + 12, usize::try_from(size.min(64 << 10)).unwrap_or(0))?;
            let parsed = match v.codec.as_str() {
                "vp9" => codec::vp9_frame(&data),
                "vp8" => codec::vp8_frame(&data),
                _ => codec::av1_obus(&data),
            };
            if let Some(c) = parsed {
                v.absorb(c);
            }
        }
        first_pts.get_or_insert(pts);
        last_pts = Some(pts);
        count += 1;
        pos += 12 + size;
    }
    v.frames = Some(if count > 0 { count } else { u64::from(frames) });
    let tick = (rate > 0 && scale > 0).then(|| f64::from(scale) / f64::from(rate));
    let duration = match (tick, first_pts, last_pts) {
        (Some(t), Some(a), Some(b)) if b > a && count > 1 => {
            // The span of the time stamps plus one average frame.
            let span = (b - a) as f64 * t;
            let per = span / (count - 1) as f64;
            v.fps = Some(1.0 / per);
            Some(span + per)
        }
        (Some(t), _, _) if frames > 0 => {
            v.fps = Some(1.0 / t);
            Some(f64::from(frames) * t)
        }
        _ => None,
    };
    Ok((v, duration))
}

/// A YUV4MPEG2 header: size, frame rate, aspect, interlacing, colour space.
fn y4m(head: &[u8], len: u64) -> Option<(Video, Option<f64>)> {
    let end = head.iter().position(|&b| b == b'\n')?;
    let line = std::str::from_utf8(&head[10..end]).ok()?;
    let mut v = Video::new("rawvideo");
    let (mut w, mut h, mut fps, mut space) = (0u32, 0u32, None, "420jpeg");
    let ratio = |s: &str| -> Option<(u32, u32)> {
        let (a, b) = s.split_once(':')?;
        Some((a.parse().ok()?, b.parse().ok()?))
    };
    for p in line.split_ascii_whitespace() {
        let (tag, val) = p.split_at(1);
        match tag {
            "W" => w = val.parse().ok()?,
            "H" => h = val.parse().ok()?,
            "F" => fps = ratio(val).filter(|r| r.0 > 0 && r.1 > 0),
            "A" => v.sar = ratio(val).filter(|r| r.0 > 0 && r.1 > 0),
            "I" => {
                v.interlaced = match val {
                    "p" => Some(false),
                    "t" | "b" | "m" => Some(true),
                    _ => None,
                };
                v.field_order = match val {
                    "t" => Some("top_first"),
                    "b" => Some("bottom_first"),
                    _ => None,
                };
            }
            "C" => space = val,
            _ => {}
        }
    }
    let (chroma, depth) = match space {
        s if s.starts_with("420") => ("4:2:0", if s.contains("p1") { s[5..].parse().unwrap_or(10) } else { 8 }),
        s if s.starts_with("422") => ("4:2:2", if s.contains("p1") { s[5..].parse().unwrap_or(10) } else { 8 }),
        s if s.starts_with("444") => ("4:4:4", if s.contains("p1") { s[5..].parse().unwrap_or(10) } else { 8 }),
        "mono" => ("4:0:0", 8),
        s if s.starts_with("mono1") => ("4:0:0", s[4..].parse().unwrap_or(16)),
        _ => ("4:2:0", 8),
    };
    v.codec_tag = Some(format!("C{space}"));
    v.chroma = Some(chroma);
    v.bit_depth = Some(depth);
    (v.width, v.height) = (Some(w), Some(h));
    v.fps = fps.map(|(a, b)| f64::from(a) / f64::from(b));
    let samples = u64::from(w) * u64::from(h);
    let planes = match chroma {
        "4:2:0" => samples * 3 / 2,
        "4:2:2" => samples * 2,
        "4:4:4" if space.contains("alpha") => samples * 4,
        "4:4:4" => samples * 3,
        _ => samples,
    };
    let frame = planes * if depth > 8 { 2 } else { 1 } + 6;
    let frames = (len.saturating_sub(end as u64 + 1)) / frame.max(1);
    v.frames = Some(frames);
    let duration = fps.map(|(a, b)| frames as f64 * f64::from(b) / f64::from(a));
    Some((v, duration))
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("h264", "hevc", "m2v", "ivf", "y4m", "obu");

    #[test]
    fn sniffs_and_y4m() {
        assert_eq!(annexb(&[0, 0, 0, 1, 0x67, 0x64]), Some("h264"));
        assert_eq!(annexb(&[0, 0, 0, 1, 0x40, 0x01]), Some("hevc"));
        assert_eq!(annexb(&[0, 0, 0, 1, 0xff, 0x01]), None);
        let mut f = b"YUV4MPEG2 W4 H2 F25:1 Ip A1:1 C420jpeg\n".to_vec();
        for _ in 0..3 {
            f.extend_from_slice(b"FRAME\n");
            f.extend_from_slice(&[0; 12]);
        }
        let (v, d) = y4m(&f, f.len() as u64).unwrap();
        assert_eq!((v.width, v.height, v.frames, v.chroma), (Some(4), Some(2), Some(3), Some("4:2:0")));
        assert_eq!(d, Some(0.12));
    }
}
