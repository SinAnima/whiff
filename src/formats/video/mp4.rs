//! MPEG-4 and QuickTime video (MP4, M4V, MOV, 3GP / 3G2, F4V, CMAF / DASH
//! segments): brands, every track (video codec configuration with profile,
//! level, size, aspect ratio, frame rate, depth, chroma, colour and HDR;
//! audio; subtitles; timecode and metadata tracks), rotation, chapters,
//! iTunes / QuickTime tags, camera make / model / software and location
//! (`com.apple.quicktime.*`, `©xyz`), XMP, encryption, and the layout
//! (fragmented, faststart).
//!
//! The file structure is read by `plugin::mp4`; codec configuration records
//! by [`super::codec`].

use serde_json::{Map, Value, json};

use super::super::audio::{self, Chapter, Stream, Tags};
use super::super::subtitle;
use super::codec::{self, Colour};
use super::{Device, Video, audio_map, finish, iso6709, labels, other_map};
use crate::plugin::mp4::{self, Track, Value as ItemValue};
use crate::plugin::{
    BlockKind, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff,
    Source,
};

/// Extractor for MP4 / QuickTime video.
pub struct Mp4Video;

static META: ExtractorMeta = ExtractorMeta {
    id: "video.mp4",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "mp4",
            name: "MPEG-4 video",
            family: "video",
            mimes: &["video/mp4", "video/x-m4v", "video/x-f4v", "video/iso.segment"],
            extensions: &["mp4", "m4v", "f4v", "m4s", "cmfv", "ismv", "mp4v", "insv", "osv"],
            magic: &[
                Magic::at(4, b"ftypisom"),
                Magic::at(4, b"ftypiso2"),
                Magic::at(4, b"ftypiso4"),
                Magic::at(4, b"ftypiso5"),
                Magic::at(4, b"ftypiso6"),
                Magic::at(4, b"ftypmp41"),
                Magic::at(4, b"ftypmp42"),
                Magic::at(4, b"ftypavc1"),
                Magic::at(4, b"ftypM4V "),
                Magic::at(4, b"ftypM4VH"),
                Magic::at(4, b"ftypM4VP"),
                Magic::at(4, b"ftypf4v "),
                Magic::at(4, b"ftypdash"),
                Magic::at(4, b"ftypcmfc"),
                Magic::at(4, b"ftypMSNV"),
                Magic::at(4, b"ftypXAVC"),
                Magic::at(4, b"ftypmmp4"),
            ],
            parent: None,
        },
        FormatSpec {
            id: "mov",
            name: "QuickTime movie",
            family: "video",
            mimes: &["video/quicktime"],
            extensions: &["mov", "qt"],
            magic: &[Magic::at(4, b"ftypqt  ")],
            parent: None,
        },
        FormatSpec {
            id: "3gp",
            name: "3GPP multimedia",
            family: "video",
            mimes: &["video/3gpp", "video/3gpp2"],
            extensions: &["3gp", "3g2", "3gpp", "3gpp2"],
            magic: &[Magic::at(4, b"ftyp3gp"), Magic::at(4, b"ftyp3g2")],
            parent: None,
        },
    ],
};

/// Major brands other extractors claim (HEIF / AVIF images, M4A audio).
const NOT_VIDEO: &[&[u8; 4]] = &[
    b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"mif1", b"msf1", b"avif", b"avis", b"M4A ", b"M4B ",
    b"M4P ", b"M4R ", b"crx ", b"jp2 ", b"jpx ", b"jpm ", b"mjp2",
];

impl Extractor for Mp4Video {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let kind = probe.head.get(4..8)?;
        if kind == b"ftyp" {
            let brand: &[u8; 4] = probe.head.get(8..12)?.try_into().ok()?;
            if NOT_VIDEO.contains(&brand) {
                return None;
            }
            let format = match brand {
                b"qt  " => "mov",
                [b'3', b'g', ..] => "3gp",
                _ => "mp4",
            };
            return Some(Sniff { format, confidence: 0.7 });
        }
        // Classic QuickTime files start with the movie, free space or the media data.
        let size = u32::from_be_bytes(probe.head.get(..4)?.try_into().ok()?);
        let known = |k: &[u8]| matches!(k, b"moov" | b"mdat" | b"wide" | b"free" | b"skip" | b"pnot");
        if !known(kind) || size < 8 {
            return None;
        }
        let next = usize::try_from(size).ok()?;
        let follows = probe.head.get(next + 4..next + 8).is_some_and(known) || u64::from(size) == probe.len;
        (kind == b"moov" || follows).then_some(Sniff { format: "mov", confidence: 0.75 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let movie = mp4::read(src)?;
        if !movie.major_brand.is_empty() {
            cx.format_set("major_brand", movie.major_brand.as_str());
            cx.format_set("minor_version", movie.minor_version);
            cx.format_set("compatible_brands", json!(movie.compatible_brands));
        }
        cx.format_set("top_level_boxes", json!(movie.top));
        cx.format_set("fragmented", movie.fragmented);
        if movie.fragments > 0 {
            cx.format_set("fragments", movie.fragments);
        }
        if let Some(f) = movie.faststart {
            cx.format_set("faststart", f);
        }
        for (when, field, key) in
            [(movie.created, DateField::Created, "created"), (movie.modified, DateField::Modified, "modified")]
        {
            if let Some(t) = mp4::mac_time(when) {
                cx.temporal().source(format!("mp4.mvhd.{key}")).content_date(field, t, true);
            }
        }
        let duration = movie.duration_s();
        let chapter_tracks: Vec<u32> = movie.tracks.iter().flat_map(|t| t.chapter_tracks.iter().copied()).collect();
        let mut tracks = Vec::new();
        let mut streams = Vec::new();
        let mut schemes = Vec::new();
        let mut texts = Vec::new();
        for t in &movie.tracks {
            let track_s = track_seconds(t);
            let mut entry = json!({
                "id": t.id,
                "handler": t.handler,
                "codec": t.codec,
                "duration_s": track_s.map(audio::round_s),
                "enabled": t.enabled,
            });
            if let Some(l) = &t.language {
                entry["language"] = json!(l);
            }
            if !t.handler_name.is_empty() {
                entry["handler_name"] = json!(crate::plugin::truncate_chars(&t.handler_name, 200));
            }
            if let Some(c) = &t.compressor {
                entry["compressor"] = json!(c);
            }
            tracks.push(entry);
            if let Some(p) = &t.protection {
                schemes.push(p.clone());
            }
            let mut map = match t.handler.as_str() {
                "vide" => video_track(t).to_map(),
                "soun" => audio_track(t),
                _ if chapter_tracks.contains(&t.id) => other_map("data", "chapters"),
                "text" | "sbtl" | "subt" | "clcp" => other_map("subtitle", subtitle_codec(&t.codec)),
                "tmcd" => other_map("data", "timecode"),
                _ => other_map("data", data_codec(&t.codec)),
            };
            if t.handler != "vide" {
                let lang = t.language.as_deref();
                labels(&mut map, lang, t.name.as_deref(), None, None);
            }
            if !t.text_samples.is_empty() {
                texts.push(subtitle::Embedded {
                    stream: streams.len(),
                    cues: text_cues(t),
                    default: t.enabled,
                    forced: false,
                });
            }
            streams.push(map);
        }
        subtitle::embedded(cx, &mut streams, &texts);
        cx.format_set("tracks", json!(tracks));
        cx.format_set("media_data_bytes", movie.mdat_bytes);
        if !schemes.is_empty() || movie.tracks.iter().any(|t| matches!(t.codec.as_str(), "drmi" | "drms")) {
            schemes.dedup();
            cx.format_set("drm", if schemes.is_empty() { json!(["fairplay"]) } else { json!(schemes) });
            cx.security().encrypted(true);
        }
        finish(cx, streams, duration, src.len());
        let mut tags = Tags::default();
        for c in &movie.chapters {
            tags.chapters.push(Chapter { start_s: c.start_s, end_s: None, title: c.title.clone() });
        }
        audio::mp4::close_chapters(&mut tags.chapters, duration);
        audio::mp4::items(&movie.items, cx, &mut tags);
        device(&movie.items, cx);
        tags.report(cx);
        if let Some(x) = movie.xmp {
            cx.emit_block(BlockKind::XMP, x);
        }
        Ok(())
    }
}

crate::register_extractor!(Mp4Video);

/// A subtitle track's text samples as cues (WebVTT payloads keep their tags).
fn text_cues(t: &Track) -> Vec<subtitle::Cue> {
    let mut markup = std::collections::BTreeSet::new();
    t.text_samples
        .iter()
        .map(|s| subtitle::Cue {
            start: s.start_s,
            end: Some(s.end_s),
            text: subtitle::plain_text(&s.text, &mut markup),
            speaker: None,
        })
        .collect()
}

fn track_seconds(t: &Track) -> Option<f64> {
    (t.timescale > 0 && t.duration > 0).then(|| t.duration as f64 / f64::from(t.timescale))
}

/// ffprobe's name for a visual sample-entry type.
fn video_codec(fourcc: &str, esds: Option<&str>) -> String {
    match fourcc {
        "avc1" | "avc2" | "avc3" | "avc4" | "dva1" | "dvav" => "h264",
        "hvc1" | "hev1" | "dvh1" | "dvhe" => "hevc",
        "vvc1" | "vvi1" => "vvc",
        "av01" | "dav1" => "av1",
        "vp08" => "vp8",
        "vp09" => "vp9",
        "mp4v" => return esds.filter(|e| *e != "other").unwrap_or("mpeg4").to_string(),
        "s263" | "h263" | "H263" => "h263",
        "jpeg" | "mjpa" | "mjpb" | "AVDJ" | "dmb1" => "mjpeg",
        "mjp2" => "jpeg2000",
        "apco" | "apcs" | "apcn" | "apch" | "ap4h" | "ap4x" => "prores",
        "dvc " | "dvcp" | "dvpp" | "dv5n" | "dv5p" | "dvh2" | "dvh3" | "dvh5" | "dvh6" | "dvhp" | "dvhq" => "dvvideo",
        "AVdn" | "AVdh" => "dnxhd",
        "png " => "png",
        "rle " => "qtrle",
        "raw " | "2vuy" | "yuv2" | "v210" | "v410" | "v308" | "yuvs" | "j420" => "rawvideo",
        "SVQ1" => "svq1",
        "SVQ3" => "svq3",
        "cvid" => "cinepak",
        "smc " => "smc",
        "rpza" => "rpza",
        "icod" => "aic",
        "hap1" | "hap5" | "hapy" | "hapm" | "hapa" => "hap",
        "mx3p" | "mx4p" | "mx5p" | "mx3n" | "mx4n" | "mx5n" | "mp2v" | "hdv1" | "hdv2" | "hdv3" | "hdv5" | "hdv6"
        | "hdv7" | "hdv8" | "hdv9" | "hdva" | "xdv1" | "xdv2" | "xdv3" | "xdv4" | "xdv5" | "xdv6" | "xdv7" | "xdv8"
        | "xdv9" | "xdva" | "xdvb" | "xdvc" | "xdvd" | "xdve" | "xdvf" | "xd54" | "xd55" | "xd59" | "xd5a" | "xd5b"
        | "xd5c" | "xd5d" | "xd5e" | "xd5f" => "mpeg2video",
        other => return other.trim().to_ascii_lowercase(),
    }
    .to_string()
}

#[allow(clippy::too_many_lines)] // one arm per configuration box
fn video_track(t: &Track) -> Video {
    let fourcc = match (t.codec.as_str(), &t.original_format) {
        ("encv", Some(f)) => f.as_str(),
        (c, _) => c,
    };
    let mut v = Video::new(video_codec(fourcc, t.profile.as_deref()));
    v.codec_tag = Some(fourcc.to_string());
    v.encrypted = t.codec == "encv";
    if let Some((w, h)) = t.dimensions.filter(|d| d.0 > 0 && d.1 > 0) {
        (v.width, v.height) = (Some(u32::from(w)), Some(u32::from(h)));
    }
    v.display = t.display;
    v.rotation = t.rotation;
    let mut colour = Colour::default();
    for (kind, body) in &t.configs {
        match kind {
            b"avcC" => {
                if let Some(c) = codec::avcc(body) {
                    v.absorb(c);
                }
            }
            b"hvcC" => {
                if let Some(c) = codec::hvcc(body) {
                    v.absorb(c);
                }
            }
            b"av1C" => {
                if let Some(c) = codec::av1c(body) {
                    v.absorb(c);
                }
            }
            b"vpcC" => {
                if let Some(c) = codec::vpcc(&v.codec, body) {
                    v.absorb(c);
                }
            }
            b"colr" if body.len() >= 10 => {
                let n = |i: usize| u32::from(u16::from_be_bytes([body[i], body[i + 1]]));
                match &body[..4] {
                    b"nclx" => colour = Colour::new(n(4), n(6), n(8), body.get(10).map(|b| b & 0x80 != 0)),
                    b"nclc" => colour = Colour::new(n(4), n(6), n(8), None),
                    _ => {}
                }
            }
            b"pasp" if body.len() >= 8 => {
                let h = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let vs = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                v.sar = Some((h, vs)).filter(|s| s.0 > 0 && s.1 > 0);
            }
            b"mdcv" if body.len() >= 24 => {
                let lum = |i: usize| f64::from(u32::from_be_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]));
                v.mastering = Some((lum(16) / 10_000.0, lum(20) / 10_000.0));
            }
            b"SmDm" if body.len() >= 28 => {
                // Full box; luminance as 24.8 and 18.14 fixed point.
                let d = &body[4..];
                let lum = |i: usize| f64::from(u32::from_be_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]));
                v.mastering = Some((lum(16) / 256.0, lum(20) / 16384.0));
            }
            b"clli" if body.len() >= 4 => {
                let n = |i: usize| u32::from(u16::from_be_bytes([body[i], body[i + 1]]));
                v.light_level = Some((n(0), n(2)));
            }
            b"CoLL" if body.len() >= 8 => {
                let n = |i: usize| u32::from(u16::from_be_bytes([body[i], body[i + 1]]));
                v.light_level = Some((n(4), n(6)));
            }
            b"dvcC" | b"dvvC" | b"dvwC" => v.dolby_vision = codec::dolby_vision(body),
            b"fiel" if body.len() >= 2 => {
                v.interlaced = Some(body[0] == 2);
                if body[0] == 2 {
                    v.field_order = match body[1] {
                        1 | 9 => Some("top_first"),
                        6 | 14 => Some("bottom_first"),
                        _ => None,
                    };
                }
            }
            b"st3d" if body.len() >= 5 => {
                v.stereo_mode = match body[4] {
                    1 => Some("top_bottom".into()),
                    2 => Some("left_right".into()),
                    3 => Some("custom".into()),
                    _ => None,
                };
            }
            _ => {}
        }
    }
    let k = &mut v.colour;
    k.primaries = colour.primaries.or(k.primaries);
    k.transfer = colour.transfer.or(k.transfer);
    k.matrix = colour.matrix.or(k.matrix);
    k.full_range = colour.full_range.or(k.full_range);
    if let Some(dsi) = &t.decoder_config {
        let c = if v.codec == "mpeg4" { codec::mpeg4_visual(dsi) } else { codec::mpeg_sequence(dsi) };
        if let Some(c) = c {
            v.absorb(c);
        }
    }
    if v.codec == "prores" {
        v.profile = codec::prores_profile(fourcc).map(Into::into);
    }
    let samples = if t.samples > 0 { t.samples } else { t.fragment_samples };
    v.frames = Some(samples).filter(|n| *n > 0);
    let seconds = track_seconds(t);
    v.fps = match (t.sample_delta, seconds) {
        (Some(d), _) if d > 0 && t.timescale > 0 => Some(f64::from(t.timescale) / f64::from(d)),
        (_, Some(s)) if samples > 0 => Some(samples as f64 / s),
        _ => v.fps,
    };
    v.vfr = (samples > 1).then_some(t.variable_delta);
    v.duration_s = seconds;
    v.bitrate_bps = t.avg_bitrate.map(u64::from).or_else(|| bitrate(t.sample_bytes, seconds));
    v.max_bitrate_bps = t.max_bitrate.map(u64::from).filter(|m| Some(*m) != v.bitrate_bps);
    v.language.clone_from(&t.language);
    v.title.clone_from(&t.name);
    v
}

fn bitrate(bytes: u64, seconds: Option<f64>) -> Option<u64> {
    let s = seconds.filter(|s| *s > 0.0)?;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, small
    Some((bytes as f64 * 8.0 / s).round() as u64).filter(|b| *b > 0)
}

fn audio_track(t: &Track) -> Map<String, Value> {
    let mut s = Stream::new(audio::mp4::codec(t));
    s.profile = t.profile.clone().filter(|p| p.starts_with("aac_") || p.starts_with("he_") || p.starts_with("xhe"));
    s.sample_rate_hz = t.sample_rate;
    s.channels = t.channels;
    s.bits_per_sample =
        t.bits.filter(|_| matches!(t.codec.as_str(), "alac" | "fLaC" | "lpcm" | "ipcm" | "sowt" | "twos" | "in24"));
    s.bitrate_bps = t.avg_bitrate.map(u64::from).or_else(|| bitrate(t.sample_bytes, track_seconds(t)));
    let mut m = audio_map(&s);
    if t.codec == "enca" {
        m.insert("encrypted".into(), json!(true));
    }
    m
}

fn subtitle_codec(fourcc: &str) -> &str {
    match fourcc {
        "tx3g" | "text" => "mov_text",
        "wvtt" => "webvtt",
        "stpp" => "ttml",
        "c608" => "eia_608",
        "c708" => "eia_708",
        other => other,
    }
}

fn data_codec(fourcc: &str) -> &str {
    match fourcc {
        "gpmd" => "gopro_telemetry",
        "camm" => "camera_motion",
        "mebx" => "timed_metadata",
        "rtp " => "rtp_hint",
        other => other,
    }
}

/// Camera make, model, software and location from QuickTime metadata,
/// `©xyz`-style user data and Android keys.
fn device(items: &[mp4::Item], cx: &mut Context<'_>) {
    let mut d = Device::default();
    for item in items {
        let ItemValue::Text(text) = &item.value else { continue };
        match item.key.as_str() {
            "com.apple.quicktime.make" | "udta:©mak" | "com.android.manufacturer" => {
                d.make.get_or_insert_with(|| text.clone());
            }
            "com.apple.quicktime.model" | "udta:©mod" | "com.android.model" => {
                d.model.get_or_insert_with(|| text.clone());
            }
            "com.apple.quicktime.software" | "udta:©swr" => {
                d.software.get_or_insert_with(|| text.clone());
            }
            "com.android.version" => {
                d.software.get_or_insert_with(|| format!("Android {text}"));
            }
            "com.apple.quicktime.location.ISO6709" | "udta:©xyz" if d.location.is_none() => {
                d.location = iso6709(text);
                d.location_source = format!("quicktime.{}", item.key.trim_start_matches("udta:"));
            }
            "com.apple.quicktime.creationdate" => {
                if let Some((v, tz)) = crate::plugin::parse_date(text) {
                    cx.temporal().source("quicktime.creationdate").content_date(DateField::Captured, v, tz);
                }
            }
            _ => {}
        }
    }
    d.report(cx);
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("mp4", "mov", "3gp");

    #[test]
    fn codec_names() {
        assert_eq!(video_codec("avc1", None), "h264");
        assert_eq!(video_codec("mp4v", Some("mpeg2video")), "mpeg2video");
        assert_eq!(video_codec("mp4v", Some("other")), "mpeg4");
        assert_eq!(video_codec("apch", None), "prores");
        assert_eq!(video_codec("XYZ1", None), "xyz1");
        assert_eq!((subtitle_codec("tx3g"), data_codec("gpmd")), ("mov_text", "gopro_telemetry"));
    }
}
