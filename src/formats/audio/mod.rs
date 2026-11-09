//! `audio` extractors (feature `common`): tagged and lossless music formats,
//! speech codecs and broadcast WAV.
//!
//! Extractors read headers, tags and indexes only; samples are never
//! decoded. Every tag system (ID3, Vorbis comments, APEv2, iTunes `ilst`,
//! RIFF `INFO`, ASF, AIFF text chunks) is kept under `metadata.<standard>`
//! in its own names and mapped onto one normalised `format.tags` object by
//! [`Tags`], which also fills `content`, `rights` and `temporal`.

// Header parsers follow their specifications' field names and keep a reader
// `r`, data `d` and stream `s` in scope: short names are clearer here.
#![allow(clippy::many_single_char_names, clippy::similar_names)]
pub(crate) mod aiff;
pub(crate) mod apetag;
pub(crate) mod asf;
pub(crate) mod caf;
pub(crate) mod dsd;
pub(crate) mod flac;
pub(crate) mod id3;
pub(crate) mod instruments;
pub(crate) mod monkey;
pub(crate) mod mp4;
pub(crate) mod mpeg;
pub(crate) mod musepack;
pub(crate) mod ogg;
pub(crate) mod other;
pub(crate) mod projects;
pub(crate) mod raw;
pub(crate) mod riff;
pub(crate) mod vorbis;
pub(crate) mod wavpack;

use serde_json::{Map, Value, json};

use crate::plugin::{Context, DateField, TextRole, parse_date, squash_whitespace, truncate_chars};

/// Longest tag value kept (lyrics and comments can be long).
const MAX_VALUE: usize = 2000;
/// Pictures handed on as children.
const MAX_PICTURES: usize = 4;
/// Chapters listed.
const MAX_CHAPTERS: usize = 500;

/// Normalised tag names, in output order.
pub(crate) const CANONICAL: &[&str] = &[
    "title",
    "subtitle",
    "artist",
    "album",
    "album_artist",
    "track",
    "track_total",
    "disc",
    "disc_total",
    "date",
    "original_date",
    "genre",
    "composer",
    "lyricist",
    "conductor",
    "remixer",
    "label",
    "copyright",
    "isrc",
    "barcode",
    "catalog_number",
    "bpm",
    "key",
    "mood",
    "grouping",
    "language",
    "compilation",
    "comment",
    "description",
    "encoded_by",
    "musicbrainz_track_id",
    "musicbrainz_recording_id",
    "musicbrainz_album_id",
    "musicbrainz_artist_id",
    "musicbrainz_album_artist_id",
    "musicbrainz_release_group_id",
    "acoustid_id",
    "replaygain_track_gain_db",
    "replaygain_track_peak",
    "replaygain_album_gain_db",
    "replaygain_album_peak",
];

/// Tags with several values (repeated Vorbis comments, ID3 lists).
const MULTI: &[&str] = &["artist", "genre", "composer", "lyricist", "conductor", "album_artist"];

/// An embedded picture (cover art).
pub(crate) struct Picture {
    pub mime: String,
    /// ID3 / FLAC picture type (3 = front cover).
    pub kind: Option<u8>,
    pub description: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub data: Vec<u8>,
}

/// A chapter: start (and end) in seconds and a title.
pub(crate) struct Chapter {
    pub start_s: f64,
    pub end_s: Option<f64>,
    pub title: String,
}

/// Tags gathered from every tag system in a file, normalised.
/// The first value set wins, so callers read the preferred system first.
#[derive(Default)]
pub(crate) struct Tags {
    values: Vec<(&'static str, Vec<String>)>,
    pub pictures: Vec<Picture>,
    pub chapters: Vec<Chapter>,
    lyrics: Vec<String>,
    /// Encoder software (`TSSE`, Vorbis vendor, `©too`).
    pub encoder: Option<String>,
    /// Tag systems found, e.g. `id3v2.4`, `ape`, `vorbis`.
    pub systems: Vec<String>,
    /// Which system set the first normalised value (for provenance).
    source: Option<String>,
}

impl Tags {
    /// Record that the file carries a tag system.
    pub(crate) fn system(&mut self, name: impl Into<String>) {
        let name = name.into();
        if !self.systems.contains(&name) {
            self.systems.push(name);
        }
    }

    /// Set a normalised tag from a raw value (`3/9` for a track also sets the
    /// total). `source` names the system, e.g. `id3`.
    pub(crate) fn set(&mut self, key: &str, value: &str, source: &str) {
        let raw = value.trim_matches(char::from(0)).trim();
        if key == "lyrics" {
            if !raw.is_empty() && self.lyrics.len() < 8 {
                self.lyrics.push(truncate_chars(raw, 20_000));
            }
            return;
        }
        let value = squash_whitespace(raw);
        let value = value.as_str();
        if value.is_empty() {
            return;
        }
        match key {
            "track" | "disc" => {
                let (n, total) = value.split_once('/').map_or((value, None), |(a, b)| (a, Some(b)));
                self.put(key, n.trim(), source);
                if let Some(t) = total {
                    self.put(if key == "track" { "track_total" } else { "disc_total" }, t.trim(), source);
                }
            }
            "encoder" => {
                self.encoder.get_or_insert_with(|| value.to_string());
            }
            _ => self.put(key, value, source),
        }
    }

    /// Set a normalised tag only if no other system set it (ID3v1, whose
    /// fields are truncated copies, and whose genre falls back to "Other").
    pub(crate) fn fill(&mut self, key: &str, value: &str, source: &str) {
        if self.get(key).is_none() {
            self.set(key, value, source);
        }
    }

    fn put(&mut self, key: &str, value: &str, source: &str) {
        let Some(&key) = CANONICAL.iter().find(|k| **k == key) else { return };
        if value.is_empty() || (matches!(key, "track" | "disc" | "track_total" | "disc_total") && value == "0") {
            return;
        }
        let value = truncate_chars(value, MAX_VALUE);
        match self.values.iter_mut().find(|(k, _)| *k == key) {
            Some((_, list)) if MULTI.contains(&key) && !list.contains(&value) && list.len() < 16 => list.push(value),
            Some(_) => {}
            None => {
                self.source.get_or_insert_with(|| source.to_string());
                self.values.push((key, vec![value]));
            }
        }
    }

    /// The first value of a normalised tag.
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.values.iter().find(|(k, _)| *k == key).and_then(|(_, v)| v.first()).map(String::as_str)
    }

    /// Write `format.tags`, `format.cover_art`, `format.chapters`, the
    /// normalised sections, lyrics (as text) and pictures (as children).
    pub(crate) fn report(self, cx: &mut Context<'_>) {
        if !self.systems.is_empty() {
            cx.format_set("tag_formats", json!(self.systems));
        }
        if let Some(e) = &self.encoder {
            cx.format_set("encoder", e.as_str());
        }
        let source = self.source.clone().unwrap_or_default();
        let mut out = Map::new();
        for key in CANONICAL {
            let Some((_, list)) = self.values.iter().find(|(k, _)| k == key) else { continue };
            let value = if MULTI.contains(key) && list.len() > 1 { json!(list) } else { typed(key, &list[0]) };
            out.insert((*key).to_string(), value);
        }
        if !self.lyrics.is_empty() {
            out.insert("lyrics".into(), json!(true));
        }
        if !out.is_empty() {
            cx.format_set("tags", Value::Object(out));
        }
        self.normalise(cx, &source);
        for l in &self.lyrics {
            cx.emit_text(TextRole::Body, l);
        }
        if !self.chapters.is_empty() {
            let list: Vec<Value> = self
                .chapters
                .iter()
                .take(MAX_CHAPTERS)
                .map(|c| {
                    let mut m = Map::new();
                    m.insert("start_s".into(), json!(round_s(c.start_s)));
                    if let Some(e) = c.end_s {
                        m.insert("end_s".into(), json!(round_s(e)));
                    }
                    if !c.title.is_empty() {
                        m.insert("title".into(), json!(c.title));
                    }
                    Value::Object(m)
                })
                .collect();
            cx.format_set("chapter_count", self.chapters.len());
            cx.format_set("chapters", Value::Array(list));
            for c in self.chapters.iter().take(crate::plugin::MAX_OUTLINE) {
                if !c.title.is_empty() {
                    cx.content().source(format!("{source}.chapter")).heading(1, c.title.as_str());
                }
            }
        }
        if !self.pictures.is_empty() {
            let list: Vec<Value> = self
                .pictures
                .iter()
                .map(|p| {
                    let mut m = Map::new();
                    m.insert("mime".into(), json!(p.mime));
                    if let Some(k) = p.kind {
                        m.insert("picture_type".into(), json!(picture_type(k)));
                    }
                    if !p.description.is_empty() {
                        m.insert("description".into(), json!(p.description));
                    }
                    if let (Some(w), Some(h)) = (p.width.filter(|w| *w > 0), p.height.filter(|h| *h > 0)) {
                        m.insert("width_px".into(), json!(w));
                        m.insert("height_px".into(), json!(h));
                    }
                    m.insert("size_bytes".into(), json!(p.data.len()));
                    Value::Object(m)
                })
                .collect();
            cx.format_set("cover_art", Value::Array(list));
            for (i, p) in self.pictures.into_iter().take(MAX_PICTURES).enumerate() {
                let ext = match p.mime.as_str() {
                    "image/jpeg" | "image/jpg" => "jpg",
                    "image/png" => "png",
                    "image/gif" => "gif",
                    "image/bmp" => "bmp",
                    "image/webp" => "webp",
                    _ => "bin",
                };
                let name = if i == 0 { format!("cover.{ext}") } else { format!("picture-{}.{ext}", i + 1) };
                if cx.emit_child(&name, p.data).is_err() {
                    break;
                }
            }
        }
    }

    fn normalise(&self, cx: &mut Context<'_>, source: &str) {
        let all = |key: &str| self.values.iter().find(|(k, _)| *k == key).map_or(&[][..], |(_, v)| v.as_slice());
        if let Some(t) = self.get("title") {
            cx.content().source(format!("{source}.title")).title(t);
        }
        for a in all("artist") {
            cx.content().source(format!("{source}.artist")).author(a.as_str());
            cx.rights().source(format!("{source}.artist")).creator(a.as_str());
        }
        for a in all("composer") {
            cx.rights().source(format!("{source}.composer")).creator(a.as_str());
        }
        if let Some(d) = self.get("comment").or_else(|| self.get("description")) {
            cx.content().source(format!("{source}.comment")).description(d);
        }
        for g in all("genre") {
            cx.content().source(format!("{source}.genre")).tag(g.as_str());
        }
        if let Some(c) = self.get("copyright") {
            cx.rights().source(format!("{source}.copyright")).copyright(c);
        }
        for (key, field) in [("date", DateField::Created), ("original_date", DateField::Published)] {
            if let Some(d) = self.get(key)
                && let Some((v, tz)) = date(d)
            {
                cx.temporal().source(format!("{source}.{key}")).content_date(field, v, tz);
            }
        }
    }
}

/// A tag date as a content date: full dates through [`parse_date`], and a
/// bare year (`2024`) or year-month as it is.
fn date(s: &str) -> Option<(String, bool)> {
    let s = s.trim();
    if let Some(d) = parse_date(s) {
        return Some(d);
    }
    let b = s.as_bytes();
    let year = b.len() >= 4 && b[..4].iter().all(u8::is_ascii_digit);
    match b.len() {
        4 if year => Some((s.to_string(), false)),
        7 if year && b[4] == b'-' && b[5..].iter().all(u8::is_ascii_digit) => Some((s.to_string(), false)),
        _ => None,
    }
}

/// A normalised tag value with its JSON type: numbers for counts and gains,
/// booleans for flags.
fn typed(key: &str, v: &str) -> Value {
    match key {
        "track" | "track_total" | "disc" | "disc_total" | "bpm" => {
            v.parse::<u64>().map_or_else(|_| json!(v), |n| json!(n))
        }
        "replaygain_track_gain_db" | "replaygain_album_gain_db" | "replaygain_track_peak" | "replaygain_album_peak" => {
            let n = v.trim_end_matches(|c: char| c.is_ascii_alphabetic() || c == ' ');
            n.trim().parse::<f64>().map_or_else(|_| json!(v), |f| json!(f))
        }
        "compilation" => json!(matches!(v, "1" | "true" | "yes" | "True" | "YES" | "Yes")),
        _ => json!(v),
    }
}

/// The normalised tag for a Vorbis-comment-style key (Vorbis, FLAC, Opus,
/// APEv2, WavPack, Musepack). `key` is upper-cased by the caller.
pub(crate) fn comment_key(key: &str) -> Option<&'static str> {
    Some(match key {
        "TITLE" => "title",
        "SUBTITLE" | "VERSION" => "subtitle",
        "ARTIST" | "PERFORMER" | "AUTHOR" => "artist",
        "ALBUM" => "album",
        "ALBUMARTIST" | "ALBUM ARTIST" | "ALBUM_ARTIST" => "album_artist",
        "TRACKNUMBER" | "TRACK" => "track",
        "TRACKTOTAL" | "TOTALTRACKS" => "track_total",
        "DISCNUMBER" | "DISC" => "disc",
        "DISCTOTAL" | "TOTALDISCS" => "disc_total",
        "DATE" | "YEAR" | "RELEASEDATE" => "date",
        "ORIGINALDATE" | "ORIGINALYEAR" => "original_date",
        "GENRE" => "genre",
        "COMPOSER" => "composer",
        "LYRICIST" | "WRITER" => "lyricist",
        "CONDUCTOR" => "conductor",
        "REMIXER" | "MIXARTIST" => "remixer",
        "LABEL" | "PUBLISHER" | "ORGANIZATION" => "label",
        "COPYRIGHT" => "copyright",
        "ISRC" => "isrc",
        "BARCODE" | "UPC" | "EAN" => "barcode",
        "CATALOGNUMBER" | "CATALOG" => "catalog_number",
        "BPM" | "TEMPO" => "bpm",
        "KEY" | "INITIALKEY" => "key",
        "MOOD" => "mood",
        "GROUPING" | "CONTENTGROUP" => "grouping",
        "LANGUAGE" => "language",
        "COMPILATION" => "compilation",
        "COMMENT" => "comment",
        "DESCRIPTION" => "description",
        "ENCODEDBY" | "ENCODED-BY" | "ENCODED BY" => "encoded_by",
        "ENCODER" | "TOOL NAME" => "encoder",
        "LYRICS" | "UNSYNCEDLYRICS" | "UNSYNCED LYRICS" => "lyrics",
        "MUSICBRAINZ_TRACKID" | "MUSICBRAINZ_RELEASETRACKID" => "musicbrainz_track_id",
        "MUSICBRAINZ_RECORDINGID" => "musicbrainz_recording_id",
        "MUSICBRAINZ_ALBUMID" => "musicbrainz_album_id",
        "MUSICBRAINZ_ARTISTID" => "musicbrainz_artist_id",
        "MUSICBRAINZ_ALBUMARTISTID" => "musicbrainz_album_artist_id",
        "MUSICBRAINZ_RELEASEGROUPID" => "musicbrainz_release_group_id",
        "ACOUSTID_ID" => "acoustid_id",
        "REPLAYGAIN_TRACK_GAIN" => "replaygain_track_gain_db",
        "REPLAYGAIN_TRACK_PEAK" => "replaygain_track_peak",
        "REPLAYGAIN_ALBUM_GAIN" => "replaygain_album_gain_db",
        "REPLAYGAIN_ALBUM_PEAK" => "replaygain_album_peak",
        _ => return None,
    })
}

/// The normalised tag for a MusicBrainz Picard / foobar2000 free-form name
/// (ID3 `TXXX`, iTunes `----`, ASF), matched without case.
pub(crate) fn freeform_key(name: &str) -> Option<&'static str> {
    let upper = name.trim().to_ascii_uppercase().replace(' ', "_");
    Some(match upper.as_str() {
        "MUSICBRAINZ_ALBUM_ID" => "musicbrainz_album_id",
        "MUSICBRAINZ_ARTIST_ID" => "musicbrainz_artist_id",
        "MUSICBRAINZ_ALBUM_ARTIST_ID" => "musicbrainz_album_artist_id",
        "MUSICBRAINZ_RELEASE_GROUP_ID" => "musicbrainz_release_group_id",
        "MUSICBRAINZ_RELEASE_TRACK_ID" | "MUSICBRAINZ_TRACK_ID" => "musicbrainz_track_id",
        "ACOUSTID_ID" => "acoustid_id",
        "CATALOGNUMBER" => "catalog_number",
        _ => return comment_key(&upper.replace('_', "")).or_else(|| comment_key(&upper)),
    })
}

/// Add a raw value to `metadata.<standard>`: a repeated key becomes an
/// array (at most 64 values), and a value already there is not repeated.
pub(crate) fn add_raw(cx: &mut Context<'_>, standard: &str, key: &str, value: Value) {
    let map = cx.metadata(standard);
    match map.get_mut(key) {
        Some(Value::Array(list)) => {
            if list.len() < 64 && !list.contains(&value) {
                list.push(value);
            }
        }
        Some(old) if *old != value => {
            let first = old.take();
            *old = Value::Array(vec![first, value]);
        }
        Some(_) => {}
        None => {
            map.insert(key.to_string(), value);
        }
    }
}

/// ID3 / FLAC picture types.
pub(crate) fn picture_type(n: u8) -> &'static str {
    match n {
        1 => "file_icon",
        2 => "other_file_icon",
        3 => "front_cover",
        4 => "back_cover",
        5 => "leaflet",
        6 => "media",
        7 => "lead_artist",
        8 => "artist",
        9 => "conductor",
        10 => "band",
        11 => "composer",
        12 => "lyricist",
        13 => "recording_location",
        14 => "during_recording",
        15 => "during_performance",
        16 => "screen_capture",
        17 => "bright_coloured_fish",
        18 => "illustration",
        19 => "band_logotype",
        20 => "publisher_logotype",
        _ => "other",
    }
}

/// The image MIME type of picture data, by its signature.
pub(crate) fn sniff_image(data: &[u8]) -> &'static str {
    if data.starts_with(b"\xff\xd8\xff") {
        "image/jpeg"
    } else if data.starts_with(b"\x89PNG") {
        "image/png"
    } else if data.starts_with(b"GIF8") {
        "image/gif"
    } else if data.starts_with(b"BM") {
        "image/bmp"
    } else if data.len() > 12 && &data[8..12] == b"WEBP" {
        "image/webp"
    } else {
        "application/octet-stream"
    }
}

/// A positive finite value as a rounded `u32`.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // range checked first
pub(crate) fn whole_u32(v: f64) -> Option<u32> {
    (v.is_finite() && v > 0.0 && v < f64::from(u32::MAX)).then(|| v.round() as u32)
}

/// Bytes as lowercase hex (MD5 sums, UMIDs, unknown GUIDs).
pub(crate) fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::with_capacity(b.len() * 2), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// Seconds rounded to the microsecond, so reports stay stable.
pub(crate) fn round_s(v: f64) -> f64 {
    (v * 1e6).round() / 1e6
}

/// One audio stream, as `physical.media.streams[]` describes it.
#[derive(Default)]
pub(crate) struct Stream {
    pub codec: String,
    pub profile: Option<String>,
    pub sample_rate_hz: Option<u32>,
    pub channels: Option<u16>,
    pub channel_layout: Option<String>,
    pub bits_per_sample: Option<u16>,
    pub bitrate_bps: Option<u64>,
    pub vbr: Option<bool>,
    pub samples: Option<u64>,
    pub language: Option<String>,
}

impl Stream {
    /// A stream with this codec.
    pub(crate) fn new(codec: impl Into<String>) -> Self {
        Self { codec: codec.into(), ..Self::default() }
    }

    /// Duration from the sample count and rate.
    pub(crate) fn duration_s(&self) -> Option<f64> {
        let (n, r) = (self.samples?, self.sample_rate_hz.filter(|r| *r > 0)?);
        Some(n as f64 / f64::from(r))
    }

    pub(crate) fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("type".into(), json!("audio"));
        m.insert("codec".into(), json!(self.codec));
        if let Some(p) = &self.profile {
            m.insert("profile".into(), json!(p));
        }
        if let Some(v) = self.sample_rate_hz.filter(|v| *v > 0) {
            m.insert("sample_rate_hz".into(), json!(v));
        }
        if let Some(v) = self.channels.filter(|v| *v > 0) {
            m.insert("channels".into(), json!(v));
            let layout = self.channel_layout.clone().or_else(|| default_layout(v).map(str::to_string));
            if let Some(l) = layout {
                m.insert("channel_layout".into(), json!(l));
            }
        }
        if let Some(v) = self.bits_per_sample.filter(|v| *v > 0) {
            m.insert("bits_per_sample".into(), json!(v));
        }
        if let Some(v) = self.bitrate_bps.filter(|v| *v > 0) {
            m.insert("bitrate_bps".into(), json!(v));
        }
        if let Some(v) = self.vbr {
            m.insert("bitrate_mode".into(), json!(if v { "vbr" } else { "cbr" }));
        }
        if let Some(v) = self.samples {
            m.insert("samples".into(), json!(v));
        }
        if let Some(l) = &self.language {
            m.insert("language".into(), json!(l));
        }
        m
    }

    /// Write the stream, the duration (from the samples unless `duration_s`
    /// is given) and the overall bitrate (from the file size if not known).
    pub(crate) fn report(&self, cx: &mut Context<'_>, duration_s: Option<f64>, file_len: u64) {
        let duration = duration_s.or_else(|| self.duration_s()).filter(|d| d.is_finite() && *d > 0.0);
        let mut p = cx.physical();
        p.stream(self.to_map());
        if let Some(d) = duration {
            p.duration_s(round_s(d));
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, far below u64::MAX
            let overall = (file_len as f64 * 8.0 / d).round() as u64;
            p.bitrate_bps(overall);
        }
    }
}

/// The usual layout for a channel count.
fn default_layout(channels: u16) -> Option<&'static str> {
    Some(match channels {
        1 => "mono",
        2 => "stereo",
        3 => "2.1",
        4 => "quad",
        6 => "5.1",
        8 => "7.1",
        _ => return None,
    })
}

/// A channel layout from a WAVE / CAF speaker mask (bit 0 = front left).
pub(crate) fn mask_layout(mask: u32) -> Option<String> {
    const NAMES: [&str; 18] = [
        "FL", "FR", "FC", "LFE", "BL", "BR", "FLC", "FRC", "BC", "SL", "SR", "TC", "TFL", "TFC", "TFR", "TBL", "TBC",
        "TBR",
    ];
    let named = match mask {
        0x4 => "mono",
        0x3 => "stereo",
        0x33 => "quad",
        0x3f => "5.1",
        0x60f => "5.1(side)",
        0x63f => "7.1",
        _ => "",
    };
    if !named.is_empty() {
        return Some(named.to_string());
    }
    let list: Vec<&str> = NAMES.iter().enumerate().filter(|(i, _)| mask & (1 << i) != 0).map(|(_, n)| *n).collect();
    (!list.is_empty()).then(|| list.join("+"))
}

/// An 80-bit IEEE 754 extended float (AIFF sample rates), as `f64`.
pub(crate) fn extended(b: &[u8; 10]) -> f64 {
    let exp = i32::from(u16::from_be_bytes([b[0], b[1]]) & 0x7fff);
    let mant = u64::from_be_bytes([b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9]]);
    if exp == 0 && mant == 0 {
        return 0.0;
    }
    let v = mant as f64 * 2f64.powi(exp - 16383 - 63);
    if b[0] & 0x80 != 0 { -v } else { v }
}

/// Text of a tag field: UTF-8, else Latin-1, NULs trimmed.
pub(crate) fn text(b: &[u8]) -> String {
    crate::plugin::latin1_or_utf8(b).trim_matches(char::from(0)).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_floats() {
        assert!((extended(&[0x40, 0x0e, 0xac, 0x44, 0, 0, 0, 0, 0, 0]) - 44100.0).abs() < 1e-9);
        assert!((extended(&[0x40, 0x0d, 0xac, 0x44, 0, 0, 0, 0, 0, 0]) - 22050.0).abs() < 1e-9);
        assert!(extended(&[0; 10]).abs() < f64::EPSILON);
    }

    #[test]
    fn keys_and_values() {
        assert_eq!(comment_key("ALBUMARTIST"), Some("album_artist"));
        assert_eq!(freeform_key("MusicBrainz Album Id"), Some("musicbrainz_album_id"));
        assert_eq!(freeform_key("replaygain_track_gain"), Some("replaygain_track_gain_db"));
        assert_eq!(typed("replaygain_track_gain_db", "-6.54 dB"), json!(-6.54));
        assert_eq!(typed("track", "03"), json!(3));
        assert_eq!(date("2024"), Some(("2024".into(), false)));
        assert_eq!(date("soon"), None);
        assert_eq!(mask_layout(0x3).as_deref(), Some("stereo"));
        assert_eq!(mask_layout(0x5).as_deref(), Some("FL+FC"));
        let mut t = Tags::default();
        t.set("track", "3/9", "id3");
        t.set("artist", "A", "id3");
        t.set("artist", "B", "vorbis");
        t.set("title", "X", "vorbis");
        t.set("title", "Y", "vorbis");
        assert_eq!((t.get("track"), t.get("track_total"), t.get("title")), (Some("3"), Some("9"), Some("X")));
        assert_eq!(t.values.iter().find(|(k, _)| *k == "artist").map(|(_, v)| v.len()), Some(2));
    }
}
