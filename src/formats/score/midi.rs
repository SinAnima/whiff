//! Standard MIDI files (formats 0, 1 and 2), karaoke files (`.kar`) and
//! RIFF MIDI (`RMID`, with its `INFO` list): the timing division, tracks
//! with their names, instruments and channels, the tempo map, time and key
//! signatures, programs (General MIDI names) and the percussion channel,
//! note counts, the GM / GM2 / GS / XG system message, markers, cue points,
//! copyright and text, lyrics, and the duration that follows from the
//! tempo map.
//!
//! Specifications: the MIDI 1.0 Detailed Specification (Standard MIDI
//! Files 1.0), General MIDI 1 and 2, Microsoft RIFF MIDI, the KMIDI
//! karaoke conventions.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use super::super::audio::{Chapter, Tags, riff};
use super::{GM_PROGRAMS, key_name, ms};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, TextRole, truncate_chars,
};

/// Extractor for MIDI files.
pub struct Midi;

static META: ExtractorMeta = ExtractorMeta {
    id: "score.midi",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "midi",
            name: "Standard MIDI file",
            family: "audio.score",
            mimes: &["audio/midi", "audio/x-midi"],
            extensions: &["mid", "midi", "kar", "smf"],
            magic: &[Magic::prefix(b"MThd\0\0\0\x06")],
            parent: None,
        },
        FormatSpec {
            id: "rmi",
            name: "RIFF MIDI",
            family: "audio.score",
            mimes: &["audio/mid"],
            extensions: &["rmi"],
            magic: &[Magic::masked(0, b"RIFF\0\0\0\0RMID", b"\xff\xff\xff\xff\0\0\0\0\xff\xff\xff\xff")],
            parent: None,
        },
    ],
};

/// Events read per file.
const MAX_EVENTS: u64 = 20_000_000;
/// Names, markers and text kept per kind.
const MAX_LISTED: usize = 64;

impl Extractor for Midi {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (bytes, _) = cx.read_bytes(src)?;
        let mut tags = Tags::default();
        let smf = if cx.format_id() == "rmi" { rmid(&bytes, cx, &mut tags)? } else { &bytes[..] };
        let song = parse(smf, cx)?;
        song.report(cx, tags);
        Ok(())
    }
}

crate::register_extractor!(Midi);

/// The SMF inside a RIFF MIDI file (`data` chunk); `INFO` lists go to `tags`.
fn rmid<'b>(b: &'b [u8], cx: &mut Context<'_>, tags: &mut Tags) -> Result<&'b [u8], ExtractError> {
    let mut at = 12;
    let mut data = None;
    while at + 8 <= b.len() {
        let n = u32::from_le_bytes([b[at + 4], b[at + 5], b[at + 6], b[at + 7]]) as usize;
        let body = &b[at + 8..(at + 8).saturating_add(n).min(b.len())];
        match &b[at..at + 4] {
            b"data" => data = data.or(Some(body)),
            b"LIST" => riff::list(body, cx, tags),
            _ => {}
        }
        at = at.saturating_add(8).saturating_add(n).saturating_add(n & 1);
    }
    data.ok_or_else(|| ExtractError::malformed("RIFF MIDI without a data chunk"))
}

/// One track's summary.
#[derive(Default)]
struct Track {
    name: Option<String>,
    instrument: Option<String>,
    events: u64,
    notes: u64,
    channels: BTreeSet<u8>,
    /// Absolute tick of the last event (end of track).
    end: u64,
}

#[derive(Default)]
struct Song {
    format: u16,
    /// Ticks per quarter note, or (frames per second, ticks per frame).
    ppq: Option<u16>,
    smpte: Option<(u8, u8)>,
    tracks: Vec<Track>,
    declared_tracks: u16,
    /// (tick, microseconds per quarter note), in tick order; per track for
    /// format 2.
    tempos: Vec<(usize, u64, u32)>,
    time_signatures: Vec<(u64, String)>,
    keys: Vec<(u64, String)>,
    programs: BTreeMap<u8, u8>,
    notes_by_channel: BTreeMap<u8, u64>,
    system: Option<&'static str>,
    markers: Vec<(u64, String)>,
    cues: u64,
    copyright: Vec<String>,
    texts: Vec<String>,
    lyrics: String,
    karaoke: bool,
    karaoke_info: Vec<String>,
    sysex: u64,
    sequencer_specific: u64,
    smpte_offset: Option<String>,
    truncated: bool,
}

/// A MIDI variable-length quantity.
fn vlq(d: &[u8], at: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for _ in 0..4 {
        let b = *d.get(*at)?;
        *at += 1;
        v = (v << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// Text of a meta event as written: UTF-8, else Latin-1 (most MIDI
/// writers); NULs removed.
fn raw_text(d: &[u8]) -> String {
    let s = match std::str::from_utf8(d) {
        Ok(s) => s.to_string(),
        Err(_) => d.iter().map(|&b| char::from(b)).collect(),
    };
    s.replace('\0', "")
}

/// Text of a meta event, trimmed.
fn text(d: &[u8]) -> String {
    raw_text(d).trim().to_string()
}

// Event parsing keeps the data `d`, track `t`, song `s`, index `i` and
// length `n` in scope: short names are clearer here.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)] // one arm per event kind
fn parse(d: &[u8], cx: &mut Context<'_>) -> Result<Song, ExtractError> {
    if d.len() < 14 || &d[..4] != b"MThd" {
        return Err(ExtractError::malformed("no MThd header"));
    }
    let header_len = u32::from_be_bytes([d[4], d[5], d[6], d[7]]) as usize;
    let mut s = Song {
        format: u16::from_be_bytes([d[8], d[9]]),
        declared_tracks: u16::from_be_bytes([d[10], d[11]]),
        ..Song::default()
    };
    let division = u16::from_be_bytes([d[12], d[13]]);
    if division & 0x8000 != 0 {
        #[allow(clippy::cast_possible_truncation)] // the SMPTE format is a negative byte
        let fps = ((division >> 8) as i8).unsigned_abs();
        s.smpte = Some((fps, (division & 0xff) as u8));
    } else {
        s.ppq = Some(division).filter(|p| *p > 0);
    }
    let mut at = 8usize.saturating_add(header_len);
    let mut total = 0u64;
    let mut words_track = false;
    while at + 8 <= d.len() {
        let n = u32::from_be_bytes([d[at + 4], d[at + 5], d[at + 6], d[at + 7]]) as usize;
        let kind = &d[at..at + 4];
        let body = &d[at + 8..(at + 8).saturating_add(n).min(d.len())];
        at = at.saturating_add(8).saturating_add(n);
        if kind != b"MTrk" {
            continue;
        }
        let index = s.tracks.len();
        let mut t = Track::default();
        let (mut i, mut tick, mut running) = (0usize, 0u64, 0u8);
        while i < body.len() {
            total += 1;
            if total > MAX_EVENTS {
                s.truncated = true;
                break;
            }
            if total.is_multiple_of(1 << 16) {
                cx.checkpoint()?;
            }
            let Some(delta) = vlq(body, &mut i) else { break };
            tick += delta;
            let Some(&first) = body.get(i) else { break };
            t.events += 1;
            let status = if first & 0x80 != 0 {
                i += 1;
                first
            } else if running != 0 {
                running
            } else {
                break; // data byte without a status
            };
            match status {
                0xff => {
                    let Some(&kind) = body.get(i) else { break };
                    i += 1;
                    let Some(len) = vlq(body, &mut i) else { break };
                    let end = i.saturating_add(usize::try_from(len).unwrap_or(usize::MAX)).min(body.len());
                    let data = &body[i..end];
                    i = end;
                    running = 0;
                    match kind {
                        0x01 => {
                            let raw = raw_text(data);
                            let v = raw.trim().to_string();
                            // Karaoke words: `@T` title lines, `@K`, `@L`, `@I`.
                            if let Some(info) = v.strip_prefix('@') {
                                s.karaoke = true;
                                if s.karaoke_info.len() < MAX_LISTED && !info.is_empty() {
                                    s.karaoke_info.push(truncate_chars(info, 200));
                                }
                            } else if words_track || s.karaoke {
                                push_lyric(&mut s.lyrics, &raw);
                            } else if s.texts.len() < MAX_LISTED && !v.is_empty() {
                                s.texts.push(truncate_chars(&v, 500));
                            }
                        }
                        0x02 => {
                            if s.copyright.len() < 8 {
                                s.copyright.push(text(data));
                            }
                        }
                        0x03 => {
                            let v = text(data);
                            words_track |= v.eq_ignore_ascii_case("words");
                            t.name.get_or_insert(v);
                        }
                        0x04 => {
                            t.instrument.get_or_insert(text(data));
                        }
                        0x05 => push_lyric(&mut s.lyrics, &raw_text(data)),
                        0x06 => {
                            if s.markers.len() < MAX_LISTED {
                                s.markers.push((tick, text(data)));
                            }
                        }
                        0x07 => s.cues += 1,
                        0x2f => break,
                        0x51 if data.len() >= 3 => {
                            let us = u32::from_be_bytes([0, data[0], data[1], data[2]]);
                            if us > 0 {
                                s.tempos.push((index, tick, us));
                            }
                        }
                        0x54 if data.len() >= 5 => {
                            s.smpte_offset.get_or_insert_with(|| {
                                format!("{:02}:{:02}:{:02}:{:02}", data[0] & 0x1f, data[1], data[2], data[3])
                            });
                        }
                        0x58 if data.len() >= 2 => {
                            if s.time_signatures.len() < MAX_LISTED {
                                let denominator = 1u64.checked_shl(u32::from(data[1])).unwrap_or(0);
                                s.time_signatures.push((tick, format!("{}/{denominator}", data[0])));
                            }
                        }
                        0x59 if data.len() >= 2 => {
                            #[allow(clippy::cast_possible_wrap)] // sharps or flats, a signed byte
                            let fifths = i64::from(data[0] as i8);
                            if s.keys.len() < MAX_LISTED
                                && let Some(k) = key_name(fifths, data[1] == 1)
                            {
                                s.keys.push((tick, k));
                            }
                        }
                        0x7f => s.sequencer_specific += 1,
                        _ => {}
                    }
                }
                0xf0 | 0xf7 => {
                    let Some(len) = vlq(body, &mut i) else { break };
                    let end = i.saturating_add(usize::try_from(len).unwrap_or(usize::MAX)).min(body.len());
                    let data = &body[i..end];
                    i = end;
                    running = 0;
                    s.sysex += 1;
                    if status == 0xf0 && s.system.is_none() {
                        s.system = system_message(data);
                    }
                }
                0x80..=0xef => {
                    running = status;
                    let channel = status & 0x0f;
                    let n = if matches!(status & 0xf0, 0xc0 | 0xd0) { 1 } else { 2 };
                    let Some(data) = body.get(i..i + n) else { break };
                    i += n;
                    t.channels.insert(channel);
                    match status & 0xf0 {
                        0x90 if data[1] > 0 => {
                            t.notes += 1;
                            *s.notes_by_channel.entry(channel).or_default() += 1;
                        }
                        0xc0 => {
                            s.programs.entry(channel).or_insert(data[0] & 0x7f);
                        }
                        _ => {}
                    }
                }
                // System common and real-time messages do not belong in files.
                _ => break,
            }
        }
        t.end = tick;
        s.tracks.push(t);
    }
    if s.tracks.is_empty() {
        return Err(ExtractError::malformed("no MTrk chunk"));
    }
    Ok(s)
}

/// Karaoke and lyric text: `/` starts a line, `\` a paragraph.
fn push_lyric(out: &mut String, v: &str) {
    if out.len() > 1 << 20 {
        return;
    }
    let (brk, rest) = match v.as_bytes().first() {
        Some(b'/') => ("\n", &v[1..]),
        Some(b'\\') => ("\n\n", &v[1..]),
        _ => ("", v),
    };
    out.push_str(brk);
    out.push_str(rest);
    if v.ends_with('\r') || v.ends_with('\n') {
        out.push('\n');
    }
}

/// GM, GM2, GS or XG from a system-exclusive message (without the F0).
fn system_message(d: &[u8]) -> Option<&'static str> {
    match d {
        [0x7e, _, 0x09, 0x01, ..] => Some("gm"),
        [0x7e, _, 0x09, 0x03, ..] => Some("gm2"),
        [0x41, _, 0x42, 0x12, 0x40, 0x00, 0x7f, ..] => Some("gs"),
        [0x43, d, 0x4c, 0x00, 0x00, 0x7e, ..] if d & 0xf0 == 0x10 => Some("xg"),
        _ => None,
    }
}

impl Song {
    /// Seconds at `tick` for track `index` under the tempo map (format 2
    /// tracks keep their own; the others share the merged map).
    fn seconds(&self, index: usize, tick: u64) -> Option<f64> {
        if let Some((fps, tpf)) = self.smpte {
            let per_second = f64::from(fps) * f64::from(tpf);
            return (per_second > 0.0).then(|| tick as f64 / per_second);
        }
        let ppq = f64::from(self.ppq?);
        let mut map: Vec<(u64, u32)> =
            self.tempos.iter().filter(|(t, _, _)| self.format != 2 || *t == index).map(|&(_, k, us)| (k, us)).collect();
        map.sort_by_key(|&(k, _)| k);
        let (mut secs, mut last_tick, mut us) = (0.0, 0u64, 500_000u32);
        for (k, tempo) in map {
            if k >= tick {
                break;
            }
            secs += (k - last_tick) as f64 * f64::from(us) / 1e6 / ppq;
            (last_tick, us) = (k, tempo);
        }
        Some(secs + (tick - last_tick) as f64 * f64::from(us) / 1e6 / ppq)
    }

    #[allow(clippy::too_many_lines)] // the fields, then the text
    fn report(mut self, cx: &mut Context<'_>, mut tags: Tags) {
        let duration = if self.format == 2 {
            (0..self.tracks.len()).filter_map(|i| self.seconds(i, self.tracks[i].end)).reduce(f64::max)
        } else {
            let end = self.tracks.iter().map(|t| t.end).max().unwrap_or(0);
            self.seconds(0, end)
        };
        if let Some(d) = duration.filter(|d| d.is_finite() && *d > 0.0) {
            cx.physical().duration_s(ms(d));
        }
        // The first track's name is the sequence name (title), unless it is
        // just a part name in a single-track file.
        let title = self.karaoke_info.iter().find_map(|i| i.strip_prefix('T')).map(str::trim).map(str::to_string);
        let first = self.tracks.first().and_then(|t| t.name.clone()).filter(|n| !n.is_empty());
        if let Some(t) = title.or(first) {
            tags.fill("title", &t, "midi");
        }
        for c in std::mem::take(&mut self.copyright) {
            tags.fill("copyright", &c, "midi");
        }
        if !self.lyrics.trim().is_empty() {
            tags.set("lyrics", self.lyrics.trim(), "midi");
        }
        for (tick, title) in &self.markers {
            if !title.is_empty() {
                let start_s = self.seconds(0, *tick).map_or(0.0, ms);
                tags.chapters.push(Chapter { start_s, end_s: None, title: title.clone() });
            }
        }
        tags.system("midi");
        let tempo = self.tempos.iter().filter(|(t, _, _)| self.format != 2 || *t == 0).min_by_key(|t| t.1);
        let mut f = Map::new();
        let mut put = |k: &str, v: Value| {
            if !v.is_null() && v != json!([]) && v != json!({}) {
                f.insert(k.into(), v);
            }
        };
        put("smf_format", json!(self.format));
        put("tracks", json!(self.tracks.len()));
        if usize::from(self.declared_tracks) != self.tracks.len() {
            put("declared_tracks", json!(self.declared_tracks));
        }
        put("ticks_per_quarter", json!(self.ppq));
        if let Some((fps, tpf)) = self.smpte {
            put("smpte_frames_per_second", json!(fps));
            put("ticks_per_frame", json!(tpf));
        }
        put("tempo_bpm", json!(tempo.map(|t| (60e8 / f64::from(t.2)).round() / 100.0)));
        let tempo_changes = self.tempos.len();
        if tempo_changes > 1 {
            put("tempo_changes", json!(tempo_changes));
        }
        put("time_signature", json!(self.time_signatures.first().map(|t| &t.1)));
        if self.time_signatures.len() > 1 {
            put("time_signature_changes", json!(self.time_signatures.len()));
        }
        put("key", json!(self.keys.first().map(|k| &k.1)));
        if self.keys.len() > 1 {
            put("key_changes", json!(self.keys.len()));
        }
        let notes: u64 = self.tracks.iter().map(|t| t.notes).sum();
        put("notes", json!(notes));
        let channels: BTreeSet<u8> = self.tracks.iter().flat_map(|t| t.channels.iter().copied()).collect();
        put("channels", json!(channels.iter().map(|c| c + 1).collect::<Vec<_>>()));
        put("percussion", json!(self.notes_by_channel.get(&9).is_some_and(|n| *n > 0)));
        let instruments: Vec<Value> = self
            .programs
            .iter()
            .filter(|(c, _)| **c != 9)
            .map(|(c, p)| json!({ "channel": c + 1, "program": p + 1, "gm_name": GM_PROGRAMS[usize::from(*p)] }))
            .collect();
        put("programs", Value::Array(instruments));
        put("system", json!(self.system));
        let listed: Vec<Value> = self
            .tracks
            .iter()
            .take(MAX_LISTED)
            .map(|t| {
                let mut m = Map::new();
                if let Some(n) = t.name.as_ref().filter(|n| !n.is_empty()) {
                    m.insert("name".into(), json!(truncate_chars(n, 200)));
                }
                if let Some(n) = t.instrument.as_ref().filter(|n| !n.is_empty()) {
                    m.insert("instrument".into(), json!(truncate_chars(n, 200)));
                }
                m.insert("events".into(), json!(t.events));
                if t.notes > 0 {
                    m.insert("notes".into(), json!(t.notes));
                }
                if !t.channels.is_empty() {
                    m.insert("channels".into(), json!(t.channels.iter().map(|c| c + 1).collect::<Vec<_>>()));
                }
                Value::Object(m)
            })
            .collect();
        put("track_list", Value::Array(listed));
        if !self.markers.is_empty() {
            put("markers", json!(self.markers.len()));
        }
        if self.cues > 0 {
            put("cue_points", json!(self.cues));
        }
        if self.karaoke {
            put("karaoke", json!(true));
            put("karaoke_info", json!(self.karaoke_info));
        }
        if self.sysex > 0 {
            put("sysex_messages", json!(self.sysex));
        }
        if self.sequencer_specific > 0 {
            put("sequencer_specific_events", json!(self.sequencer_specific));
        }
        put("smpte_offset", json!(self.smpte_offset));
        if self.truncated {
            put("events_not_read", json!(true));
        }
        cx.format().append(&mut f);
        let text: Vec<String> = self.texts.iter().filter(|t| t.chars().any(char::is_alphabetic)).cloned().collect();
        if !text.is_empty() {
            cx.format_set("text_events", json!(text.iter().take(16).collect::<Vec<_>>()));
            cx.emit_text(TextRole::Comment, &text.join("\n"));
        }
        tags.report(cx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::testing::report_for;

    crate::fixture_tests!("midi", "rmi");

    #[test]
    fn smpte_minus_128() {
        // Fuzz regression: an SMPTE division byte of -128 used to overflow.
        let r = report_for("x.mid", b"MThd\0\0\0\x06\0\0\0\x01\x80\x28");
        assert_eq!(r.identification.format, "midi");
    }

    /// A format-1 file: a tempo track (120 then 60 bpm) and a note track.
    fn smf() -> Vec<u8> {
        let mut d = b"MThd\0\0\0\x06\0\x01\0\x02\x01\xe0".to_vec(); // 480 ppq
        let tempo: &[u8] = &[
            0x00, 0xff, 0x03, 0x04, b'S', b'o', b'n', b'g', // name
            0x00, 0xff, 0x51, 0x03, 0x07, 0xa1, 0x20, // 500 000 µs
            0x00, 0xff, 0x58, 0x04, 0x03, 0x02, 0x18, 0x08, // 3/4
            0x00, 0xff, 0x59, 0x02, 0xfd, 0x00, // Eb major
            0x83, 0x60, 0xff, 0x51, 0x03, 0x0f, 0x42, 0x40, // at 480: 1 000 000 µs
            0x00, 0xff, 0x2f, 0x00,
        ];
        let notes: &[u8] = &[
            0x00, 0xf0, 0x05, 0x7e, 0x7f, 0x09, 0x01, 0xf7, // GM on
            0x00, 0xc0, 0x28, // violin
            0x00, 0x90, 0x3c, 0x40, 0x83, 0x60, 0x3c, 0x00, // running status: off
            0x00, 0x99, 0x24, 0x64, 0x83, 0x60, 0x89, 0x24, 0x00, // drum
            0x00, 0xff, 0x05, 0x03, b'L', b'a', b'h', 0x00, 0xff, 0x2f, 0x00,
        ];
        for t in [tempo, notes] {
            d.extend_from_slice(b"MTrk");
            d.extend_from_slice(&u32::try_from(t.len()).unwrap().to_be_bytes());
            d.extend_from_slice(t);
        }
        d
    }

    #[test]
    fn tempo_map_and_fields() {
        let r = report_for("song.mid", &smf());
        let f = &r.format["midi"];
        assert_eq!((f["tracks"].clone(), f["notes"].clone()), (json!(2), json!(2)));
        assert_eq!(f["tempo_bpm"], 120.0);
        assert_eq!(f["time_signature"], "3/4");
        assert_eq!(f["key"], "Eb major");
        assert_eq!(f["system"], "gm");
        assert_eq!(f["percussion"], true);
        assert_eq!(f["programs"][0]["gm_name"], "Violin");
        // 480 ticks at 120 bpm (0.5 s) and 480 at 60 bpm (1 s).
        assert_eq!(r.physical.media.as_ref().unwrap().duration_s, Some(1.5));
        assert_eq!(r.content.title.as_deref(), Some("Song"));
    }

    #[test]
    fn pieces() {
        let mut at = 0;
        assert_eq!(vlq(&[0x81, 0x80, 0x00], &mut at), Some(16384));
        assert_eq!(vlq(&[0xff, 0xff, 0xff, 0xff, 0x7f], &mut 0), None);
        assert_eq!(system_message(&[0x43, 0x10, 0x4c, 0, 0, 0x7e, 0, 0xf7]), Some("xg"));
        let mut l = String::new();
        for w in ["Hel", "lo ", "/world", "\\Next"] {
            push_lyric(&mut l, w);
        }
        assert_eq!(l, "Hello \nworld\n\nNext");
        let r = report_for("empty.mid", b"MThd\0\0\0\x06\0\0\0\x01\0\x60");
        assert!(r.diagnostics.extractors.iter().any(|e| e.id == "score.midi" && e.error.is_some()));
    }
}
