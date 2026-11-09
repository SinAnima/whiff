//! Edit decision lists, timelines and terminal recordings:
//!
//! * CMX 3600 EDLs: title, frame-count mode, events, reels, tracks,
//!   transitions, clip names and the record range;
//! * OpenTimelineIO (`.otio`): timeline name, tracks by kind, clips, gaps,
//!   transitions, markers, rate and the longest track;
//! * Final Cut Pro XML (`.fcpxml`): version, formats, assets, events,
//!   projects, clips and the sequence length;
//! * Kdenlive / MLT XML: the MLT and Kdenlive versions, the profile (size,
//!   rate), producers, playlists, tracks and entries;
//! * Adobe Premiere Pro projects (`.prproj`, gzip-compressed XML): project
//!   version, sequences, clips, bins and media;
//! * asciinema casts (v1 – v3): terminal size and type, duration, event
//!   counts, title, command, shell and the recording time.
//!
//! Media files are listed by name; their full paths only with
//! `--privacy off`. A cast's keystrokes and output are never copied.
//!
//! Specifications: the CMX 3600 EDL format; the OpenTimelineIO schema;
//! Apple's FCPXML reference; MLT's XML format; asciinema's asciicast v1 / v2
//! / v3. Premiere's XML is read as Premiere writes it.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::plugin::{
    Compression, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, xmlwalk,
};

/// Extractor for edit lists, timelines and casts.
pub struct Edit;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, [$($ext:literal),*]) => {
        FormatSpec { id: $id, name: $name, family: "video", mimes: &[$mime], extensions: &[$($ext),*], magic: &[], parent: None }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "video.edit",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!("edl", "CMX 3600 edit decision list", "text/x-edl", ["edl"]),
        spec!("otio", "OpenTimelineIO timeline", "application/vnd.pixar.opentimelineio+json", ["otio"]),
        spec!("fcpxml", "Final Cut Pro XML", "application/x-fcpxml", ["fcpxml"]),
        spec!("mlt", "Kdenlive / MLT project", "application/x-kdenlive", ["kdenlive", "mlt"]),
        spec!("premiere", "Adobe Premiere Pro project", "application/x-premiere-project", ["prproj"]),
        spec!("asciicast", "asciinema recording", "application/x-asciicast", ["cast"]),
    ],
};

/// Names listed.
const MAX_LISTED: usize = 100;

impl Extractor for Edit {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or("").to_ascii_lowercase();
        let pick = |format: &'static str| Some(Sniff { format, confidence: 0.93 });
        if h.starts_with(b"\x1f\x8b") && ext == "prproj" {
            return pick("premiere");
        }
        let text = String::from_utf8_lossy(&h[..h.len().min(8192)]);
        let t = text.trim_start_matches('\u{feff}').trim_start();
        if t.contains("\"OTIO_SCHEMA\"") && t.contains("Timeline.") {
            return pick("otio");
        }
        if t.contains("<fcpxml") {
            return pick("fcpxml");
        }
        if t.contains("<mlt") && (t.contains("<profile") || t.contains("<producer") || ext == "kdenlive") {
            return pick("mlt");
        }
        if t.contains("<PremiereData") {
            return pick("premiere");
        }
        if t.starts_with("TITLE:") || (ext == "edl" && t.lines().any(|l| l.starts_with("001 "))) {
            return pick("edl");
        }
        if t.starts_with('{')
            && let Some(first) = t.lines().next()
            && let Ok(v) = serde_json::from_str::<Value>(first)
            && matches!(v.get("version").and_then(Value::as_u64), Some(2 | 3))
            && (v.get("width").is_some() || v.get("term").is_some())
        {
            return pick("asciicast");
        }
        if ext == "cast" && t.starts_with('{') && t.contains("\"stdout\"") {
            return pick("asciicast");
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, cut) = cx.read_bytes(src)?;
        if cut {
            cx.format_set("truncated", true);
        }
        match cx.format_id() {
            "edl" => edl(cx, &String::from_utf8_lossy(&b)),
            "otio" => otio(cx, &b),
            "fcpxml" => fcpxml(cx, &String::from_utf8_lossy(&b))?,
            "mlt" => mlt(cx, &String::from_utf8_lossy(&b))?,
            "premiere" => {
                let xml =
                    if b.starts_with(b"\x1f\x8b") { cx.inflate(&b, Compression::Gzip, cx.parse_limit())? } else { b };
                premiere(cx, &String::from_utf8_lossy(&xml))?;
            }
            _ => cast(cx, &String::from_utf8_lossy(&b)),
        }
        Ok(())
    }
}

crate::register_extractor!(Edit);

fn file_ref(strict: bool, path: &str) -> String {
    let p = path.strip_prefix("file://").unwrap_or(path);
    if strict { p.rsplit(['/', '\\']).next().unwrap_or(p).to_string() } else { p.to_string() }
}

fn attr<'a>(a: &'a [(String, String)], k: &str) -> Option<&'a str> {
    xmlwalk::attr(a, k)
}

// --- EDL ----------------------------------------------------------------------------------------

fn edl(cx: &mut Context<'_>, text: &str) {
    let (mut events, mut reels, mut tracks, mut transitions) =
        (0u64, BTreeSet::new(), BTreeSet::new(), BTreeMap::<String, u64>::new());
    let (mut clips, mut first, mut last, mut drop) = (BTreeSet::new(), None::<String>, None::<String>, None);
    for line in text.lines() {
        let l = line.trim_end();
        if let Some(t) = l.strip_prefix("TITLE:") {
            let t = t.trim();
            if !t.is_empty() {
                cx.content().title(t.to_string());
                cx.format_set("title", t);
            }
        } else if let Some(f) = l.strip_prefix("FCM:") {
            drop = Some(f.trim().to_string());
        } else if let Some(c) = l.strip_prefix("* FROM CLIP NAME:") {
            clips.insert(c.trim().to_string());
        } else {
            let w: Vec<&str> = l.split_whitespace().collect();
            if w.len() >= 8 && w[0].len() >= 3 && w[0].bytes().all(|b| b.is_ascii_digit()) {
                events += 1;
                reels.insert(w[1].to_string());
                tracks.insert(w[2].to_string());
                *transitions.entry(w[3].chars().next().unwrap_or('C').to_string()).or_default() += 1;
                let rec_in = w[w.len() - 2];
                let rec_out = w[w.len() - 1];
                if first.as_deref().is_none_or(|f| rec_in < f) {
                    first = Some(rec_in.to_string());
                }
                if last.as_deref().is_none_or(|l| rec_out > l) {
                    last = Some(rec_out.to_string());
                }
            }
        }
    }
    if let Some(d) = drop {
        cx.format_set("frame_count_mode", d);
    }
    cx.format_set("events", events);
    cx.format_set("reels", reels.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("tracks", tracks.into_iter().collect::<Vec<_>>());
    let named: BTreeMap<String, u64> = transitions
        .into_iter()
        .map(|(k, n)| {
            let name = match k.as_str() {
                "C" => "cut",
                "D" => "dissolve",
                "W" => "wipe",
                "K" => "key",
                _ => "other",
            };
            (name.to_string(), n)
        })
        .collect();
    cx.format_set("transitions", json!(named));
    cx.format_set("clip_names", clips.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    if let (Some(a), Some(b)) = (first, last) {
        cx.format_set("record_range", json!([a, b]));
    }
}

// --- OpenTimelineIO -----------------------------------------------------------------------------

/// Seconds of an OTIO `RationalTime`.
fn rt(v: Option<&Value>) -> Option<f64> {
    let v = v?;
    let (value, rate) = (v.get("value")?.as_f64()?, v.get("rate")?.as_f64()?);
    (rate > 0.0).then(|| value / rate)
}

fn otio(cx: &mut Context<'_>, b: &[u8]) {
    let Ok(v) = serde_json::from_slice::<Value>(b) else {
        cx.warn("the timeline is not valid JSON");
        return;
    };
    let strict = cx.privacy_strict();
    cx.format_set("schema", v.get("OTIO_SCHEMA").cloned().unwrap_or(Value::Null));
    if let Some(n) = v.get("name").and_then(Value::as_str).filter(|n| !n.is_empty()) {
        cx.content().title(n.to_string());
        cx.format_set("name", n);
    }
    let (mut kinds, mut items, mut markers, mut media, mut rate) =
        (BTreeMap::<String, u64>::new(), BTreeMap::<String, u64>::new(), 0u64, BTreeSet::new(), None);
    let mut longest = 0f64;
    let tracks = v.pointer("/tracks/children").and_then(Value::as_array).cloned().unwrap_or_default();
    for t in &tracks {
        *kinds.entry(t.get("kind").and_then(Value::as_str).unwrap_or("unknown").to_lowercase()).or_default() += 1;
        let mut length = 0f64;
        for c in t.get("children").and_then(Value::as_array).into_iter().flatten() {
            let schema = c
                .get("OTIO_SCHEMA")
                .and_then(Value::as_str)
                .unwrap_or("")
                .split('.')
                .next()
                .unwrap_or("")
                .to_lowercase();
            *items.entry(schema.clone()).or_default() += 1;
            markers += c.get("markers").and_then(Value::as_array).map_or(0, Vec::len) as u64;
            if schema != "transition" {
                length += rt(c.pointer("/source_range/duration")).unwrap_or(0.0);
            }
            rate = rate.or_else(|| c.pointer("/source_range/duration/rate").and_then(Value::as_f64));
            for r in [c.pointer("/media_reference/target_url"), c.pointer("/media_references/DEFAULT_MEDIA/target_url")]
                .into_iter()
                .flatten()
            {
                if let Some(u) = r.as_str() {
                    media.insert(file_ref(strict, u));
                }
            }
        }
        longest = longest.max(length);
    }
    cx.format_set("tracks", json!(kinds));
    cx.format_set("items", json!(items));
    cx.format_set("markers", markers);
    if let Some(r) = rate {
        cx.format_set("rate", r);
    }
    cx.format_set("media", media.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    if longest > 0.0 {
        cx.physical().duration_s((longest * 1000.0).round() / 1000.0);
    }
}

// --- FCPXML -----------------------------------------------------------------------------------------

/// `"3003/30000s"` or `"10s"` → seconds.
fn fcp_time(t: &str) -> Option<f64> {
    let t = t.strip_suffix('s')?;
    match t.split_once('/') {
        Some((n, d)) => {
            let (n, d) = (n.parse::<f64>().ok()?, d.parse::<f64>().ok()?);
            (d > 0.0).then(|| n / d)
        }
        None => t.parse().ok(),
    }
}

fn fcpxml(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let strict = cx.privacy_strict();
    let (mut formats, mut assets, mut events, mut projects) = (Vec::new(), 0u64, Vec::new(), Vec::new());
    let (mut clips, mut media, mut sequence) = (BTreeMap::<String, u64>::new(), BTreeSet::new(), None::<f64>);
    let mut depth_in_spine = 0usize;
    xmlwalk::walk(text, cx, 20_000_000, |cx, ev| match ev {
        xmlwalk::Ev::Start(name, a) => match name {
            "fcpxml" => {
                if let Some(v) = attr(a, "version") {
                    cx.format_set("version", v);
                }
            }
            "format" => {
                let size = match (attr(a, "width"), attr(a, "height")) {
                    (Some(w), Some(h)) => format!("{w}x{h}"),
                    _ => String::new(),
                };
                let fps = attr(a, "frameDuration")
                    .and_then(fcp_time)
                    .filter(|d| *d > 0.0)
                    .map(|d| ((1.0 / d) * 1000.0).round() / 1000.0);
                formats.push(json!({ "name": attr(a, "name"), "size": size, "frame_rate": fps }));
            }
            "asset" => {
                assets += 1;
                if let Some(s) = attr(a, "src") {
                    media.insert(file_ref(strict, s));
                }
            }
            "media-rep" => {
                if let Some(s) = attr(a, "src") {
                    media.insert(file_ref(strict, s));
                }
            }
            "event" => events.extend(attr(a, "name").map(str::to_string)),
            "project" => projects.extend(attr(a, "name").map(str::to_string)),
            "sequence" => {
                if sequence.is_none() {
                    sequence = attr(a, "duration").and_then(fcp_time);
                }
            }
            "spine" => depth_in_spine += 1,
            "asset-clip" | "clip" | "ref-clip" | "sync-clip" | "mc-clip" | "gap" | "title" | "audition" | "video"
            | "audio"
                if depth_in_spine > 0 =>
            {
                *clips.entry(name.to_string()).or_default() += 1;
            }
            _ => {}
        },
        xmlwalk::Ev::End(name) => {
            if name == "spine" {
                depth_in_spine = depth_in_spine.saturating_sub(1);
            }
        }
        xmlwalk::Ev::Text(_) => {}
    })?;
    if let Some(p) = projects.first() {
        cx.content().title(p.clone());
    }
    cx.format_set("formats", formats);
    cx.format_set("assets", assets);
    cx.format_set("events", events.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("projects", projects.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("timeline_items", json!(clips));
    cx.format_set("media", media.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    if let Some(d) = sequence.filter(|d| *d > 0.0) {
        cx.physical().duration_s((d * 1000.0).round() / 1000.0);
    }
    Ok(())
}

// --- MLT / Kdenlive -------------------------------------------------------------------------------------

fn mlt(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let strict = cx.privacy_strict();
    let (mut producers, mut playlists, mut entries, mut tracks) = (0u64, 0u64, 0u64, 0u64);
    let (mut media, mut property, mut services) = (BTreeSet::new(), None::<String>, BTreeMap::<String, u64>::new());
    xmlwalk::walk(text, cx, 20_000_000, |cx, ev| match ev {
        xmlwalk::Ev::Start(name, a) => match name {
            "mlt" => {
                for (k, key) in [("version", "mlt_version"), ("title", "title"), ("producer", "main_producer")] {
                    if let Some(v) = attr(a, k) {
                        cx.format_set(key, v);
                    }
                }
            }
            "profile" => {
                if let (Some(w), Some(h)) = (attr(a, "width"), attr(a, "height")) {
                    cx.format_set("size", format!("{w}x{h}"));
                }
                if let (Some(n), Some(d)) = (
                    attr(a, "frame_rate_num").and_then(|v| v.parse::<f64>().ok()),
                    attr(a, "frame_rate_den").and_then(|v| v.parse::<f64>().ok()),
                ) && d > 0.0
                {
                    cx.format_set("frame_rate", (n / d * 1000.0).round() / 1000.0);
                }
                if let Some(d) = attr(a, "description") {
                    cx.format_set("profile", d);
                }
            }
            "producer" | "chain" => producers += 1,
            "playlist" => playlists += 1,
            "entry" => entries += 1,
            "track" => tracks += 1,
            "property" => property = attr(a, "name").map(str::to_string),
            _ => {}
        },
        xmlwalk::Ev::Text(t) => match property.as_deref() {
            Some("resource") => {
                if t.contains('.') && !t.starts_with('#') && t != "black" && media.len() < 10_000 {
                    media.insert(file_ref(strict, t));
                }
            }
            Some("mlt_service") => *services.entry(t.to_string()).or_default() += 1,
            Some("kdenlive:docproperties.version") => cx.format_set("kdenlive_document_version", t),
            Some("kdenlive:docproperties.kdenliveversion") => cx.format_set("kdenlive_version", t),
            _ => {}
        },
        xmlwalk::Ev::End(name) => {
            if name == "property" {
                property = None;
            }
        }
    })?;
    cx.format_set("producers", producers);
    cx.format_set("playlists", playlists);
    cx.format_set("entries", entries);
    cx.format_set("tracks", tracks);
    cx.format_set("services", json!(services));
    cx.format_set("media", media.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    Ok(())
}

// --- Premiere ------------------------------------------------------------------------------------------

fn premiere(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let strict = cx.privacy_strict();
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let (mut media, mut names, mut current) = (BTreeSet::new(), Vec::new(), None::<&'static str>);
    xmlwalk::walk(text, cx, 50_000_000, |cx, ev| match ev {
        xmlwalk::Ev::Start(name, a) => {
            let key = match name {
                "PremiereData" => {
                    if let Some(v) = attr(a, "Version") {
                        cx.format_set("premiere_data_version", v);
                    }
                    return;
                }
                "Project" => {
                    if let Some(v) = attr(a, "Version").filter(|_| attr(a, "ObjectID").is_some()) {
                        cx.format_set("project_version", v);
                    }
                    return;
                }
                "Sequence" if attr(a, "ObjectUID").is_some() => "sequences",
                "ClipProjectItem" if attr(a, "ObjectUID").is_some() => "clips",
                "BinProjectItem" if attr(a, "ObjectUID").is_some() => "bins",
                "Media" if attr(a, "ObjectUID").is_some() => "media",
                "VideoTrack" if attr(a, "ObjectID").is_some() => "video_tracks",
                "AudioTrack" if attr(a, "ObjectID").is_some() => "audio_tracks",
                "Name" => {
                    current = Some("name");
                    return;
                }
                "FilePath" | "ActualMediaFilePath" => {
                    current = Some("path");
                    return;
                }
                _ => return,
            };
            *counts.entry(key).or_default() += 1;
        }
        xmlwalk::Ev::Text(t) => match current.take() {
            Some("path") if media.len() < 10_000 => _ = media.insert(file_ref(strict, t)),
            Some("name") if names.len() < MAX_LISTED => names.push(t.to_string()),
            _ => {}
        },
        xmlwalk::Ev::End(_) => current = None,
    })?;
    cx.format_set("counts", json!(counts));
    cx.format_set("names", names);
    cx.format_set("media", media.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    Ok(())
}

// --- asciinema --------------------------------------------------------------------------------------------

fn cast(cx: &mut Context<'_>, text: &str) {
    let mut lines = text.lines();
    let Some(Ok(head)) = lines.next().map(serde_json::from_str::<Value>) else {
        cx.warn("the cast header is not JSON");
        return;
    };
    let version = head.get("version").and_then(Value::as_u64).unwrap_or(0);
    cx.format_set("cast_version", version);
    let (cols, rows) = match head.get("term") {
        Some(t) => (t.get("cols"), t.get("rows")),
        None => (head.get("width"), head.get("height")),
    };
    if let (Some(c), Some(r)) = (cols.and_then(Value::as_u64), rows.and_then(Value::as_u64)) {
        cx.format_set("columns", c);
        cx.format_set("rows", r);
    }
    let term = head.pointer("/term/type").or_else(|| head.pointer("/env/TERM")).and_then(Value::as_str);
    if let Some(t) = term {
        cx.format_set("terminal", t);
    }
    if let Some(s) = head.pointer("/env/SHELL").and_then(Value::as_str) {
        cx.format_set("shell", s.rsplit('/').next().unwrap_or(s));
    }
    for (k, key) in [("title", "title"), ("command", "command")] {
        if let Some(v) = head.get(k).and_then(Value::as_str) {
            if k == "title" {
                cx.content().title(v.to_string());
            }
            cx.format_set(key, v);
        }
    }
    if let Some(ts) = head.get("timestamp").and_then(Value::as_i64) {
        cx.format_set("recorded_unix_time", ts);
    }
    if let Some(i) = head.get("idle_time_limit").and_then(Value::as_f64) {
        cx.format_set("idle_time_limit_s", i);
    }
    // Events: v1 keeps them in the header's `stdout`; v2 has absolute and
    // v3 relative times, one JSON array per line.
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let mut duration = 0f64;
    if version == 1 {
        for e in head.get("stdout").and_then(Value::as_array).into_iter().flatten() {
            duration += e.get(0).and_then(Value::as_f64).unwrap_or(0.0);
            *kinds.entry("o".into()).or_default() += 1;
        }
        duration = duration.max(head.get("duration").and_then(Value::as_f64).unwrap_or(0.0));
    } else {
        for line in lines.take(10_000_000) {
            let Ok(Value::Array(e)) = serde_json::from_str::<Value>(line) else { continue };
            let t = e.first().and_then(Value::as_f64).unwrap_or(0.0);
            duration = if version >= 3 { duration + t } else { duration.max(t) };
            *kinds.entry(e.get(1).and_then(Value::as_str).unwrap_or("?").to_string()).or_default() += 1;
        }
    }
    let named: BTreeMap<String, u64> = kinds
        .into_iter()
        .map(|(k, n)| {
            let name = match k.as_str() {
                "o" => "output",
                "i" => "input",
                "m" => "marker",
                "r" => "resize",
                "x" => "exit",
                _ => "other",
            };
            (name.to_string(), n)
        })
        .collect();
    cx.format_set("events", json!(named));
    if duration > 0.0 {
        cx.physical().duration_s((duration * 1000.0).round() / 1000.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("edl", "otio", "fcpxml", "mlt", "premiere", "asciicast");

    #[test]
    fn times() {
        assert_eq!(fcp_time("3003/30000s"), Some(0.1001));
        assert_eq!(fcp_time("10s"), Some(10.0));
    }
}
