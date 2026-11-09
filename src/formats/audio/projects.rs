//! Audio workstation projects:
//!
//! * Audacity (`.aup`, XML): the version that wrote it, project rate, wave
//!   and label tracks, clips, labels, the longest track and the tags;
//! * Ableton Live sets (`.als`, gzip-compressed XML): the Live version,
//!   tempo and time signature, tracks by kind, clips, scenes, devices and
//!   plug-ins, sample files;
//! * FL Studio projects (`.flp`): format, channels, PPQ, the FL version,
//!   tempo, title, patterns, plug-ins and sample files;
//! * REAPER projects (`.rpp`): version, tempo and time signature, sample
//!   rate, tracks, items, FX and plug-ins, markers, the project length.
//!
//! Sample files are listed by name; their full paths (and FL Studio's
//! registered user name) only with `--privacy off`.
//!
//! Specifications: none published. Audacity's and Ableton's XML, FL
//! Studio's event stream (as documented by the PyFLP project) and REAPER's
//! RPP chunk syntax are read as their applications write them.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use crate::plugin::{
    Compression, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    xmlwalk,
};

/// Extractor for audio workstation projects.
pub struct Projects;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, [$($ext:literal),*], [$($magic:expr),*]) => {
        FormatSpec { id: $id, name: $name, family: "audio", mimes: &[$mime], extensions: &[$($ext),*], magic: &[$($magic),*], parent: None }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.project",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!("audacity", "Audacity project", "application/x-audacity-project", ["aup"], []),
        // `.als` is also Alloy source: the set is recognised by its content.
        spec!("ableton", "Ableton Live set", "application/x-ableton-live-set", ["alc"], []),
        spec!("fl_studio", "FL Studio project", "application/x-flp", [], [Magic::prefix(b"FLhd\x06\0\0\0")]),
        spec!(
            "reaper",
            "REAPER project",
            "application/x-reaper-project",
            ["rpp", "rpp-bak"],
            [Magic::prefix(b"<REAPER_PROJECT")]
        ),
    ],
};

/// Names listed.
const MAX_LISTED: usize = 100;

impl Extractor for Projects {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or("");
        if h.starts_with(b"\x1f\x8b") && (ext.eq_ignore_ascii_case("als") || ext.eq_ignore_ascii_case("alc")) {
            return Some(Sniff { format: "ableton", confidence: 0.9 });
        }
        let text = String::from_utf8_lossy(&h[..h.len().min(4096)]);
        if text.contains("<project") && text.contains("audacity.sourceforge.net/xml") {
            return Some(Sniff { format: "audacity", confidence: 0.95 });
        }
        if text.contains("<Ableton ") && text.contains("<LiveSet") {
            return Some(Sniff { format: "ableton", confidence: 0.95 });
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, cut) = cx.read_bytes(src)?;
        if cut {
            cx.format_set("truncated", true);
        }
        match cx.format_id() {
            "audacity" => audacity(cx, &String::from_utf8_lossy(&b))?,
            "ableton" => {
                let xml =
                    if b.starts_with(b"\x1f\x8b") { cx.inflate(&b, Compression::Gzip, cx.parse_limit())? } else { b };
                ableton(cx, &String::from_utf8_lossy(&xml))?;
            }
            "fl_studio" => fl_studio(cx, &b),
            _ => reaper(cx, &String::from_utf8_lossy(&b)),
        }
        Ok(())
    }
}

crate::register_extractor!(Projects);

/// A sample file as the privacy mode allows: its name, or the whole path.
fn file_ref(strict: bool, path: &str) -> String {
    if strict { path.rsplit(['/', '\\']).next().unwrap_or(path).to_string() } else { path.to_string() }
}

fn attr<'a>(a: &'a [(String, String)], k: &str) -> Option<&'a str> {
    xmlwalk::attr(a, k)
}

// --- Audacity --------------------------------------------------------------------------------

fn audacity(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut wave, mut label_tracks, mut clips, mut labels) = (0u64, 0u64, 0u64, Vec::new());
    let (mut rate, mut longest) = (0f64, 0f64);
    let (mut track_rate, mut clip_offset, mut tags) = (0f64, 0f64, BTreeMap::new());
    let mut names = Vec::new();
    xmlwalk::walk(text, cx, 10_000_000, |cx, ev| {
        let xmlwalk::Ev::Start(name, a) = ev else { return };
        let num = |k: &str| attr(a, k).and_then(|v| v.parse::<f64>().ok());
        match name {
            "project" => {
                for (k, key) in [
                    ("audacityversion", "audacity_version"),
                    ("version", "format_version"),
                    ("projname", "data_folder"),
                ] {
                    if let Some(v) = attr(a, k) {
                        cx.format_set(key, v);
                    }
                }
                rate = num("rate").unwrap_or(0.0);
            }
            "wavetrack" => {
                wave += 1;
                track_rate = num("rate").unwrap_or(rate);
                names.extend(attr(a, "name").map(str::to_string));
            }
            "labeltrack" => label_tracks += 1,
            "waveclip" => {
                clips += 1;
                clip_offset = num("offset").unwrap_or(0.0);
            }
            "sequence" => {
                if let Some(n) = num("numsamples").filter(|_| track_rate > 0.0) {
                    longest = f64::max(longest, clip_offset + n / track_rate);
                }
            }
            "label" => {
                labels.extend(attr(a, "title").map(str::to_string));
                longest = f64::max(longest, num("t1").unwrap_or(0.0));
            }
            "tag" => {
                if let (Some(k), Some(v)) = (attr(a, "name"), attr(a, "value")) {
                    tags.insert(k.to_string(), v.to_string());
                }
            }
            _ => {}
        }
    })?;
    if rate > 0.0 {
        cx.format_set("project_rate_hz", rate);
    }
    cx.format_set("wave_tracks", wave);
    cx.format_set("track_names", names.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("label_tracks", label_tracks);
    cx.format_set("clips", clips);
    cx.format_set("labels", labels.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    if let Some(t) = tags.get("TITLE") {
        cx.content().title(t.clone());
    }
    if !tags.is_empty() {
        cx.format_set("tags", json!(tags));
    }
    if longest > 0.0 {
        cx.physical().duration_s((longest * 1000.0).round() / 1000.0);
    }
    Ok(())
}

// --- Ableton Live -----------------------------------------------------------------------------

fn ableton(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let strict = cx.privacy_strict();
    let mut tracks: BTreeMap<String, u64> = BTreeMap::new();
    let (mut clips, mut scenes, mut devices, mut plugins) =
        (BTreeMap::<String, u64>::new(), 0u64, BTreeMap::<String, u64>::new(), BTreeSet::new());
    let (mut samples, mut names, mut path) = (BTreeSet::new(), Vec::new(), Vec::<String>::new());
    let (mut tempo, mut numerator, mut denominator) = (None::<f64>, None::<String>, None::<String>);
    xmlwalk::walk(text, cx, 50_000_000, |cx, ev| match ev {
        xmlwalk::Ev::Start(name, a) => {
            let parent = path.last().cloned().unwrap_or_default();
            path.push(name.to_string());
            let value = attr(a, "Value");
            match name {
                "Ableton" => {
                    if let Some(c) = attr(a, "Creator") {
                        cx.format_set("creator", c);
                    }
                    for (k, key) in
                        [("MajorVersion", "major_version"), ("MinorVersion", "minor_version"), ("Revision", "revision")]
                    {
                        if let Some(v) = attr(a, k) {
                            cx.format_set(key, v);
                        }
                    }
                }
                "AudioTrack" | "MidiTrack" | "ReturnTrack" | "GroupTrack" if parent == "Tracks" => {
                    *tracks.entry(name.trim_end_matches("Track").to_lowercase()).or_default() += 1;
                }
                "EffectiveName" if path.len() >= 3 && path[path.len() - 3].ends_with("Track") => {
                    names.extend(value.map(str::to_string));
                }
                "AudioClip" | "MidiClip" => {
                    *clips.entry(name.trim_end_matches("Clip").to_lowercase()).or_default() += 1;
                }
                "Scene" if parent == "Scenes" => scenes += 1,
                "Manual" if parent == "Tempo" && tempo.is_none() => tempo = value.and_then(|v| v.parse().ok()),
                "PlugName" | "Name" if parent.ends_with("PluginInfo") => {
                    if let Some(v) = value.filter(|v| !v.is_empty()) {
                        plugins.insert(v.to_string());
                    }
                }
                "Path" | "RelativePath" if parent == "FileRef" => {
                    if let Some(v) = value.filter(|v| !v.is_empty())
                        && samples.len() < 10_000
                    {
                        samples.insert(file_ref(strict, v));
                    }
                }
                "Numerator" if numerator.is_none() && parent.contains("TimeSignature") => {
                    numerator = value.map(str::to_string);
                }
                "Denominator" if denominator.is_none() && parent.contains("TimeSignature") => {
                    denominator = value.map(str::to_string);
                }
                _ if parent == "Devices" => *devices.entry(name.to_string()).or_default() += 1,
                _ => {}
            }
        }
        xmlwalk::Ev::End(_) => {
            path.pop();
        }
        xmlwalk::Ev::Text(_) => {}
    })?;
    if let Some(t) = tempo {
        cx.format_set("tempo_bpm", t);
    }
    if let (Some(n), Some(d)) = (numerator, denominator) {
        cx.format_set("time_signature", format!("{n}/{d}"));
    }
    cx.format_set("tracks", json!(tracks));
    cx.format_set("track_names", names.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("clips", json!(clips));
    cx.format_set("scenes", scenes);
    cx.format_set("devices", json!(devices));
    cx.format_set("plugins", plugins.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("sample_files", samples.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    Ok(())
}

// --- FL Studio ------------------------------------------------------------------------------------

/// FL Studio text: UTF-16LE in version 11.5 and later, else 8-bit.
fn fl_text(b: &[u8]) -> String {
    let utf16 = b.len() >= 2
        && b.len().is_multiple_of(2)
        && b.iter().skip(1).step_by(2).filter(|&&c| c == 0).count() * 2 >= b.len() / 2;
    let s = if utf16 {
        let u: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        String::from_utf16_lossy(&u)
    } else {
        crate::plugin::latin1_or_utf8(b)
    };
    s.trim_end_matches('\0').trim().to_string()
}

fn fl_studio(cx: &mut Context<'_>, b: &[u8]) {
    let strict = cx.privacy_strict();
    let le16 = |at: usize| b.get(at..at + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]));
    cx.format_set("format", le16(8));
    cx.format_set("channels", le16(10));
    cx.format_set("ppq", le16(12));
    let Some(start) = b.windows(4).position(|w| w == b"FLdt").map(|p| p + 8) else { return };
    let (mut at, mut events) = (start, 0usize);
    let (mut plugins, mut samples, mut patterns, mut mixer_names) =
        (BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), 0u64);
    let mut tempo_legacy = None;
    while at < b.len() && events < 5_000_000 {
        events += 1;
        let id = b[at];
        at += 1;
        let value: &[u8] = match id {
            0..=63 => {
                at += 1;
                &b[at - 1..at.min(b.len())]
            }
            64..=127 => {
                at += 2;
                b.get(at - 2..at).unwrap_or_default()
            }
            128..=191 => {
                at += 4;
                b.get(at - 4..at).unwrap_or_default()
            }
            _ => {
                // A 7-bit variable-length size, then the data.
                let mut n = 0usize;
                let mut shift = 0;
                while let Some(&c) = b.get(at) {
                    at += 1;
                    n |= usize::from(c & 0x7f) << shift;
                    shift += 7;
                    if c & 0x80 == 0 || shift > 28 {
                        break;
                    }
                }
                let v = b.get(at..at.saturating_add(n).min(b.len())).unwrap_or_default();
                at = at.saturating_add(n);
                v
            }
        };
        let word = || value.get(..2).map(|s| u16::from_le_bytes([s[0], s[1]]));
        let dword = || value.get(..4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]));
        match id {
            65 => {
                if let Some(p) = word() {
                    patterns.insert(p);
                }
            }
            66 => tempo_legacy = word(),
            156 => {
                if let Some(t) = dword() {
                    cx.format_set("tempo_bpm", f64::from(t) / 1000.0);
                }
            }
            194 => {
                let t = fl_text(value);
                if !t.is_empty() {
                    cx.content().title(t.clone());
                    cx.format_set("title", t);
                }
            }
            196 => {
                let t = fl_text(value);
                if !t.is_empty() && samples.len() < 10_000 {
                    samples.insert(file_ref(strict, &t));
                }
            }
            199 => cx.format_set("fl_version", fl_text(value)),
            200 if !strict => cx.format_set("registered_to", fl_text(value)),
            201 | 203 => {
                let t = fl_text(value);
                if !t.is_empty() {
                    plugins.insert(t);
                }
            }
            204 => mixer_names += 1,
            206 => cx.format_set("genre", fl_text(value)),
            207 => {
                let t = fl_text(value);
                if !t.is_empty() {
                    cx.content().author(t.clone());
                    cx.format_set("artists", t);
                }
            }
            _ => {}
        }
    }
    if let Some(t) = tempo_legacy {
        cx.format_set("tempo_bpm_legacy", t);
    }
    cx.format_set("events", events);
    cx.format_set("patterns", patterns.len());
    cx.format_set("plugins", plugins.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("sample_files", samples.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    if mixer_names > 0 {
        cx.format_set("named_mixer_tracks", mixer_names);
    }
}

// --- REAPER ---------------------------------------------------------------------------------------------

/// The words of an RPP line, with quoted strings kept whole.
fn words(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = line.trim();
    while !rest.is_empty() {
        let (w, r) = if let Some(q @ ('"' | '\'' | '`')) = rest.chars().next() {
            let body = &rest[1..];
            let end = body.find(q).unwrap_or(body.len());
            (&body[..end], body.get(end + 1..).unwrap_or(""))
        } else {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            (&rest[..end], &rest[end..])
        };
        out.push(w);
        rest = r.trim_start();
    }
    out
}

fn reaper(cx: &mut Context<'_>, text: &str) {
    let strict = cx.privacy_strict();
    let (mut tracks, mut items, mut markers, mut fx) = (Vec::new(), 0u64, 0u64, BTreeMap::<String, u64>::new());
    let (mut sources, mut stack, mut length) = (BTreeSet::new(), Vec::<String>::new(), 0f64);
    let (mut position, mut item_len) = (0f64, 0f64);
    for line in text.lines() {
        let t = line.trim();
        if let Some(open) = t.strip_prefix('<') {
            let w = words(open);
            let tag = w.first().copied().unwrap_or("").to_string();
            match tag.as_str() {
                "REAPER_PROJECT" => {
                    if let Some(v) = w.get(2) {
                        cx.format_set("reaper_version", *v);
                    }
                    if let Some(ts) = w.get(3).and_then(|v| v.parse::<i64>().ok())
                        && ts > 0
                    {
                        cx.format_set("saved_unix_time", ts);
                    }
                }
                "TRACK" => tracks.push(String::new()),
                "ITEM" => {
                    items += 1;
                    (position, item_len) = (0.0, 0.0);
                }
                "VST" | "AU" | "JS" | "CLAP" | "DX" | "LV2" => {
                    let name = w.get(1).copied().unwrap_or("").to_string();
                    *fx.entry(name).or_default() += 1;
                }
                _ => {}
            }
            stack.push(tag);
            continue;
        }
        if t == ">" {
            if stack.pop().as_deref() == Some("ITEM") {
                length = f64::max(length, position + item_len);
            }
            continue;
        }
        let w = words(t);
        let in_ = |tag: &str| stack.last().is_some_and(|s| s == tag);
        match (w.first().copied(), stack.len()) {
            (Some("TEMPO"), 1) => {
                if let Some(bpm) = w.get(1).and_then(|v| v.parse::<f64>().ok()) {
                    cx.format_set("tempo_bpm", bpm);
                }
                if let (Some(n), Some(d)) = (w.get(2), w.get(3)) {
                    cx.format_set("time_signature", format!("{n}/{d}"));
                }
            }
            (Some("SAMPLERATE"), 1) => {
                if let Some(r) = w.get(1) {
                    cx.format_set("sample_rate_hz", r.parse::<u32>().unwrap_or(0));
                }
            }
            (Some("MARKER"), 1) => markers += 1,
            (Some("NAME"), _) if in_("TRACK") => {
                if let Some(last) = tracks.last_mut() {
                    *last = w.get(1).copied().unwrap_or("").to_string();
                }
            }
            (Some("POSITION"), _) if in_("ITEM") => position = w.get(1).and_then(|v| v.parse().ok()).unwrap_or(0.0),
            (Some("LENGTH"), _) if in_("ITEM") => item_len = w.get(1).and_then(|v| v.parse().ok()).unwrap_or(0.0),
            (Some("FILE"), _) if in_("SOURCE") => {
                if let Some(f) = w.get(1)
                    && sources.len() < 10_000
                {
                    sources.insert(file_ref(strict, f));
                }
            }
            _ => {}
        }
    }
    cx.format_set("tracks", tracks.len());
    cx.format_set("track_names", tracks.into_iter().filter(|n| !n.is_empty()).take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("items", items);
    cx.format_set("markers", markers);
    cx.format_set("fx", json!(fx));
    cx.format_set("source_files", sources.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    if length > 0.0 {
        cx.physical().duration_s((length * 1000.0).round() / 1000.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("audacity", "ableton", "fl_studio", "reaper");

    #[test]
    fn rpp_words() {
        assert_eq!(words(r#"NAME "Lead vocal" 1"#), vec!["NAME", "Lead vocal", "1"]);
        assert_eq!(
            words("<VST \"VST3: ReaEQ (Cockos)\" reaeq.vst3 0"),
            vec!["<VST", "VST3: ReaEQ (Cockos)", "reaeq.vst3", "0"]
        );
    }
}
