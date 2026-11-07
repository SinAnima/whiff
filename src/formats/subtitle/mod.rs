//! `text.subtitle` extractors (feature `common`): subtitles, captions and
//! lyrics. Every format is read into [`Subtitles`] (cues with times, text
//! and speakers, plus header facts) and reported the same way: cue count,
//! the time span covered, language, styles, speakers, and the transcript
//! text for the text analyzers.

pub(crate) mod ass;
pub(crate) mod bitmap;
pub(crate) mod caption;
pub(crate) mod markup;
pub(crate) mod timed;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::plugin::{Context, TextRole, decode_entities, truncate_chars};

/// Cues kept per file.
pub(crate) const MAX_CUES: usize = 1 << 20;
/// Transcript bytes handed to the text analyzers.
const MAX_TRANSCRIPT: usize = 4 << 20;
/// Names listed for speakers and styles.
const MAX_LISTED: usize = 20;

/// One timed cue.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Cue {
    /// Start, seconds.
    pub start: f64,
    /// End, seconds; `None` when the format only marks starts.
    pub end: Option<f64>,
    /// Plain text, lines separated by `\n`.
    pub text: String,
    /// Speaker or voice, when the format names one.
    pub speaker: Option<String>,
}

/// A subtitle file, as every format reads it.
#[derive(Debug, Default)]
pub(crate) struct Subtitles {
    /// Codec name for `physical.media.streams[]` (ffmpeg's names).
    pub codec: &'static str,
    pub cues: Vec<Cue>,
    /// Language declared by the file, with the field it came from.
    pub language: Option<(String, &'static str)>,
    pub title: Option<String>,
    pub author: Option<String>,
    pub copyright: Option<String>,
    /// Frame rate the times are counted in (MicroDVD, SCC, EBU STL, TTML).
    pub frame_rate: Option<f64>,
    /// Style names (ASS, TTML, SAMI classes).
    pub styles: Vec<String>,
    /// Inline formatting seen in the cue text: `italic`, `colour`, `position`, …
    pub markup: BTreeSet<&'static str>,
    /// Cues dropped because the file has more than [`MAX_CUES`].
    pub dropped: u64,
    /// The cues are pictures (PGS, VobSub): they have no text and are all
    /// counted. Text cues without text only clear the screen, and are
    /// counted apart.
    pub bitmap: bool,
    /// Format-specific fields.
    pub format: Map<String, Value>,
    /// Streams of a file holding several tracks (VobSub); one stream for
    /// the cues otherwise.
    pub tracks: Vec<Map<String, Value>>,
}

impl Subtitles {
    pub(crate) fn new(codec: &'static str) -> Self {
        Self { codec, ..Self::default() }
    }

    /// Add a cue (times must be finite and not negative).
    pub(crate) fn push(&mut self, cue: Cue) {
        if !cue.start.is_finite() || cue.start < 0.0 || cue.end.is_some_and(|e| !e.is_finite()) {
            return;
        }
        if self.cues.len() >= MAX_CUES {
            self.dropped += 1;
            return;
        }
        self.cues.push(cue);
    }

    /// Set a format field unless it is null or empty.
    pub(crate) fn set(&mut self, key: &str, v: impl Into<Value>) {
        let v = v.into();
        let empty = match &v {
            Value::Null => true,
            Value::String(s) => s.trim().is_empty(),
            Value::Array(a) => a.is_empty(),
            Value::Object(o) => o.is_empty(),
            _ => false,
        };
        if !empty {
            self.format.insert(key.into(), v);
        }
    }

    /// Declared language (`en-US`, `fre`), if it looks like a language tag.
    pub(crate) fn declare_language(&mut self, tag: &str, source: &'static str) {
        if self.language.is_none()
            && let Some(code) = language_code(tag)
        {
            self.language = Some((code, source));
        }
    }

    /// Cues whose end is unknown end where the next one starts.
    pub(crate) fn close_open_cues(&mut self) {
        let starts: Vec<f64> = self.cues.iter().map(|c| c.start).collect();
        for (i, c) in self.cues.iter_mut().enumerate() {
            if c.end.is_none() {
                c.end = starts.get(i + 1).copied().filter(|&s| s >= c.start);
            }
        }
    }

    /// Write the report.
    #[allow(clippy::too_many_lines)] // one pass over the cues, then the fields
    pub(crate) fn report(mut self, cx: &mut Context<'_>) {
        let before = self.cues.len();
        if !self.bitmap {
            self.cues.retain(|c| !c.text.trim().is_empty());
        }
        let empty = (before - self.cues.len()) as u64;
        let n = self.cues.len();
        let (mut first, mut last_end) = (None::<f64>, None::<f64>);
        let (mut lines, mut max_lines, mut sdh, mut music, mut overlaps, mut unordered) =
            (0u64, 0usize, 0u64, 0u64, 0u64, 0u64);
        let mut speakers: BTreeMap<String, u64> = BTreeMap::new();
        let mut prev: Option<&Cue> = None;
        let mut transcript = String::new();
        let mut last_text = "";
        for c in &self.cues {
            first = Some(first.map_or(c.start, |f| f.min(c.start)));
            let end = c.end.unwrap_or(c.start).max(c.start);
            last_end = Some(last_end.map_or(end, |l| l.max(end)));
            let text = c.text.trim();
            if !text.is_empty() {
                let k = text.lines().count();
                lines += k as u64;
                max_lines = max_lines.max(k);
            }
            if text.lines().any(sound_line) {
                sdh += 1;
            }
            if text.contains(['♪', '♫']) {
                music += 1;
            }
            if let Some(s) = c.speaker.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                *speakers.entry(truncate_chars(s, 80)).or_default() += 1;
            }
            if let Some(p) = prev {
                if c.start < p.start {
                    unordered += 1;
                } else if p.end.is_some_and(|e| c.start < e - 0.000_5) {
                    overlaps += 1;
                }
            }
            prev = Some(c);
            // Roll-up captions and karaoke repeat the same text cue after cue.
            // Speakers are listed, not prefixed: their names would lead the
            // keywords.
            if !text.is_empty() && text != last_text && transcript.len() < MAX_TRANSCRIPT {
                transcript.push_str(text);
                transcript.push('\n');
                last_text = text;
            }
        }

        if let Some(t) = self.title.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            cx.content().source("subtitle.title").title(truncate_chars(t, 300));
            cx.emit_text(TextRole::Title, t);
        }
        if let Some(a) = self.author.as_deref().map(str::trim).filter(|a| !a.is_empty()) {
            cx.content().source("subtitle.author").author(truncate_chars(a, 200));
        }
        if let Some(c) = self.copyright.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
            cx.rights().source("subtitle.copyright").copyright(truncate_chars(c, 300));
        }
        if let Some((code, source)) = &self.language {
            cx.content().source(*source).language(code.clone(), 1.0);
        }
        if !transcript.is_empty() {
            cx.emit_text(TextRole::Body, &transcript);
        }

        let mut stream = Map::new();
        stream.insert("type".into(), json!("subtitle"));
        stream.insert("codec".into(), json!(self.codec));
        if let Some((code, _)) = &self.language {
            stream.insert("language".into(), json!(code));
        }
        stream.insert("cues".into(), json!(n));
        {
            let mut p = cx.physical();
            if self.tracks.is_empty() {
                p.stream(stream);
            }
            for t in std::mem::take(&mut self.tracks) {
                p.stream(t);
            }
            if let Some(d) = last_end.filter(|d| *d > 0.0) {
                p.duration_s(ms(d));
            }
        }

        let mut f = Map::new();
        f.insert("cues".into(), json!(n));
        if let Some(v) = first {
            f.insert("first_cue_s".into(), json!(ms(v)));
        }
        if let Some(v) = last_end {
            f.insert("last_cue_end_s".into(), json!(ms(v)));
        }
        if let Some(r) = self.frame_rate {
            f.insert("frame_rate".into(), json!((r * 1000.0).round() / 1000.0));
        }
        if lines > 0 {
            f.insert("text_lines".into(), json!(lines));
            f.insert("max_lines_per_cue".into(), json!(max_lines));
        }
        for (k, v) in [
            ("empty_cues", empty),
            ("sound_description_cues", sdh),
            ("music_cues", music),
            ("overlapping_cues", overlaps),
            ("out_of_order_cues", unordered),
            ("cues_not_read", self.dropped),
        ] {
            if v > 0 {
                f.insert(k.into(), json!(v));
            }
        }
        if !speakers.is_empty() {
            let mut top: Vec<(String, u64)> = speakers.into_iter().collect();
            top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            f.insert("speakers".into(), json!(top.len()));
            f.insert(
                "top_speakers".into(),
                Value::Object(top.into_iter().take(MAX_LISTED).map(|(k, n)| (k, json!(n))).collect()),
            );
        }
        if !self.styles.is_empty() {
            f.insert("styles".into(), json!(self.styles.len()));
            self.styles.truncate(MAX_LISTED);
            f.insert("style_names".into(), json!(self.styles));
        }
        if !self.markup.is_empty() {
            f.insert("markup".into(), json!(self.markup));
        }
        f.append(&mut self.format);
        let fmt = cx.format();
        fmt.append(&mut f);
    }
}

/// A subtitle track inside a video container, with its decoded cues.
pub(crate) struct Embedded {
    /// Index of the track's stream among the streams reported.
    pub stream: usize,
    pub cues: Vec<Cue>,
    pub default: bool,
    pub forced: bool,
}

/// Note each embedded track's cue count and span on its stream, and give
/// the text of one track to the text analyzers: a default track that is not
/// forced (forced tracks hold only foreign-language lines), else the one
/// with the most cues.
pub(crate) fn embedded(cx: &mut Context<'_>, streams: &mut [Map<String, Value>], tracks: &[Embedded]) {
    for t in tracks {
        let Some(m) = streams.get_mut(t.stream) else { continue };
        m.insert("cues".into(), json!(t.cues.len()));
        let end = t.cues.iter().map(|c| c.end.unwrap_or(c.start)).fold(0.0, f64::max);
        if end > 0.0 {
            m.insert("last_cue_end_s".into(), json!(ms(end)));
        }
    }
    let pick = tracks
        .iter()
        .filter(|t| !t.cues.is_empty())
        .max_by_key(|t| (t.default && !t.forced, !t.forced, t.cues.len(), std::cmp::Reverse(t.stream)));
    let Some(t) = pick else { return };
    let mut transcript = String::new();
    let mut last = "";
    for c in &t.cues {
        let text = c.text.trim();
        if !text.is_empty() && text != last && transcript.len() < MAX_TRANSCRIPT {
            transcript.push_str(text);
            transcript.push('\n');
            last = text;
        }
    }
    if !transcript.is_empty() {
        cx.emit_text(TextRole::Caption, &transcript);
        cx.format_set("transcript_stream", t.stream);
    }
}

/// Seconds rounded to the millisecond.
pub(crate) fn ms(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// A sound description line in hearing-impaired subtitles: `[door slams]`,
/// `(LAUGHTER)`.
fn sound_line(line: &str) -> bool {
    let l = line.trim().trim_start_matches(['-', ' ']);
    l.len() > 2 && ((l.starts_with('[') && l.ends_with(']')) || (l.starts_with('(') && l.ends_with(')')))
}

/// `en-US` → `en`, `fre` → `fre`; `None` for anything that is not a tag.
pub(crate) fn language_code(tag: &str) -> Option<String> {
    let primary = tag.trim().split(['-', '_']).next()?.to_ascii_lowercase();
    ((2..=3).contains(&primary.len())
        && primary.chars().all(|c| c.is_ascii_lowercase())
        && !matches!(primary.as_str(), "und" | "zxx" | "mul" | "xx"))
    .then_some(primary)
}

/// A clock time `[[h:]m:]s[.,frac]` in seconds. Hours and minutes may be
/// missing (WebVTT `mm:ss.ttt`); `None` unless every part is a number.
pub(crate) fn clock(s: &str) -> Option<f64> {
    let s = s.trim();
    if s.is_empty() || s.len() > 24 {
        return None;
    }
    let mut parts: Vec<&str> = s.split(':').collect();
    let last = parts.pop()?;
    if parts.len() > 2 {
        return None;
    }
    let (secs, frac) = match last.find(['.', ',']) {
        Some(i) => (&last[..i], &last[i + 1..]),
        None => (last, ""),
    };
    let num = |p: &str| -> Option<u64> {
        (!p.is_empty() && p.len() <= 10 && p.bytes().all(|b| b.is_ascii_digit())).then(|| p.parse().ok()).flatten()
    };
    let mut total = num(secs)? as f64;
    if !frac.is_empty() {
        let f = num(frac)?;
        total += f as f64 / 10f64.powi(i32::try_from(frac.len()).ok()?);
    }
    for (i, p) in parts.iter().rev().enumerate() {
        total += num(p)? as f64 * if i == 0 { 60.0 } else { 3600.0 };
    }
    Some(total)
}

/// Cue text without markup: HTML-like tags (`<i>`, `<c.red>`, `<v Bob>`,
/// `<00:01.000>`), ASS override blocks (`{\an8}`), ASS line breaks, and
/// character entities. Formatting seen is noted in `markup`.
pub(crate) fn plain_text(raw: &str, markup: &mut BTreeSet<&'static str>) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(i) = rest.find(['<', '{', '\\']) {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let c = tail.as_bytes()[0];
        if c == b'\\' {
            match tail.as_bytes().get(1) {
                Some(b'N' | b'n') => out.push('\n'),
                Some(b'h') => out.push(' '),
                _ => {
                    out.push('\\');
                    rest = &tail[1..];
                    continue;
                }
            }
            rest = &tail[2..];
            continue;
        }
        let close = if c == b'<' { '>' } else { '}' };
        match prefix(tail, 512).find(close) {
            Some(j) if c == b'<' && is_tag(&tail[1..j]) => {
                note_tag(&tail[1..j], markup);
                rest = &tail[j + 1..];
            }
            Some(j) if c == b'{' && tail[1..j].starts_with('\\') => {
                note_override(&tail[1..j], markup);
                rest = &tail[j + 1..];
            }
            _ => {
                out.push(c as char);
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    let decoded = decode_entities(&out);
    let mut text = String::with_capacity(decoded.len());
    for line in decoded.lines() {
        let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if !line.is_empty() {
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(&line);
        }
    }
    text.replace(['\u{200e}', '\u{200f}'], "")
}

/// Whether `<inner>` is a markup tag rather than literal text (`a < b > c`).
fn is_tag(inner: &str) -> bool {
    let t = inner.trim_start_matches('/');
    t.chars().next().is_some_and(|c| c.is_ascii_alphanumeric()) && !inner.contains('<')
}

fn note_tag(inner: &str, markup: &mut BTreeSet<&'static str>) {
    let name: String = inner
        .trim_start_matches('/')
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase();
    let kind = match name.as_str() {
        "i" | "em" => "italic",
        "b" | "strong" => "bold",
        "u" => "underline",
        "s" => "strikethrough",
        "font" => {
            if inner.to_ascii_lowercase().contains("color") {
                "colour"
            } else {
                "font"
            }
        }
        "c" => "class",
        "v" => "voice",
        "ruby" | "rt" => "ruby",
        "lang" => "language_span",
        n if n.chars().next().is_some_and(|c| c.is_ascii_digit()) => "karaoke_timing",
        _ => return,
    };
    markup.insert(kind);
}

fn note_override(block: &str, markup: &mut BTreeSet<&'static str>) {
    for tag in block.split('\\').filter(|t| !t.is_empty()) {
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        let t = tag.trim_start_matches(|c: char| c.is_ascii_digit());
        let kind = if t.starts_with("pos")
            || t.starts_with("move")
            || t.starts_with("an")
            || (t.starts_with('a') && digits(&t[1..]))
        {
            "position"
        } else if t.starts_with(['k', 'K']) {
            "karaoke"
        } else if t.starts_with("fad") {
            "fade"
        } else if t.starts_with("c&") || t == "c" {
            "colour"
        } else if t.starts_with("fn") || t.starts_with("fs") {
            "font"
        } else if t.starts_with('i') && digits(&t[1..]) {
            "italic"
        } else if t.starts_with('b') && digits(&t[1..]) {
            "bold"
        } else if t.starts_with('p') && digits(&t[1..]) {
            "drawing"
        } else if t.starts_with("t(") {
            "animation"
        } else {
            continue;
        };
        markup.insert(kind);
    }
}

/// At most `max` bytes of `s`, cut on a character boundary.
pub(crate) fn prefix(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// A sniffer's view of the first bytes as text (any BOM honoured).
///
/// Every file passes through these sniffers, so the character-set guess
/// runs only for text in a legacy encoding. UTF-8 (a character cut at the
/// end included) reads as `decode_text` would; a head with NUL bytes and no
/// BOM is binary, and a lossy view of it fails the sniffers' text checks
/// as well as a guessed one.
pub(crate) fn head_text(head: &[u8]) -> std::borrow::Cow<'_, str> {
    let cut = &head[..head.len().min(16 * 1024)];
    let bom = cut.starts_with(b"\xef\xbb\xbf") || cut.starts_with(b"\xff\xfe") || cut.starts_with(b"\xfe\xff");
    if !bom {
        match std::str::from_utf8(cut) {
            Ok(s) => return s.into(),
            Err(e) if e.error_len().is_none() || cut.contains(&0) => return String::from_utf8_lossy(cut),
            Err(_) => {}
        }
    }
    crate::plugin::decode_text(cut).text.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_text_matches_decode() {
        let cases: [&[u8]; 6] = [
            b"1\n00:00:01,000 --> 00:00:02,000\nhi\n",
            "caf\u{e9}\n".as_bytes(),
            b"caf\xc3",                // a character cut at the end
            b"caf\xe9 cr\xe8me\n",     // windows-1252
            b"\xff\xfeh\0i\0",         // UTF-16LE BOM
            b"\x00\x01\x02\xffbinary", // binary
        ];
        for c in cases {
            let ours = head_text(c);
            if c.contains(&0) && !c.starts_with(b"\xff\xfe") {
                assert!(ours.contains("binary"));
            } else {
                assert_eq!(ours, crate::plugin::decode_text(c).text, "{c:?}");
            }
        }
    }

    #[test]
    fn clocks_and_text() {
        assert_eq!(clock("01:02:03,250"), Some(3723.25));
        assert_eq!(clock("02:03.5"), Some(123.5));
        assert_eq!(clock("7"), Some(7.0));
        assert_eq!(clock("1:2:3:4"), None);
        assert_eq!(clock("aa:00"), None);
        assert_eq!(clock(""), None);
        let mut m = BTreeSet::new();
        assert_eq!(plain_text("<i>Hi</i>  there\\N{\\an8}<v Bob>you &amp; me", &mut m), "Hi there\nyou & me");
        assert_eq!(m.into_iter().collect::<Vec<_>>(), ["italic", "position", "voice"]);
        let mut m = BTreeSet::new();
        assert_eq!(plain_text("a < b > c {not override}", &mut m), "a < b > c {not override}");
        assert!(m.is_empty());
        assert_eq!(language_code("en-US").as_deref(), Some("en"));
        assert_eq!(language_code("und"), None);
        assert_eq!(language_code("English"), None);
        assert!(sound_line("[DOOR SLAMS]"));
        assert!(sound_line("- (laughs)"));
        assert!(!sound_line("[a"));
        assert_eq!(prefix("aÅb", 2), "a");
        assert_eq!(prefix("ab", 9), "ab");
    }

    #[test]
    fn open_cues_close_at_the_next_start() {
        let mut s = Subtitles::new("text");
        for t in [1.0, 2.5, 4.0] {
            s.push(Cue { start: t, text: "x".into(), ..Cue::default() });
        }
        s.push(Cue { start: f64::NAN, ..Cue::default() });
        s.close_open_cues();
        assert_eq!(s.cues.iter().map(|c| c.end).collect::<Vec<_>>(), [Some(2.5), Some(4.0), None]);
    }
}
