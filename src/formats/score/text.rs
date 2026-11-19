//! Text notation: ABC (one or more tunes: reference numbers, titles,
//! composer, origin, rhythm, meter, unit length, tempo, key, voices, notes
//! and lyrics) and LilyPond (`\version`, the `\header` fields, scores,
//! staves, the first key, time and tempo, included files, lyrics).
//!
//! Specifications: the ABC standard 2.1; the LilyPond notation reference.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::super::subtitle::head_text;
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, TextRole,
    truncate_chars,
};

/// Extractor for ABC and LilyPond files.
pub struct Text;

static META: ExtractorMeta = ExtractorMeta {
    id: "score.text",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "abc",
            name: "ABC notation",
            family: "audio.score",
            mimes: &["text/vnd.abc"],
            extensions: &["abc"],
            // Not extension-only: `.abc` is also Alembic geometry.
            magic: &[Magic::prefix(b"X:"), Magic::prefix(b"%abc"), Magic::prefix(b"\xEF\xBB\xBFX:")],
            parent: None,
        },
        FormatSpec {
            id: "lilypond",
            name: "LilyPond score",
            family: "audio.score",
            mimes: &["text/x-lilypond"],
            extensions: &["ly", "ily"],
            magic: &[],
            parent: None,
        },
    ],
};

/// Tunes listed from an ABC tune book.
const MAX_LISTED: usize = 50;

impl Extractor for Text {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let text = head_text(probe.head);
        let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).take(40).collect();
        // ABC after leading comments: an `X:` line soon followed by `T:` and `K:`.
        if let Some(i) = lines.iter().position(|l| l.starts_with("X:"))
            && lines[..i].iter().all(|l| l.starts_with('%'))
            && lines[i..].iter().any(|l| l.starts_with("T:"))
            && lines[i..].iter().any(|l| l.starts_with("K:"))
        {
            return Some(Sniff { format: "abc", confidence: 0.9 });
        }
        let code: Vec<&&str> = lines.iter().filter(|l| !l.starts_with('%')).collect();
        let lily = code.first().is_some_and(|l| l.starts_with("\\version \""))
            || (code.iter().any(|l| l.starts_with("\\header")) && code.iter().any(|l| l.contains("\\relative")));
        lily.then_some(Sniff { format: "lilypond", confidence: 0.85 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        cx.checkpoint()?;
        if cx.format_id() == "abc" {
            abc(&text, cx);
        } else {
            lilypond(&text, cx);
        }
        Ok(())
    }
}

crate::register_extractor!(Text);

/// One ABC tune's header fields.
#[derive(Default)]
struct Tune {
    number: Option<String>,
    titles: Vec<String>,
    composers: Vec<String>,
    fields: BTreeMap<&'static str, String>,
    voices: u64,
    notes: u64,
}

/// An ABC key (`K:`) as `G major`, `D minor`, `A mixolydian`.
fn abc_key(k: &str) -> Option<String> {
    let k = k.split('%').next()?.trim();
    let mut chars = k.chars();
    let tonic = chars.next().filter(|c| matches!(c, 'A'..='G'))?;
    let rest: String = chars.collect();
    let (acc, mode) = match rest.chars().next() {
        Some(a @ ('#' | 'b')) => (a.to_string(), rest[1..].trim().to_ascii_lowercase()),
        _ => (String::new(), rest.trim().to_ascii_lowercase()),
    };
    let word = mode.split_whitespace().next().unwrap_or("");
    let mode = if word.is_empty() || word.starts_with("maj") || word.starts_with("ion") {
        "major"
    } else if word == "m" || word.starts_with("min") || word.starts_with("aeo") {
        "minor"
    } else if word.starts_with("mix") {
        "mixolydian"
    } else if word.starts_with("dor") {
        "dorian"
    } else if word.starts_with("phr") {
        "phrygian"
    } else if word.starts_with("lyd") {
        "lydian"
    } else if word.starts_with("loc") {
        "locrian"
    } else {
        return Some(format!("{tonic}{acc}"));
    };
    Some(format!("{tonic}{acc} {mode}"))
}

/// Notes in an ABC music line: letters outside quoted chords, `!`
/// decorations and `[K:…]` inline fields.
fn abc_notes(line: &str) -> u64 {
    let (mut n, mut quoted, mut deco, mut field) = (0u64, false, false, false);
    let b = line.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'"' if !deco => quoted = !quoted,
            b'!' if !quoted => deco = !deco,
            b'[' if !quoted && !deco && b.get(i + 2) == Some(&b':') => field = true,
            b']' if field => field = false,
            b'%' if !quoted => break,
            b'A'..=b'G' | b'a'..=b'g' if !quoted && !deco && !field => n += 1,
            _ => {}
        }
    }
    n
}

#[allow(clippy::too_many_lines)] // the fields, then the report
fn abc(text: &str, cx: &mut Context<'_>) {
    let mut tunes: Vec<Tune> = Vec::new();
    let mut file_fields: Vec<(String, String)> = Vec::new();
    let mut version = None;
    let mut lyrics = String::new();
    let mut in_body = false;
    for line in text.lines() {
        let l = line.trim_end();
        if let Some(v) = l.strip_prefix("%abc-") {
            version.get_or_insert_with(|| v.trim().to_string());
            continue;
        }
        if l.starts_with('%') || l.trim().is_empty() {
            if l.trim().is_empty() {
                in_body = false;
            }
            continue;
        }
        let field = l.as_bytes().get(1) == Some(&b':') && l.as_bytes()[0].is_ascii_alphabetic();
        if field {
            let (k, v) = (&l[..1], l[2..].trim());
            if k == "X" {
                tunes.push(Tune { number: Some(v.to_string()), ..Tune::default() });
                in_body = false;
                continue;
            }
            let Some(t) = tunes.last_mut() else {
                if file_fields.len() < 32 {
                    file_fields.push((k.to_string(), v.to_string()));
                }
                continue;
            };
            match k {
                "T" if t.titles.len() < 4 => t.titles.push(v.to_string()),
                "C" if t.composers.len() < 4 => t.composers.push(v.to_string()),
                "K" => {
                    if !in_body {
                        t.fields.entry("key").or_insert_with(|| abc_key(v).unwrap_or_else(|| v.to_string()));
                    }
                    in_body = true;
                }
                "M" => {
                    t.fields.entry("meter").or_insert_with(|| v.to_string());
                }
                "L" => {
                    t.fields.entry("unit_note_length").or_insert_with(|| v.to_string());
                }
                "Q" => {
                    t.fields.entry("tempo").or_insert_with(|| v.trim_matches('"').to_string());
                }
                "R" => {
                    t.fields.entry("rhythm").or_insert_with(|| v.to_string());
                }
                "O" => {
                    t.fields.entry("origin").or_insert_with(|| v.to_string());
                }
                "S" => {
                    t.fields.entry("source").or_insert_with(|| v.to_string());
                }
                "Z" => {
                    t.fields.entry("transcription").or_insert_with(|| v.to_string());
                }
                "V" => t.voices += 1,
                // `w:` syllables: `-` joins, `_` and `*` hold.
                "w" | "W" if lyrics.len() < 1 << 20 => {
                    let line = v.replace("\\-", "\u{1}").replace(['_', '*', '~'], " ");
                    let joined = line.replace(" -", "-").replace("- ", "-").replace('-', "").replace('\u{1}', "-");
                    lyrics.push_str(&joined.split_whitespace().collect::<Vec<_>>().join(" "));
                    lyrics.push('\n');
                }
                _ => {}
            }
            continue;
        }
        if in_body && let Some(t) = tunes.last_mut() {
            t.notes += abc_notes(l);
        }
    }
    let first = tunes.first();
    let mut f = Map::new();
    let mut put = |k: &str, v: Value| {
        if !v.is_null() && v != json!([]) {
            f.insert(k.into(), v);
        }
    };
    put("version", json!(version));
    put("tunes", json!(tunes.len()));
    if tunes.len() == 1
        && let Some(t) = first
    {
        for (k, v) in &t.fields {
            put(k, json!(truncate_chars(v, 200)));
        }
        if t.voices > 0 {
            put("voices", json!(t.voices));
        }
        put("notes", json!(t.notes));
        put("subtitle", json!(t.titles.get(1)));
    } else {
        let listed: Vec<Value> = tunes
            .iter()
            .take(MAX_LISTED)
            .map(|t| {
                json!({
                    "number": t.number,
                    "title": t.titles.first().map(|x| truncate_chars(x, 200)),
                    "key": t.fields.get("key"),
                    "meter": t.fields.get("meter"),
                })
            })
            .collect();
        put("tune_list", Value::Array(listed));
        put("notes", json!(tunes.iter().map(|t| t.notes).sum::<u64>()));
    }
    let book = file_fields.iter().find(|(k, _)| k == "B").map(|x| x.1.clone());
    put("book", json!(book));
    cx.format().append(&mut f);
    // A tune book's own title is its `B:` (book) field; a single tune's is its `T:`.
    let title = if tunes.len() == 1 { first.and_then(|t| t.titles.first().cloned()) } else { book };
    if let Some(t) = title.filter(|t| !t.is_empty()) {
        cx.content().source("abc.T").title(truncate_chars(&t, 300));
    }
    let mut composers: Vec<&String> = tunes.iter().flat_map(|t| t.composers.iter()).collect();
    composers.sort();
    composers.dedup();
    for c in composers.into_iter().take(MAX_LISTED) {
        cx.content().source("abc.C").author(truncate_chars(c, 200));
    }
    let titles: String = tunes.iter().flat_map(|t| t.titles.iter()).flat_map(|t| [t.as_str(), "\n"]).collect();
    if !titles.is_empty() {
        cx.emit_text(TextRole::Heading(2), &titles);
    }
    if !lyrics.trim().is_empty() {
        cx.emit_text(TextRole::Body, lyrics.trim());
    }
}

/// The value of `key = "…"` (or `key = \markup { … }` words) inside a
/// LilyPond `\header` block.
fn header_fields(block: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in block.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let k = k.trim();
        if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            continue;
        }
        let v = v.trim();
        let value = if let Some(q) = v.strip_prefix('"') {
            q.split('"').next().unwrap_or("").to_string()
        } else {
            // `\markup { \bold "Title" }`: the quoted words.
            v.split('"').skip(1).step_by(2).collect::<Vec<_>>().join(" ")
        };
        if !value.trim().is_empty() && out.len() < 64 {
            out.push((k.to_string(), value.trim().to_string()));
        }
    }
    out
}

/// The text of the `{ … }` block that follows `at` in `s` (balanced braces).
fn block(s: &str, at: usize) -> Option<&str> {
    let open = s[at..].find('{')? + at;
    let mut depth = 0usize;
    for (i, c) in s[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[open + 1..open + i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// LilyPond source without `%` line comments and `%{ … %}` block comments.
fn uncomment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut quotes = 0usize;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        quotes += rest[..i].matches('"').count();
        let tail = &rest[i..];
        // A `%` inside a string ends nothing: keep it when quotes are open.
        if quotes % 2 == 1 {
            out.push('%');
            rest = &tail[1..];
            continue;
        }
        rest = if let Some(b) = tail.strip_prefix("%{") {
            b.find("%}").map_or("", |j| &b[j + 2..])
        } else {
            tail.find('\n').map_or("", |j| &tail[j..])
        };
    }
    out.push_str(rest);
    out
}

fn lilypond(raw: &str, cx: &mut Context<'_>) {
    let text = uncomment(raw);
    let mut f = Map::new();
    let quoted = |at: usize| text[at..].split('"').nth(1).map(str::to_string);
    if let Some(i) = text.find("\\version") {
        f.insert("version".into(), json!(quoted(i)));
    }
    let header = text.find("\\header").and_then(|i| block(&text, i)).map(header_fields).unwrap_or_default();
    let field = |k: &str| header.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    if let Some(t) = field("title") {
        cx.content().source("lilypond.title").title(truncate_chars(&t, 300));
        cx.emit_text(TextRole::Title, &t);
    }
    for role in ["composer", "poet", "arranger", "lyricist"] {
        if let Some(c) = field(role) {
            cx.content().source(format!("lilypond.{role}")).author(truncate_chars(&c, 200));
        }
    }
    if let Some(c) = field("copyright") {
        cx.rights().source("lilypond.copyright").copyright(truncate_chars(&c, 300));
    }
    let mut h = Map::new();
    for (k, v) in &header {
        if !matches!(k.as_str(), "title" | "composer" | "copyright" | "tagline") {
            h.insert(k.clone(), json!(truncate_chars(v, 200)));
        }
    }
    if !h.is_empty() {
        f.insert("header".into(), Value::Object(h));
    }
    let count = |needle: &str| text.matches(needle).count();
    f.insert("scores".into(), json!(count("\\score")));
    let staves =
        count("\\new Staff") + count("\\new TabStaff") + count("\\new DrumStaff") + count("\\new RhythmicStaff");
    if staves > 0 {
        f.insert("staves".into(), json!(staves));
    }
    let after = |cmd: &str| -> Option<String> {
        let i = text.find(cmd)? + cmd.len();
        let line = text[i..].lines().next()?.trim();
        Some(line.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
    };
    if let Some(k) = after("\\key ") {
        let mut w = k.split_whitespace();
        if let (Some(tonic), Some(mode)) = (w.next(), w.next()) {
            let tonic = tonic.replace("is", "#").replace("es", "b");
            let mut c = tonic.chars();
            let tonic = c.next().map(|h| h.to_uppercase().chain(c).collect::<String>()).unwrap_or_default();
            f.insert("key".into(), json!(format!("{tonic} {}", mode.trim_start_matches('\\'))));
        }
    }
    if let Some(t) = after("\\time ") {
        f.insert("time_signature".into(), json!(t.split_whitespace().next()));
    }
    if let Some(t) = after("\\tempo ") {
        f.insert("tempo".into(), json!(truncate_chars(t.trim_matches('"'), 80)));
    }
    let includes: Vec<String> =
        text.match_indices("\\include").filter_map(|(i, _)| quoted(i)).filter(|s| !s.is_empty()).take(32).collect();
    if !includes.is_empty() {
        f.insert("includes".into(), json!(includes));
    }
    // `\lyricmode { … }` and `\addlyrics { … }`: syllables joined at `--`.
    let mut lyrics = String::new();
    for cmd in ["\\lyricmode", "\\addlyrics", "\\lyricsto"] {
        for (i, _) in text.match_indices(cmd) {
            if let Some(b) = block(&text, i) {
                let words: String = b
                    .replace(" -- ", "")
                    .split_whitespace()
                    .filter(|w| !w.starts_with('\\') && *w != "__" && *w != "_")
                    .collect::<Vec<_>>()
                    .join(" ");
                lyrics.push_str(words.trim_matches('"'));
                lyrics.push('\n');
            }
        }
    }
    if !lyrics.trim().is_empty() {
        cx.emit_text(TextRole::Body, lyrics.trim());
    }
    cx.format().append(&mut f);
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("abc", "lilypond");

    #[test]
    fn lilypond_non_ascii_key() {
        // Fuzz regression: a key tonic that starts with a multi-byte letter.
        let r = crate::plugin::testing::report_for("x.ly", "\\version \"2.24.0\"\n\\key \u{d2}s \\major\n".as_bytes());
        assert_eq!(r.identification.format, "lilypond");
    }

    #[test]
    fn helpers() {
        assert_eq!(abc_key("G").as_deref(), Some("G major"));
        assert_eq!(abc_key("Bbm").as_deref(), Some("Bb minor"));
        assert_eq!(abc_key("A Mix").as_deref(), Some("A mixolydian"));
        assert_eq!(abc_key("D dorian % comment").as_deref(), Some("D dorian"));
        assert_eq!(abc_key("none"), None);
        assert_eq!(abc_notes("\"G\"ABc d2 !trill!e [K:D] f % gg"), 6);
        assert_eq!(
            header_fields("  title = \"Tide\"\n  composer = \\markup { \\italic \"Ana\" }\n"),
            [("title".to_string(), "Tide".to_string()), ("composer".to_string(), "Ana".to_string())]
        );
        assert_eq!(block("\\header { a = { b } c }", 0), Some(" a = { b } c "));
        assert_eq!(uncomment("a % note\nb %{ x %} c \"50%\""), "a \nb  c \"50%\"");
    }
}
