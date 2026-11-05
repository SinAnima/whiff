//! Interactive fiction:
//! * Twee (Twine 2 source, Twee 3 and 1): title, IFID, story format and
//!   version, start passage, passages, tags, links, the story text;
//! * Ink sources: knots, stitches, functions, choices, includes,
//!   variables, header tags (title, author), the story text; compiled Ink
//!   JSON: ink version, named containers, list definitions;
//! * Z-code story files (`.z1`–`.z8`): version, release, serial, the
//!   checksum (verified), file length, Inform version, IFID;
//! * Glulx story files (`.ulx`): Glulx version, memory layout, the
//!   checksum (verified), Inform version and serial, IFID;
//! * Blorb (`.zblorb`, `.gblorb`): the story inside, resources, the
//!   frontispiece, and the iFiction record (title, author, headline,
//!   first published, genre, description, language, IFID).
//!
//! Specifications: Twee 3 specification (Twine Cookbook); Ink "Writing
//! with Ink" and "ink JSON runtime format"; The Z-Machine Standards
//! Document 1.1; Glulx VM specification 3.1.3; Blorb 2.0; The Treaty of
//! Babel (IFIDs, iFiction).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{bump, hist};
use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    TextRole, truncate_chars,
    xmlwalk::{Ev, walk},
};

/// Extractor for interactive fiction.
pub struct Fiction;

static META: ExtractorMeta = ExtractorMeta {
    id: "game.fiction",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "twee",
            name: "Twee (Twine source)",
            family: "game",
            mimes: &["text/vnd.twine.twee"],
            extensions: &["twee", "tw"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "ink",
            name: "Ink story source",
            family: "game",
            mimes: &[],
            extensions: &["ink"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "ink_json",
            name: "Compiled Ink story (JSON)",
            family: "game",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: Some("json"),
        },
        // The first byte is the version: sniffed with the header.
        FormatSpec {
            id: "zcode",
            name: "Z-code story file",
            family: "game",
            mimes: &["application/x-zmachine"],
            extensions: &["z1", "z2", "z3", "z4", "z5", "z6", "z7", "z8", "zcode"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "glulx",
            name: "Glulx story file",
            family: "game",
            mimes: &["application/x-glulx"],
            extensions: &["ulx"],
            magic: &[Magic::prefix(b"Glul")],
            parent: None,
        },
        FormatSpec {
            id: "blorb",
            name: "Blorb story package",
            family: "game",
            mimes: &["application/x-blorb"],
            extensions: &["zblorb", "gblorb", "blorb", "blb", "zlb", "glb"],
            magic: &[Magic::at(8, b"IFRS")],
            parent: None,
        },
    ],
};

const MAX_LIST: usize = 100;

/// Links in Twine passages: `[[text]]`, `[[text->target]]`, `[[target<-text]]`, `[[text|target]]`.
fn twine_links(body: &str) -> u64 {
    body.matches("[[").count() as u64
}

fn twee(cx: &mut Context<'_>, text: &str) {
    let mut passages = 0u64;
    let mut names = Vec::new();
    let mut tags: BTreeMap<String, u64> = BTreeMap::new();
    let mut links = 0u64;
    let mut cur: Option<String> = None;
    let mut body = String::new();
    let mut title = None;
    let mut data = None;
    let mut story = String::new();
    let mut flush = |name: Option<String>, body: &mut String, story: &mut String| {
        if let Some(n) = name {
            match n.as_str() {
                "StoryTitle" => title = Some(truncate_chars(body.trim(), 300)),
                "StoryData" => data = serde_json::from_str::<Value>(body.trim()).ok(),
                _ => {
                    if story.len() < 4 << 20 {
                        story.push_str(body);
                        story.push('\n');
                    }
                }
            }
        }
        body.clear();
    };
    for line in text.lines() {
        if let Some(head) = line.strip_prefix("::") {
            flush(cur.take(), &mut body, &mut story);
            let head = head.trim();
            // `Name [tag tag] {"position":"…"}`; escaped brackets are rare.
            let name_end = head.find(['[', '{']).unwrap_or(head.len());
            let name = head[..name_end].trim().to_string();
            if let Some(t) = head.find('[').and_then(|i| head[i + 1..].find(']').map(|j| &head[i + 1..i + 1 + j])) {
                for tag in t.split_whitespace() {
                    bump(&mut tags, tag, 100);
                }
            }
            if name != "StoryTitle" && name != "StoryData" {
                passages += 1;
                if names.len() < MAX_LIST {
                    names.push(truncate_chars(&name, 200));
                }
            }
            cur = Some(name);
        } else if cur.is_some() {
            if cur.as_deref() != Some("StoryData") && cur.as_deref() != Some("StoryTitle") {
                links += twine_links(line);
            }
            body.push_str(line);
            body.push('\n');
        }
    }
    flush(cur.take(), &mut body, &mut story);
    if let Some(t) = title {
        cx.content().title(t.clone());
        cx.format_set("title", t);
    }
    if let Some(d) = data {
        for (k, out) in [
            ("ifid", "ifid"),
            ("format", "story_format"),
            ("format-version", "story_format_version"),
            ("start", "start"),
        ] {
            if let Some(v) = d.get(k).and_then(Value::as_str) {
                cx.format_set(out, truncate_chars(v, 200));
            }
        }
        cx.format_set("twee_version", 3);
    } else {
        cx.format_set("twee_version", if text.contains(":: StoryIncludes") { 2 } else { 1 });
    }
    cx.format_set("passage_count", passages);
    cx.format_set("passages", names);
    cx.format_set("link_count", links);
    if !tags.is_empty() {
        cx.format_set("tags", hist(tags));
    }
    cx.emit_text(TextRole::Body, &story);
}

fn ink(cx: &mut Context<'_>, text: &str) {
    let (mut knots, mut stitches, mut functions, mut choices, mut gathers) = (Vec::new(), 0u64, 0u64, 0u64, 0u64);
    let mut includes = Vec::new();
    let mut vars: BTreeMap<String, u64> = BTreeMap::new();
    let mut story = String::new();
    let mut header = true;
    let mut block_comment = false;
    for line in text.lines() {
        let t = line.trim();
        if block_comment {
            block_comment = !t.contains("*/");
            continue;
        }
        if t.starts_with("/*") {
            block_comment = !t.contains("*/");
            continue;
        }
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        // Tags before the first content line are the story's global tags.
        if let Some(tag) = t.strip_prefix('#') {
            if header && let Some((k, v)) = tag.split_once(':') {
                let v = truncate_chars(v.trim(), 300);
                match k.trim().to_ascii_lowercase().as_str() {
                    "title" => {
                        cx.content().title(v.clone());
                        cx.format_set("title", v);
                    }
                    "author" => {
                        cx.content().author(v.clone());
                        cx.format_set("author", v);
                    }
                    _ => {}
                }
            }
            continue;
        }
        header = false;
        if let Some(rest) = t.strip_prefix("==") {
            let name = rest.trim_matches(|c| c == '=' || c == ' ');
            if name.starts_with("function ") {
                functions += 1;
            } else if knots.len() < 1000 {
                knots.push(truncate_chars(name.split('(').next().unwrap_or(name).trim(), 200));
            }
        } else if t.starts_with('=') {
            stitches += 1;
        } else if t.starts_with('*') || t.starts_with('+') {
            choices += 1;
            story.push_str(t.trim_start_matches(['*', '+', ' ']));
            story.push('\n');
        } else if t.starts_with("- ") || t == "-" {
            gathers += 1;
        } else if let Some(f) = t.strip_prefix("INCLUDE ") {
            if includes.len() < MAX_LIST {
                includes.push(truncate_chars(f.trim(), 300));
            }
        } else if let Some(kind) = ["VAR ", "CONST ", "LIST ", "EXTERNAL "].iter().find(|k| t.starts_with(**k)) {
            bump(&mut vars, kind.trim().to_ascii_lowercase().as_str(), 10);
        } else if !t.starts_with('~') && !t.starts_with("->") && !t.starts_with('{') && story.len() < 4 << 20 {
            story.push_str(t);
            story.push('\n');
        }
    }
    cx.format_set("knot_count", knots.len());
    cx.format_set("knots", knots.into_iter().take(MAX_LIST).collect::<Vec<_>>());
    cx.format_set("stitch_count", stitches);
    cx.format_set("function_count", functions);
    cx.format_set("choice_count", choices);
    cx.format_set("gather_count", gathers);
    if !includes.is_empty() {
        cx.format_set("includes", includes);
    }
    if !vars.is_empty() {
        cx.format_set("declarations", hist(vars));
    }
    cx.emit_text(TextRole::Body, &story);
}

fn ink_json(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let v: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map_err(|e| ExtractError::Malformed(e.to_string()))?;
    if let Some(n) = v.get("inkVersion").and_then(Value::as_u64) {
        cx.format_set("ink_version", n);
    }
    // The root container's last element holds the named knots.
    if let Some(named) = v.get("root").and_then(Value::as_array).and_then(|r| r.last()).and_then(Value::as_object) {
        let names: Vec<Value> = named
            .keys()
            .filter(|k| !k.starts_with('#') && k.as_str() != "global decl")
            .take(MAX_LIST)
            .map(|k| k.clone().into())
            .collect();
        cx.format_set(
            "knot_count",
            named.keys().filter(|k| !k.starts_with('#') && k.as_str() != "global decl").count(),
        );
        cx.format_set("knots", names);
        if named.contains_key("global decl") {
            cx.format_set("global_variables", true);
        }
    }
    if let Some(l) = v.get("listDefs").and_then(Value::as_object)
        && !l.is_empty()
    {
        cx.format_set("lists", l.keys().take(MAX_LIST).cloned().collect::<Vec<_>>());
    }
    Ok(())
}

/// `UUID://…//` in a story file (the Treaty of Babel IFID).
fn embedded_ifid(b: &[u8]) -> Option<String> {
    let i = b.windows(7).position(|w| w == b"UUID://")?;
    let rest = &b[i + 7..b.len().min(i + 7 + 60)];
    let end = rest.windows(2).position(|w| w == b"//")?;
    let id = std::str::from_utf8(&rest[..end]).ok()?;
    (id.len() >= 8 && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')).then(|| id.to_ascii_uppercase())
}

fn zcode(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let h = b.get(..0x40).ok_or(ExtractError::Malformed("short Z-code header".into()))?;
    let be = |i: usize| u16::from_be_bytes([h[i], h[i + 1]]);
    let version = h[0];
    let release = be(2);
    let serial = String::from_utf8_lossy(&h[0x12..0x18]).into_owned();
    let scale = match version {
        1..=3 => 2,
        4 | 5 => 4,
        _ => 8,
    };
    let length = usize::from(be(0x1A)) * scale;
    let checksum = be(0x1C);
    cx.format_set("version", version);
    cx.format_set("release", release);
    if serial.bytes().all(|c| c.is_ascii_digit()) {
        cx.format_set("serial", serial.clone());
    }
    if length > 0 {
        cx.format_set("declared_length", length);
        if let Some(body) = b.get(0x40..length) {
            let sum = body.iter().fold(0u16, |a, &x| a.wrapping_add(u16::from(x)));
            cx.format_set("checksum_valid", sum == checksum);
        }
    }
    cx.format_set("checksum", format!("{checksum:04x}"));
    let inform = &h[0x3C..0x40];
    if inform[0].is_ascii_digit() && inform[1] == b'.' && inform[2..].iter().all(u8::is_ascii_digit) {
        cx.format_set("inform_version", String::from_utf8_lossy(inform).into_owned());
    }
    let ifid = embedded_ifid(b).unwrap_or_else(|| format!("ZCODE-{release}-{serial}-{checksum:04X}"));
    cx.format_set("ifid", ifid);
    Ok(())
}

fn glulx(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let h = b.get(..0x40).ok_or(ExtractError::Malformed("short Glulx header".into()))?;
    let be = |i: usize| u32::from_be_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]);
    let v = be(4);
    cx.format_set("glulx_version", format!("{}.{}.{}", v >> 16, (v >> 8) & 0xFF, v & 0xFF));
    let (ram, ext, end) = (be(8), be(12), be(16));
    cx.format_set("ram_start", ram);
    cx.format_set("story_bytes", ext);
    cx.format_set("memory_bytes", end);
    cx.format_set("stack_bytes", be(20));
    let checksum = be(32);
    cx.format_set("checksum", format!("{checksum:08x}"));
    if let Some(game) = b.get(..ext as usize) {
        // The sum of every word, the checksum field counted as zero.
        let sum = game.chunks(4).enumerate().fold(0u32, |a, (i, w)| {
            let word = if i == 8 {
                0
            } else {
                u32::from_be_bytes([w[0], *w.get(1).unwrap_or(&0), *w.get(2).unwrap_or(&0), *w.get(3).unwrap_or(&0)])
            };
            a.wrapping_add(word)
        });
        cx.format_set("checksum_valid", sum == checksum);
    }
    // Inform's header extension: "Info", its version, the Inform and
    // Glulx back-end versions, then release and serial.
    if &h[0x24..0x28] == b"Info" {
        let ascii = |s: &[u8]| s.iter().all(u8::is_ascii_graphic).then(|| String::from_utf8_lossy(s).into_owned());
        if let Some(i) = ascii(&h[0x2C..0x30]) {
            cx.format_set("inform_version", i);
        }
        let serial = &h[0x36..0x3C];
        if serial.iter().all(u8::is_ascii_digit) {
            cx.format_set("release", u16::from_be_bytes([h[0x34], h[0x35]]));
            cx.format_set("serial", String::from_utf8_lossy(serial).into_owned());
        }
    }
    if let Some(id) = embedded_ifid(b) {
        cx.format_set("ifid", id);
    } else if &h[0x24..0x28] == b"Info" {
        let serial = String::from_utf8_lossy(&h[0x36..0x3C]).into_owned();
        cx.format_set("ifid", format!("GLULX-{}-{serial}-{checksum:08X}", u16::from_be_bytes([h[0x34], h[0x35]])));
    } else {
        cx.format_set("ifid", format!("GLULX-{checksum:08X}"));
    }
    Ok(())
}

/// iFiction bibliographic fields.
fn ifiction(cx: &mut Context<'_>, xml: &str) -> Result<Map<String, Value>, ExtractError> {
    let mut m = Map::new();
    let mut path: Vec<String> = Vec::new();
    walk(xml, cx, 100_000, |_, ev| match ev {
        Ev::Start(n, _) => path.push(n.to_string()),
        Ev::End(_) => {
            path.pop();
        }
        Ev::Text(t) => {
            let leaf = path.last().map_or("", String::as_str);
            let parent = path.iter().rev().nth(1).map_or("", String::as_str);
            let key = match (parent, leaf) {
                (
                    "bibliographic",
                    "title" | "author" | "headline" | "firstpublished" | "genre" | "language" | "group" | "series",
                ) => leaf,
                ("bibliographic", "description") => "description",
                ("identification", "ifid") => "ifid",
                ("identification", "format") => "story_format",
                ("description", _) if path.iter().any(|p| p == "bibliographic") => "description",
                _ => return,
            };
            let v = truncate_chars(t, 2000);
            match m.get_mut(key) {
                Some(Value::String(s)) if key == "description" => {
                    s.push(' ');
                    s.push_str(&v);
                }
                Some(_) => {}
                None => {
                    m.insert(key.to_string(), v.into());
                }
            }
        }
    })?;
    Ok(m)
}

fn blorb(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(b);
    r.tag(b"FORM")?;
    let size = r.be_u32()? as usize;
    r.tag(b"IFRS")?;
    let end = (8 + size).min(b.len());
    let mut chunks: BTreeMap<String, u64> = BTreeMap::new();
    let mut usages: BTreeMap<String, u64> = BTreeMap::new();
    let mut story = None;
    let mut meta = None;
    let mut exec_at = None;
    while r.position() + 8 <= end {
        let id = r.array::<4>()?;
        let n = r.be_u32()? as usize;
        let start = r.position();
        let Ok(d) = r.bytes(n.min(end - start)) else { break };
        let name = String::from_utf8_lossy(&id).trim_end().to_string();
        bump(&mut chunks, &name, 50);
        match &id {
            b"RIdx" => {
                let mut c = ByteReader::new(d);
                let count = c.be_u32()?;
                for _ in 0..count.min(100_000) {
                    let usage = c.array::<4>()?;
                    c.advance(8)?;
                    let u = match &usage {
                        b"Pict" => "pictures",
                        b"Snd " => "sounds",
                        b"Exec" => "executables",
                        b"Data" => "data",
                        _ => "other",
                    };
                    bump(&mut usages, u, 10);
                }
            }
            b"ZCOD" | b"GLUL" | b"TAD2" | b"TAD3" | b"HUGO" | b"ADRI" | b"LEVE" | b"AGT " | b"MAGS" | b"ADVS"
            | b"EXEC" => {
                story = Some(match &id {
                    b"ZCOD" => "Z-code",
                    b"GLUL" => "Glulx",
                    b"TAD2" | b"TAD3" => "TADS",
                    b"HUGO" => "Hugo",
                    _ => "other",
                });
                exec_at = Some((start, n));
            }
            b"IFmd" => meta = Some(String::from_utf8_lossy(d).into_owned()),
            b"Fspc" => {
                cx.format_set(
                    "frontispiece",
                    u32::from_be_bytes(d.get(..4).unwrap_or(&[0; 4]).try_into().unwrap_or_default()),
                );
            }
            _ => {}
        }
        // Chunks are padded to even lengths.
        let next = start + n + (n & 1);
        if r.seek(next.min(b.len())).is_err() || next > end {
            break;
        }
    }
    if let Some(s) = story {
        cx.format_set("story_format", s);
    }
    cx.format_set("chunks", hist(chunks));
    if !usages.is_empty() {
        cx.format_set("resources", hist(usages));
    }
    if let Some((at, n)) = exec_at {
        let story_bytes = &b[at..(at + n).min(b.len())];
        let mut info = Map::new();
        if story_bytes.starts_with(b"Glul") {
            info.insert("format".into(), "Glulx".into());
        } else if let Some(&v) = story_bytes.first() {
            info.insert("version".into(), v.into());
            if story_bytes.len() >= 0x18 {
                info.insert("release".into(), u16::from_be_bytes([story_bytes[2], story_bytes[3]]).into());
                info.insert("serial".into(), String::from_utf8_lossy(&story_bytes[0x12..0x18]).into_owned().into());
            }
        }
        cx.format_set("story", info);
    }
    if let Some(xml) = meta {
        let m = ifiction(cx, &xml)?;
        if let Some(t) = m.get("title").and_then(Value::as_str) {
            cx.content().title(t.to_string());
        }
        if let Some(a) = m.get("author").and_then(Value::as_str) {
            cx.content().author(a.to_string());
        }
        if let Some(d) = m.get("description").and_then(Value::as_str) {
            cx.content().description(d.to_string());
        }
        if let Some(Value::String(l)) = m.get("language") {
            cx.content().language(l.clone(), 1.0);
        }
        cx.format_set("ifiction", m);
    }
    Ok(())
}

/// A plausible Z-code header for a file of `len` bytes.
fn zcode_header(h: &[u8], len: u64) -> bool {
    if h.len() < 0x40 || !(1..=8).contains(&h[0]) {
        return false;
    }
    let be = |i: usize| u64::from(u16::from_be_bytes([h[i], h[i + 1]]));
    let scale = match h[0] {
        1..=3 => 2,
        4 | 5 => 4,
        _ => 8,
    };
    let declared = be(0x1A) * scale;
    // High memory, dictionary, objects, globals and static memory lie
    // inside the file, past the header.
    let inside = [4, 8, 0x0A, 0x0C, 0x0E].iter().all(|&i| be(i) >= 0x40 && be(i) < len.max(declared));
    inside && (declared == 0 || declared <= len) && h[0x12..0x18].iter().all(u8::is_ascii_digit)
}

impl Extractor for Fiction {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or("");
        let sure = |format| Some(Sniff { format, confidence: 0.97 });
        if (ext.starts_with('z') && ext.len() == 2 || ext == "zcode") && zcode_header(h, probe.len) {
            return sure("zcode");
        }
        let text = std::str::from_utf8(&h[..h.len().min(4096)]).ok()?;
        if ext == "json" || ext.is_empty() {
            let t = text.trim_start_matches('\u{feff}').trim_start();
            if t.starts_with("{\"inkVersion\"") || t.starts_with("{ \"inkVersion\"") {
                return sure("ink_json");
            }
        }
        if matches!(ext, "twee" | "tw" | "txt") && text.lines().any(|l| l.starts_with(":: ")) {
            return sure("twee");
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let id = cx.format_id().to_string();
        match id.as_str() {
            "twee" | "ink" | "ink_json" => {
                let text = cx.read_text(src)?.text;
                match id.as_str() {
                    "twee" => twee(cx, &text),
                    "ink" => ink(cx, &text),
                    _ => return ink_json(cx, &text),
                }
                Ok(())
            }
            _ => {
                let (b, _) = cx.read_bytes(src)?;
                match id.as_str() {
                    "zcode" => zcode(cx, &b),
                    "glulx" => glulx(cx, &b),
                    _ => blorb(cx, &b),
                }
            }
        }
    }
}

crate::register_extractor!(Fiction);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifids() {
        assert_eq!(
            embedded_ifid(b"..UUID://1974a053-7db0-4103-93c1-50b2e5c9e5c0//..").as_deref(),
            Some("1974A053-7DB0-4103-93C1-50B2E5C9E5C0")
        );
        assert_eq!(embedded_ifid(b"UUID://x//"), None);
    }

    crate::fixture_tests!("twee", "ink", "ink_json", "zcode", "glulx", "blorb");
}
