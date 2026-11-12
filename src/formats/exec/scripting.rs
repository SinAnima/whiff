//! Scripts packaged to run, and Rust's compiled libraries:
//!
//! * Windows script hosts: HTML applications (`.hta`: the `HTA:APPLICATION`
//!   settings), Windows Script Files (`.wsf`: jobs, objects, type library
//!   references) and scriptlets (`.sct`, `.wsc`: the COM registration and
//!   the public properties, methods and events). For each: the script
//!   languages, inline and external scripts, and the COM objects created;
//!   the scripts run with the user's rights, so they are active content,
//!   external scripts are external references and shell objects
//!   (`WScript.Shell`, `Shell.Application`) are shell actions. Nothing is
//!   run;
//! * compiled AppleScript (`FasdUAS`): the format version;
//! * Rust libraries: `rlib` archives (the crate from the member names, the
//!   codegen units, the metadata member) and `rmeta` metadata (the
//!   metadata version and the rustc version that wrote it).
//!
//! Specifications: Microsoft's HTA, Windows Script Host and Windows Script
//! Components references; rustc's `rmeta` header (`METADATA_HEADER`); the
//! `ar` format (GNU and BSD member names).

use std::collections::BTreeMap;

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, latin1_or_utf8,
};

/// Extractor for script hosts, compiled AppleScript and Rust libraries.
pub struct Scripting;

static META: ExtractorMeta = ExtractorMeta {
    id: "exec.scripting",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "hta",
            name: "HTML application (HTA)",
            family: "exec",
            mimes: &["application/hta"],
            extensions: &["hta"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "wsf",
            name: "Windows Script File",
            family: "exec",
            mimes: &["text/xml"],
            extensions: &["wsf"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "scriptlet",
            name: "Windows Script Component (scriptlet)",
            family: "exec",
            mimes: &["text/scriptlet"],
            extensions: &["sct", "wsc"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            // `applescript` is the source language (code.source).
            id: "applescript_compiled",
            name: "Compiled AppleScript",
            family: "exec",
            mimes: &["application/x-apple-script"],
            extensions: &["scpt"],
            magic: &[Magic::prefix(b"FasdUAS ")],
            parent: None,
        },
        FormatSpec {
            id: "rust_rlib",
            name: "Rust library (rlib)",
            family: "exec",
            mimes: &["application/x-archive"],
            extensions: &["rlib"],
            magic: &[],
            parent: Some("ar"),
        },
        FormatSpec {
            id: "rust_rmeta",
            name: "Rust crate metadata (rmeta)",
            family: "exec",
            mimes: &["application/octet-stream"],
            extensions: &["rmeta"],
            magic: &[Magic::prefix(b"rust\0\0\0")],
            parent: None,
        },
    ],
};

/// Members, objects and names listed.
const MAX_LISTED: usize = 50;
/// `ar` members read.
const MAX_MEMBERS: usize = 1 << 16;

impl Extractor for Scripting {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.starts_with(b"!<arch>\n") {
            let has = |n: &[u8]| h.windows(n.len()).any(|w| w == n);
            return (has(b"lib.rmeta") || has(b"rust.metadata.bin"))
                .then_some(Sniff { format: "rust_rlib", confidence: 0.95 });
        }
        let lower: Vec<u8> = h[..h.len().min(8192)].to_ascii_lowercase();
        let has = |n: &[u8]| lower.windows(n.len()).any(|w| w == n);
        if has(b"<hta:application") {
            return Some(Sniff { format: "hta", confidence: 0.95 });
        }
        if has(b"<scriptlet") || (has(b"<component") && has(b"<registration")) {
            return Some(Sniff { format: "scriptlet", confidence: 0.9 });
        }
        if has(b"<job") && has(b"<script") && (has(b"<package") || probe.extension == Some("wsf")) {
            return Some(Sniff { format: "wsf", confidence: 0.9 });
        }
        if probe.extension == Some("hta") && has(b"<script") {
            return Some(Sniff { format: "hta", confidence: 0.8 });
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let format = cx.format_id().to_string();
        match format.as_str() {
            "applescript_compiled" => {
                let h = src.read_vec(0, usize::try_from(src.len().min(64)).unwrap_or(0))?;
                let v = h
                    .get(8..)
                    .unwrap_or(&[])
                    .iter()
                    .take_while(|b| b.is_ascii_digit() || **b == b'.')
                    .copied()
                    .collect::<Vec<_>>();
                cx.format_set("version", latin1_or_utf8(&v));
                Ok(())
            }
            "rust_rlib" => rlib(src, cx),
            "rust_rmeta" => {
                let h = src.read_vec(0, usize::try_from(src.len().min(1024)).unwrap_or(0))?;
                rmeta(cx, &h);
                if let Some(name) = src.name_hint().and_then(crate_from_file) {
                    cx.format_set("crate", name);
                }
                Ok(())
            }
            kind => {
                let n = src.len().min(cx.parse_limit() as u64);
                let text = src.read_vec(0, usize::try_from(n).unwrap_or(0))?;
                host(cx, kind, &crate::plugin::decode_text(&text).text);
                Ok(())
            }
        }
    }
}

crate::register_extractor!(Scripting);

// --- tags --------------------------------------------------------------------------

/// A start tag: its lowercase name and attributes (lowercase keys).
struct Tag {
    name: String,
    attrs: Vec<(String, String)>,
    /// Byte offset just after the tag.
    end: usize,
}

/// The start tags of an HTML or XML text (comments skipped).
fn tags(text: &str) -> Vec<Tag> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = text[i..].find('<') {
        let at = i + p + 1;
        if text[at..].starts_with("!--") {
            i = text[at..].find("-->").map_or(bytes.len(), |e| at + e + 3);
            continue;
        }
        let name_end = bytes[at..]
            .iter()
            .position(|c| c.is_ascii_whitespace() || *c == b'>' || *c == b'/')
            .map_or(bytes.len(), |e| at + e);
        let name = text[at..name_end].to_ascii_lowercase();
        let Some(close) = text[name_end..].find('>') else { break };
        let close = name_end + close;
        let mut attrs = Vec::new();
        let mut r = &text[name_end..close];
        while let Some(eq) = r.find('=') {
            let key = r[..eq].trim().rsplit(char::is_whitespace).next().unwrap_or("").to_ascii_lowercase();
            let rest = r[eq + 1..].trim_start();
            let (value, next) = if let Some(q @ ('"' | '\'')) = rest.chars().next() {
                let v = &rest[1..];
                let e = v.find(q).unwrap_or(v.len());
                (&v[..e], v.get(e + 1..).unwrap_or(""))
            } else {
                let e = rest.find(char::is_whitespace).unwrap_or(rest.len());
                (&rest[..e], &rest[e..])
            };
            if !key.is_empty() {
                attrs.push((key, value.to_string()));
            }
            r = next;
        }
        if !name.is_empty() && !name.starts_with('/') && !name.starts_with('?') && !name.starts_with('!') {
            out.push(Tag { name, attrs, end: close + 1 });
        }
        i = close + 1;
    }
    out
}

fn attr<'a>(t: &'a Tag, key: &str) -> Option<&'a str> {
    t.attrs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty())
}

/// COM objects created by name: `CreateObject("x")`, `GetObject("x")`,
/// `new ActiveXObject("x")`.
fn com_objects(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut out: Vec<String> = Vec::new();
    for call in ["createobject(", "activexobject(", "getobject("] {
        let mut from = 0;
        while let Some(p) = lower[from..].find(call) {
            let at = from + p + call.len();
            let rest = text[at..].trim_start();
            if let Some(q @ ('"' | '\'')) = rest.chars().next() {
                let v = &rest[1..];
                if let Some(e) = v.find(q) {
                    let name = v[..e].trim();
                    if !name.is_empty() && !out.iter().any(|o| o.eq_ignore_ascii_case(name)) && out.len() < MAX_LISTED {
                        out.push(name.to_string());
                    }
                }
            }
            from = at;
        }
    }
    out
}

#[allow(clippy::too_many_lines)] // three kinds of host, one pass over the tags
fn host(cx: &mut Context<'_>, kind: &str, text: &str) {
    let tags = tags(text);
    let mut languages: BTreeMap<String, u64> = BTreeMap::new();
    let (mut inline, mut external) = (0u64, Vec::new());
    for t in tags.iter().filter(|t| t.name == "script") {
        let lang = attr(t, "language").or_else(|| attr(t, "type")).unwrap_or("JScript");
        let lang = lang.trim_start_matches("text/").to_string();
        *languages.entry(lang).or_default() += 1;
        match attr(t, "src") {
            Some(s) => external.push(s.to_string()),
            None => inline += 1,
        }
    }
    match kind {
        "hta" => {
            if let Some(app) = tags.iter().find(|t| t.name == "hta:application") {
                let settings: serde_json::Map<String, serde_json::Value> =
                    app.attrs.iter().take(64).map(|(k, v)| (k.clone(), v.clone().into())).collect();
                if let Some(n) = attr(app, "applicationname") {
                    cx.content().title(n.to_string());
                }
                cx.format_set("application", settings);
            }
            if let Some(t) = tags.iter().find(|t| t.name == "title") {
                let end = text[t.end..].find('<').map_or(text.len(), |e| t.end + e);
                let title = text[t.end..end].trim();
                if !title.is_empty() {
                    cx.format_set("title", title);
                    cx.content().title(title.to_string());
                }
            }
        }
        "wsf" => {
            let jobs: Vec<&str> =
                tags.iter().filter(|t| t.name == "job").map(|t| attr(t, "id").unwrap_or("(unnamed)")).collect();
            cx.format_set(
                "jobs",
                jobs.iter().take(MAX_LISTED).map(|j| serde_json::Value::from(*j)).collect::<Vec<_>>(),
            );
            let refs: Vec<&str> = tags
                .iter()
                .filter(|t| t.name == "reference")
                .filter_map(|t| attr(t, "object").or_else(|| attr(t, "guid")))
                .collect();
            if !refs.is_empty() {
                cx.format_set(
                    "references",
                    refs.iter().take(MAX_LISTED).map(|r| serde_json::Value::from(*r)).collect::<Vec<_>>(),
                );
            }
            let objects: Vec<&str> = tags
                .iter()
                .filter(|t| t.name == "object")
                .filter_map(|t| attr(t, "progid").or_else(|| attr(t, "classid")))
                .collect();
            if !objects.is_empty() {
                cx.format_set(
                    "declared_objects",
                    objects.iter().take(MAX_LISTED).map(|o| serde_json::Value::from(*o)).collect::<Vec<_>>(),
                );
            }
        }
        _ => {
            if let Some(reg) = tags.iter().find(|t| t.name == "registration") {
                for key in ["progid", "classid", "description", "version"] {
                    if let Some(v) = attr(reg, key) {
                        cx.format_set(key, v);
                    }
                }
                if attr(reg, "remotable").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
                    cx.format_set("remotable", true);
                }
            }
            for (member, key) in [("property", "properties"), ("method", "methods"), ("event", "events")] {
                let names: Vec<&str> =
                    tags.iter().filter(|t| t.name == member).filter_map(|t| attr(t, "name")).collect();
                if !names.is_empty() {
                    cx.format_set(
                        key,
                        names.iter().take(MAX_LISTED).map(|n| serde_json::Value::from(*n)).collect::<Vec<_>>(),
                    );
                }
            }
        }
    }
    cx.format_set("script_languages", serde_json::json!(languages));
    cx.format_set("inline_scripts", inline);
    if !languages.is_empty() {
        cx.security()
            .active_content(kind)
            .risk("script", Some(format!("{} script block(s)", inline + external.len() as u64)));
    }
    if !external.is_empty() {
        cx.format_set(
            "external_scripts",
            external.iter().take(MAX_LISTED).map(|s| serde_json::Value::from(s.as_str())).collect::<Vec<_>>(),
        );
        cx.security().external_references(external.len() as u64);
        for s in external.iter().take(MAX_LISTED) {
            cx.security().risk("external_reference", Some(s.clone()));
        }
    }
    let objects = com_objects(text);
    for o in &objects {
        if o.eq_ignore_ascii_case("WScript.Shell") || o.eq_ignore_ascii_case("Shell.Application") {
            cx.security().risk("shell_action", Some(o.clone()));
        }
    }
    if !objects.is_empty() {
        cx.format_set("com_objects", objects);
    }
}

// --- Rust ------------------------------------------------------------------------

/// `libharbour-1a2b3c.rmeta` / `libharbour.rlib` → `harbour`.
fn crate_from_file(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next()?;
    let stem = base.strip_prefix("lib")?.rsplit_once('.')?.0;
    let name = stem.split_once('-').map_or(stem, |(n, _)| n);
    (!name.is_empty()).then(|| name.to_string())
}

fn rmeta(cx: &mut Context<'_>, h: &[u8]) {
    if let Some(&v) = h.get(7).filter(|_| h.starts_with(b"rust\0\0\0")) {
        cx.format_set("metadata_version", v);
    }
    // The rustc version string follows the header.
    if let Some(p) = h.windows(6).position(|w| w == b"rustc ") {
        let v: Vec<u8> = h[p..].iter().take(200).take_while(|b| (0x20..0x7f).contains(*b)).copied().collect();
        cx.format_set("rustc_version", latin1_or_utf8(&v));
    }
}

fn rlib(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    let (mut at, mut long_names) = (8u64, Vec::new());
    let mut members: Vec<String> = Vec::new();
    let (mut objects, mut crate_name, mut meta) = (0u64, None::<String>, None::<(u64, u64)>);
    for _ in 0..MAX_MEMBERS {
        if at + 60 > len {
            break;
        }
        let h = src.read_vec(at, 60)?;
        if &h[58..60] != b"`\n" {
            cx.warn(format!("bad ar member header at offset {at}"));
            break;
        }
        let field = |a: usize, b: usize| latin1_or_utf8(&h[a..b]).trim().to_string();
        let size: u64 = field(48, 58).parse().unwrap_or(0);
        let raw = field(0, 16);
        let mut data_at = at + 60;
        let mut data_len = size;
        // BSD: `#1/len`, the name ahead of the data; GNU: `/n` into the
        // long-name table, `name/` otherwise.
        let name = if let Some(n) = raw.strip_prefix("#1/") {
            let n: u64 = n.parse().unwrap_or(0).min(size);
            let b = src.read_vec(data_at, usize::try_from(n).unwrap_or(0))?;
            data_at += n;
            data_len -= n;
            latin1_or_utf8(b.split(|&c| c == 0).next().unwrap_or(&[]))
        } else if raw == "//" {
            long_names = src.read_vec(data_at, usize::try_from(size.min(1 << 20)).unwrap_or(0))?;
            String::new()
        } else if let Some(off) = raw.strip_prefix('/').and_then(|n| n.parse::<usize>().ok()) {
            let s = long_names.get(off..).unwrap_or(&[]);
            latin1_or_utf8(s.split(|&c| c == b'\n').next().unwrap_or(&[])).trim_end_matches('/').to_string()
        } else {
            raw.trim_end_matches('/').to_string()
        };
        if name == "lib.rmeta" || name == "rust.metadata.bin" {
            meta = Some((data_at, data_len));
        } else if std::path::Path::new(&name).extension().is_some_and(|x| x.eq_ignore_ascii_case("o")) {
            objects += 1;
            // `harbour.harbour.c1b2…-cgu.0.rcgu.o`, or with the crate hash
            // first: `harbour-5f2a….harbour.c1b2…-cgu.0.rcgu.o`.
            if crate_name.is_none() {
                let first = name.split('.').next().unwrap_or("");
                crate_name = Some(first.split('-').next().unwrap_or(first).to_string()).filter(|c| !c.is_empty());
            }
        }
        if !name.is_empty() && !name.starts_with("__.SYMDEF") && members.len() < MAX_LISTED {
            members.push(name);
        }
        at = at.saturating_add(60).saturating_add(size.next_multiple_of(2));
    }
    if let Some(c) = crate_name.or_else(|| src.name_hint().and_then(crate_from_file)) {
        cx.format_set("crate", c.clone());
        cx.content().title(c);
    }
    cx.format_set("codegen_units", objects);
    cx.format_set("members", members);
    if let Some((off, n)) = meta {
        let h = src.read_vec(off, usize::try_from(n.min(1024)).unwrap_or(0))?;
        rmeta(cx, &h);
    } else {
        cx.warn("no lib.rmeta member");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::testing::report_for;

    crate::fixture_tests!("hta", "wsf", "scriptlet", "applescript_compiled", "rust_rlib", "rust_rmeta");

    #[test]
    fn tags_and_objects() {
        let t = tags(
            r#"<!-- <script> --><HTA:APPLICATION ID="x" applicationName='Tides' border=thin><script language="VBScript" src="a.vbs"></script>"#,
        );
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].name, "hta:application");
        assert_eq!(attr(&t[0], "applicationname"), Some("Tides"));
        assert_eq!(attr(&t[0], "border"), Some("thin"));
        assert_eq!(attr(&t[1], "src"), Some("a.vbs"));
        let o = com_objects(
            r#"Set a = CreateObject("Scripting.FileSystemObject") : var b = new ActiveXObject('Msxml2.XMLHTTP');"#,
        );
        assert_eq!(o, ["Scripting.FileSystemObject", "Msxml2.XMLHTTP"]);
        assert_eq!(crate_from_file("libharbour-1a2b.rmeta").as_deref(), Some("harbour"));
        assert_eq!(crate_from_file("harbour.rmeta"), None);
    }

    /// Risk signals on neutral, in-memory input (never a fixture).
    #[test]
    fn script_host_risks() {
        let hta = br#"<html><head><HTA:APPLICATION applicationName="Notes"/>
<script language="VBScript" src="https://example.com/notes.vbs"></script>
<script language="VBScript">Set s = CreateObject("WScript.Shell")</script></head></html>"#;
        let r = report_for("notes.hta", hta);
        let kinds: Vec<&str> = r.security.risks.iter().map(|x| x.kind.as_str()).collect();
        assert!(kinds.contains(&"script"), "{kinds:?}");
        assert!(kinds.contains(&"external_reference"), "{kinds:?}");
        assert!(kinds.contains(&"shell_action"), "{kinds:?}");
        assert_eq!(r.security.external_references, Some(1));
    }
}
