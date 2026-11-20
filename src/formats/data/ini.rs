//! INI-style configuration (INI, systemd units, desktop entries, git config,
//! `EditorConfig`, Windows `.reg` and `.inf`), Java properties and dotenv:
//! sections and keys, with secret-looking values redacted (key names kept)
//! and every dotenv value redacted (both unless `--redaction off`).

use serde_json::{Map, Value, json};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole, is_secret_key,
    truncate_chars,
};

/// Extractor for INI, properties and dotenv files.
pub struct Ini;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.ini",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "ini",
            name: "INI configuration",
            family: "data.ini",
            mimes: &["text/plain"],
            extensions: &[
                "ini",
                "cfg",
                "conf",
                "inf",
                "reg",
                "desktop",
                "service",
                "socket",
                "timer",
                "mount",
                "target",
                "path",
                "slice",
                "gitconfig",
                "gitmodules",
                "editorconfig",
                "url",
            ],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "properties",
            name: "Java properties",
            family: "data.ini",
            mimes: &["text/x-java-properties"],
            extensions: &["properties"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "dotenv",
            name: "dotenv file",
            family: "data.ini",
            mimes: &["text/plain"],
            extensions: &["env"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

/// Sections and keys listed in the report.
const MAX_SECTIONS: usize = 100;
const MAX_KEYS: usize = 100;

impl Extractor for Ini {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let name = probe.name?.to_ascii_lowercase();
        let base = name.rsplit(['/', '\\']).next().unwrap_or(&name);
        if base == ".env" || base.starts_with(".env.") {
            return Some(Sniff { format: "dotenv", confidence: 0.9 });
        }
        matches!(base, ".gitconfig" | ".gitmodules" | ".editorconfig" | ".npmrc" | ".pypirc" | "setup.cfg" | "tox.ini")
            .then_some(Sniff { format: "ini", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        cx.emit_text(TextRole::Data, &text);
        let doc = match cx.format_id() {
            "properties" => properties(&text),
            "dotenv" => dotenv(&text),
            _ => ini(&text),
        };
        let name = src.name_hint().unwrap_or("").to_ascii_lowercase();
        let dialect = match cx.format_id() {
            "properties" => "java_properties",
            "dotenv" => "dotenv",
            _ => dialect(&name, &text, &doc),
        };
        report(&doc, dialect, cx);
        Ok(())
    }
}

crate::register_extractor!(Ini);

#[derive(Default)]
struct Section {
    name: String,
    entries: Vec<(String, String)>,
}

#[derive(Default)]
struct Doc {
    sections: Vec<Section>,
    comments: u64,
    invalid: u64,
}

impl Doc {
    fn section(&mut self) -> &mut Section {
        if self.sections.is_empty() {
            self.sections.push(Section::default());
        }
        self.sections.last_mut().expect("just pushed")
    }
}

fn ini(text: &str) -> Doc {
    let mut doc = Doc::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with(';') || line.starts_with('#') {
            doc.comments += 1;
        } else if line.starts_with('[') && line.ends_with(']') {
            doc.sections.push(Section { name: line[1..line.len() - 1].trim().to_string(), entries: Vec::new() });
        } else if let Some((k, v)) = line.split_once('=').or_else(|| line.split_once(':')) {
            doc.section().entries.push((k.trim().trim_matches('"').to_string(), unquote(v.trim())));
        } else if line.starts_with("Windows Registry Editor") || line == "REGEDIT4" {
            doc.comments += 1;
        } else {
            doc.invalid += 1;
        }
    }
    doc
}

fn properties(text: &str) -> Doc {
    let mut doc = Doc::default();
    let mut pending = String::new();
    for raw in text.lines() {
        let line = raw.trim_start();
        if pending.is_empty() && (line.starts_with('#') || line.starts_with('!')) {
            doc.comments += 1;
            continue;
        }
        // A trailing backslash continues the logical line.
        if let Some(cont) = line.strip_suffix('\\') {
            pending.push_str(cont);
            continue;
        }
        pending.push_str(line);
        let logical = std::mem::take(&mut pending);
        if logical.trim().is_empty() {
            continue;
        }
        // The key ends at the first `=`, `:` or whitespace; then come optional
        // whitespace, at most one `=`/`:`, and more whitespace.
        let key_end = logical.trim_start().find(|c: char| c == '=' || c == ':' || c.is_whitespace());
        let logical = logical.trim_start();
        let (k, rest) = key_end.map_or((logical, ""), |i| logical.split_at(i));
        let rest = rest.trim_start();
        let v = rest.strip_prefix(['=', ':']).unwrap_or(rest).trim_start();
        doc.section().entries.push((k.trim().to_string(), v.trim().to_string()));
    }
    doc
}

fn dotenv(text: &str) -> Doc {
    let mut doc = Doc::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            doc.comments += 1;
        } else if let Some((k, v)) = line.strip_prefix("export ").unwrap_or(line).split_once('=') {
            doc.section().entries.push((k.trim().to_string(), unquote(v.trim())));
        } else {
            doc.invalid += 1;
        }
    }
    doc
}

fn unquote(v: &str) -> String {
    let v = v.split(" #").next().unwrap_or(v).trim();
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return v[1..v.len() - 1].to_string();
        }
    }
    v.to_string()
}

fn dialect(name: &str, text: &str, doc: &Doc) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("");
    let has = |s: &str| doc.sections.iter().any(|x| x.name.eq_ignore_ascii_case(s));
    if text.starts_with("Windows Registry Editor") || text.starts_with("REGEDIT4") || ext == "reg" {
        "windows_registry"
    } else if has("Desktop Entry") {
        "desktop_entry"
    } else if has("InternetShortcut") {
        "internet_shortcut"
    } else if has("Unit")
        || has("Service")
        || has("Install")
        || ["service", "socket", "timer", "mount", "target"].contains(&ext)
    {
        "systemd_unit"
    } else if has("Version")
        && doc.sections.iter().any(|s| s.entries.iter().any(|(k, _)| k.eq_ignore_ascii_case("Signature")))
    {
        "windows_inf"
    } else if name.ends_with("gitconfig")
        || name.ends_with(".gitmodules")
        || doc.sections.iter().any(|s| s.name.starts_with("remote "))
    {
        "git_config"
    } else if name.ends_with(".editorconfig") {
        "editorconfig"
    } else {
        "ini"
    }
}

fn report(doc: &Doc, dialect: &'static str, cx: &mut Context<'_>) {
    // Dotenv files hold credentials; every value is one under `--redaction on`.
    let hide = cx.redaction_on();
    let redact_all = hide && dialect == "dotenv";
    let mut secret_keys = 0u64;
    let mut values = Map::new();
    let mut sections = Vec::new();
    let mut total = 0usize;
    for s in &doc.sections {
        total += s.entries.len();
        let mut map = Map::new();
        for (k, v) in s.entries.iter().take(MAX_KEYS) {
            let secret = hide && is_secret_key(k);
            secret_keys += u64::from(secret);
            let value = if redact_all || secret {
                json!("[redacted]")
            } else {
                json!(truncate_chars(&cx.redact_sensitive(v), 200))
            };
            map.insert(k.clone(), value);
        }
        if sections.len() < MAX_SECTIONS {
            sections.push(json!({ "name": s.name, "keys": s.entries.len() }));
            let key = if s.name.is_empty() { "(global)".to_string() } else { s.name.clone() };
            values.entry(key).or_insert(Value::Object(map));
        }
    }
    let lookup = |section: &str, key: &str| {
        doc.sections
            .iter()
            .filter(|s| s.name.eq_ignore_ascii_case(section))
            .flat_map(|s| s.entries.iter())
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    };
    match dialect {
        "desktop_entry" => {
            if let Some(n) = lookup("Desktop Entry", "Name") {
                cx.content().source("desktop.Name").title(n);
            }
            if let Some(c) = lookup("Desktop Entry", "Comment") {
                cx.content().source("desktop.Comment").description(c);
            }
            if lookup("Desktop Entry", "Exec").is_some() {
                cx.security().active_content("exec_command");
            }
        }
        "systemd_unit" => {
            if let Some(d) = lookup("Unit", "Description") {
                cx.content().source("systemd.Description").description(d);
            }
        }
        "internet_shortcut" => {
            if let Some(u) = lookup("InternetShortcut", "URL") {
                cx.format_set("target", truncate_chars(&cx.redact_secrets(u), 500));
                cx.security().external_references(1);
            }
        }
        _ => {}
    }
    if secret_keys > 0 || (redact_all && total > 0) {
        cx.format_set("redacted_values", if redact_all { total as u64 } else { secret_keys });
    }
    cx.format_set("dialect", dialect);
    cx.format_set("sections", Value::Array(sections));
    cx.format_set("keys", total);
    if doc.comments > 0 {
        cx.format_set("comment_lines", doc.comments);
    }
    if doc.invalid > 0 {
        cx.format_set("unparsed_lines", doc.invalid);
    }
    cx.format_set("values", Value::Object(values));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsers() {
        let d = ini("; c\nroot=1\n[db]\nhost = localhost\npassword = \"s3cret\"\n");
        assert_eq!(d.sections.len(), 2);
        assert_eq!(d.sections[1].entries[1], ("password".into(), "s3cret".into()));
        let p = properties("a=1\nb : two\nc three \\\n  four\n! comment\n");
        assert_eq!(p.sections[0].entries[2], ("c".into(), "three four".into()));
        let e = dotenv("export A=1\nB='x y' # note\n");
        assert_eq!(e.sections[0].entries[1], ("B".into(), "x y".into()));
    }

    crate::fixture_tests!("ini", "properties", "dotenv");
}
