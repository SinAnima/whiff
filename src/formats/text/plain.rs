//! Plain text (`text`), log files (`log`) and unified diffs / patches (`diff`).
//!
//! `wc` statistics for every text file come from the engine; this extractor
//! adds a title, licence and copyright detection and the body text for the
//! analyzers. Logs get a dialect, level histogram and time range; diffs get
//! files changed, hunks and line counts. Extensionless project files
//! (`README`, `LICENSE`, `COPYING`, `AUTHORS`, `CHANGELOG`, `NEWS` …) are
//! recognised by name and get their kind; change logs also their versions.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};

use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole,
    find_copyright, identify_license, parse_date, redact_secrets, truncate_chars,
};

/// Extractor for plain text, logs and diffs.
pub struct Plain;

static META: ExtractorMeta = ExtractorMeta {
    id: "text.plain",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "text",
            name: "Plain text",
            family: "text.plain",
            mimes: &["text/plain"],
            extensions: &["txt", "text"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "log",
            name: "Log file",
            family: "text.plain",
            mimes: &["text/x-log"],
            extensions: &["log"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "diff",
            name: "Unified diff / patch",
            family: "text.plain",
            mimes: &["text/x-diff"],
            extensions: &["diff", "patch"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

impl Extractor for Plain {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // By name, when the head is text (Chrome's `History` is SQLite).
        let head = &probe.head[..probe.head.len().min(4096)];
        let texty = !head.contains(&0) && std::str::from_utf8(head).is_ok_and(|t| !t.trim().is_empty());
        if texty && probe.name.and_then(project_file).is_some() {
            return Some(Sniff { format: "text", confidence: 0.6 });
        }
        let head = std::str::from_utf8(&probe.head[..probe.head.len().min(4096)]).ok()?;
        let diff = head.starts_with("diff --git ")
            || head.starts_with("Index: ")
            || (head.starts_with("From ") && head.contains("\nSubject: ") && head.contains("\n---"))
            || (head.starts_with("--- ") && head.lines().nth(1).is_some_and(|l| l.starts_with("+++ ")));
        diff.then_some(Sniff { format: "diff", confidence: 0.85 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let decoded = cx.read_text(src)?;
        let text = strip_ansi(&decoded.text);
        if text.len() != decoded.text.len() {
            cx.format_set("ansi_escapes", true);
        }
        match cx.format_id() {
            "log" => log(&text, cx),
            "diff" => diff(&text, cx),
            _ => {
                plain(&text, cx);
                if let Some(kind) = src.name_hint().and_then(project_file) {
                    cx.format_set("document_kind", kind);
                    if kind == "changelog" {
                        changelog(&text, cx);
                    }
                }
            }
        }
        Ok(())
    }
}

crate::register_extractor!(Plain);

fn plain(text: &str, cx: &mut Context<'_>) {
    cx.emit_text(TextRole::Body, text);
    if let Some(title) = title(text) {
        cx.content().title(title);
    }
    if let Some(id) = identify_license(text) {
        cx.rights().license(Some(id), None);
        cx.format_set("license", id);
    }
    if let Some(c) = find_copyright(text) {
        cx.rights().copyright(c);
    }
    let paragraphs = text.split("\n\n").filter(|p| !p.trim().is_empty()).count();
    cx.format_set("paragraphs", paragraphs);
    let urls = text.matches("http://").count() + text.matches("https://").count();
    if urls > 0 {
        cx.format_set("urls", urls);
    }
}

/// The kind of an extensionless project file, from its name (`README`,
/// `LICENSE-MIT`, `COPYING.LESSER` …).
fn project_file(name: &str) -> Option<&'static str> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    // `README`, `License`, `ChangeLog`; lowercase `install` or `history` are
    // usually scripts or databases.
    if !base.starts_with(|c: char| c.is_ascii_uppercase()) {
        return None;
    }
    let upper = base.to_ascii_uppercase();
    let stem = upper.split(['.', '-', '_']).next().unwrap_or("");
    let kind = match stem {
        "README" => "readme",
        "LICENSE" | "LICENCE" | "COPYING" | "UNLICENSE" => "license",
        "AUTHORS" | "CONTRIBUTORS" | "MAINTAINERS" | "CREDITS" | "THANKS" => "authors",
        "CHANGELOG" | "CHANGES" | "NEWS" | "HISTORY" | "RELEASES" => "changelog",
        "CONTRIBUTING" => "contributing",
        "NOTICE" => "notice",
        "INSTALL" => "install",
        "SECURITY" => "security",
        "TODO" => "todo",
        _ => return None,
    };
    // `README.md`, `LICENSE.txt` … belong to their extension's extractor;
    // only `-MIT` / `_old` style suffixes and licence names after a dot stay.
    let rest = &upper[stem.len()..];
    let suffix_ok = match rest.as_bytes().first() {
        None | Some(b'-' | b'_') => true,
        Some(b'.') => matches!(&rest[1..], "LESSER" | "LIB" | "GPL" | "LGPL" | "MIT" | "BSD" | "APACHE" | "OLD"),
        _ => false,
    };
    (suffix_ok && base.chars().all(|c| c.is_ascii_graphic())).then_some(kind)
}

/// Versions in a change log: headings or lines that start with a version
/// (`## [1.2.0] - 2026-01-01`, `v1.2.0 (2026-01-01)`, `1.2.0:`).
fn changelog(text: &str, cx: &mut Context<'_>) {
    static VERSION: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?m)^(?:#{1,3}\s*|\*\s*|Version\s+)?\[?v?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)\]?(?:[\s:,(-]+(\d{4}-\d{2}-\d{2}))?",
        )
        .expect("valid")
    });
    let mut versions: Vec<(String, Option<String>)> = Vec::new();
    for c in VERSION.captures_iter(text).take(1000) {
        let v = c[1].to_string();
        if !versions.iter().any(|(x, _)| *x == v) {
            versions.push((v, c.get(2).map(|d| d.as_str().to_string())));
        }
    }
    let unreleased = text.lines().any(|l| {
        let l = l.trim_start_matches(['#', ' ', '[']).to_ascii_lowercase();
        l.starts_with("unreleased")
    });
    if unreleased {
        cx.format_set("unreleased_section", true);
    }
    let Some((latest, date)) = versions.first() else { return };
    cx.format_set("versions", versions.len());
    cx.format_set("latest_version", latest.as_str());
    if let Some(d) = date {
        cx.format_set("latest_date", d.as_str());
    }
    if let Some((oldest, _)) = versions.last().filter(|_| versions.len() > 1) {
        cx.format_set("oldest_version", oldest.as_str());
    }
}

/// A heading-like first line: underlined (`===` / `---`), or short and
/// followed by a blank line without ending in a full stop.
fn title(text: &str) -> Option<String> {
    let mut lines = text.lines().skip_while(|l| l.trim().is_empty());
    let first = lines.next()?.trim();
    let next = lines.next().map(str::trim);
    let underlined = next.is_some_and(|n| n.len() >= 3 && (n.chars().all(|c| c == '=') || n.chars().all(|c| c == '-')));
    let short = (2..=80).contains(&first.chars().count())
        && next.is_some_and(str::is_empty)
        && !first.ends_with(['.', ',', ';', ':'])
        && first.chars().any(char::is_alphabetic);
    (underlined || short).then(|| first.trim_matches(['#', '=', '*', ' ']).to_string()).filter(|t| !t.is_empty())
}

/// Remove ANSI escape sequences (colours, cursor moves).
fn strip_ansi(text: &str) -> std::borrow::Cow<'_, str> {
    static ANSI: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])").expect("valid")
    });
    ANSI.replace_all(text, "")
}

// --- logs ----------------------------------------------------------------

static LEVEL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?-u:\b)(TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|CRITICAL|CRIT|FATAL|ALERT|EMERG|SEVERE)(?-u:\b)",
    )
    .expect("valid")
});
/// Lower-case levels only count in an unambiguous position: `error:`, `[warn]`, `level=info`.
static LEVEL_LOWER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:\[|level=|(?-u:\b))(trace|debug|info|notice|warn|warning|error|err|critical|crit|fatal|alert|emerg|severe)(?:\]|:)")
        .expect("valid")
});
static ISO_TS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\[?(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d| UTC)?)\]?").expect("valid")
});
static SYSLOG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:<\d+>)?([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (\S+) ([\w./-]+?)(?:\[\d+\])?: ").expect("valid")
});
static CLF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(\S+) \S+ \S+ \[([^\]]+)\] "(\w+) [^"]*?(?: HTTP/[\d.]+)?" (\d{3}) (\d+|-)"#).expect("valid")
});

/// Lines examined in detail; the rest are only counted.
const LOG_SAMPLE_LINES: u64 = 200_000;

#[derive(Default)]
struct LogStats {
    dialects: BTreeMap<&'static str, u64>,
    levels: BTreeMap<String, u64>,
    sources: BTreeMap<String, u64>,
    status: BTreeMap<String, u64>,
    methods: BTreeMap<String, u64>,
    first: Option<(String, bool)>,
    last: Option<(String, bool)>,
    syslog_first: Option<String>,
    syslog_last: Option<String>,
    errors: Vec<String>,
}

impl LogStats {
    fn time(&mut self, raw: &str) {
        if let Some(t) = parse_date(raw) {
            if self.first.is_none() {
                self.first = Some(t.clone());
            }
            self.last = Some(t);
        }
    }

    fn level(&mut self, level: &str, line: &str) {
        let norm = match level.to_ascii_uppercase().as_str() {
            "WARNING" => "WARN".to_string(),
            "ERR" => "ERROR".to_string(),
            "CRIT" => "CRITICAL".to_string(),
            other => other.to_string(),
        };
        if matches!(norm.as_str(), "ERROR" | "CRITICAL" | "FATAL" | "ALERT" | "EMERG" | "SEVERE")
            && self.errors.len() < 5
        {
            self.errors.push(truncate_chars(&redact_secrets(line.trim()), 200));
        }
        *self.levels.entry(norm).or_default() += 1;
    }
}

fn log(text: &str, cx: &mut Context<'_>) {
    let mut s = LogStats::default();
    let mut lines = 0u64;
    for line in text.lines() {
        lines += 1;
        if lines > LOG_SAMPLE_LINES || line.trim().is_empty() {
            continue;
        }
        if line.starts_with('{')
            && let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(line)
        {
            *s.dialects.entry("json_lines").or_default() += 1;
            let get = |keys: &[&str]| keys.iter().find_map(|k| obj.get(*k)).and_then(Value::as_str).map(str::to_string);
            if let Some(t) = get(&["@timestamp", "timestamp", "time", "ts", "date"]) {
                s.time(&t);
            }
            if let Some(l) = get(&["level", "lvl", "severity", "log.level"]) {
                s.level(&l, line);
            }
            continue;
        }
        if let Some(c) = CLF.captures(line) {
            *s.dialects.entry("common_log_format").or_default() += 1;
            s.time(&c[2]);
            *s.status.entry(c[4].to_string()).or_default() += 1;
            *s.methods.entry(c[3].to_string()).or_default() += 1;
            if c[4].starts_with('5') && s.errors.len() < 5 {
                s.errors.push(truncate_chars(&redact_secrets(line), 200));
            }
            continue;
        }
        if let Some(c) = SYSLOG.captures(line) {
            *s.dialects.entry("syslog").or_default() += 1;
            *s.sources.entry(c[3].to_string()).or_default() += 1;
            // BSD syslog timestamps have no year, so they are kept as written.
            if s.syslog_first.is_none() {
                s.syslog_first = Some(c[1].to_string());
            }
            s.syslog_last = Some(c[1].to_string());
        } else if let Some(c) = ISO_TS.captures(line) {
            *s.dialects.entry("timestamped").or_default() += 1;
            s.time(&c[1]);
        }
        if let Some(m) = LEVEL.find(line) {
            s.level(m.as_str(), line);
        } else if let Some(c) = LEVEL_LOWER.captures(line) {
            s.level(&c[1], line);
        }
    }
    cx.emit_text(TextRole::Data, text);
    let dialect = s.dialects.iter().max_by_key(|(_, n)| **n).map_or("unstructured", |(d, _)| *d);
    cx.format_set("dialect", dialect);
    cx.format_set("lines", lines);
    for (key, map) in [("levels", &s.levels), ("http_status", &s.status), ("http_methods", &s.methods)] {
        if !map.is_empty() {
            cx.format_set(key, json!(map));
        }
    }
    if !s.sources.is_empty() {
        let mut top: Vec<(&String, &u64)> = s.sources.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        let top: Vec<Value> = top.into_iter().take(10).map(|(k, n)| json!({ "source": k, "lines": n })).collect();
        cx.format_set("top_sources", top);
    }
    if !s.errors.is_empty() {
        cx.format_set("sample_errors", s.errors.clone());
    }
    if let Some((first, tz)) = s.first.clone() {
        cx.format_set("first_timestamp", first.clone());
        cx.temporal().source("log.first_timestamp").content_date(DateField::Created, first, tz);
    }
    if let Some((last, tz)) = s.last {
        cx.format_set("last_timestamp", last.clone());
        cx.temporal().source("log.last_timestamp").content_date(DateField::Modified, last, tz);
    }
    if let (Some(first), Some(last)) = (s.syslog_first.take(), s.syslog_last.take())
        && s.first.is_none()
    {
        cx.format_set("time_range_without_year", json!([first, last]));
    }
    if lines > LOG_SAMPLE_LINES {
        cx.format_set("lines_examined", LOG_SAMPLE_LINES);
    }
}

// --- diffs -----------------------------------------------------------------

#[derive(Default)]
struct FileDiff {
    path: String,
    status: &'static str,
    additions: u64,
    deletions: u64,
}

fn diff(text: &str, cx: &mut Context<'_>) {
    let mut files: Vec<FileDiff> = Vec::new();
    let mut hunks = 0u64;
    // Lines left in the current hunk (old side, new side), from `@@ -a,b +c,d @@`.
    let (mut old_left, mut new_left) = (0u64, 0u64);
    // After `diff --git`, the `---`/`+++` lines belong to that file.
    let mut git_header = false;
    let mut in_header = text.starts_with("From ");
    let mut message = Vec::new();
    for line in text.lines() {
        if in_header {
            in_header = patch_header(line, &mut message, cx);
            if in_header {
                continue;
            }
        }
        if old_left > 0 || new_left > 0 {
            match line.as_bytes().first() {
                Some(b'+') => {
                    new_left = new_left.saturating_sub(1);
                    if let Some(f) = files.last_mut() {
                        f.additions += 1;
                    }
                }
                Some(b'-') => {
                    old_left = old_left.saturating_sub(1);
                    if let Some(f) = files.last_mut() {
                        f.deletions += 1;
                    }
                }
                Some(b'\\') => {}
                _ => {
                    old_left = old_left.saturating_sub(1);
                    new_left = new_left.saturating_sub(1);
                }
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("diff --git ") {
            let path = rest.split_once(" b/").map_or(rest, |(_, b)| b);
            files.push(FileDiff { path: path.to_string(), status: "modified", ..FileDiff::default() });
            git_header = true;
        } else if let Some(old) = line.strip_prefix("--- ") {
            if !git_header {
                files.push(FileDiff { status: "modified", ..FileDiff::default() });
            }
            if let Some(f) = files.last_mut() {
                if old.starts_with("/dev/null") {
                    f.status = "added";
                } else if f.path.is_empty() {
                    f.path = clean_path(old, "a/");
                }
            }
        } else if let Some(new) = line.strip_prefix("+++ ") {
            if let Some(f) = files.last_mut() {
                if new.starts_with("/dev/null") {
                    f.status = "deleted";
                } else {
                    f.path = clean_path(new, "b/");
                }
            }
        } else if let Some(f) = files.last_mut().filter(|_| git_header) {
            if line.starts_with("new file mode") {
                f.status = "added";
            } else if line.starts_with("deleted file mode") {
                f.status = "deleted";
            } else if line.starts_with("rename from ") {
                f.status = "renamed";
            }
        }
        if let Some(range) = line.strip_prefix("@@ ") {
            hunks += 1;
            git_header = false;
            let count = |side: &str| side.split_once(',').map_or(Some(1), |(_, n)| n.parse().ok()).unwrap_or(0);
            let mut sides = range.split_whitespace();
            old_left = sides.next().map_or(0, count);
            new_left = sides.next().map_or(0, count);
        }
    }
    let message = message.join("\n");
    if !message.trim().is_empty() {
        cx.emit_text(TextRole::Body, message.trim());
    }
    cx.emit_text(TextRole::Code, text);
    cx.format_set("files_changed", files.len());
    cx.format_set("hunks", hunks);
    cx.format_set("additions", files.iter().map(|f| f.additions).sum::<u64>());
    cx.format_set("deletions", files.iter().map(|f| f.deletions).sum::<u64>());
    let list: Vec<Value> = files
        .iter()
        .take(100)
        .map(|f| json!({ "path": f.path, "status": f.status, "additions": f.additions, "deletions": f.deletions }))
        .collect();
    cx.format_set("files", list);
}

/// One line of a `git format-patch` mail header; `false` once the header ends.
fn patch_header<'t>(line: &'t str, message: &mut Vec<&'t str>, cx: &mut Context<'_>) -> bool {
    if let Some(v) = line.strip_prefix("From: ") {
        cx.content().source("diff.From").author(strip_email(v));
    } else if let Some(v) = line.strip_prefix("Subject: ") {
        let subject = v.split_once("] ").map_or(v, |(_, s)| s).trim();
        cx.content().source("diff.Subject").title(subject);
    } else if let Some(v) = line.strip_prefix("Date: ") {
        if let Some((d, tz)) = parse_date(v) {
            cx.temporal().source("diff.Date").content_date(DateField::Created, d, tz);
        }
    } else if line == "---" || line.starts_with("diff --git ") {
        return false;
    } else if !line.starts_with("From ") {
        message.push(line);
    }
    true
}

/// `b/src/main.rs\t2026-01-01 …` → `src/main.rs`.
fn clean_path(p: &str, prefix: &str) -> String {
    let p = p.split('\t').next().unwrap_or(p).trim();
    p.strip_prefix(prefix).unwrap_or(p).to_string()
}

/// `Ada Lovelace <ada@example.org>` → `Ada Lovelace`.
fn strip_email(v: &str) -> &str {
    v.split('<').next().unwrap_or(v).trim().trim_matches('"')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles() {
        assert_eq!(title("Release notes\n=============\n\nText.").as_deref(), Some("Release notes"));
        assert_eq!(title("Harbour Guide\n\nBoats arrive at dusk.").as_deref(), Some("Harbour Guide"));
        assert_eq!(title("This is a sentence.\n\nMore."), None);
        assert_eq!(title("one line only"), None);
    }

    #[test]
    fn paths() {
        assert_eq!(clean_path("b/src/main.rs\t2026-01-01", "b/"), "src/main.rs");
        assert_eq!(strip_email("\"Ada Lovelace\" <ada@example.org>"), "Ada Lovelace");
    }

    #[test]
    fn project_files() {
        assert_eq!(project_file("README"), Some("readme"));
        assert_eq!(project_file("dir/LICENSE-MIT"), Some("license"));
        assert_eq!(project_file("COPYING.LESSER"), Some("license"));
        assert_eq!(project_file("ChangeLog"), Some("changelog"));
        assert_eq!(project_file("README.md"), None);
        assert_eq!(project_file("Readme me"), None);
        assert_eq!(project_file("Readme_notes"), Some("readme"));
        assert_eq!(project_file("install"), None);
        assert_eq!(project_file("README.pdf"), None);
        assert_eq!(project_file("Makefile"), None);
    }

    #[test]
    fn ansi() {
        assert_eq!(strip_ansi("\x1b[31mred\x1b[0m text"), "red text");
    }

    crate::fixture_tests!("text", "log", "diff");
}
