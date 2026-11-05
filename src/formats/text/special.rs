//! Plain-text files with a known layout:
//! * NFO / DIZ release notes and ANSI art (`.nfo`, `.diz`, `.ans`): code
//!   page 437 unless the text is UTF-8, ANSI escapes, box-drawing art, the
//!   `Key: value` release fields, and the SAUCE record (title, author,
//!   group, date, data and file type, width, height, font);
//! * hosts files: entries, addresses, blocked names (an ad-block list);
//! * `CODEOWNERS`: rules, owners by kind (users, teams, e-mail
//!   addresses), the default rule;
//! * Vim swap files: Vim version, the file being edited, whether it had
//!   unsaved changes, file format, time, process (user and host only when
//!   privacy is off);
//! * Kindle `My Clippings.txt`: highlights, notes and bookmarks, books,
//!   date range, and the highlighted text;
//! * GNU info files: makeinfo version, source, nodes, directory entries.
//!
//! Specifications: SAUCE 00.5 (<https://www.acid.org/info/sauce/sauce.htm>),
//! hosts(5), GitHub docs "About code owners", Vim `src/memline.c`
//! (`struct block0`), GNU Texinfo manual "Info Format Specification".

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    TextRole, decode_cp437, parse_date, truncate_chars, user_path,
};

/// Extractor for NFO files, hosts files and `CODEOWNERS`.
pub struct Special;

static META: ExtractorMeta = ExtractorMeta {
    id: "text.special",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "nfo",
            name: "NFO / DIZ info file (ANSI art)",
            family: "text.plain",
            mimes: &["text/x-nfo"],
            extensions: &["nfo", "diz", "ans"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "hosts",
            name: "Hosts file",
            family: "text.plain",
            mimes: &["text/plain"],
            extensions: &[],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "codeowners",
            name: "CODEOWNERS",
            family: "text.plain",
            mimes: &["text/plain"],
            extensions: &[],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "vim_swap",
            name: "Vim swap file",
            family: "text.plain",
            mimes: &["application/x-vim-swap"],
            extensions: &["swp", "swo", "swn"],
            magic: &[Magic::prefix(b"b0VIM ")],
            parent: None,
        },
        FormatSpec {
            id: "kindle_clippings",
            name: "Kindle clippings",
            family: "text.plain",
            mimes: &["text/plain"],
            extensions: &[],
            magic: &[],
            parent: Some("text"),
        },
        // `.info` is also an LCOV tracefile: sniffed.
        FormatSpec {
            id: "gnu_info",
            name: "GNU info",
            family: "text.plain",
            mimes: &["application/x-info"],
            extensions: &[],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

impl Extractor for Special {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let name = probe.name?;
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
        let format = match base {
            "hosts" => "hosts",
            "CODEOWNERS" => "codeowners",
            "My Clippings.txt" => "kindle_clippings",
            _ if matches!(probe.extension, None | Some("info")) => {
                let head = &probe.head[..probe.head.len().min(4096)];
                let info = head.starts_with(b"This is ") && find(head, b"produced by makeinfo").is_some()
                    || find(head, b"\x1f\nFile: ").is_some_and(|_| find(head, b"Node: ").is_some());
                return info.then_some(Sniff { format: "gnu_info", confidence: 0.9 });
            }
            _ => return None,
        };
        Some(Sniff { format, confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let id = cx.format_id().to_string();
        if id == "nfo" || id == "vim_swap" {
            let (bytes, _) = cx.read_bytes(src)?;
            if id == "nfo" {
                nfo(&bytes, cx);
            } else {
                vim_swap(&bytes, cx);
            }
            return Ok(());
        }
        let text = cx.read_text(src)?.text;
        match id.as_str() {
            "hosts" => {
                cx.emit_text(TextRole::Data, &text);
                hosts(&text, cx);
            }
            "codeowners" => {
                cx.emit_text(TextRole::Data, &text);
                codeowners(&text, cx);
            }
            "kindle_clippings" => clippings(&text, cx),
            _ => info(&text, cx),
        }
        Ok(())
    }
}

crate::register_extractor!(Special);

// --- NFO / ANSI art --------------------------------------------------------

/// A SAUCE record: the 128 bytes at the end of the file.
struct Sauce {
    title: String,
    author: String,
    group: String,
    date: String,
    data_type: u8,
    file_type: u8,
    tinfo: [u16; 4],
    comments: u8,
    flags: u8,
    font: String,
}

fn sauce(bytes: &[u8]) -> Option<(Sauce, usize)> {
    let at = bytes.len().checked_sub(128)?;
    let r = &bytes[at..];
    if &r[..7] != b"SAUCE00" {
        return None;
    }
    let field = |a: usize, b: usize| decode_cp437(&r[a..b]).trim_end_matches([' ', '\0']).trim().to_string();
    let u16_at = |o: usize| u16::from_le_bytes([r[o], r[o + 1]]);
    let s = Sauce {
        title: field(7, 42),
        author: field(42, 62),
        group: field(62, 82),
        date: field(82, 90),
        data_type: r[94],
        file_type: r[95],
        tinfo: [u16_at(96), u16_at(98), u16_at(100), u16_at(102)],
        comments: r[104],
        flags: r[105],
        font: field(106, 128),
    };
    // The comment block (`COMNT` + 64 bytes a line) and the EOF mark precede it.
    let mut start = at;
    let block = 5 + 64 * usize::from(s.comments);
    if s.comments > 0 && at >= block && &bytes[at - block..at - block + 5] == b"COMNT" {
        start = at - block;
    }
    if start > 0 && bytes[start - 1] == 0x1a {
        start -= 1;
    }
    Some((s, start))
}

const CHARACTER_TYPES: [&str; 9] =
    ["ASCII", "ANSi", "ANSiMation", "RIP script", "PCBoard", "Avatar", "HTML", "Source", "TundraDraw"];

fn report_sauce(s: &Sauce, cx: &mut Context<'_>) {
    let mut m = Map::new();
    for (k, v) in [("title", &s.title), ("author", &s.author), ("group", &s.group)] {
        if !v.is_empty() {
            m.insert(k.into(), json!(v));
        }
    }
    if !s.title.is_empty() {
        cx.content().title(s.title.clone());
    }
    if !s.author.is_empty() {
        cx.content().author(s.author.clone());
    }
    if s.date.len() == 8 && s.date.bytes().all(|b| b.is_ascii_digit()) {
        let d = format!("{}-{}-{}", &s.date[..4], &s.date[4..6], &s.date[6..]);
        cx.temporal().content_date(DateField::Created, d.clone(), false);
        m.insert("date".into(), json!(d));
    }
    let data_type = match s.data_type {
        0 => "none",
        1 => "character",
        2 => "bitmap",
        3 => "vector",
        4 => "audio",
        5 => "binary text",
        6 => "XBin",
        7 => "archive",
        8 => "executable",
        _ => "unknown",
    };
    m.insert("data_type".into(), json!(data_type));
    if s.data_type == 1 {
        if let Some(t) = CHARACTER_TYPES.get(usize::from(s.file_type)) {
            m.insert("file_type".into(), json!(t));
        }
        // ASCII, ANSi and ANSiMation give width and height in characters.
        if s.file_type <= 2 {
            for (k, v) in [("width", s.tinfo[0]), ("height", s.tinfo[1])] {
                if v > 0 {
                    m.insert(k.into(), json!(v));
                }
            }
            if s.flags & 1 != 0 {
                m.insert("ice_colors".into(), json!(true));
            }
        }
    }
    if !s.font.is_empty() {
        m.insert("font".into(), json!(s.font));
    }
    if s.comments > 0 {
        m.insert("comment_lines".into(), json!(s.comments));
    }
    cx.format_set("sauce", Value::Object(m));
}

/// Release fields worth keeping (`Release Date ..: 2026-01-01`), by the
/// lowercase key with dots, colons and runs of spaces removed.
const NFO_KEYS: [&str; 24] = [
    "title",
    "release",
    "release name",
    "release date",
    "date",
    "artist",
    "album",
    "genre",
    "year",
    "label",
    "size",
    "format",
    "source",
    "language",
    "runtime",
    "length",
    "platform",
    "publisher",
    "developer",
    "group",
    "supplier",
    "protection",
    "version",
    "url",
];

fn nfo_fields(text: &str) -> Map<String, Value> {
    let mut out = Map::new();
    for line in text.lines().take(2000) {
        let line = line.trim_matches(|c: char| c.is_whitespace() || !(c.is_ascii() || c.is_alphanumeric()));
        let Some(i) = line.find([':', '.']) else { continue };
        let key: String = line[..i].split_whitespace().collect::<Vec<_>>().join(" ").to_ascii_lowercase();
        let value = line[i..].trim_start_matches([':', '.', ' ', '\t']).trim();
        if value.is_empty() || out.len() >= 20 {
            continue;
        }
        if let Some(k) = NFO_KEYS.iter().find(|k| **k == key) {
            out.entry((*k).replace(' ', "_")).or_insert_with(|| json!(truncate_chars(value, 200)));
        }
    }
    out
}

fn nfo(bytes: &[u8], cx: &mut Context<'_>) {
    let (record, end) = sauce(bytes).map_or((None, bytes.len()), |(s, at)| (Some(s), at));
    let body = &bytes[..end];
    let body = body.iter().position(|&b| b == 0x1a).map_or(body, |i| &body[..i]);
    let (text, encoding) = match std::str::from_utf8(body) {
        Ok(t) => (t.to_string(), if body.is_ascii() { "us-ascii" } else { "utf-8" }),
        Err(_) => (decode_cp437(body), "cp437"),
    };
    cx.format_set("encoding", encoding);
    let plain = strip_ansi(&text);
    if plain.len() != text.len() {
        cx.format_set("ansi_escapes", true);
    }
    let art = plain.chars().filter(|c| matches!(c, '\u{2500}'..='\u{259f}')).count();
    if art > 0 {
        cx.format_set("box_drawing_chars", art);
    }
    let lines = plain.lines().count();
    let width = plain.lines().map(|l| l.chars().count()).max().unwrap_or(0);
    cx.format_set("lines", lines);
    cx.format_set("max_width", width);
    let fields = nfo_fields(&plain);
    if let Some(t) = fields.get("title").or_else(|| fields.get("release")).and_then(Value::as_str) {
        cx.content().source("nfo").title(t);
    }
    if !fields.is_empty() {
        cx.format_set("fields", Value::Object(fields));
    }
    if let Some(s) = &record {
        report_sauce(s, cx);
    }
    // Prose without the art: the lines that hold letters.
    let prose: Vec<&str> = plain
        .lines()
        .map(str::trim)
        .filter(|l| l.chars().filter(|c| c.is_alphanumeric()).count() * 2 > l.chars().count())
        .collect();
    cx.emit_text(TextRole::Body, &prose.join("\n"));
}

/// ANSI escape sequences (CSI and the two-byte forms) removed.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        if chars.next_if_eq(&'[').is_some() {
            for n in chars.by_ref() {
                if ('@'..='~').contains(&n) {
                    break;
                }
            }
        } else {
            chars.next();
        }
    }
    out
}

// --- hosts -----------------------------------------------------------------

fn hosts(text: &str, cx: &mut Context<'_>) {
    let (mut entries, mut names, mut blocked) = (0u64, BTreeSet::new(), 0u64);
    let mut addresses: BTreeMap<&str, u64> = BTreeMap::new();
    let (mut v4, mut v6) = (0u64, 0u64);
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut words = line.split_whitespace();
        let Some(addr) = words.next() else { continue };
        if addr.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        if addr.contains(':') {
            v6 += 1;
        } else {
            v4 += 1;
        }
        let sink = matches!(addr, "0.0.0.0" | "127.0.0.1" | "::" | "::1" | "0:0:0:0:0:0:0:0");
        for name in words {
            entries += 1;
            let local = matches!(name, "localhost" | "localhost.localdomain" | "broadcasthost" | "local")
                || name.starts_with("ip6-");
            if sink && !local {
                blocked += 1;
            }
            if names.len() < 1_000_000 {
                names.insert(name.to_ascii_lowercase());
            }
        }
        if addresses.len() < 10_000 {
            *addresses.entry(addr).or_default() += 1;
        }
    }
    cx.format_set("entries", entries);
    cx.format_set("names", names.len());
    cx.format_set("addresses", addresses.len());
    cx.format_set("ip_versions", json!({ "ipv4": v4, "ipv6": v6 }));
    if blocked > 0 {
        cx.format_set("blocked_names", blocked);
    }
    // Thousands of names pointed at 0.0.0.0: an ad-block or malware list.
    cx.format_set("blocklist", blocked >= 100 && blocked * 2 >= entries);
}

// --- CODEOWNERS ------------------------------------------------------------

fn codeowners(text: &str, cx: &mut Context<'_>) {
    let (mut rules, mut unowned, mut default_rule) = (0u64, 0u64, false);
    let (mut users, mut teams, mut emails) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    let mut sections = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // GitLab sections: `[Section name]`, `^[Optional]`.
        if line.starts_with('[') || line.starts_with("^[") {
            if sections.len() < 50 {
                let name = line.trim_start_matches('^').trim_start_matches('[');
                sections.push(truncate_chars(name.split(']').next().unwrap_or(name), 100));
            }
            continue;
        }
        let mut words = line.split_whitespace();
        let Some(pattern) = words.next() else { continue };
        rules += 1;
        default_rule |= pattern == "*";
        let mut owned = false;
        for owner in words.take_while(|w| !w.starts_with('#')) {
            owned = true;
            if owner.contains('@') && !owner.starts_with('@') {
                emails.insert(owner.to_ascii_lowercase());
            } else if owner.contains('/') {
                teams.insert(owner.to_string());
            } else {
                users.insert(owner.to_ascii_lowercase());
            }
        }
        if !owned {
            unowned += 1;
        }
    }
    cx.format_set("rules", rules);
    cx.format_set("default_rule", default_rule);
    if unowned > 0 {
        cx.format_set("unowned_rules", unowned);
    }
    // Team handles name an organisation, not a person; users and
    // addresses are only counted.
    cx.format_set("owners", json!({ "users": users.len(), "teams": teams.len(), "emails": emails.len() }));
    if !teams.is_empty() {
        cx.format_set("teams", json!(teams.iter().take(50).collect::<Vec<_>>()));
    }
    if !sections.is_empty() {
        cx.format_set("sections", json!(sections));
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

// --- Vim swap files --------------------------------------------------------

fn vim_swap(b: &[u8], cx: &mut Context<'_>) {
    // `struct block0`: id, version, page size, mtime, inode, pid (each
    // four bytes, least significant first), user, host, file name.
    let field = |a: usize, n: usize| -> String {
        let s = b.get(a..(a + n).min(b.len())).unwrap_or(&[]);
        let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
        String::from_utf8_lossy(&s[..end]).into_owned()
    };
    let num = |a: usize| b.get(a..a + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]));
    cx.format_set("vim_version", field(2, 10).trim_start_matches("VIM ").trim());
    if let Some(p) = num(12) {
        cx.format_set("page_size", p);
    }
    if let Some(t) = num(16).and_then(|t| super::unix_time(i64::from(t))) {
        cx.temporal().content_date(DateField::Modified, t, true);
    }
    let fname = field(108, 900);
    if !fname.is_empty() {
        cx.format_set("file", user_path(cx, &fname));
    }
    if !cx.privacy_strict() {
        cx.format_set("user", field(28, 40));
        cx.format_set("host", field(68, 40));
        if let Some(pid) = num(24) {
            cx.format_set("pid", pid);
        }
    }
    // The last two bytes of the file-name field: flags, then the dirty mark.
    if let (Some(&flags), Some(&dirty)) = (b.get(108 + 898), b.get(108 + 899)) {
        cx.format_set("modified", dirty == 0x55);
        if flags != 0 {
            let ff = match flags & 3 {
                1 => Some("unix"),
                2 => Some("dos"),
                3 => Some("mac"),
                _ => None,
            };
            if let Some(f) = ff {
                cx.format_set("fileformat", f);
            }
            cx.format_set("same_dir", flags & 4 != 0);
        }
    }
}

// --- Kindle clippings ------------------------------------------------------

fn clippings(text: &str, cx: &mut Context<'_>) {
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let mut books: BTreeMap<String, u64> = BTreeMap::new();
    let mut dates: BTreeSet<String> = BTreeSet::new();
    let mut body = String::new();
    let mut entries = 0u64;
    for entry in text.split("==========") {
        let mut lines = entry.lines().map(str::trim).skip_while(|l| l.is_empty());
        let (Some(title), Some(meta)) = (lines.next(), lines.next()) else { continue };
        let Some(meta) = meta.strip_prefix("- ") else { continue };
        entries += 1;
        let title = title.trim_start_matches('\u{feff}');
        if books.len() < 10_000 {
            *books.entry(truncate_chars(title, 300)).or_default() += 1;
        }
        // `Your Highlight on page 12 | Location 100-101 | Added on …`.
        let kind = meta.split_whitespace().nth(1).unwrap_or("").to_ascii_lowercase();
        *kinds.entry(kind).or_default() += 1;
        // `Added on Wednesday, 5 November 2025 08:12:40`: the date without the day name and time.
        if let Some(added) = meta.rsplit('|').next().and_then(|p| p.trim().strip_prefix("Added on")) {
            let date = added.split_once(", ").map_or(added, |(_, r)| r);
            let words: Vec<&str> = date.split_whitespace().collect();
            let day = words.iter().take_while(|w| !w.contains(':')).copied().collect::<Vec<_>>().join(" ");
            if let Some((d, _)) = parse_date(&day) {
                dates.insert(d);
            }
        }
        let quote: Vec<&str> = lines.filter(|l| !l.is_empty()).collect();
        if !quote.is_empty() && body.len() < 4 << 20 {
            body.push_str(&quote.join(" "));
            body.push_str("\n\n");
        }
    }
    cx.emit_text(TextRole::Body, &body);
    cx.format_set("entries", entries);
    cx.format_set("kinds", json!(kinds));
    cx.format_set("books", books.len());
    let mut top: Vec<_> = books.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let top: Map<String, Value> = top.into_iter().take(20).map(|(k, n)| (k, json!(n))).collect();
    cx.format_set("top_books", Value::Object(top));
    if let (Some(a), Some(z)) = (dates.first(), dates.last()) {
        cx.format_set("added", json!({ "first": a, "last": z }));
    }
}

// --- GNU info --------------------------------------------------------------

fn info(text: &str, cx: &mut Context<'_>) {
    // `This is grep.info, produced by makeinfo version 7.1 from grep.texi.`,
    // wrapped over two lines.
    let first: String = text.split("\n\n").next().unwrap_or("").split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(rest) = first.strip_prefix("This is ") {
        let (file, rest) = rest.split_once(", produced by makeinfo version ").unwrap_or((rest, ""));
        cx.format_set("file", file.trim());
        let (version, source) = rest.split_once(" from ").unwrap_or((rest, ""));
        if !version.is_empty() {
            cx.format_set("makeinfo_version", version.trim());
        }
        if !source.is_empty() {
            cx.format_set("source", source.trim().trim_end_matches('.'));
        }
    }
    let mut nodes = Vec::new();
    let (mut dir_section, mut dir_entries, mut in_dir) = (None, 0u64, false);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("INFO-DIR-SECTION ") {
            dir_section.get_or_insert_with(|| rest.trim().to_string());
        } else if line.starts_with("START-INFO-DIR-ENTRY") {
            in_dir = true;
        } else if line.starts_with("END-INFO-DIR-ENTRY") {
            in_dir = false;
        } else if in_dir && line.starts_with('*') {
            dir_entries += 1;
        } else if let Some(at) = line.find("Node: ").filter(|_| line.starts_with("File: "))
            && nodes.len() < 5000
        {
            let n = line[at + 6..].split(',').next().unwrap_or("").trim();
            nodes.push(truncate_chars(n, 200));
        }
    }
    cx.format_set("nodes", nodes.len());
    cx.format_set("has_top_node", nodes.iter().any(|n| n == "Top"));
    if text.contains("\x1f\nTag Table:") {
        cx.format_set("tag_table", true);
    }
    if text.contains("\x1f\nIndirect:") {
        cx.format_set("split", true);
    }
    if let Some(s) = dir_section {
        cx.format_set("dir_section", s);
    }
    if dir_entries > 0 {
        cx.format_set("dir_entries", dir_entries);
    }
    // The prose: node bodies without the node header lines.
    let body: String = text
        .split('\x1f')
        .skip(1)
        .filter_map(|n| n.split_once('\n').map(|(_, rest)| rest))
        .filter_map(|n| n.split_once('\n').map(|(_, rest)| rest))
        .collect::<Vec<_>>()
        .join("\n");
    cx.emit_text(TextRole::Body, &body);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sauce_record() {
        let mut f = b"HELLO\x1a".to_vec();
        let mut r = b"SAUCE00".to_vec();
        r.extend(format!("{:<35}{:<20}{:<20}20260105", "Harbour Lights", "Ada", "Saltmere").as_bytes());
        r.extend(6u32.to_le_bytes());
        r.extend([1, 1]);
        r.extend([80, 0, 25, 0, 0, 0, 0, 0]);
        r.extend([0, 1]);
        r.extend(b"IBM VGA\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        f.extend(&r);
        let (s, start) = sauce(&f).unwrap();
        assert_eq!((s.title.as_str(), s.author.as_str(), s.group.as_str()), ("Harbour Lights", "Ada", "Saltmere"));
        assert_eq!((s.date.as_str(), s.tinfo[0], s.tinfo[1], s.font.as_str()), ("20260105", 80, 25, "IBM VGA"));
        assert_eq!(start, 5);
    }

    #[test]
    fn fields_and_ansi() {
        let f = nfo_fields("  Release Date ....: 2026-01-05\n  Size : 3 x 4.7GB\n Nothing here");
        assert_eq!(f["release_date"], "2026-01-05");
        assert_eq!(f["size"], "3 x 4.7GB");
        assert_eq!(strip_ansi("\u{1b}[1;31mred\u{1b}[0m!"), "red!");
    }

    #[test]
    fn info_sniff() {
        let probe =
            |head: &'static [u8]| Probe { head, tail: &[], len: 0, name: Some("grep.info"), extension: Some("info") };
        assert!(
            Special.sniff(&probe(b"This is grep.info, produced by makeinfo version 7.1 from grep.texi.\n")).is_some()
        );
        assert!(Special.sniff(&probe(b"TN:\nSF:/src/a.c\n")).is_none());
    }

    crate::fixture_tests!("nfo", "hosts", "codeowners", "vim_swap", "kindle_clippings", "gnu_info");
}
