//! Lightweight markup other than Markdown: reStructuredText, `AsciiDoc`,
//! Org, Textile, `MediaWiki`, Perl POD, roff (man, mdoc, ms, me), Texinfo,
//! Creole, `DokuWiki`, Djot and Gemtext.
//!
//! Each is read line by line (no recursion): the title and document
//! fields (authors, date, version, language, keywords), the outline,
//! links (internal and external, top hosts), images, code blocks by
//! language, tables, included files, and what is special to the format:
//! reST directives, `AsciiDoc` attributes and admonitions, Org TODO states,
//! tags and timestamps, wiki templates and categories, man page name and
//! section, Texinfo nodes.
//!
//! Specifications: Docutils "reStructuredText Markup Specification";
//! "`AsciiDoc` Language Documentation"; "Org Syntax"; Textile 2 reference;
//! `MediaWiki` "Help:Wikitext"; perlpodspec; `groff_man`(7), mdoc(7),
//! `groff_ms`(7); GNU Texinfo manual; Creole 1.0; `DokuWiki` "syntax"; Djot
//! syntax reference; Gemini protocol specification §5 (text/gemini).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

use super::url_host;
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole,
    find_copyright, identify_license, parse_date, truncate_chars,
};

/// Extractor for lightweight markup languages.
pub struct LightMarkup;

macro_rules! formats {
    ($( $id:literal $name:literal $mime:literal [$($ext:literal),*] )*) => {
        &[$(FormatSpec {
            id: $id, name: $name, family: "text.lightmarkup", mimes: &[$mime], extensions: &[$($ext),*],
            magic: &[], parent: Some("text"),
        }),*]
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "text.lightmarkup",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    // `.asc` (AsciiDoc or an armoured OpenPGP block) and the numbered man
    // page extensions (`.1` … `.9`) are sniffed.
    formats: formats! {
        "rst" "reStructuredText" "text/x-rst" ["rst", "rest"]
        "asciidoc" "AsciiDoc" "text/x-asciidoc" ["adoc", "asciidoc"]
        "org" "Org-mode" "text/x-org" ["org"]
        "textile" "Textile" "text/x-textile" ["textile"]
        "mediawiki" "MediaWiki markup" "text/x-wiki" ["wiki", "mediawiki", "wikitext"]
        "pod" "Perl POD" "text/x-pod" ["pod"]
        "roff" "troff / man page" "text/troff" ["man", "mdoc", "ms", "me", "roff"]
        "texinfo" "Texinfo" "application/x-texinfo" ["texi", "texinfo", "txi"]
        "creole" "Creole" "text/x-creole" ["creole"]
        "dokuwiki" "DokuWiki" "text/x-dokuwiki" ["dokuwiki"]
        "djot" "Djot" "text/x-djot" ["dj", "djot"]
        "gemtext" "Gemtext" "text/gemini" ["gmi", "gemini"]
    },
};

impl Extractor for LightMarkup {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let ext = probe.extension?;
        let head = std::str::from_utf8(&probe.head[..probe.head.len().min(4096)])
            .or_else(|e| std::str::from_utf8(&probe.head[..e.valid_up_to()]))
            .ok()?;
        let first = head.lines().map(str::trim_end).find(|l| !l.is_empty() && !l.starts_with("//"))?;
        let format = match ext {
            "asc" if first.starts_with("= ") || (first.starts_with(':') && first[1..].contains(": ")) => "asciidoc",
            // `ls.1`, `printf.3p`, `ssl.7ssl`.
            e if e.starts_with(|c: char| c.is_ascii_digit() && c != '0')
                && e.len() <= 6
                && e[1..].chars().all(|c| c.is_ascii_alphabetic()) =>
            {
                let roff = head.lines().take(40).any(|l| {
                    l.starts_with(".TH ") || l.starts_with(".Dd") || l.starts_with(".Dt ") || l.starts_with(".so ")
                }) || first.starts_with(".\\\"")
                    || first.starts_with("'\\\"");
                if !roff {
                    return None;
                }
                "roff"
            }
            _ => return None,
        };
        Some(Sniff { format, confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        let mut d = Doc::default();
        match cx.format_id() {
            "rst" => rst(&text, &mut d),
            "asciidoc" => asciidoc(&text, &mut d),
            "org" => org(&text, &mut d),
            "textile" => textile(&text, &mut d),
            "mediawiki" => {
                mediawiki(&text, &mut d);
                // A page's title is its name, not its first heading.
                let stem = src.name_hint().and_then(|n| n.rsplit(['/', '\\']).next()).and_then(|n| n.rsplit_once('.'));
                d.title = stem.map(|(s, _)| s.replace('_', " ")).filter(|s| !s.is_empty());
            }
            "pod" => pod(&text, &mut d),
            "roff" => roff(&text, &mut d),
            "texinfo" => texinfo(&text, &mut d),
            "creole" => wiki_lines(&text, &mut d, false),
            "dokuwiki" => wiki_lines(&text, &mut d, true),
            "djot" => djot(&text, &mut d),
            _ => gemtext(&text, &mut d),
        }
        cx.checkpoint()?;
        if let Some(c) = find_copyright(&text) {
            cx.rights().copyright(c);
        }
        if let Some(id) = identify_license(&text) {
            cx.rights().license(Some(id), None);
        }
        d.report(cx);
        Ok(())
    }
}

crate::register_extractor!(LightMarkup);

/// What a document holds, filled by the per-format scanners.
#[derive(Default)]
struct Doc {
    title: Option<String>,
    subtitle: Option<String>,
    description: Option<String>,
    authors: Vec<String>,
    date: Option<String>,
    version: Option<String>,
    language: Option<String>,
    keywords: Vec<String>,
    headings: Vec<(u8, String)>,
    links_internal: u64,
    links_external: u64,
    hosts: BTreeMap<String, u64>,
    images: u64,
    code_blocks: u64,
    languages: BTreeMap<String, u64>,
    tables: u64,
    includes: Vec<String>,
    prose: String,
    /// Format-specific fields.
    m: Map<String, Value>,
}

impl Doc {
    fn heading(&mut self, level: u8, text: &str) {
        let t = clean_inline(text);
        if !t.is_empty() && self.headings.len() < 2000 {
            self.headings.push((level.clamp(1, 6), truncate_chars(&t, 300)));
        }
    }
    fn link(&mut self, target: &str) {
        let target = target.trim();
        if let Some(host) = url_host(target) {
            self.links_external += 1;
            if self.hosts.len() < 1000 {
                *self.hosts.entry(host).or_default() += 1;
            }
        } else if !target.is_empty() {
            self.links_internal += 1;
        }
    }
    fn code(&mut self, lang: Option<&str>) {
        self.code_blocks += 1;
        if let Some(l) = lang.map(str::trim).filter(|l| !l.is_empty() && l.len() <= 40)
            && self.languages.len() < 100
        {
            *self.languages.entry(l.to_ascii_lowercase()).or_default() += 1;
        }
    }
    fn include(&mut self, path: &str) {
        let p = path.trim();
        if !p.is_empty() && self.includes.len() < 200 {
            self.includes.push(truncate_chars(p, 300));
        }
    }
    fn author(&mut self, name: &str) {
        let n = name.split('<').next().unwrap_or(name).trim().trim_matches(['"', ',', ';']).trim();
        if !n.is_empty() && !n.contains('@') && self.authors.len() < 50 && !self.authors.iter().any(|a| a == n) {
            self.authors.push(truncate_chars(n, 200));
        }
    }
    fn prose(&mut self, line: &str) {
        if self.prose.len() < 4 << 20 {
            let t = clean_inline(line);
            if !t.is_empty() {
                self.prose.push_str(&t);
                self.prose.push('\n');
            }
        } else if line.trim().is_empty() {
            self.prose.push('\n');
        }
    }
    fn paragraph_break(&mut self) {
        if !self.prose.is_empty() && !self.prose.ends_with("\n\n") {
            self.prose.push('\n');
        }
    }
    fn count(&mut self, key: &str) {
        let n = self.m.get(key).and_then(Value::as_u64).unwrap_or(0);
        self.m.insert(key.into(), json!(n + 1));
    }
    fn bump(&mut self, key: &str, name: &str) {
        let Value::Object(h) = self.m.entry(key).or_insert_with(|| json!({})) else { return };
        if h.len() < 100 || h.contains_key(name) {
            let n = h.get(name).and_then(Value::as_u64).unwrap_or(0);
            h.insert(name.to_string(), json!(n + 1));
        }
    }

    fn report(mut self, cx: &mut Context<'_>) {
        let title = self.title.take().or_else(|| self.headings.first().map(|(_, t)| t.clone()));
        if let Some(t) = &title {
            cx.content().title(t.clone());
            cx.emit_text(TextRole::Title, t);
        }
        if let Some(s) = &self.subtitle {
            cx.format_set("subtitle", s.as_str());
        }
        if let Some(d) = &self.description {
            cx.content().description(d.clone());
        }
        for a in &self.authors {
            cx.content().author(a.clone());
        }
        for k in &self.keywords {
            cx.content().keyword(k.clone());
        }
        if let Some(l) = &self.language {
            cx.content().language(l.clone(), 1.0);
        }
        if let Some(d) = &self.date {
            match parse_date(d) {
                Some((iso, tz)) => {
                    cx.temporal().content_date(DateField::Created, iso, tz);
                }
                None => cx.format_set("date", d.as_str()),
            }
        }
        if let Some(v) = &self.version {
            cx.format_set("version", v.as_str());
        }
        for (level, h) in &self.headings {
            cx.emit_text(TextRole::Heading(*level), h);
        }
        cx.emit_text(TextRole::Body, &self.prose);
        cx.security().external_references(self.links_external);
        cx.format_set("headings", self.headings.len());
        cx.format_set("links", json!({ "internal": self.links_internal, "external": self.links_external }));
        if !self.hosts.is_empty() {
            let mut v: Vec<_> = self.hosts.iter().collect();
            v.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
            let top: Map<String, Value> = v.into_iter().take(10).map(|(k, n)| (k.clone(), json!(n))).collect();
            cx.format_set("top_link_hosts", Value::Object(top));
        }
        for (k, v) in [("images", self.images), ("code_blocks", self.code_blocks), ("tables", self.tables)] {
            cx.format_set(k, v);
        }
        if !self.languages.is_empty() {
            cx.format_set("code_languages", json!(self.languages));
        }
        if !self.includes.is_empty() {
            cx.format_set("includes", json!(self.includes));
        }
        for (k, v) in self.m {
            cx.format_set(&k, v);
        }
    }
}

/// Inline markup dropped for the prose: emphasis marks, link brackets.
fn clean_inline(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.trim().chars() {
        if !matches!(c, '*' | '`' | '[' | ']' | '{' | '}' | '|' | '~' | '^') {
            out.push(c);
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn regex(p: &str) -> Regex {
    Regex::new(p).expect("valid")
}

static URL: LazyLock<Regex> = LazyLock::new(|| regex(r#"(?-u:\b)(?:https?|ftp|gemini|gopher)://[^\s<>"'\])|]+"#));

/// Count the bare URLs on a line as external links.
fn bare_urls(line: &str, d: &mut Doc) {
    for m in URL.find_iter(line) {
        d.link(m.as_str());
    }
}

fn is_image(target: &str) -> bool {
    let t = target.to_ascii_lowercase();
    let t = t.split(['?', '#']).next().unwrap_or("");
    [".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".bmp"].iter().any(|e| t.ends_with(e))
}

// --- reStructuredText -----------------------------------------------------

fn adornment(line: &str) -> Option<char> {
    let c = line.chars().next()?;
    let ok = line.len() >= 2 && "=-`:'\"~^_*+#<>.".contains(c) && line.trim_end().chars().all(|x| x == c);
    ok.then_some(c)
}

fn rst(text: &str, d: &mut Doc) {
    static DIRECTIVE: LazyLock<Regex> = LazyLock::new(|| regex(r"^\s*\.\.\s+(?:\|[^|]+\|\s+)?([\w:-]+)::\s*(.*)$"));
    static TARGET: LazyLock<Regex> = LazyLock::new(|| regex(r"^\s*\.\.\s+_[^:]+:\s*(\S+)"));
    static INLINE: LazyLock<Regex> = LazyLock::new(|| regex(r"`[^`<]*<([^>`]+)>`_"));
    static FIELD: LazyLock<Regex> = LazyLock::new(|| regex(r"^:([A-Za-z][\w -]*):\s*(.*)$"));
    let lines: Vec<&str> = text.lines().collect();
    // Adornment styles in order of first use: (character, overlined).
    let mut styles: Vec<(char, bool)> = Vec::new();
    let mut fields = BTreeMap::new();
    let (mut in_literal, mut literal_indent) = (false, 0usize);
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let indent = line.len() - line.trim_start().len();
        if in_literal {
            if line.trim().is_empty() || indent > literal_indent {
                i += 1;
                continue;
            }
            in_literal = false;
        }
        // Over- and underlined, or underlined, section titles.
        let next = lines.get(i + 1).copied().unwrap_or("");
        if let Some(c) = adornment(line)
            && !next.trim().is_empty()
            && lines.get(i + 2).copied().and_then(adornment) == Some(c)
        {
            heading_style(&mut styles, (c, true), next.trim(), d);
            i += 3;
            continue;
        }
        if !line.trim().is_empty()
            && indent == 0
            && let Some(c) = adornment(next)
            && next.trim_end().chars().count() >= line.trim_end().chars().count().min(3)
            && adornment(line).is_none()
        {
            heading_style(&mut styles, (c, false), line.trim(), d);
            i += 2;
            continue;
        }
        if let Some(c) = DIRECTIVE.captures(line) {
            let (name, arg) = (c[1].to_ascii_lowercase(), c[2].trim().to_string());
            d.bump("directives", &name);
            match name.as_str() {
                "code" | "code-block" | "sourcecode" => {
                    d.code(Some(&arg));
                    (in_literal, literal_indent) = (true, indent);
                }
                "image" | "figure" => d.images += 1,
                "include" | "literalinclude" => d.include(&arg),
                "table" | "csv-table" | "list-table" => d.tables += 1,
                "raw" if arg.eq_ignore_ascii_case("html") => d.count("raw_html_blocks"),
                "meta" => {
                    for l in lines.iter().skip(i + 1).take_while(|l| l.starts_with(' ')) {
                        if let Some((k, v)) = l.trim().strip_prefix(':').and_then(|r| r.split_once(':')) {
                            match k.trim() {
                                "description" => d.description = Some(truncate_chars(v.trim(), 500)),
                                "keywords" => d.keywords.extend(v.split(',').map(|k| k.trim().to_string())),
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
            i += 1;
            continue;
        }
        if let Some(c) = TARGET.captures(line) {
            d.link(&c[1]);
        } else if line.trim_start().starts_with(".. [") {
            d.count("footnotes");
        } else if line.trim_start().starts_with(".. ") {
            // A comment.
        } else if d.prose.trim().is_empty()
            && let Some(c) = FIELD.captures(line)
        {
            fields.insert(c[1].to_ascii_lowercase(), c[2].trim().to_string());
        } else if line.starts_with("+-") && line.trim_end().ends_with('+') {
            if !lines.get(i.wrapping_sub(1)).is_some_and(|p| p.starts_with('+') || p.starts_with('|')) {
                d.tables += 1;
            }
        } else {
            for c in INLINE.captures_iter(line) {
                d.link(&c[1]);
            }
            bare_urls(&INLINE.replace_all(line, ""), d);
            if line.trim().is_empty() {
                d.paragraph_break();
            } else {
                d.prose(line);
            }
        }
        if line.trim_end().ends_with("::") && !line.trim_start().starts_with("..") {
            d.code(None);
            (in_literal, literal_indent) = (true, indent);
        }
        i += 1;
    }
    docinfo(fields, d);
}

fn heading_style(styles: &mut Vec<(char, bool)>, style: (char, bool), text: &str, d: &mut Doc) {
    let level = styles.iter().position(|s| *s == style).unwrap_or_else(|| {
        styles.push(style);
        styles.len() - 1
    });
    // A lone overlined title followed by a lone second style is the
    // document title and subtitle (Docutils `doctitle_xform`).
    if level == 1 && d.headings.len() == 1 && d.subtitle.is_none() && d.title.is_none() {
        d.subtitle = Some(truncate_chars(text, 300));
    }
    d.heading(u8::try_from(level + 1).unwrap_or(6), text);
}

/// The reST bibliographic fields.
fn docinfo(fields: BTreeMap<String, String>, d: &mut Doc) {
    let mut kept = Map::new();
    for (k, v) in fields {
        match k.as_str() {
            "author" | "authors" => v.split([';', ',']).for_each(|a| d.author(a)),
            "date" => d.date = Some(v.clone()),
            "version" | "revision" => d.version = Some(v.clone()),
            "abstract" => d.description = Some(truncate_chars(&v, 500)),
            "contact" | "address" => continue,
            _ => {}
        }
        if kept.len() < 30 {
            kept.insert(k, json!(truncate_chars(&v, 200)));
        }
    }
    if !kept.is_empty() {
        d.m.insert("fields".into(), Value::Object(kept));
    }
}

// --- AsciiDoc --------------------------------------------------------------

#[allow(clippy::too_many_lines)] // one branch per block kind
fn asciidoc(text: &str, d: &mut Doc) {
    static ATTR: LazyLock<Regex> = LazyLock::new(|| regex(r"^:(!?[\w][\w-]*!?):\s*(.*)$"));
    static SECTION: LazyLock<Regex> = LazyLock::new(|| regex(r"^(={1,6}|#{1,6})\s+(\S.*)$"));
    static MACRO: LazyLock<Regex> = LazyLock::new(|| regex(r"(?:^|[\s(])(image|include|link|xref)::?([^\[\s]*)\["));
    static ADMONITION: LazyLock<Regex> = LazyLock::new(|| {
        regex(r"^(?:\[(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]|(NOTE|TIP|IMPORTANT|WARNING|CAUTION):\s)")
    });
    let mut attributes = Vec::new();
    let mut header = true;
    let (mut delim, mut pending_lang): (Option<String>, Option<String>) = (None, None);
    let mut line_no = 0usize;
    for line in text.lines() {
        line_no += 1;
        let t = line.trim_end();
        if let Some(open) = &delim {
            if t == open {
                delim = None;
            }
            continue;
        }
        if t.starts_with("//") {
            if t.starts_with("////") && t.chars().all(|c| c == '/') {
                delim = Some(t.to_string());
            }
            continue;
        }
        // Delimited blocks: listing, literal, passthrough, comment, tables.
        if t.len() >= 4 && (t.chars().all(|c| c == '-') || t.chars().all(|c| c == '.') || t.chars().all(|c| c == '+')) {
            if t.starts_with('+') {
                d.count("passthrough_blocks");
            } else {
                d.code(pending_lang.take().as_deref());
            }
            delim = Some(t.to_string());
            continue;
        }
        if t.starts_with("```") {
            d.code(Some(t.trim_start_matches('`')));
            delim = Some("```".into());
            continue;
        }
        if t == "|===" || t == ",===" || t == ":===" {
            d.tables += 1;
            delim = Some(t.to_string());
            continue;
        }
        if t.starts_with('[') && t.ends_with(']') {
            let inner = &t[1..t.len() - 1];
            let mut parts = inner.split(',').map(str::trim);
            if matches!(parts.next(), Some("source" | "listing")) {
                pending_lang = parts.next().map(str::to_string);
            }
        }
        if let Some(c) = ADMONITION.captures(t) {
            let kind = c.get(1).or_else(|| c.get(2)).map_or("", |m| m.as_str()).to_ascii_lowercase();
            d.bump("admonitions", &kind);
        }
        if let Some(c) = ATTR.captures(t) {
            let (key, v) = (c[1].trim_matches('!').to_ascii_lowercase(), c[2].trim().to_string());
            match key.as_str() {
                "author" => d.author(&v),
                "authors" => v.split([';', ',']).for_each(|a| d.author(a)),
                "revnumber" => d.version = Some(v.trim_start_matches('v').to_string()),
                "revdate" => d.date = Some(v.clone()),
                "description" => d.description = Some(truncate_chars(&v, 500)),
                "keywords" => d.keywords.extend(v.split(',').map(|k| k.trim().to_string()).filter(|k| !k.is_empty())),
                "lang" => d.language = Some(v.clone()),
                "doctype" => {
                    d.m.insert("doctype".into(), json!(v));
                }
                _ => {}
            }
            if attributes.len() < 50 && key != "email" {
                attributes.push(key);
            }
            continue;
        }
        if let Some(c) = SECTION.captures(t) {
            let level = c[1].len();
            if level == 1 && d.title.is_none() && d.headings.is_empty() {
                d.title = Some(truncate_chars(c[2].trim(), 300));
            } else {
                d.heading(u8::try_from(level - 1).unwrap_or(6), &c[2]);
            }
            header = level == 1;
            continue;
        }
        // The author and revision lines under the document title.
        if header && d.title.is_some() && !t.is_empty() && line_no <= 4 {
            if d.authors.is_empty() && !t.starts_with('v') && !t.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                t.split(';').for_each(|a| d.author(a));
            } else if let Some((rev, rest)) = t.split_once(',') {
                d.version.get_or_insert_with(|| rev.trim().trim_start_matches('v').to_string());
                let date = rest.split(':').next().unwrap_or(rest).trim();
                if !date.is_empty() {
                    d.date.get_or_insert_with(|| date.to_string());
                }
            }
            continue;
        }
        header = false;
        for c in MACRO.captures_iter(t) {
            match &c[1] {
                "image" => d.images += 1,
                "include" => d.include(&c[2]),
                "link" => d.link(&c[2]),
                _ => d.links_internal += 1,
            }
        }
        d.links_internal += t.matches("<<").count() as u64;
        bare_urls(t, d);
        if t.is_empty() { d.paragraph_break() } else { d.prose(t) }
    }
    if !attributes.is_empty() {
        d.m.insert("attributes".into(), json!(attributes));
    }
}

// --- Org -------------------------------------------------------------------

#[allow(clippy::too_many_lines)] // one branch per element kind
fn org(text: &str, d: &mut Doc) {
    static KEYWORD: LazyLock<Regex> = LazyLock::new(|| regex(r"(?i)^#\+([A-Z_]+):\s*(.*)$"));
    static HEADLINE: LazyLock<Regex> = LazyLock::new(|| regex(r"^(\*+)\s+(.*?)\s*$"));
    static TAGS: LazyLock<Regex> = LazyLock::new(|| regex(r"\s+(:[\w@#%:]+:)$"));
    static LINK: LazyLock<Regex> = LazyLock::new(|| regex(r"\[\[([^\]]+)\](?:\[[^\]]*\])?\]"));
    static STAMP: LazyLock<Regex> = LazyLock::new(|| regex(r"[<\[](\d{4}-\d{2}-\d{2})(?: [^>\]]*)?[>\]]"));
    let mut todo_words: Vec<String> = vec!["TODO".into(), "DONE".into()];
    let mut done_words: Vec<String> = vec!["DONE".into()];
    // Custom TODO sequences come first in the file, usually; read them up front.
    for c in text.lines().take(500).filter_map(|l| KEYWORD.captures(l)) {
        if matches!(c[1].to_ascii_uppercase().as_str(), "TODO" | "SEQ_TODO" | "TYP_TODO") {
            let (open, done) = c[2].split_once('|').unwrap_or((&c[2], ""));
            todo_words.extend(open.split_whitespace().map(|w| w.split('(').next().unwrap_or(w).to_string()));
            let done: Vec<String> =
                done.split_whitespace().map(|w| w.split('(').next().unwrap_or(w).to_string()).collect();
            todo_words.extend(done.iter().cloned());
            done_words.extend(done);
        }
    }
    let mut tags = BTreeSet::new();
    let (mut stamps, mut in_block) = (BTreeSet::new(), false);
    let (mut tasks, mut tasks_done, mut in_table) = (0u64, 0u64, false);
    for line in text.lines() {
        let t = line.trim();
        let upper = t.to_ascii_uppercase();
        if in_block {
            in_block = !upper.starts_with("#+END_");
            continue;
        }
        if let Some(rest) = upper.strip_prefix("#+BEGIN_") {
            let kind = rest.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
            if kind == "src" {
                d.code(t.split_whitespace().nth(1));
            } else {
                d.bump("blocks", &kind);
            }
            in_block = true;
            continue;
        }
        if let Some(c) = KEYWORD.captures(t) {
            let v = c[2].trim();
            match c[1].to_ascii_uppercase().as_str() {
                "TITLE" => d.title = Some(truncate_chars(v, 300)),
                "SUBTITLE" => d.subtitle = Some(truncate_chars(v, 300)),
                "AUTHOR" => v.split([',', ';']).for_each(|a| d.author(a)),
                "DATE" => d.date = Some(STAMP.captures(v).map_or(v.to_string(), |s| s[1].to_string())),
                "LANGUAGE" => d.language = Some(v.to_string()),
                "DESCRIPTION" => d.description = Some(truncate_chars(v, 500)),
                "KEYWORDS" => d.keywords.extend(v.split([',', ' ']).filter(|k| !k.is_empty()).map(str::to_string)),
                "FILETAGS" => tags.extend(v.split([':', ' ']).filter(|k| !k.is_empty()).map(str::to_string)),
                "INCLUDE" | "SETUPFILE" => d.include(v.split_whitespace().next().unwrap_or(v).trim_matches('"')),
                _ => {}
            }
            continue;
        }
        if let Some(c) = HEADLINE.captures(line) {
            let mut rest = c[2].to_string();
            if let Some(tm) = TAGS.captures(&rest) {
                tags.extend(tm[1].split(':').filter(|t| !t.is_empty()).map(str::to_string));
                rest.truncate(tm.get(0).map_or(rest.len(), |m| m.start()));
            }
            let mut words = rest.splitn(2, ' ');
            let first = words.next().unwrap_or("");
            if todo_words.iter().any(|w| w == first) {
                d.bump("todo_states", first);
                if done_words.iter().any(|w| w == first) {
                    d.count("done_items");
                } else {
                    d.count("open_items");
                }
                rest = words.next().unwrap_or("").to_string();
            }
            // `[#A]`.
            let cookie = rest.strip_prefix("[#").and_then(|r| {
                let mut c = r.chars();
                let p = c.next()?;
                c.as_str().strip_prefix(']').map(|after| (p, after.trim_start().to_string()))
            });
            if let Some((p, after)) = cookie {
                d.bump("priorities", &p.to_string());
                rest = after;
            }
            d.heading(u8::try_from(c[1].len()).unwrap_or(6), &rest);
            continue;
        }
        let mut planning = false;
        for kw in ["SCHEDULED:", "DEADLINE:", "CLOSED:", "CLOCK:"] {
            if t.contains(kw) {
                d.count(&kw.trim_end_matches(':').to_ascii_lowercase());
                planning = true;
            }
        }
        if t == ":PROPERTIES:" {
            d.count("property_drawers");
            continue;
        }
        // Drawer lines: `:PROPERTIES:`, `:COST: 400`, `:END:`.
        if t.starts_with(':') && t[1..].contains(':') {
            continue;
        }
        for s in STAMP.captures_iter(t) {
            if stamps.len() < 100_000 {
                stamps.insert(s[1].to_string());
            }
        }
        if t.starts_with('|') {
            if !in_table {
                d.tables += 1;
            }
            in_table = true;
            continue;
        }
        in_table = false;
        if let Some(rest) = t.strip_prefix("- [").or_else(|| t.strip_prefix("+ [")) {
            tasks += 1;
            tasks_done += u64::from(rest.starts_with('X') || rest.starts_with('x'));
        }
        for c in LINK.captures_iter(t) {
            let target = c[1].strip_prefix("file:").unwrap_or(&c[1]);
            if is_image(target) && c.get(0).is_some_and(|m| !m.as_str().contains("][")) {
                d.images += 1;
            } else {
                d.link(target);
            }
        }
        if t.is_empty() {
            d.paragraph_break();
        } else if !planning {
            d.prose(&LINK.replace_all(t, ""));
        }
    }
    if !tags.is_empty() {
        d.m.insert("tags".into(), json!(tags.iter().take(100).collect::<Vec<_>>()));
    }
    if let (Some(first), Some(last)) = (stamps.first(), stamps.last()) {
        d.m.insert("timestamps".into(), json!({ "count": stamps.len(), "first": first, "last": last }));
    }
    if tasks > 0 {
        d.m.insert("checkboxes".into(), json!({ "total": tasks, "done": tasks_done }));
    }
}

// --- Textile ---------------------------------------------------------------

fn textile(text: &str, d: &mut Doc) {
    static HEADING: LazyLock<Regex> =
        LazyLock::new(|| regex(r"^h([1-6])(?:\([^)]*\)|\{[^}]*\}|\[[^\]]*\]|[<>=]+)*\.\s+(.*)$"));
    static BLOCK: LazyLock<Regex> = LazyLock::new(|| regex(r"^(bc|pre|bq|fn\d+|notextile|p)(?:\([^)]*\))?(\.\.?)\s"));
    static LINK: LazyLock<Regex> = LazyLock::new(|| regex(r#""[^"]+":([^\s"<>]+[^\s"<>.,;:!?)])"#));
    static IMAGE: LazyLock<Regex> = LazyLock::new(|| regex(r"![^\s!]+(?:\([^)]*\))?!"));
    let mut in_table = false;
    for line in text.lines() {
        let t = line.trim_end();
        if let Some(c) = HEADING.captures(t) {
            d.heading(c[1].parse().unwrap_or(1), &c[2]);
            continue;
        }
        if let Some(c) = BLOCK.captures(t) {
            match &c[1] {
                "bc" | "pre" => d.code(None),
                "bq" => d.count("block_quotes"),
                k if k.starts_with("fn") => d.count("footnotes"),
                _ => {}
            }
        }
        let table_row = t.starts_with('|') || t.starts_with("table");
        if table_row && !in_table {
            d.tables += 1;
        }
        in_table = table_row;
        d.images += IMAGE.find_iter(t).count() as u64;
        for c in LINK.captures_iter(t) {
            d.link(&c[1]);
        }
        if t.is_empty() { d.paragraph_break() } else { d.prose(&LINK.replace_all(t, "")) }
    }
}

// --- MediaWiki -------------------------------------------------------------

fn mediawiki(text: &str, d: &mut Doc) {
    static HEADING: LazyLock<Regex> = LazyLock::new(|| regex(r"^(={1,6})\s*(.+?)\s*(={1,6})\s*$"));
    static TEMPLATE: LazyLock<Regex> = LazyLock::new(|| regex(r"\{\{\s*([^|{}\n#][^|{}\n]*?)\s*(?:[|}]|$)"));
    static MARKUP: LazyLock<Regex> = LazyLock::new(|| regex(r"<[^>]*>|__[A-Z]+__|\{\{[^{}]*\}\}|'{2,}"));
    static LINK: LazyLock<Regex> = LazyLock::new(|| regex(r"\[\[([^\]|\n]+)(?:\|[^\]\n]*)?\]\]"));
    static EXTERNAL: LazyLock<Regex> = LazyLock::new(|| regex(r"\[((?:https?|ftp)://[^\s\]]+)"));
    static CODE: LazyLock<Regex> =
        LazyLock::new(|| regex(r#"<(?:syntaxhighlight|source)\b[^>]*?(?:lang="?([\w+-]+))?"?[^>]*>"#));
    static MAGIC: LazyLock<Regex> = LazyLock::new(|| regex(r"__([A-Z]+)__"));
    let (mut categories, mut interwiki, mut magic) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    if let Some(rest) = text.trim_start().get(..9).filter(|p| p.eq_ignore_ascii_case("#redirect"))
        && let Some(c) = LINK.captures(&text.trim_start()[rest.len()..])
    {
        d.m.insert("redirect".into(), json!(truncate_chars(c[1].trim(), 300)));
    }
    for line in text.lines() {
        let t = line.trim_end();
        if let Some(c) = HEADING.captures(t)
            && c[1].len() == c[3].len()
        {
            d.heading(u8::try_from(c[1].len().saturating_sub(1).max(1)).unwrap_or(6), &c[2]);
            continue;
        }
        if t.starts_with("{|") {
            d.tables += 1;
        }
        d.count_refs(t);
        for c in TEMPLATE.captures_iter(t) {
            let name = c[1].trim().replace('_', " ");
            let name = name.strip_prefix("Template:").unwrap_or(&name);
            if !name.contains(':') || name.starts_with("subst:") {
                d.bump("templates", &truncate_chars(name.trim_start_matches("subst:"), 100));
            }
        }
        for c in CODE.captures_iter(t) {
            d.code(c.get(1).map(|m| m.as_str()));
        }
        for m in MAGIC.captures_iter(t) {
            magic.insert(m[1].to_string());
        }
        for c in LINK.captures_iter(t) {
            let target = c[1].trim();
            let (ns, rest) = target.split_once(':').unwrap_or(("", target));
            match ns.to_ascii_lowercase().as_str() {
                "category" => {
                    if categories.len() < 100 {
                        categories.insert(truncate_chars(rest.trim(), 200));
                    }
                }
                "file" | "image" | "media" => d.images += 1,
                l if l.len() == 2 && l.chars().all(|c| c.is_ascii_lowercase()) && !rest.is_empty() => {
                    interwiki.insert(l.to_string());
                }
                _ => d.links_internal += 1,
            }
        }
        for c in EXTERNAL.captures_iter(t) {
            d.link(&c[1]);
        }
        let plain = MARKUP.replace_all(&LINK.replace_all(t, ""), "").into_owned();
        if t.is_empty() {
            d.paragraph_break();
        } else if !t.starts_with(['{', '|', '!', '<']) {
            d.prose(&plain);
        }
    }
    for (k, v) in [("categories", categories), ("language_links", interwiki), ("magic_words", magic)] {
        if !v.is_empty() {
            d.m.insert(k.into(), json!(v.into_iter().collect::<Vec<_>>()));
        }
    }
}

impl Doc {
    /// `<ref>` footnotes, as `MediaWiki` writes them.
    fn count_refs(&mut self, line: &str) {
        let n = line.matches("<ref").count() - line.matches("<references").count();
        if n > 0 {
            let total = self.m.get("references").and_then(Value::as_u64).unwrap_or(0);
            self.m.insert("references".into(), json!(total + n as u64));
        }
    }
}

// --- POD -------------------------------------------------------------------

fn pod(text: &str, d: &mut Doc) {
    static LINK: LazyLock<Regex> = LazyLock::new(|| regex(r"L<([^>]+)>"));
    let mut section = String::new();
    let mut section_text: BTreeMap<String, String> = BTreeMap::new();
    let (mut in_pod, mut verbatim) = (!text.trim_start().starts_with("#!"), false);
    for line in text.lines() {
        if let Some(cmd) = line.strip_prefix('=') {
            let (name, arg) = cmd.split_once(char::is_whitespace).unwrap_or((cmd, ""));
            in_pod = name != "cut";
            d.bump("commands", name);
            match name {
                "head1" | "head2" | "head3" | "head4" => {
                    let level = name[4..].parse().unwrap_or(1);
                    d.heading(level, &pod_text(arg));
                    if level == 1 {
                        section = arg.trim().to_ascii_uppercase();
                    }
                }
                "encoding" => {
                    d.m.insert("encoding".into(), json!(arg.trim()));
                }
                "begin" | "for" => d.bump("formats", arg.split_whitespace().next().unwrap_or("")),
                _ => {}
            }
            verbatim = false;
            continue;
        }
        if !in_pod {
            continue;
        }
        if line.starts_with([' ', '\t']) && !line.trim().is_empty() {
            if !verbatim {
                d.code(None);
                verbatim = true;
            }
            continue;
        }
        verbatim = false;
        for c in LINK.captures_iter(line) {
            let target = c[1].rsplit('|').next().unwrap_or(&c[1]);
            d.link(target);
        }
        let plain = pod_text(line);
        if !section.is_empty() {
            let s = section_text.entry(section.clone()).or_default();
            if s.len() < 2000 {
                s.push_str(&plain);
                s.push(' ');
            }
        }
        if line.trim().is_empty() { d.paragraph_break() } else { d.prose(&plain) }
    }
    // `Module::Name - what it does`.
    if let Some(name) = section_text.get("NAME") {
        let (n, desc) = name.split_once(" - ").unwrap_or((name.as_str(), ""));
        d.title = Some(truncate_chars(n.trim(), 300));
        if !desc.trim().is_empty() {
            d.description = Some(truncate_chars(desc.trim(), 500));
        }
    }
    for key in ["AUTHOR", "AUTHORS"] {
        if let Some(a) = section_text.get(key) {
            a.split([',', '\n']).take(10).for_each(|x| d.author(x));
        }
    }
    if let Some(v) = section_text.get("VERSION") {
        let v = v.split_whitespace().find(|w| w.starts_with(|c: char| c.is_ascii_digit() || c == 'v'));
        d.version = v.map(|v| v.trim_start_matches('v').trim_end_matches('.').to_string());
    }
}

/// POD formatting codes (`B<bold>`, `C<code>`, `E<gt>`) reduced to their text.
fn pod_text(s: &str) -> String {
    static CODE: LazyLock<Regex> = LazyLock::new(|| regex(r"[BCFIJLSXZ]<+ ?([^<>]*?) ?>+"));
    let mut t = s.to_string();
    for _ in 0..4 {
        let next = CODE.replace_all(&t, "$1").into_owned();
        if next == t {
            break;
        }
        t = next;
    }
    t.replace("E<gt>", ">").replace("E<lt>", "<")
}

// --- roff ------------------------------------------------------------------

/// Arguments of a roff request, honouring double quotes.
fn roff_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '"' => quoted = !quoted,
            ' ' | '\t' if !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Text with roff escapes (`\fB`, `\-`, `\(em`, `\*(lq`) removed.
fn roff_text(s: &str) -> String {
    static ESC: LazyLock<Regex> = LazyLock::new(|| {
        regex(r"\\(?:f(?:\[[^\]]*\]|\(..|.)|s[-+]?\d|\*(?:\(..|\[[^\]]*\]|.)|\(..|\[[^\]]*\]|[&|^%c])")
    });
    ESC.replace_all(s, "").replace("\\-", "-").replace("\\e", "\\").replace("\\ ", " ")
}

#[allow(clippy::too_many_lines)] // one arm per request
fn roff(text: &str, d: &mut Doc) {
    let mut package = None;
    let (mut in_name, mut name_text) = (false, String::new());
    let mut next_is = "";
    let mut sections = Vec::new();
    let mut page = Map::new();
    for line in text.lines() {
        if line.starts_with(".\\\"") || line.starts_with("'\\\"") || line.starts_with("\\\"") {
            continue;
        }
        let Some(req) = line.strip_prefix('.').or_else(|| line.strip_prefix('\'')) else {
            let t = roff_text(line);
            match std::mem::take(&mut next_is) {
                "title" => d.title = Some(truncate_chars(t.trim(), 300)),
                "author" => d.author(&t),
                "heading" => {
                    in_name = t.trim().eq_ignore_ascii_case("NAME");
                    if sections.len() < 100 {
                        sections.push(truncate_chars(t.trim(), 200));
                    }
                    d.heading(1, &t);
                    continue;
                }
                _ => {}
            }
            if in_name && name_text.len() < 500 {
                name_text.push_str(&t);
                name_text.push(' ');
            }
            d.prose(&t);
            continue;
        };
        let (name, rest) = req.trim_start().split_once(char::is_whitespace).unwrap_or((req.trim(), ""));
        let args = roff_args(rest);
        let arg = |i: usize| args.get(i).map(|a| roff_text(a));
        match name {
            "TH" => {
                package.get_or_insert("man");
                for (i, k) in ["name", "section", "date", "source", "manual"].iter().enumerate() {
                    if let Some(v) = arg(i).filter(|v| !v.is_empty()) {
                        page.insert((*k).into(), json!(truncate_chars(&v, 200)));
                    }
                }
            }
            "Dt" => {
                package = Some("mdoc");
                for (i, k) in ["name", "section", "architecture"].iter().enumerate() {
                    if let Some(v) = arg(i) {
                        page.insert((*k).into(), json!(truncate_chars(&v, 200)));
                    }
                }
            }
            "Dd" => {
                package = Some("mdoc");
                page.insert("date".into(), json!(truncate_chars(&roff_text(rest.trim()), 100)));
            }
            "Os" if !rest.trim().is_empty() => {
                page.insert("source".into(), json!(truncate_chars(&roff_text(rest.trim()), 100)));
            }
            "Nd" => d.description = Some(truncate_chars(&roff_text(rest.trim()), 500)),
            "SH" | "Sh" | "NH" | "SS" | "Ss" | "sh" => {
                let level = if matches!(name, "SS" | "Ss") { 2 } else { 1 };
                let title = roff_text(rest.trim()).trim_matches('"').to_string();
                in_name = title.eq_ignore_ascii_case("NAME");
                // `.NH` / `.SH` alone: the heading is the next text line.
                let numbered = title.chars().all(|c| c.is_ascii_digit() || c == ' ');
                if title.is_empty() || (name == "NH" && numbered) {
                    next_is = "heading";
                } else {
                    if sections.len() < 100 {
                        sections.push(title.clone());
                    }
                    d.heading(level, &title);
                }
                if name == "NH" {
                    package = Some("ms");
                } else if name == "sh" {
                    package = Some("me");
                }
            }
            "TL" => {
                package = Some("ms");
                next_is = "title";
            }
            "AU" => {
                package = Some("ms");
                next_is = "author";
            }
            "so" => d.include(rest.trim()),
            "EX" | "nf" | "Bd" => d.code(None),
            "TS" => d.tables += 1,
            "UR" | "MT" => {
                if name == "UR"
                    && let Some(u) = arg(0)
                {
                    d.link(&u);
                }
            }
            "pp" | "lp" | "ip" => {
                package.get_or_insert("me");
            }
            _ => {}
        }
    }
    // `ls \- list directory contents`.
    if let Some((n, desc)) = name_text.split_once(" - ") {
        d.description.get_or_insert_with(|| truncate_chars(desc.trim(), 500));
        page.entry("names").or_insert_with(|| json!(n.split(',').map(str::trim).collect::<Vec<_>>()));
    }
    if let (Some(n), Some(s)) = (page.get("name").and_then(Value::as_str), page.get("section").and_then(Value::as_str))
    {
        d.title.get_or_insert_with(|| format!("{}({s})", n.to_ascii_lowercase()));
    }
    if let Some(p) = package {
        d.m.insert("macro_package".into(), json!(p));
    }
    if !page.is_empty() {
        d.m.insert("page".into(), Value::Object(page));
    }
    if !sections.is_empty() {
        d.m.insert("sections".into(), json!(sections));
    }
}

// --- Texinfo ---------------------------------------------------------------

fn texinfo(text: &str, d: &mut Doc) {
    static COMMAND: LazyLock<Regex> = LazyLock::new(|| regex(r"^@(\w+)\s*(.*)$"));
    static LINK: LazyLock<Regex> = LazyLock::new(|| regex(r"@u?ref\{([^,}]+)|@url\{([^,}]+)"));
    let mut in_block: Option<String> = None;
    let mut sets = Map::new();
    for line in text.lines() {
        if let Some(end) = &in_block {
            if line.trim() == format!("@end {end}") {
                in_block = None;
            }
            continue;
        }
        let Some(c) = COMMAND.captures(line) else {
            for c in LINK.captures_iter(line) {
                d.link(c.get(1).or_else(|| c.get(2)).map_or("", |m| m.as_str()));
            }
            if line.trim().is_empty() {
                d.paragraph_break();
            } else {
                d.prose(&texi_text(line));
            }
            continue;
        };
        let (cmd, arg) = (&c[1], c[2].trim());
        let level = match cmd {
            "top" | "chapter" | "unnumbered" | "appendix" | "majorheading" | "chapheading" => Some(1),
            "section" | "unnumberedsec" | "appendixsec" | "heading" => Some(2),
            "subsection" | "unnumberedsubsec" | "appendixsubsec" | "subheading" => Some(3),
            "subsubsection" | "unnumberedsubsubsec" | "appendixsubsubsec" | "subsubheading" => Some(4),
            _ => None,
        };
        if let Some(l) = level {
            d.heading(l, &texi_text(arg));
            continue;
        }
        match cmd {
            "settitle" => d.title = Some(truncate_chars(&texi_text(arg), 300)),
            "title" if d.title.is_none() => d.title = Some(truncate_chars(&texi_text(arg), 300)),
            "subtitle" => d.subtitle = Some(truncate_chars(&texi_text(arg), 300)),
            "author" => d.author(&texi_text(arg)),
            "documentlanguage" => d.language = Some(arg.to_string()),
            "setfilename" => {
                d.m.insert("output_file".into(), json!(truncate_chars(arg, 200)));
            }
            "documentencoding" => {
                d.m.insert("encoding".into(), json!(arg));
            }
            "dircategory" => {
                d.m.insert("dir_category".into(), json!(truncate_chars(arg, 200)));
            }
            "node" => d.count("nodes"),
            "include" => d.include(arg),
            "set" => {
                let (k, v) = arg.split_once(char::is_whitespace).unwrap_or((arg, ""));
                if sets.len() < 30 {
                    sets.insert(k.to_string(), json!(truncate_chars(v.trim(), 200)));
                }
                if k.eq_ignore_ascii_case("version") || k.eq_ignore_ascii_case("edition") {
                    d.version.get_or_insert_with(|| v.trim().to_string());
                }
                if k.eq_ignore_ascii_case("updated") {
                    d.date.get_or_insert_with(|| v.trim().to_string());
                }
            }
            "example" | "smallexample" | "lisp" | "smalllisp" | "verbatim" | "display" => {
                d.code(if cmd.contains("lisp") { Some("lisp") } else { None });
                in_block = Some(cmd.to_string());
            }
            "multitable" | "table" | "ftable" | "vtable" => d.tables += 1,
            "image" => d.images += 1,
            "copying" | "ignore" | "tex" | "html" | "iftex" | "ifhtml" | "titlepage" => {
                if matches!(cmd, "ignore" | "tex" | "html") {
                    in_block = Some(cmd.to_string());
                }
            }
            _ => {}
        }
    }
    if !sets.is_empty() {
        d.m.insert("flags".into(), Value::Object(sets));
    }
}

/// Texinfo inline commands (`@code{x}`, `@emph{y}`, `@@`) reduced to text.
fn texi_text(s: &str) -> String {
    static INLINE: LazyLock<Regex> = LazyLock::new(|| regex(r"@\w+\{([^{}]*)\}"));
    let mut t = s.to_string();
    for _ in 0..4 {
        let next = INLINE.replace_all(&t, "$1").into_owned();
        if next == t {
            break;
        }
        t = next;
    }
    t.replace("@@", "@").replace("@{", "{").replace("@}", "}")
}

// --- Creole and DokuWiki ---------------------------------------------------

fn wiki_lines(text: &str, d: &mut Doc, dokuwiki: bool) {
    static HEADING: LazyLock<Regex> = LazyLock::new(|| regex(r"^\s*(={1,6})\s*(.+?)\s*=*\s*$"));
    static LINK: LazyLock<Regex> = LazyLock::new(|| regex(r"\[\[([^\]|]+)(?:\|[^\]]*)?\]\]"));
    static IMAGE: LazyLock<Regex> = LazyLock::new(|| regex(r"\{\{([^}|]+)(?:\|[^}]*)?\}\}"));
    static CODE: LazyLock<Regex> = LazyLock::new(|| regex(r"^<(code|file)(?:\s+([\w+-]+))?"));
    let (mut in_pre, mut in_table) = (false, false);
    let mut tags = BTreeSet::new();
    for line in text.lines() {
        let t = line.trim_end();
        if in_pre {
            in_pre = !(t.starts_with("}}}") || t.starts_with("</code>") || t.starts_with("</file>"));
            continue;
        }
        if t.starts_with("{{{") && !t.contains("}}}") {
            d.code(None);
            in_pre = true;
            continue;
        }
        if dokuwiki && let Some(c) = CODE.captures(t) {
            d.code(c.get(2).map(|m| m.as_str()));
            in_pre = !t.contains("</code>") && !t.contains("</file>");
            continue;
        }
        if let Some(c) = HEADING.captures(t) {
            let n = c[1].len();
            // DokuWiki counts down: six `=` is the top level.
            let level = if dokuwiki { 7usize.saturating_sub(n).max(1) } else { n };
            d.heading(u8::try_from(level).unwrap_or(6), &c[2]);
            continue;
        }
        let row = t.starts_with('|') || (dokuwiki && t.starts_with('^'));
        if row && !in_table {
            d.tables += 1;
        }
        in_table = row;
        for c in IMAGE.captures_iter(t) {
            let target = c[1].trim();
            if let Some(tag) = target.strip_prefix("tag>") {
                tags.extend(tag.split_whitespace().map(str::to_string));
            } else {
                d.images += 1;
            }
        }
        for c in LINK.captures_iter(t) {
            d.link(&c[1]);
        }
        let plain = IMAGE.replace_all(&LINK.replace_all(t, ""), "").into_owned();
        bare_urls(&plain, d);
        if t.is_empty() { d.paragraph_break() } else { d.prose(&plain) }
    }
    if !tags.is_empty() {
        d.m.insert("tags".into(), json!(tags.into_iter().take(100).collect::<Vec<_>>()));
    }
}

// --- Djot ------------------------------------------------------------------

fn djot(text: &str, d: &mut Doc) {
    static HEADING: LazyLock<Regex> = LazyLock::new(|| regex(r"^(#{1,6})\s+(.*)$"));
    static LINK: LazyLock<Regex> = LazyLock::new(|| regex(r"(!?)\[[^\]]*\]\(([^)\s]+)\)"));
    static AUTOLINK: LazyLock<Regex> = LazyLock::new(|| regex(r"<((?:https?|ftp)://[^>\s]+)>"));
    let mut fence: Option<String> = None;
    let mut in_table = false;
    for line in text.lines() {
        let t = line.trim_end();
        if let Some(f) = &fence {
            if t.trim_start().starts_with(f.as_str()) && t.trim().chars().all(|c| c == '`' || c == '~') {
                fence = None;
            }
            continue;
        }
        let ticks: String = t.trim_start().chars().take_while(|c| *c == '`' || *c == '~').collect();
        if ticks.len() >= 3 {
            let lang = t.trim_start()[ticks.len()..].trim();
            d.code(Some(lang.trim_start_matches('=')));
            fence = Some(ticks);
            continue;
        }
        if let Some(c) = HEADING.captures(t) {
            d.heading(u8::try_from(c[1].len()).unwrap_or(6), &c[2]);
            continue;
        }
        if t.starts_with(":::") {
            if let Some(class) = t.trim_start_matches(':').split_whitespace().next() {
                d.bump("divs", class);
            }
            continue;
        }
        if t.starts_with("[^") && t.contains("]:") {
            d.count("footnotes");
        }
        if t.starts_with('{') && t.ends_with('}') {
            d.count("attributes");
            continue;
        }
        let row = t.starts_with('|');
        if row && !in_table {
            d.tables += 1;
        }
        in_table = row;
        for c in LINK.captures_iter(t) {
            if &c[1] == "!" { d.images += 1 } else { d.link(&c[2]) }
        }
        for c in AUTOLINK.captures_iter(t) {
            d.link(&c[1]);
        }
        if t.is_empty() {
            d.paragraph_break();
        } else {
            d.prose(&AUTOLINK.replace_all(&LINK.replace_all(t, ""), ""));
        }
    }
}

// --- Gemtext ---------------------------------------------------------------

fn gemtext(text: &str, d: &mut Doc) {
    let mut pre = false;
    let mut schemes: BTreeMap<String, u64> = BTreeMap::new();
    for line in text.lines() {
        if let Some(alt) = line.strip_prefix("```") {
            if !pre {
                d.code(alt.split_whitespace().next());
            }
            pre = !pre;
            continue;
        }
        if pre {
            continue;
        }
        if let Some(rest) = line.strip_prefix("=>") {
            let rest = rest.trim_start();
            let (url, label) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            let scheme = url.split_once("://").map_or("relative", |(s, _)| s);
            *schemes.entry(scheme.to_ascii_lowercase()).or_default() += 1;
            if is_image(url) {
                d.images += 1;
            }
            d.link(url);
            d.prose(label);
            continue;
        }
        let hashes = line.chars().take_while(|c| *c == '#').count();
        if (1..=3).contains(&hashes) {
            d.heading(u8::try_from(hashes).unwrap_or(3), &line[hashes..]);
            continue;
        }
        if line.starts_with('>') {
            d.count("quotes");
        }
        if line.trim().is_empty() { d.paragraph_break() } else { d.prose(line.trim_start_matches(['*', '>'])) }
    }
    if !schemes.is_empty() {
        d.m.insert("link_schemes".into(), json!(schemes));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(f: fn(&str, &mut Doc), text: &str) -> Doc {
        let mut d = Doc::default();
        f(text, &mut d);
        d
    }

    #[test]
    fn rst_outline_and_fields() {
        let d = doc(
            rst,
            "=======\nHarbour\n=======\n\nTides\n-----\n\n:Author: Ada Lovelace\n:Date: 2026-01-05\n\nSection\n=======\n\n.. code-block:: python\n\n   x = 1\n\n.. _site: https://example.org/\n",
        );
        let h: Vec<_> = d.headings.iter().map(|(l, t)| (*l, t.as_str())).collect();
        assert_eq!(h, [(1, "Harbour"), (2, "Tides"), (3, "Section")]);
        assert_eq!(d.subtitle.as_deref(), Some("Tides"));
        assert_eq!(d.authors, ["Ada Lovelace"]);
        assert_eq!(d.date.as_deref(), Some("2026-01-05"));
        assert_eq!((d.code_blocks, d.links_external), (1, 1));
    }

    #[test]
    fn asciidoc_header() {
        let d = doc(
            asciidoc,
            "= Harbour Guide\nAda Lovelace <ada@example.org>\nv1.2, 2026-01-05: First\n:lang: en\n\n== Moorings\n\n[source,rust]\n----\nfn main() {}\n----\n",
        );
        assert_eq!(d.title.as_deref(), Some("Harbour Guide"));
        assert_eq!((d.authors.as_slice(), d.version.as_deref()), (&["Ada Lovelace".to_string()][..], Some("1.2")));
        assert_eq!((d.date.as_deref(), d.language.as_deref()), (Some("2026-01-05"), Some("en")));
        assert_eq!(d.headings, [(1, "Moorings".to_string())]);
        assert_eq!(d.languages.get("rust"), Some(&1));
    }

    #[test]
    fn org_states() {
        let d = doc(
            org,
            "#+TITLE: Log\n* TODO [#A] Paint the hull :boat:\n** DONE Buy rope\nSCHEDULED: <2026-01-05 Mon>\n",
        );
        assert_eq!(d.headings, [(1, "Paint the hull".to_string()), (2, "Buy rope".to_string())]);
        assert_eq!(d.m["todo_states"], json!({"DONE": 1, "TODO": 1}));
        assert_eq!(d.m["tags"], json!(["boat"]));
        assert_eq!(d.m["timestamps"]["first"], "2026-01-05");
    }

    #[test]
    fn man_page() {
        let d = doc(
            roff,
            ".TH LS 1 \"January 2026\" \"coreutils\" \"User Commands\"\n.SH NAME\nls \\- list directory contents\n.SH SYNOPSIS\n",
        );
        assert_eq!(d.title.as_deref(), Some("ls(1)"));
        assert_eq!(d.description.as_deref(), Some("list directory contents"));
        assert_eq!(d.m["page"]["source"], "coreutils");
    }

    #[test]
    fn inline_codes() {
        assert_eq!(pod_text("B<bold> and C<< $x >>"), "bold and $x");
        assert_eq!(texi_text("@code{make} @@ @emph{now}"), "make @ now");
        assert_eq!(roff_text("\\fBbold\\fR \\- dash"), "bold - dash");
    }

    crate::fixture_tests!(
        "rst",
        "asciidoc",
        "org",
        "textile",
        "mediawiki",
        "pod",
        "roff",
        "texinfo",
        "creole",
        "dokuwiki",
        "djot",
        "gemtext"
    );
}
