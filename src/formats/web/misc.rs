//! Small web files:
//! * `robots.txt` (user-agent groups, allow / disallow rules, sitemaps,
//!   crawl delay, whether everything or named AI crawlers are blocked),
//!   `security.txt` (RFC 9116 fields, expiry, signed) and `humans.txt`;
//! * proxy auto-config (`.pac`): proxies returned, `DIRECT`, the helper
//!   functions used;
//! * Metalink 3 and 4 (`.metalink`, `.meta4`): files, sizes, hashes,
//!   mirrors;
//! * Adblock filter lists: header fields, rules by kind;
//! * Netscape cookie jars (`cookies.txt`): cookies, domains, secure and
//!   HTTP-only flags, expiry range; never the values;
//! * browser bookmarks (Netscape HTML export, Chrome `Bookmarks`, Firefox
//!   JSON backup): bookmarks, folders, date range;
//! * credentials files `.netrc`, `.wgetrc`, `.curlrc`: entries and
//!   options; passwords are flagged, never copied;
//! * WARC web archives: records by type, target URIs, date range,
//!   software, payload types.
//!
//! Hosts in cookie jars, bookmarks and `.netrc` are counted, and listed
//! only when privacy is off. Credential files and cookie jars are not
//! passed to the text pipeline.
//!
//! Specifications: RFC 9309 (robots), RFC 9116 (security.txt), Netscape
//! "Navigator Proxy Auto-Config File Format", RFC 5854 (Metalink 4),
//! Adblock Plus "How to write filters", curl(1) / wget(1) / netrc(5),
//! ISO 28500:2017 (WARC 1.1).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    TextRole, truncate_chars,
    xmlwalk::{Ev, walk, xml_root},
};

/// Extractor for small web files.
pub struct WebMisc;

macro_rules! formats {
    ($( $id:literal $name:literal $mime:literal [$($ext:literal),*] [$($magic:expr),*] )*) => {
        &[$(FormatSpec {
            id: $id, name: $name, family: "web.misc", mimes: &[$mime], extensions: &[$($ext),*],
            magic: &[$($magic),*], parent: None,
        }),*]
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "web.misc",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: formats! {
        "robots_txt" "robots.txt / security.txt / humans.txt" "text/plain" [] []
        "pac" "PAC proxy auto-config" "application/x-ns-proxy-autoconfig" ["pac"] []
        "metalink" "Magnet / metalink" "application/metalink4+xml" ["metalink", "meta4"] []
        "adblock_list" "Proxy lists / Adblock filter lists" "text/plain" [] []
        "cookie_jar" "Cookie jar (Netscape)" "text/plain" [] []
        "bookmarks" "Browser bookmarks HTML / JSON" "text/html" [] []
        "netrc" "Wget / curl config, .netrc" "text/plain" ["netrc", "wgetrc", "curlrc"] []
        "warc" "WARC web archive" "application/warc" ["warc"] [Magic::prefix(b"WARC/1.")]
    },
};

impl Extractor for WebMisc {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        const BOOKMARKS: &str = "<!DOCTYPE NETSCAPE-Bookmark-file-1>";
        let sure = |format| Some(Sniff { format, confidence: 0.95 });
        let name = probe.name.map_or("", |n| n.rsplit(['/', '\\']).next().unwrap_or(n));
        match name.to_ascii_lowercase().as_str() {
            // A signed security.txt is also a cleartext OpenPGP message.
            "robots.txt" | "security.txt" | "humans.txt" => {
                return Some(Sniff { format: "robots_txt", confidence: 0.97 });
            }
            ".netrc" | "_netrc" | ".wgetrc" | ".curlrc" | "_curlrc" => return sure("netrc"),
            _ => {}
        }
        let head = std::str::from_utf8(&probe.head[..probe.head.len().min(4096)])
            .or_else(|e| std::str::from_utf8(&probe.head[..e.valid_up_to()]))
            .ok()?;
        let start = head.trim_start_matches('\u{feff}').trim_start();
        if start.starts_with("# Netscape HTTP Cookie File") || start.starts_with("# HTTP Cookie File") {
            return sure("cookie_jar");
        }
        if start.get(..BOOKMARKS.len()).is_some_and(|p| p.eq_ignore_ascii_case(BOOKMARKS)) {
            return sure("bookmarks");
        }
        if start.starts_with("[Adblock") || (start.starts_with("! Title:") && head.contains("\n! ")) {
            return sure("adblock_list");
        }
        if start.starts_with('{')
            && (head.contains("\"bookmark_bar\"") || head.contains("\"text/x-moz-place-container\""))
        {
            return sure("bookmarks");
        }
        if matches!(probe.extension, Some("pac" | "js" | "dat")) && head.contains("FindProxyForURL") {
            return sure("pac");
        }
        if matches!(probe.extension, Some("xml" | "metalink" | "meta4"))
            && xml_root(probe.head).is_some_and(|(r, _)| r == "metalink")
        {
            return sure("metalink");
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let id = cx.format_id().to_string();
        if id == "warc" {
            let (b, _) = cx.read_bytes(src)?;
            return warc(&b, cx);
        }
        let text = cx.read_text(src)?.text;
        let name = src.name_hint().unwrap_or("").rsplit(['/', '\\']).next().unwrap_or("").to_ascii_lowercase();
        match id.as_str() {
            "robots_txt" => {
                cx.emit_text(TextRole::Data, &text);
                match name.as_str() {
                    "security.txt" => security_txt(&text, cx),
                    "humans.txt" => humans_txt(&text, cx),
                    _ => robots(&text, cx),
                }
            }
            "pac" => {
                cx.emit_text(TextRole::Code, &text);
                pac(&text, cx);
            }
            "metalink" => metalink(&text, cx)?,
            "adblock_list" => adblock(&text, cx),
            "cookie_jar" => cookies(&text, cx),
            "bookmarks" => bookmarks(&text, cx),
            _ => credentials(&text, &name, cx),
        }
        Ok(())
    }
}

crate::register_extractor!(WebMisc);

fn regex(p: &str) -> Regex {
    Regex::new(p).expect("valid")
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?;
    let host = host.split(':').next()?.trim_start_matches("www.").to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn top(h: &BTreeMap<String, u64>, n: usize) -> Value {
    let mut v: Vec<_> = h.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    Value::Object(v.into_iter().take(n).map(|(k, c)| (k.clone(), json!(c))).collect())
}

// --- robots.txt, security.txt, humans.txt ----------------------------------

/// Crawlers that collect text for AI models.
const AI_CRAWLERS: [&str; 14] = [
    "gptbot",
    "chatgpt-user",
    "oai-searchbot",
    "ccbot",
    "claudebot",
    "claude-web",
    "anthropic-ai",
    "google-extended",
    "applebot-extended",
    "perplexitybot",
    "bytespider",
    "meta-externalagent",
    "amazonbot",
    "cohere-ai",
];

fn robots(text: &str, cx: &mut Context<'_>) {
    let (mut groups, mut allow, mut disallow) = (0u64, 0u64, 0u64);
    let mut agents: BTreeSet<String> = BTreeSet::new();
    let mut sitemaps = Vec::new();
    let mut delay = None;
    let mut current: Vec<String> = Vec::new();
    let mut in_rules = false;
    let (mut blocks_all, mut ai_blocked) = (false, BTreeSet::new());
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((k, v)) = line.split_once(':') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match k.as_str() {
            "user-agent" => {
                if in_rules {
                    current.clear();
                    in_rules = false;
                }
                if current.is_empty() {
                    groups += 1;
                }
                let a = v.to_ascii_lowercase();
                current.push(a.clone());
                if agents.len() < 200 {
                    agents.insert(a);
                }
            }
            "allow" => {
                in_rules = true;
                allow += 1;
            }
            "disallow" => {
                in_rules = true;
                if v.is_empty() {
                    continue;
                }
                disallow += 1;
                if v == "/" {
                    for a in &current {
                        if a == "*" {
                            blocks_all = true;
                        } else if let Some(c) = AI_CRAWLERS.iter().find(|c| a.contains(*c)) {
                            ai_blocked.insert((*c).to_string());
                        }
                    }
                }
            }
            "crawl-delay" => delay = v.parse::<f64>().ok(),
            "sitemap" if sitemaps.len() < 50 => sitemaps.push(truncate_chars(v, 300)),
            _ => {}
        }
    }
    cx.format_set("kind", "robots.txt");
    cx.format_set("groups", groups);
    cx.format_set("user_agents", json!(agents));
    cx.format_set("rules", json!({ "allow": allow, "disallow": disallow }));
    cx.format_set("blocks_all_crawlers", blocks_all);
    if !ai_blocked.is_empty() {
        cx.format_set("ai_crawlers_blocked", json!(ai_blocked));
    }
    if let Some(d) = delay {
        cx.format_set("crawl_delay", d);
    }
    if !sitemaps.is_empty() {
        cx.security().external_references(sitemaps.len() as u64);
        cx.format_set("sitemaps", json!(sitemaps));
    }
}

fn security_txt(text: &str, cx: &mut Context<'_>) {
    let mut fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('#') || l.starts_with('-') {
            continue;
        }
        if let Some((k, v)) = l.split_once(':')
            && !k.contains(' ')
        {
            let list = fields.entry(k.trim().to_ascii_lowercase()).or_default();
            if list.len() < 20 {
                list.push(v.trim().to_string());
            }
        }
    }
    cx.format_set("kind", "security.txt");
    cx.format_set("signed", text.contains("-----BEGIN PGP SIGNED MESSAGE-----"));
    if let Some(e) = fields.get("expires").and_then(|v| v.first()) {
        cx.temporal().content_date(DateField::Expires, e.clone(), true);
        cx.format_set("expires", e.as_str());
    }
    // Contacts: the scheme and, for addresses, only the domain.
    if let Some(c) = fields.get("contact") {
        let shown: Vec<String> = c
            .iter()
            .map(|c| match c.split_once(':') {
                Some(("mailto", addr)) => format!("mailto:…@{}", addr.rsplit('@').next().unwrap_or("")),
                Some(("tel", _)) => "tel:…".to_string(),
                _ => truncate_chars(c, 300),
            })
            .collect();
        cx.format_set("contact", json!(shown));
    }
    for k in ["encryption", "acknowledgments", "policy", "hiring", "canonical", "preferred-languages", "csaf"] {
        if let Some(v) = fields.get(k) {
            cx.format_set(&k.replace('-', "_"), json!(v.iter().map(|s| truncate_chars(s, 300)).collect::<Vec<_>>()));
        }
    }
}

fn humans_txt(text: &str, cx: &mut Context<'_>) {
    let sections: Vec<String> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("/*").and_then(|r| r.strip_suffix("*/")))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .take(50)
        .collect();
    cx.format_set("kind", "humans.txt");
    cx.format_set("sections", json!(sections));
}

// --- proxy auto-config -----------------------------------------------------

fn pac(text: &str, cx: &mut Context<'_>) {
    static RETURN: LazyLock<Regex> =
        LazyLock::new(|| regex(r"(?i)(PROXY|SOCKS[45]?|HTTPS?)\s+([A-Za-z0-9_.\-\[\]:]+)"));
    static CALL: LazyLock<Regex> = LazyLock::new(|| {
        regex(
            r"(?-u:\b)(isPlainHostName|dnsDomainIs|localHostOrDomainIs|isResolvable|isInNet|dnsResolve|myIpAddress|dnsDomainLevels|shExpMatch|weekdayRange|dateRange|timeRange|alert)\s*\(",
        )
    });
    let mut proxies: BTreeSet<String> = BTreeSet::new();
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    for c in RETURN.captures_iter(text) {
        *kinds.entry(c[1].to_ascii_uppercase()).or_default() += 1;
        if proxies.len() < 100 {
            proxies.insert(c[2].to_string());
        }
    }
    let mut calls: BTreeMap<String, u64> = BTreeMap::new();
    for c in CALL.captures_iter(text) {
        *calls.entry(c[1].to_string()).or_default() += 1;
    }
    cx.security().active_content("javascript");
    cx.format_set("proxies", json!(proxies));
    cx.format_set("proxy_kinds", json!(kinds));
    cx.format_set("direct", text.contains("DIRECT"));
    if !calls.is_empty() {
        cx.format_set("functions_used", json!(calls));
    }
}

// --- Metalink --------------------------------------------------------------

fn metalink(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut stack: Vec<String> = Vec::new();
    let (mut files, mut urls, mut size, mut hashes) = (Vec::new(), 0u64, 0u64, BTreeSet::new());
    let mut hosts: BTreeMap<String, u64> = BTreeMap::new();
    let (mut version, mut generator, mut published) = (None, None, None);
    walk(text, cx, 1_000_000, |_, ev| match ev {
        Ev::Start(name, attrs) => {
            match name {
                "metalink" => {
                    let v = attrs.iter().find(|(k, _)| k == "version").map(|(_, v)| v.clone());
                    version = Some(v.unwrap_or_else(|| "4.0".into()));
                }
                "file" => {
                    if let Some((_, n)) = attrs.iter().find(|(k, _)| k == "name")
                        && files.len() < 200
                    {
                        files.push(truncate_chars(n, 300));
                    }
                }
                "hash" => {
                    if let Some((_, t)) = attrs.iter().find(|(k, _)| k == "type") {
                        hashes.insert(t.to_ascii_lowercase());
                    }
                }
                _ => {}
            }
            stack.push(name.to_string());
        }
        Ev::End(_) => {
            stack.pop();
        }
        Ev::Text(t) => match stack.last().map(String::as_str) {
            Some("url") => {
                urls += 1;
                if let Some(h) = host_of(t) {
                    *hosts.entry(h).or_default() += 1;
                }
            }
            Some("size") => size += t.parse::<u64>().unwrap_or(0),
            Some("generator") => generator = Some(truncate_chars(t, 200)),
            Some("published" | "pubdate") => published = Some(t.to_string()),
            _ => {}
        },
    })?;
    if let Some(v) = version {
        cx.format_set("version", v);
    }
    if let Some(g) = generator {
        cx.format_set("generator", g);
    }
    if let Some(p) = published {
        cx.temporal().content_date(DateField::Published, p, true);
    }
    cx.format_set("file_count", files.len());
    cx.format_set("files", json!(files));
    if size > 0 {
        cx.format_set("total_size", size);
    }
    cx.format_set("urls", urls);
    cx.security().external_references(urls);
    if !hosts.is_empty() {
        cx.format_set("top_hosts", top(&hosts, 10));
    }
    if !hashes.is_empty() {
        cx.format_set("hash_types", json!(hashes));
    }
    Ok(())
}

// --- Adblock filter lists --------------------------------------------------

fn adblock(text: &str, cx: &mut Context<'_>) {
    let mut header = Map::new();
    let (mut network, mut exceptions, mut hiding, mut hiding_exceptions, mut scriptlets) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('[') {
            continue;
        }
        if let Some(c) = t.strip_prefix('!') {
            if let Some((k, v)) = c.split_once(':') {
                let k = k.trim().to_ascii_lowercase();
                if matches!(
                    k.as_str(),
                    "title" | "version" | "last modified" | "expires" | "homepage" | "license" | "description"
                ) && !header.contains_key(&k)
                {
                    header.insert(k.replace(' ', "_"), json!(truncate_chars(v.trim(), 300)));
                }
            }
            continue;
        }
        if t.contains("#@#") {
            hiding_exceptions += 1;
        } else if t.contains("##+js(") || t.contains("#%#") {
            scriptlets += 1;
        } else if t.contains("##") || t.contains("#?#") {
            hiding += 1;
        } else if t.starts_with("@@") {
            exceptions += 1;
        } else {
            network += 1;
        }
    }
    if let Some(t) = header.get("title").and_then(Value::as_str) {
        cx.content().title(t.to_string());
    }
    if !header.is_empty() {
        cx.format_set("header", Value::Object(header));
    }
    cx.format_set(
        "rules",
        json!({
            "network": network, "exceptions": exceptions, "element_hiding": hiding,
            "element_hiding_exceptions": hiding_exceptions, "scriptlets": scriptlets,
        }),
    );
}

// --- cookie jars -----------------------------------------------------------

fn cookies(text: &str, cx: &mut Context<'_>) {
    let (mut n, mut secure, mut http_only, mut session) = (0u64, 0u64, 0u64, 0u64);
    let mut domains: BTreeMap<String, u64> = BTreeMap::new();
    let (mut first, mut last) = (i64::MAX, i64::MIN);
    for line in text.lines() {
        let (line, ho) = match line.strip_prefix("#HttpOnly_") {
            Some(rest) => (rest, true),
            None if line.starts_with('#') => continue,
            None => (line, false),
        };
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 7 {
            continue;
        }
        n += 1;
        http_only += u64::from(ho);
        secure += u64::from(f[3].eq_ignore_ascii_case("TRUE"));
        match f[4].parse::<i64>() {
            Ok(0) | Err(_) => session += 1,
            Ok(t) => {
                first = first.min(t);
                last = last.max(t);
            }
        }
        if domains.len() < 10_000 {
            *domains.entry(f[0].trim_start_matches('.').to_ascii_lowercase()).or_default() += 1;
        }
    }
    cx.format_set("cookies", n);
    cx.format_set("domains", domains.len());
    cx.format_set("secure", secure);
    cx.format_set("http_only", http_only);
    cx.format_set("session_cookies", session);
    if first <= last {
        let at = |t| super::unix_time(t).map_or(Value::Null, Value::String);
        cx.format_set("expiry", json!({ "first": at(first), "last": at(last) }));
    }
    if !cx.privacy_strict() && !domains.is_empty() {
        cx.format_set("top_domains", top(&domains, 20));
    }
    if n > 0 {
        cx.security().risk("embedded_secret", Some(format!("{n} browser cookies (session tokens)")));
    }
}

// --- bookmarks -------------------------------------------------------------

fn bookmarks(text: &str, cx: &mut Context<'_>) {
    static ADD_DATE: LazyLock<Regex> = LazyLock::new(|| regex(r#"(?i)ADD_DATE="(\d+)""#));
    static HREF: LazyLock<Regex> = LazyLock::new(|| regex(r#"(?i)<A\s[^>]*HREF="([^"]+)""#));
    let (mut count, mut folders, mut times) = (0u64, 0u64, Vec::new());
    let mut hosts: BTreeMap<String, u64> = BTreeMap::new();
    let mut add = |url: &str, hosts: &mut BTreeMap<String, u64>| {
        count += 1;
        if let Some(h) = host_of(url)
            && hosts.len() < 10_000
        {
            *hosts.entry(h).or_default() += 1;
        }
    };
    let kind;
    if text.trim_start().starts_with('{') {
        let v: Value = serde_json::from_str(text).unwrap_or(Value::Null);
        kind = if v.get("roots").is_some() { "chrome" } else { "firefox" };
        // Walk iteratively: folders hold `children`.
        let mut stack = vec![&v];
        while let Some(node) = stack.pop() {
            match node {
                Value::Object(m) => {
                    let url = m.get("url").or_else(|| m.get("uri")).and_then(Value::as_str);
                    if let Some(u) = url {
                        add(u, &mut hosts);
                        for k in ["date_added", "dateAdded"] {
                            // Chrome: µs since 1601; Firefox: µs since 1970.
                            if let Some(t) = m
                                .get(k)
                                .and_then(|t| t.as_str().and_then(|s| s.parse::<i64>().ok()).or_else(|| t.as_i64()))
                            {
                                let secs =
                                    if k == "date_added" { t / 1_000_000 - 11_644_473_600 } else { t / 1_000_000 };
                                times.push(secs);
                            }
                        }
                    } else if m.contains_key("children") {
                        folders += 1;
                    }
                    if stack.len() < 100_000 {
                        stack.extend(m.values());
                    }
                }
                Value::Array(a) if stack.len() < 100_000 => stack.extend(a),
                _ => {}
            }
        }
    } else {
        kind = "netscape_html";
        folders = text.matches("<H3").count() as u64 + text.matches("<h3").count() as u64;
        for c in HREF.captures_iter(text) {
            add(&c[1], &mut hosts);
        }
        times.extend(ADD_DATE.captures_iter(text).filter_map(|c| c[1].parse::<i64>().ok()));
    }
    cx.format_set("export", kind);
    cx.format_set("bookmarks", count);
    cx.format_set("folders", folders);
    cx.format_set("hosts", hosts.len());
    if let (Some(a), Some(b)) = (times.iter().min(), times.iter().max()) {
        let at = |t: i64| super::unix_time(t).map_or(Value::Null, Value::String);
        cx.format_set("added", json!({ "first": at(*a), "last": at(*b) }));
    }
    if !cx.privacy_strict() && !hosts.is_empty() {
        cx.format_set("top_hosts", top(&hosts, 20));
    }
}

// --- .netrc, .wgetrc, .curlrc ----------------------------------------------

fn credentials(text: &str, name: &str, cx: &mut Context<'_>) {
    // `.netrc`, `_netrc`, `work.netrc` …
    if name.ends_with("netrc") {
        return netrc(text, cx);
    }
    let tool = if name.ends_with("curlrc") { "curl" } else { "wget" };
    let mut options: BTreeMap<String, u64> = BTreeMap::new();
    let (mut passwords, mut insecure, mut proxy) = (0u64, false, false);
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let (k, v) = t.split_once(['=', ':', ' ', '\t']).unwrap_or((t, ""));
        let k = k.trim().trim_start_matches('-').to_ascii_lowercase().replace('-', "_");
        let v = v.trim().trim_start_matches(['=', ':']).trim().trim_matches('"');
        if options.len() < 200 {
            *options.entry(k.clone()).or_default() += 1;
        }
        passwords += u64::from(
            k.ends_with("password")
                || k == "pass"
                || ((k == "user" || k == "u" || k == "proxy_user") && v.contains(':')),
        );
        insecure |= k == "insecure" || k == "k" || (k == "check_certificate" && v.eq_ignore_ascii_case("off"));
        proxy |= k.contains("proxy");
    }
    cx.format_set("tool", tool);
    cx.format_set("options", json!(options));
    cx.format_set("tls_verification_off", insecure);
    cx.format_set("proxy", proxy);
    if passwords > 0 {
        cx.security().risk("embedded_secret", Some(format!("{passwords} passwords in the {tool} configuration")));
    }
}

fn netrc(text: &str, cx: &mut Context<'_>) {
    let (mut machines, mut logins, mut passwords, mut default, mut macros) = (Vec::new(), 0u64, 0u64, false, 0u64);
    let mut words = text.split_whitespace();
    while let Some(w) = words.next() {
        match w {
            "machine" => {
                if let Some(m) = words.next()
                    && machines.len() < 500
                {
                    machines.push(m.to_ascii_lowercase());
                }
            }
            "default" => default = true,
            "login" => {
                words.next();
                logins += 1;
            }
            "password" | "account" => {
                words.next();
                passwords += u64::from(w == "password");
            }
            "macdef" => {
                words.next();
                macros += 1;
            }
            _ => {}
        }
    }
    cx.format_set("tool", "netrc");
    cx.format_set("machines", machines.len());
    if !cx.privacy_strict() {
        cx.format_set("machine_names", json!(machines));
    }
    cx.format_set("default_entry", default);
    cx.format_set("logins", logins);
    if macros > 0 {
        cx.format_set("macros", macros);
    }
    if passwords > 0 {
        cx.security().risk("embedded_secret", Some(format!("{passwords} passwords in .netrc")));
    }
}

// --- WARC ------------------------------------------------------------------

fn warc(b: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut payloads: BTreeMap<String, u64> = BTreeMap::new();
    let mut hosts: BTreeMap<String, u64> = BTreeMap::new();
    let (mut pos, mut records, mut uris) = (0usize, 0u64, 0u64);
    let (mut first, mut last): (Option<String>, Option<String>) = (None, None);
    let (mut version, mut software) = (None, None);
    while pos < b.len() && records < 1_000_000 {
        if records % 1024 == 0 {
            cx.checkpoint()?;
        }
        // Skip the CRLF pairs between records.
        while pos < b.len() && matches!(b[pos], b'\r' | b'\n') {
            pos += 1;
        }
        let Some(end) = find(&b[pos..], b"\r\n\r\n").map(|e| pos + e) else { break };
        let head = String::from_utf8_lossy(&b[pos..end]);
        let mut lines = head.lines();
        let Some(v) = lines.next().filter(|l| l.starts_with("WARC/")) else {
            cx.warn(format!("no WARC record at offset {pos}"));
            break;
        };
        version.get_or_insert_with(|| v.trim_start_matches("WARC/").trim().to_string());
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        for l in lines {
            if let Some((k, val)) = l.split_once(':') {
                fields.insert(k.trim().to_ascii_lowercase(), val.trim().to_string());
            }
        }
        let len: usize = fields.get("content-length").and_then(|l| l.parse().ok()).unwrap_or(0);
        let body_start = end + 4;
        let body = b.get(body_start..body_start.saturating_add(len)).unwrap_or(&b[body_start.min(b.len())..]);
        records += 1;
        let kind = fields.get("warc-type").cloned().unwrap_or_default();
        *types.entry(kind.clone()).or_default() += 1;
        if let Some(d) = fields.get("warc-date") {
            if first.as_ref().is_none_or(|f| d < f) {
                first = Some(d.clone());
            }
            if last.as_ref().is_none_or(|l| d > l) {
                last = Some(d.clone());
            }
        }
        if let Some(u) = fields.get("warc-target-uri") {
            uris += 1;
            if let Some(h) = host_of(u.trim_matches(['<', '>']))
                && hosts.len() < 10_000
            {
                *hosts.entry(h).or_default() += 1;
            }
        }
        if kind == "warcinfo" {
            for l in String::from_utf8_lossy(&body[..body.len().min(4096)]).lines() {
                if let Some(s) = l.strip_prefix("software:") {
                    software.get_or_insert_with(|| truncate_chars(s.trim(), 200));
                }
            }
        }
        if kind == "response" {
            // The HTTP response's Content-Type.
            let http = String::from_utf8_lossy(&body[..body.len().min(8192)]);
            if let Some(ct) = http.lines().take_while(|l| !l.is_empty()).find_map(|l| {
                l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.trim())
            }) {
                let ct = ct.split(';').next().unwrap_or(ct).trim().to_ascii_lowercase();
                if payloads.len() < 100 || payloads.contains_key(&ct) {
                    *payloads.entry(ct).or_default() += 1;
                }
            }
        }
        pos = body_start.saturating_add(len);
    }
    if let Some(v) = version {
        cx.format_set("version", v);
    }
    if let Some(s) = software {
        cx.format_set("software", s);
    }
    cx.format_set("records", records);
    cx.format_set("record_types", json!(types));
    cx.format_set("target_uris", uris);
    if !hosts.is_empty() {
        cx.format_set("top_hosts", top(&hosts, 10));
    }
    if !payloads.is_empty() {
        cx.format_set("payload_types", json!(payloads));
    }
    if let (Some(a), Some(z)) = (first, last) {
        cx.temporal().content_date(DateField::Created, a.clone(), true);
        cx.format_set("dates", json!({ "first": a, "last": z }));
    }
    Ok(())
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(host_of("https://user@www.Example.org:8443/x").as_deref(), Some("example.org"));
        assert_eq!(host_of("relative/path"), None);
    }

    crate::fixture_tests!("robots_txt", "pac", "metalink", "adblock_list", "cookie_jar", "bookmarks", "netrc", "warc");
}
