//! Distribution and R packaging: R `DESCRIPTION`, Debian `debian/control`,
//! `debian/changelog` and machine-readable `debian/copyright` (DEP-5),
//! Arch `PKGBUILD` and RPM `.spec` files. Shell and RPM macros are read as
//! text, never expanded beyond simple `%{name}` substitutions.
//!
//! People are reported by name only: e-mail addresses are dropped.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

use super::{MAX_DEPS, Package, put_pairs};
use crate::plugin::{Context, DateField, TextRole, parse_date, redact_secrets, truncate_chars};

pub(super) fn extract(id: &str, text: &str, cx: &mut Context<'_>) {
    match id {
        "r_description" => r_description(text, cx),
        "debian_control" => debian_control(text, cx),
        "debian_changelog" => debian_changelog(text, cx),
        "debian_copyright" => debian_copyright(text, cx),
        "pkgbuild" => pkgbuild(text, cx),
        _ => rpm_spec(text, cx),
    }
}

type Paragraph = Vec<(String, String)>;

/// Debian control (DCF / deb822) paragraphs: `Key: value` fields with
/// indented continuation lines, separated by blank lines.
fn dcf(text: &str) -> Vec<Paragraph> {
    let mut out: Vec<Paragraph> = vec![Vec::new()];
    for line in text.lines() {
        if line.trim().is_empty() {
            if out.last().is_some_and(|p| !p.is_empty()) {
                out.push(Vec::new());
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let para = out.last_mut().expect("never empty");
        if line.starts_with([' ', '\t']) {
            if let Some((_, v)) = para.last_mut() {
                v.push('\n');
                v.push_str(line.trim());
            }
        } else if let Some((k, v)) = line.split_once(':') {
            para.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    out.retain(|p| !p.is_empty());
    out
}

fn field<'p>(p: &'p Paragraph, key: &str) -> Option<&'p str> {
    p.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v.as_str())
}

/// `Ada Lovelace <ada@example.org>` → `Ada Lovelace`.
fn name_only(person: &str) -> String {
    person.split('<').next().unwrap_or(person).trim().trim_matches('"').to_string()
}

/// `pkg (>= 1.0), other [amd64] | alt` → (`pkg`, `>= 1.0`), (`other`, `*`), …
fn relations(list: &str) -> Vec<(String, String)> {
    list.split(',')
        .flat_map(|alt| alt.split('|').take(1))
        .filter_map(|d| {
            let d = d.trim();
            let name = d.split([' ', '(', '[', '<', '\n']).next()?.trim();
            if name.is_empty() || name.starts_with('$') {
                return None;
            }
            let version = d.split_once('(').and_then(|(_, r)| r.split(')').next()).map_or("*", str::trim);
            Some((name.to_string(), version.split_whitespace().collect::<Vec<_>>().join(" ")))
        })
        .collect()
}

fn r_description(text: &str, cx: &mut Context<'_>) {
    let paras = dcf(text);
    let Some(p) = paras.first() else { return };
    let mut authors: Vec<String> = Vec::new();
    if let Some(a) = field(p, "Authors@R") {
        static PERSON: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r#"person\(\s*(?:given\s*=\s*)?(?:c\()?"([^"]+)"[^,)]*(?:,\s*(?:family\s*=\s*)?"([^"]+)")?"#)
                .expect("valid")
        });
        authors.extend(PERSON.captures_iter(a).map(|c| match c.get(2) {
            Some(f) => format!("{} {}", &c[1], f.as_str()),
            None => c[1].to_string(),
        }));
    } else if let Some(a) = field(p, "Author") {
        authors.extend(
            a.split([',', '\n'])
                .map(|x| x.split('[').next().unwrap_or(x).trim().to_string())
                .filter(|x| !x.is_empty() && x != "and"),
        );
    }
    let url = field(p, "URL").map(|u| u.split([',', ' ', '\n']).next().unwrap_or(u));
    let title = field(p, "Title");
    Package {
        ecosystem: "cran",
        name: field(p, "Package"),
        version: field(p, "Version"),
        description: field(p, "Description"),
        license: field(p, "License"),
        authors,
        repository: url,
    }
    .write(cx);
    if let Some(t) = title {
        cx.content().source("r.description").title(t.replace('\n', " "));
    }
    if let Some(m) = field(p, "Maintainer") {
        cx.format_set("maintainer", name_only(m));
    }
    let mut requires_r = None;
    for (key, group) in
        [("Depends", "depends"), ("Imports", "dependencies"), ("Suggests", "suggests"), ("LinkingTo", "linking_to")]
    {
        let Some(list) = field(p, key) else { continue };
        let (r, pkgs): (Vec<_>, Vec<_>) = relations(list).into_iter().partition(|(n, _)| n == "R");
        requires_r = requires_r.or_else(|| r.into_iter().next().map(|(_, v)| v));
        put_pairs(cx, group, pkgs);
    }
    if let Some(r) = requires_r {
        cx.format_set("requires_r", r);
    }
    for (key, out) in [
        ("Encoding", "encoding"),
        ("NeedsCompilation", "needs_compilation"),
        ("Repository", "repository_name"),
        ("RoxygenNote", "roxygen_version"),
        ("BugReports", "bug_reports"),
    ] {
        if let Some(v) = field(p, key) {
            cx.format_set(out, v);
        }
    }
    if let Some((d, tz)) = field(p, "Date/Publication").and_then(parse_date) {
        cx.temporal().content_date(DateField::Published, d, tz);
    }
}

fn debian_control(text: &str, cx: &mut Context<'_>) {
    let paras = dcf(text);
    let Some(first) = paras.first() else { return };
    let source = field(first, "Source").is_some();
    let binaries: Vec<&Paragraph> = paras.iter().filter(|p| field(p, "Package").is_some()).collect();
    let synopsis = |p: &Paragraph| field(p, "Description").map(|d| d.lines().next().unwrap_or("").to_string());
    let name = field(first, "Source").or_else(|| field(first, "Package"));
    let description = if source { None } else { synopsis(first) };
    Package {
        ecosystem: "debian",
        name,
        version: field(first, "Version"),
        description: description.as_deref(),
        license: None,
        authors: Vec::new(),
        repository: field(first, "Vcs-Git").or_else(|| field(first, "Vcs-Browser")),
    }
    .write(cx);
    cx.format_set("control_kind", if source { "source" } else { "binary" });
    if let Some(m) = field(first, "Maintainer") {
        cx.format_set("maintainer", name_only(m));
    }
    if let Some(u) = field(first, "Uploaders") {
        cx.format_set("uploaders", u.split(',').filter(|x| !x.trim().is_empty()).count());
    }
    for (key, out) in [
        ("Section", "section"),
        ("Priority", "priority"),
        ("Standards-Version", "standards_version"),
        ("Homepage", "homepage"),
        ("Architecture", "architecture"),
        ("Rules-Requires-Root", "rules_requires_root"),
        ("Installed-Size", "installed_size_kib"),
    ] {
        if let Some(v) = field(first, key) {
            cx.format_set(out, v);
        }
    }
    for (key, group) in [("Build-Depends", "build_dependencies"), ("Build-Depends-Indep", "build_dependencies_indep")] {
        if let Some(list) = field(first, key) {
            put_pairs(cx, group, relations(list));
        }
    }
    let mut depends = BTreeMap::new();
    for p in &binaries {
        for key in ["Depends", "Pre-Depends"] {
            for (n, v) in field(p, key).map(relations).unwrap_or_default() {
                depends.entry(n).or_insert(v);
            }
        }
    }
    put_pairs(cx, "dependencies", depends);
    if source {
        let list: Vec<Value> = binaries
            .iter()
            .take(MAX_DEPS)
            .map(|p| json!({ "name": field(p, "Package"), "architecture": field(p, "Architecture"), "synopsis": synopsis(p) }))
            .collect();
        cx.format_set("binary_packages", Value::Array(list));
    }
}

/// `pkg (1.2-1) unstable; urgency=medium`
pub(super) fn is_debian_changelog_line(line: &str) -> bool {
    changelog_header(line).is_some()
}

fn changelog_header(line: &str) -> Option<(&str, &str, &str, &str)> {
    let (package, rest) = line.split_once(" (")?;
    let (version, rest) = rest.split_once(") ")?;
    let (dists, rest) = rest.split_once(';')?;
    let urgency = rest.split("urgency=").nth(1)?.split([',', ' ']).next()?;
    let valid = !package.is_empty() && package.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c));
    valid.then_some((package, version, dists.trim(), urgency))
}

fn debian_changelog(text: &str, cx: &mut Context<'_>) {
    let mut entries: Vec<Map<String, Value>> = Vec::new();
    let mut maintainers = BTreeSet::new();
    let mut package = None;
    for line in text.lines() {
        if let Some((p, version, dist, urgency)) = changelog_header(line) {
            package.get_or_insert_with(|| p.to_string());
            let mut e = Map::new();
            e.insert("version".into(), json!(version));
            e.insert("distribution".into(), json!(dist));
            e.insert("urgency".into(), json!(urgency));
            entries.push(e);
        } else if let Some(trailer) = line.strip_prefix(" -- ")
            && let Some((who, date)) = trailer.split_once(">  ").or_else(|| trailer.split_once("> "))
        {
            maintainers.insert(name_only(who));
            if let (Some(e), Some((d, _))) = (entries.last_mut(), parse_date(date)) {
                e.insert("date".into(), json!(d));
            }
        }
    }
    cx.format_set("ecosystem", "debian");
    if let Some(p) = &package {
        cx.format_set("name", p.as_str());
        cx.content().source("debian.changelog").title(p.as_str());
    }
    cx.format_set("entries", entries.len());
    cx.format_set("maintainers", maintainers.len());
    if let Some(latest) = entries.first() {
        cx.format_set("latest", Value::Object(latest.clone()));
        if let Some(d) = latest.get("date").and_then(Value::as_str) {
            cx.temporal().content_date(DateField::Modified, d.to_string(), true);
        }
    }
    if let Some(oldest) = entries.last().filter(|_| entries.len() > 1) {
        cx.format_set("oldest", Value::Object(oldest.clone()));
        if let Some(d) = oldest.get("date").and_then(Value::as_str) {
            cx.temporal().content_date(DateField::Created, d.to_string(), true);
        }
    }
}

fn debian_copyright(text: &str, cx: &mut Context<'_>) {
    let paras = dcf(text);
    let Some(header) = paras.first() else { return };
    cx.format_set("ecosystem", "debian");
    if let Some(f) = field(header, "Format") {
        cx.format_set("format", f);
    }
    if let Some(n) = field(header, "Upstream-Name") {
        cx.format_set("upstream_name", n);
        cx.content().source("debian.copyright").title(n);
    }
    if let Some(c) = field(header, "Upstream-Contact") {
        cx.format_set("upstream_contact", name_only(c.lines().next().unwrap_or(c)));
    }
    if let Some(s) = field(header, "Source") {
        cx.format_set("source", redact_secrets(s).as_ref());
    }
    let mut licenses: BTreeMap<String, u64> = BTreeMap::new();
    let mut files = 0u64;
    for p in &paras[1..] {
        let Some(l) = field(p, "License") else { continue };
        let short = l.lines().next().unwrap_or(l).trim().to_string();
        if let Some(pattern) = field(p, "Files") {
            files += 1;
            if pattern.split_whitespace().any(|f| f == "*") {
                cx.rights().source("debian.copyright").license(Some(&short), None);
                if let Some(c) = field(p, "Copyright") {
                    cx.rights().copyright(truncate_chars(c.lines().next().unwrap_or(c), 300));
                }
            }
            *licenses.entry(short).or_default() += 1;
        }
    }
    cx.format_set("files_paragraphs", files);
    cx.format_set("licenses", json!(licenses));
    let standalone = paras[1..].iter().filter(|p| field(p, "Files").is_none() && field(p, "License").is_some()).count();
    if standalone > 0 {
        cx.format_set("license_paragraphs", standalone);
    }
}

/// Shell assignments `name=value` and arrays `name=(a 'b c')`, possibly over several lines.
fn shell_vars(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let t = line.trim_start();
        let Some((name, value)) = t.split_once('=') else { continue };
        if line.starts_with([' ', '\t'])
            || name.is_empty()
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        let words = if let Some(body) = value.strip_prefix('(') {
            let mut body = body.to_string();
            while !closes(&body) {
                let Some(next) = lines.next() else { break };
                body.push('\n');
                body.push_str(next);
            }
            let body = body.rsplit_once(')').map_or(body.as_str(), |(b, _)| b).to_string();
            shell_words(&body)
        } else {
            shell_words(value).into_iter().take(1).collect()
        };
        out.entry(name.to_string()).or_insert(words);
    }
    out
}

/// Whether an array body has its closing `)` outside quotes.
fn closes(body: &str) -> bool {
    let mut quote = None;
    for c in body.chars() {
        match (quote, c) {
            (None, '\'' | '"') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, ')') => return true,
            _ => {}
        }
    }
    false
}

/// Words of a shell line, with quotes removed and `#` comments dropped.
fn shell_words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote = None;
    let mut any = false;
    for c in s.chars() {
        match (quote, c) {
            (None, '\'' | '"') => {
                quote = Some(c);
                any = true;
            }
            (Some(q), c) if c == q => quote = None,
            (None, '#') if cur.is_empty() => break,
            (None, c) if c.is_whitespace() => {
                if any || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                any = false;
            }
            _ => cur.push(c),
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn pkgbuild(text: &str, cx: &mut Context<'_>) {
    static FUNC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^(\w+)\s*\(\)\s*\{?").expect("valid"));
    let vars = shell_vars(text);
    let one = |k: &str| vars.get(k).and_then(|v| v.first()).map(String::as_str);
    let names = vars.get("pkgname").cloned().unwrap_or_default();
    let version = match (one("epoch"), one("pkgver"), one("pkgrel")) {
        (e, Some(v), r) => Some(format!(
            "{}{v}{}",
            e.map(|e| format!("{e}:")).unwrap_or_default(),
            r.map(|r| format!("-{r}")).unwrap_or_default()
        )),
        _ => None,
    };
    Package {
        ecosystem: "arch",
        name: one("pkgbase").or_else(|| names.first().map(String::as_str)),
        version: version.as_deref(),
        description: one("pkgdesc"),
        license: vars.get("license").and_then(|l| l.first()).map(String::as_str),
        authors: Vec::new(),
        repository: one("url"),
    }
    .write(cx);
    if names.len() > 1 {
        cx.format_set("split_packages", json!(names));
    }
    if let Some(a) = vars.get("arch") {
        cx.format_set("arch", json!(a));
    }
    for (var, group) in [
        ("depends", "dependencies"),
        ("makedepends", "build_dependencies"),
        ("checkdepends", "check_dependencies"),
        ("optdepends", "optional_dependencies"),
    ] {
        let Some(list) = vars.get(var) else { continue };
        put_pairs(cx, group, list.iter().map(|d| split_constraint(d.split(':').next().unwrap_or(d))));
    }
    if let Some(src) = vars.get("source") {
        let vcs = src.iter().filter(|s| s.contains("git+") || s.contains("hg+") || s.contains("svn+")).count();
        cx.format_set("sources", src.len());
        if vcs > 0 {
            cx.format_set("vcs_sources", vcs);
        }
    }
    let skipped: usize = ["sha256sums", "sha512sums", "b2sums", "md5sums", "sha1sums"]
        .iter()
        .filter_map(|k| vars.get(*k))
        .map(|v| v.iter().filter(|s| *s == "SKIP").count())
        .sum();
    let algorithms: Vec<&str> = ["sha256sums", "sha512sums", "b2sums", "md5sums", "sha1sums"]
        .into_iter()
        .filter(|k| vars.contains_key(*k))
        .collect();
    if !algorithms.is_empty() {
        cx.format_set("checksums", json!(algorithms));
    }
    if skipped > 0 {
        cx.format_set("skipped_checksums", skipped);
    }
    if let Some(keys) = vars.get("validpgpkeys") {
        cx.format_set("pgp_keys", keys.len());
    }
    let functions: Vec<&str> = FUNC.captures_iter(text).map(|c| c.get(1).map_or("", |m| m.as_str())).collect();
    if !functions.is_empty() {
        cx.format_set("functions", json!(functions));
    }
    let maintainers =
        text.lines().filter(|l| l.starts_with("# Maintainer:") || l.starts_with("# Contributor:")).count();
    if maintainers > 0 {
        cx.format_set("maintainers", maintainers);
    }
    // An `.install` file runs shell functions as root when the package is installed.
    if let Some(i) = one("install") {
        cx.security().active_content("install_scripts").risk("install_script", Some(format!("PKGBUILD install={i}")));
    }
}

/// `python>=3.11` → (`python`, `>=3.11`).
fn split_constraint(d: &str) -> (String, String) {
    let d = d.trim();
    match d.find(['<', '>', '=']) {
        Some(i) => (d[..i].to_string(), d[i..].to_string()),
        None => (d.to_string(), "*".into()),
    }
}

/// RPM spec sections other than scriptlets.
const SECTIONS: &[&str] = &[
    "%description",
    "%package",
    "%prep",
    "%conf",
    "%generate_buildrequires",
    "%build",
    "%install",
    "%check",
    "%clean",
    "%files",
    "%changelog",
    "%sourcelist",
    "%patchlist",
];

/// RPM scriptlets: shell run by the package manager around install / removal.
const SCRIPTLETS: &[&str] = &[
    "%pre",
    "%post",
    "%preun",
    "%postun",
    "%pretrans",
    "%posttrans",
    "%preuntrans",
    "%postuntrans",
    "%triggerin",
    "%triggerun",
    "%triggerpostun",
    "%verifyscript",
];

#[allow(clippy::too_many_lines)]
fn rpm_spec(text: &str, cx: &mut Context<'_>) {
    let mut defines: BTreeMap<String, String> = BTreeMap::new();
    let mut tags: Vec<(String, String)> = Vec::new();
    let mut section = String::from("preamble");
    let mut description = String::new();
    let mut subpackages = Vec::new();
    let mut scriptlets = BTreeSet::new();
    let mut changelog: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("%global ").or_else(|| t.strip_prefix("%define ")) {
            if let Some((k, v)) = rest.trim().split_once(char::is_whitespace) {
                defines.insert(k.to_string(), v.trim().to_string());
            }
            continue;
        }
        if t.starts_with('%') {
            let word = t.split_whitespace().next().unwrap_or(t);
            if SECTIONS.contains(&word) || SCRIPTLETS.contains(&word) {
                section = word.to_string();
                if section == "%package" {
                    subpackages.push(t.split_whitespace().last().unwrap_or("").to_string());
                }
                if SCRIPTLETS.contains(&word) {
                    scriptlets.insert(word.to_string());
                }
                continue;
            }
        }
        match section.as_str() {
            "preamble" | "%package" => {
                if let Some((k, v)) = t.split_once(':')
                    && !k.is_empty()
                    && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '(' || c == ')')
                {
                    tags.push((k.to_string(), v.trim().to_string()));
                }
            }
            "%description" if description.len() < 4000 => {
                description.push_str(t);
                description.push('\n');
            }
            "%changelog" => {
                if let Some(head) = t.strip_prefix("* ") {
                    let words: Vec<&str> = head.split_whitespace().collect();
                    let date = words.get(1..4).map(|w| w.join(" ")).unwrap_or_default();
                    let version = head.rsplit_once(" - ").map_or("", |(_, v)| v.trim()).to_string();
                    changelog.push((date, version));
                }
            }
            _ => {}
        }
    }
    let expand = |v: &str| expand_macros(v, &defines, &tags);
    let tag = |k: &str| tags.iter().find(|(t, _)| t.eq_ignore_ascii_case(k)).map(|(_, v)| expand(v));
    let (name, version, release) = (tag("Name"), tag("Version"), tag("Release"));
    let full = version.as_ref().map(|v| match &release {
        Some(r) => format!("{v}-{r}"),
        None => v.clone(),
    });
    let description = description.trim();
    Package {
        ecosystem: "rpm",
        name: name.as_deref(),
        version: full.as_deref(),
        description: tag("Summary").as_deref().or((!description.is_empty()).then_some(description)),
        license: tag("License").as_deref(),
        authors: Vec::new(),
        repository: tag("URL").as_deref(),
    }
    .write(cx);
    if !description.is_empty() {
        cx.emit_text(TextRole::Body, description);
    }
    for (k, out) in [("BuildArch", "build_arch"), ("Group", "group"), ("Epoch", "epoch")] {
        if let Some(v) = tag(k) {
            cx.format_set(out, v);
        }
    }
    let list = |key: &str| -> Vec<(String, String)> {
        tags.iter()
            .filter(|(t, _)| t.split('(').next().is_some_and(|b| b.eq_ignore_ascii_case(key)))
            .flat_map(|(_, v)| split_rpm_deps(&expand(v)))
            .collect()
    };
    put_pairs(cx, "build_dependencies", list("BuildRequires"));
    put_pairs(cx, "dependencies", list("Requires"));
    let count = |prefix: &str| {
        tags.iter().filter(|(t, _)| t.len() >= prefix.len() && t[..prefix.len()].eq_ignore_ascii_case(prefix)).count()
    };
    cx.format_set("sources", count("Source"));
    if count("Patch") > 0 {
        cx.format_set("patches", count("Patch"));
    }
    if !subpackages.is_empty() {
        cx.format_set("subpackages", json!(subpackages));
    }
    if !defines.is_empty() {
        cx.format_set("macro_definitions", defines.len());
    }
    cx.format_set("changelog_entries", changelog.len());
    if let Some((date, v)) = changelog.first() {
        if !v.is_empty() {
            cx.format_set("latest_changelog_version", v.as_str());
        }
        if let Some((d, tz)) = parse_date(date) {
            cx.temporal().content_date(DateField::Modified, d, tz);
        }
    }
    if !scriptlets.is_empty() {
        let list: Vec<String> = scriptlets.into_iter().collect();
        cx.format_set("scriptlets", json!(list));
        cx.security().active_content("install_scripts").risk("install_script", Some(list.join(", ")));
    }
}

/// `%{name}`, `%name`, `%{?dist}` from `%global` / `%define` and the preamble tags.
fn expand_macros(v: &str, defines: &BTreeMap<String, String>, tags: &[(String, String)]) -> String {
    let lookup = |k: &str| -> Option<String> {
        defines.get(k).cloned().or_else(|| tags.iter().find(|(t, _)| t.eq_ignore_ascii_case(k)).map(|(_, v)| v.clone()))
    };
    let mut out = v.to_string();
    for _ in 0..4 {
        if !out.contains('%') {
            break;
        }
        let mut next = String::new();
        let mut rest = out.as_str();
        while let Some(i) = rest.find('%') {
            next.push_str(&rest[..i]);
            let tail = &rest[i + 1..];
            let (key, used) = if let Some(body) = tail.strip_prefix('{') {
                match body.find('}') {
                    Some(j) => (&body[..j], j + 2),
                    None => (body, body.len() + 1),
                }
            } else {
                let j = tail.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(tail.len());
                (&tail[..j], j)
            };
            let optional = key.starts_with('?');
            let k = key.trim_start_matches(['?', '!']);
            match lookup(k) {
                Some(v) => next.push_str(&v),
                _ if optional => {}
                _ => {
                    next.push('%');
                    next.push_str(&tail[..used]);
                }
            }
            rest = &tail[used..];
        }
        next.push_str(rest);
        if next == out {
            break;
        }
        out = next;
    }
    out
}

/// `python3-devel >= 3.11, gcc make` → pairs.
fn split_rpm_deps(v: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let words: Vec<&str> = v.split([',', ' ']).filter(|w| !w.is_empty()).collect();
    let mut i = 0;
    while i < words.len() {
        let name = words[i];
        if matches!(words.get(i + 1), Some(&(">=" | "<=" | "=" | ">" | "<"))) && i + 2 < words.len() {
            out.push((name.to_string(), format!("{} {}", words[i + 1], words[i + 2])));
            i += 3;
        } else {
            out.push((name.to_string(), "*".into()));
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsers() {
        assert!(is_debian_changelog_line("tide-gauge (1.2-1) unstable; urgency=medium"));
        assert!(!is_debian_changelog_line("Version 1.2 (stable)"));
        assert_eq!(
            relations("libc6 (>= 2.36), python3 | python3-minimal"),
            [("libc6".into(), ">= 2.36".into()), ("python3".into(), "*".into())]
        );
        let vars = shell_vars("pkgname=tide\ndepends=('glibc'\n  'python>=3.11' # note\n)\n");
        assert_eq!(vars["depends"], ["glibc", "python>=3.11"]);
        let d = BTreeMap::from([("ver".to_string(), "1.4".to_string())]);
        let t = vec![("Name".to_string(), "tide".to_string())];
        assert_eq!(expand_macros("%{name}-%{ver}%{?dist}", &d, &t), "tide-1.4");
        assert_eq!(
            split_rpm_deps("python3-devel >= 3.11, gcc"),
            [("python3-devel".into(), ">= 3.11".into()), ("gcc".into(), "*".into())]
        );
    }

    #[test]
    fn install_hooks_are_flagged() {
        let spec = b"Name: tide\nVersion: 1\n%description\nx\n%post\n/bin/true\n";
        let r = crate::plugin::testing::report_for("tide.spec", spec);
        assert!(r.security.risks.iter().any(|x| x.kind == "install_script"));
        let r = crate::plugin::testing::report_for("PKGBUILD", b"pkgname=tide\npkgver=1\ninstall=tide.install\n");
        assert!(r.security.risks.iter().any(|x| x.kind == "install_script"));
    }
}
