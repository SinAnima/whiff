//! Ruby and Apple ecosystems: Bundler `Gemfile` / `Gemfile.lock`,
//! CocoaPods `Podfile` / `Podfile.lock`, `SwiftPM` `Package.swift` /
//! `Package.resolved`, Homebrew formulae, casks and `Brewfile`s. The Ruby
//! and Swift files are read as text, never run.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

use super::{MAX_DEPS, Package, parse_json, parse_yaml, put_pairs, quoted, s};
use crate::plugin::{Context, ExtractError, redact_secrets};

pub(super) fn extract(id: &str, text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    match id {
        "gemfile" => gemfile(text, cx),
        "gemfile_lock" => gemfile_lock(text, cx),
        "podfile" => podfile(text, cx),
        "podfile_lock" => podfile_lock(&parse_yaml(text)?, cx),
        "swift_package" => swift_package(text, cx),
        "swift_package_resolved" => swift_resolved(&parse_json(text)?, cx),
        "brewfile" => brewfile(text, cx),
        _ => homebrew(text, cx),
    }
    Ok(())
}

fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid pattern")
}

/// `gem "name", "~> 1.0", git: "…"` (and `pod`): the name, the first
/// version string and the source options.
fn dependency(line: &str, keyword: &str) -> Option<(String, String)> {
    let rest = line.trim_start().strip_prefix(keyword)?;
    if !rest.starts_with([' ', '(']) {
        return None;
    }
    let args = quoted(rest);
    let name = args.first()?.clone();
    let version =
        if let Some(src) = ["git:", "github:", "path:", ":git =>", ":path =>"].iter().find(|o| rest.contains(**o)) {
            let after = &rest[rest.find(src).unwrap_or(0) + src.len()..];
            format!(
                "{}: {}",
                src.trim_start_matches(':').split([':', ' ']).next().unwrap_or("source"),
                quoted(after).first().map_or("?", String::as_str)
            )
        } else {
            let versions: Vec<&String> = args
                .iter()
                .skip(1)
                .filter(|a| a.starts_with(|c: char| c.is_ascii_digit() || "~<>=!".contains(c)))
                .collect();
            if versions.is_empty() {
                "*".into()
            } else {
                versions.iter().map(|v| v.as_str()).collect::<Vec<_>>().join(", ")
            }
        };
    Some((name, version))
}

/// Nesting of `… do` blocks, with the group a block belongs to.
fn block_group(line: &str, stack: &mut Vec<Option<String>>, opener: &Regex) {
    let t = line.trim();
    if t == "end" || t.starts_with("end ") {
        stack.pop();
    } else if t.ends_with(" do") || t.contains(" do |") {
        let group = opener.captures(t).map(|c| c[1].replace([':', ' '], "").replace(',', "+"));
        stack.push(group);
    }
}

fn gemfile(text: &str, cx: &mut Context<'_>) {
    static GROUP: LazyLock<Regex> = LazyLock::new(|| re(r"^group\s+(.+?)\s+do"));
    let (mut deps, mut dev) = (Vec::new(), Vec::new());
    let mut groups = std::collections::BTreeSet::new();
    let mut stack: Vec<Option<String>> = Vec::new();
    let mut sources = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(src) = t.strip_prefix("source ").and_then(|r| quoted(r).into_iter().next()) {
            sources.push(redact_secrets(&src).into_owned());
        } else if let Some(v) = t.strip_prefix("ruby ").and_then(|r| quoted(r).into_iter().next()) {
            cx.format_set("ruby_version", v);
        } else if t == "gemspec" || t.starts_with("gemspec ") {
            cx.format_set("gemspec", true);
        } else if let Some(d) = dependency(t, "gem") {
            let group = stack.iter().rev().flatten().next().cloned().or_else(|| {
                t.split("group:")
                    .nth(1)
                    .map(|g| g.trim().trim_start_matches(':').split([',', ' ']).next().unwrap_or("").to_string())
            });
            match group {
                Some(g) => {
                    let is_dev = g.contains("development") || g.contains("test");
                    groups.extend(g.split('+').map(str::to_string));
                    if is_dev { dev.push(d) } else { deps.push(d) }
                }
                None => deps.push(d),
            }
        }
        block_group(line, &mut stack, &GROUP);
    }
    cx.format_set("ecosystem", "rubygems");
    for src in &sources {
        if !src.contains("rubygems.org") {
            cx.security().risk("custom_package_index", Some(src.clone()));
        }
    }
    if !sources.is_empty() {
        cx.format_set("sources", json!(sources));
    }
    put_pairs(cx, "dependencies", deps);
    put_pairs(cx, "dev_dependencies", dev);
    if !groups.is_empty() {
        cx.format_set("groups", json!(groups));
    }
}

fn gemfile_lock(text: &str, cx: &mut Context<'_>) {
    let mut section = "";
    let mut specs: BTreeMap<String, u64> = BTreeMap::new();
    let mut packages = Vec::new();
    let (mut remotes, mut platforms) = (Vec::new(), Vec::new());
    let mut direct = 0u64;
    let mut next_is = "";
    for line in text.lines() {
        if !line.starts_with(' ') && !line.trim().is_empty() {
            section = line.trim();
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let t = line.trim();
        match (section, indent) {
            ("GEM" | "GIT" | "PATH", 2) => {
                if let Some(r) = t.strip_prefix("remote: ") {
                    remotes.push(redact_secrets(r).into_owned());
                }
            }
            ("GEM" | "GIT" | "PATH", 4) => {
                *specs.entry(section.to_ascii_lowercase()).or_default() += 1;
                let (name, version) = t.split_once(" (").unwrap_or((t, ""));
                packages.push((name.to_string(), version.trim_end_matches(')').to_string()));
            }
            ("PLATFORMS", _) if !t.is_empty() => platforms.push(t.to_string()),
            ("DEPENDENCIES", 2) => direct += 1,
            ("RUBY VERSION", _) => next_is = "ruby",
            ("BUNDLED WITH", _) => next_is = "bundler",
            _ => {}
        }
        if !t.is_empty() {
            match std::mem::take(&mut next_is) {
                "ruby" => cx.format_set("ruby_version", t.trim_start_matches("ruby ")),
                "bundler" => cx.format_set("bundler_version", t),
                _ => {}
            }
        }
    }
    cx.format_set("ecosystem", "rubygems");
    cx.format_set("resolved_packages", packages.len());
    cx.format_set("sources", json!(specs));
    put_pairs(cx, "packages", packages);
    cx.format_set("dependencies_count", direct);
    if !remotes.is_empty() {
        cx.format_set("remotes", json!(remotes));
    }
    if !platforms.is_empty() {
        cx.format_set("platforms", json!(platforms));
    }
}

fn podfile(text: &str, cx: &mut Context<'_>) {
    static TARGET: LazyLock<Regex> = LazyLock::new(|| re(r#"^(?:abstract_)?target\s+['"]([^'"]+)['"]\s+do"#));
    let mut deps = Vec::new();
    let mut targets = Vec::new();
    let mut sources = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("platform ") {
            let mut parts = rest.split(',');
            let os = parts.next().unwrap_or("").trim().trim_start_matches(':');
            let version = parts.next().and_then(|v| quoted(v).into_iter().next());
            cx.format_set("platform", json!({ "os": os, "version": version }));
        } else if let Some(src) = t.strip_prefix("source ").and_then(|r| quoted(r).into_iter().next()) {
            sources.push(redact_secrets(&src).into_owned());
        } else if let Some(c) = TARGET.captures(t) {
            targets.push(c[1].to_string());
        } else if t.starts_with("use_frameworks!") {
            cx.format_set("use_frameworks", true);
        } else if t.starts_with("post_install") || t.starts_with("pre_install") {
            let hook = t.split_whitespace().next().unwrap_or("post_install");
            cx.security()
                .active_content("install_scripts")
                .risk("install_script", Some(format!("Podfile {hook} hook")));
        } else if let Some(d) = dependency(t, "pod") {
            deps.push(d);
        }
    }
    cx.format_set("ecosystem", "cocoapods");
    for src in &sources {
        if !src.contains("cdn.cocoapods.org") && !src.contains("github.com/CocoaPods/Specs") {
            cx.security().risk("custom_package_index", Some(src.clone()));
        }
    }
    if !sources.is_empty() {
        cx.format_set("sources", json!(sources));
    }
    put_pairs(cx, "dependencies", deps);
    if !targets.is_empty() {
        cx.format_set("targets", json!(targets));
    }
}

fn podfile_lock(v: &Value, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "cocoapods");
    let pods = v.get("PODS").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    let pairs = pods.iter().filter_map(|p| {
        let entry = p.as_str().map(str::to_string).or_else(|| p.as_object()?.keys().next().cloned())?;
        let (name, version) = entry.split_once(" (")?;
        Some((name.to_string(), version.trim_end_matches(')').to_string()))
    });
    put_pairs(cx, "packages", pairs);
    cx.format_set("resolved_packages", pods.len());
    if let Some(d) = v.get("DEPENDENCIES").and_then(Value::as_array) {
        cx.format_set("dependencies_count", d.len());
    }
    if let Some(Value::Object(repos)) = v.get("SPEC REPOS") {
        cx.format_set("spec_repos", json!(repos.keys().collect::<Vec<_>>()));
    }
    if let Some(c) = v.get("COCOAPODS") {
        cx.format_set("cocoapods_version", c.clone());
    }
}

/// `Package.swift`: tools version, name, platforms, products, dependencies and targets.
fn swift_package(text: &str, cx: &mut Context<'_>) {
    static NAME: LazyLock<Regex> = LazyLock::new(|| re(r#"Package\s*\(\s*name:\s*"([^"]+)""#));
    static PLATFORM: LazyLock<Regex> = LazyLock::new(|| {
        re(r"\.(iOS|macOS|tvOS|watchOS|visionOS|macCatalyst|driverKit)\(\s*(?:\.v([\d_]+)|\x22([^\x22]+)\x22)")
    });
    static PRODUCT: LazyLock<Regex> = LazyLock::new(|| re(r#"\.(library|executable|plugin)\(\s*name:\s*"([^"]+)""#));
    static DEP: LazyLock<Regex> = LazyLock::new(|| {
        re(r#"\.package\(\s*(?:name:\s*"[^"]*",\s*)?(url|path|id):\s*"([^"]+)"\s*(?:,\s*([^)]*))?\)"#)
    });
    static TARGET: LazyLock<Regex> = LazyLock::new(|| {
        re(r#"\.(target|executableTarget|testTarget|binaryTarget|macro|plugin|systemLibrary)\(\s*name:\s*"([^"]+)""#)
    });
    if let Some(v) = text.lines().next().and_then(|l| l.split("swift-tools-version:").nth(1)) {
        cx.format_set("tools_version", v.trim());
    }
    let name = NAME.captures(text).map(|c| c[1].to_string());
    Package {
        ecosystem: "swiftpm",
        name: name.as_deref(),
        version: None,
        description: None,
        license: None,
        authors: Vec::new(),
        repository: None,
    }
    .write(cx);
    let platforms: Map<String, Value> = PLATFORM
        .captures_iter(text)
        .map(|c| (c[1].to_string(), json!(c.get(2).map_or_else(|| c[3].to_string(), |v| v.as_str().replace('_', ".")))))
        .collect();
    if !platforms.is_empty() {
        cx.format_set("platforms", Value::Object(platforms));
    }
    let mut products: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for c in PRODUCT.captures_iter(text) {
        products.entry(c[1].to_string()).or_default().push(c[2].to_string());
    }
    if !products.is_empty() {
        cx.format_set("products", json!(products));
    }
    let deps = DEP.captures_iter(text).map(|c| {
        let location = &c[2];
        let dep =
            location.trim_end_matches('/').trim_end_matches(".git").rsplit('/').next().unwrap_or(location).to_string();
        let requirement = match &c[1] {
            "path" => format!("path: {location}"),
            _ => c.get(3).map_or("*", |r| r.as_str().trim()).replace('"', ""),
        };
        (dep, requirement)
    });
    put_pairs(cx, "dependencies", deps);
    let mut targets: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for c in TARGET.captures_iter(text) {
        targets.entry(c[1].to_string()).or_default().push(c[2].to_string());
    }
    if !targets.is_empty() {
        cx.format_set("targets", json!(targets));
    }
}

fn swift_resolved(v: &Value, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "swiftpm");
    if let Some(n) = v.get("version") {
        cx.format_set("lockfile_version", n.clone());
    }
    let pins = v
        .get("pins")
        .or_else(|| v.get("object").and_then(|o| o.get("pins")))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let pairs = pins.iter().filter_map(|p| {
        let name = s(p, &["identity"]).or_else(|| s(p, &["package"]))?;
        let state = p.get("state")?;
        let at = s(state, &["version"])
            .map(str::to_string)
            .or_else(|| s(state, &["branch"]).map(|b| format!("branch: {b}")))
            .or_else(|| s(state, &["revision"]).map(|r| format!("revision: {}", &r[..r.len().min(12)])))?;
        Some((name.to_string(), at))
    });
    put_pairs(cx, "packages", pairs);
    cx.format_set("resolved_packages", pins.len());
}

/// `Brewfile`: taps, formulae, casks, Mac App Store apps and editor extensions.
fn brewfile(text: &str, cx: &mut Context<'_>) {
    let mut kinds: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for line in text.lines() {
        let t = line.trim();
        let Some((word, rest)) = t.split_once(' ') else { continue };
        let kind = match word {
            "tap" | "brew" | "cask" | "mas" | "vscode" | "whalebrew" | "go" | "cargo" | "uv" => word,
            _ => continue,
        };
        if let Some(name) = quoted(rest).into_iter().next() {
            let list = kinds.entry(kind).or_default();
            if list.len() < MAX_DEPS {
                list.push(name);
            }
        }
    }
    cx.format_set("ecosystem", "homebrew");
    let counts: BTreeMap<&str, usize> = kinds.iter().map(|(k, v)| (*k, v.len())).collect();
    cx.format_set("counts", json!(counts));
    for (kind, list) in kinds {
        let key = match kind {
            "tap" => "taps",
            "brew" => "formulae",
            "cask" => "casks",
            "mas" => "mac_app_store",
            "vscode" => "vscode_extensions",
            other => other,
        };
        cx.format_set(key, json!(list));
    }
}

/// A Homebrew formula (`class X < Formula`) or cask (`cask "x" do`).
fn homebrew(text: &str, cx: &mut Context<'_>) {
    static CLASS: LazyLock<Regex> = LazyLock::new(|| re(r"(?m)^class\s+(\w+)\s*<\s*Formula"));
    static CASK: LazyLock<Regex> = LazyLock::new(|| re(r#"(?m)^cask\s+"([^"]+)"\s+do"#));
    static FIELD: LazyLock<Regex> =
        LazyLock::new(|| re(r#"(?m)^  (desc|homepage|url|version|license|head|name|sha256)\s+(?:"([^"]*)"|(:\w+))"#));
    static DEPENDS: LazyLock<Regex> =
        LazyLock::new(|| re(r#"(?m)^  depends_on\s+"([^"]+)"(?:\s*=>\s*(\[[^\]]*\]|:\w+))?"#));
    static ARTIFACT: LazyLock<Regex> = LazyLock::new(|| re(r#"(?m)^  (app|pkg|binary|font|installer)\s+"([^"]+)""#));
    let cask = CASK.captures(text).map(|c| c[1].to_string());
    let class = CLASS.captures(text).map(|c| c[1].to_string());
    let mut fields: BTreeMap<&str, String> = BTreeMap::new();
    for c in FIELD.captures_iter(text) {
        let key = c.get(1).map_or("", |m| m.as_str());
        let value = c.get(2).or_else(|| c.get(3)).map_or("", |m| m.as_str());
        fields.entry(key).or_insert_with(|| value.to_string());
    }
    let get = |k: &str| fields.get(k).map(String::as_str);
    let name = cask.clone().or_else(|| class.as_deref().map(formula_name));
    Package {
        ecosystem: "homebrew",
        name: name.as_deref(),
        version: get("version"),
        description: get("desc"),
        license: get("license"),
        authors: Vec::new(),
        repository: get("homepage"),
    }
    .write(cx);
    cx.format_set("kind", if cask.is_some() { "cask" } else { "formula" });
    if let Some(n) = get("name").filter(|_| cask.is_some()) {
        cx.content().source("homebrew.name").title(n);
    }
    if let Some(u) = get("url") {
        cx.format_set("url", redact_secrets(u).as_ref());
    }
    match get("sha256") {
        Some(":no_check") => cx.format_set("checksum", false),
        Some(_) => cx.format_set("checksum", true),
        None => {}
    }
    if get("head").is_some() {
        cx.format_set("head", true);
    }
    let (mut runtime, mut build) = (Vec::new(), Vec::new());
    for c in DEPENDS.captures_iter(text) {
        let tag = c.get(2).map_or("", |m| m.as_str());
        if tag.contains("build") { build.push(c[1].to_string()) } else { runtime.push(c[1].to_string()) }
    }
    put_pairs(cx, "dependencies", runtime.into_iter().map(|d| (d, "*".to_string())));
    put_pairs(cx, "build_dependencies", build.into_iter().map(|d| (d, "*".to_string())));
    let mut artifacts: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for c in ARTIFACT.captures_iter(text) {
        artifacts.entry(c[1].to_string()).or_default().push(c[2].to_string());
    }
    if !artifacts.is_empty() {
        cx.format_set("artifacts", json!(artifacts));
    }
    for (marker, key) in [
        ("\n  bottle do", "bottle"),
        ("\n  service do", "service"),
        ("\n  livecheck do", "livecheck"),
        ("\n  zap ", "zap"),
    ] {
        if text.contains(marker) {
            cx.format_set(key, true);
        }
    }
}

/// `class ImageMagickAT7 < Formula` → `image-magick@7`.
fn formula_name(class: &str) -> String {
    let mut out = String::new();
    let mut chars = class.chars().peekable();
    while let Some(c) = chars.next() {
        if c == 'A' && chars.peek() == Some(&'T') {
            let mut probe = chars.clone();
            probe.next();
            if probe.peek().is_some_and(char::is_ascii_digit) {
                chars.next();
                out.push('@');
                continue;
            }
        }
        if c.is_ascii_uppercase() {
            if !out.is_empty() && !out.ends_with('@') {
                out.push('-');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_helpers() {
        assert_eq!(dependency("gem \"rails\", \"~> 7.1\"", "gem"), Some(("rails".into(), "~> 7.1".into())));
        assert_eq!(
            dependency("gem 'tide', git: 'https://example.test/tide.git'", "gem"),
            Some(("tide".into(), "git: https://example.test/tide.git".into()))
        );
        assert_eq!(dependency("gemspec", "gem"), None);
        assert_eq!(formula_name("SaltmereTide"), "saltmere-tide");
        assert_eq!(formula_name("ImagemagickAT6"), "imagemagick@6");
    }

    #[test]
    fn podfile_hooks_are_flagged() {
        let r =
            crate::plugin::testing::report_for("Podfile", b"platform :ios, '15.0'\npost_install do |installer|\nend\n");
        assert!(r.security.risks.iter().any(|x| x.kind == "install_script"));
    }
}
