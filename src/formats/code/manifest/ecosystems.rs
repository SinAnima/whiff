//! Manifests of the other language ecosystems and build tools: Gradle,
//! Composer, Dart pub, Elixir Mix, Haskell Cabal / Stack, Conan, vcpkg,
//! Deno, Julia, Elm, Gleam, Zig, opam, CPAN, rebar3, Nix flakes, Bazel
//! modules, Terraform dependency locks, Snapcraft, Flatpak and
//! `CITATION.cff`. Build scripts (Gradle, Mix, Conan, Nix, Starlark) are
//! read as text, never run.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

use super::python::ini_sections;
use super::{
    MAX_DEPS, Package, bracketed, deps, parse_json, parse_jsonc, parse_toml, parse_yaml, person, put_deps, put_pairs,
    quoted, s,
};
use crate::plugin::{Context, DateField, ExtractError, parse_date, redact_secrets};

pub(super) fn extract(id: &str, text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    match id {
        "gradle_build" => gradle(text, cx),
        "composer_json" => composer(&parse_json(text)?, cx),
        "composer_lock" => composer_lock(&parse_json(text)?, cx),
        "pubspec" => pubspec(&parse_yaml(text)?, cx),
        "pubspec_lock" => pubspec_lock(&parse_yaml(text)?, cx),
        "mix_project" => mix(text, cx),
        "mix_lock" => mix_lock(text, cx),
        "cabal" => cabal(text, cx),
        "stack_yaml" => stack(&parse_yaml(text)?, cx),
        "conanfile" => conan(text, cx),
        "vcpkg_json" => vcpkg(&parse_json(text)?, cx),
        "deno_config" => deno(&parse_jsonc(text)?, cx),
        "julia_project" => julia_project(&parse_toml(text)?, cx),
        "julia_manifest" => julia_manifest(&parse_toml(text)?, cx),
        "citation_cff" => cff(&parse_yaml(text)?, cx),
        "nix_flake" => flake(text, cx),
        "nix_flake_lock" => flake_lock(&parse_json(text)?, cx),
        "bazel_module" => bazel_module(text, cx),
        "terraform_lock" => terraform_lock(text, cx),
        "snapcraft" => snapcraft(&parse_yaml(text)?, cx),
        "flatpak_manifest" => flatpak(&parse_jsonc(text).or_else(|_| parse_yaml(text))?, cx),
        "opam" => opam(text, cx),
        "cpan_meta" => cpan(&parse_json(text)?, cx),
        "rebar_config" => rebar(text, cx),
        "elm_json" => elm(&parse_json(text)?, cx),
        "gleam_toml" => gleam(&parse_toml(text)?, cx),
        _ => zon(text, cx),
    }
    Ok(())
}

fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid pattern")
}

fn first<'t>(r: &Regex, text: &'t str) -> Option<&'t str> {
    r.captures(text).and_then(|c| c.get(1)).map(|m| m.as_str())
}

/// Keys of an object, as a list.
fn keys(v: Option<&Value>) -> Option<Value> {
    match v {
        Some(Value::Object(o)) if !o.is_empty() => Some(json!(o.keys().collect::<Vec<_>>())),
        _ => None,
    }
}

fn set_keys(cx: &mut Context<'_>, key: &str, v: Option<&Value>) {
    if let Some(k) = keys(v) {
        cx.format_set(key, k);
    }
}

fn copy(cx: &mut Context<'_>, v: &Value, fields: &[(&str, &str)]) {
    for (from, to) in fields {
        if let Some(x) = v.get(*from).filter(|x| !x.is_null()) {
            cx.format_set(to, x.clone());
        }
    }
}

/// Gradle configurations whose dependencies are for tests.
const TEST_CONFIGURATIONS: &[&str] = &[
    "testImplementation",
    "testRuntimeOnly",
    "testCompileOnly",
    "androidTestImplementation",
    "testFixturesImplementation",
];

#[allow(clippy::too_many_lines)]
fn gradle(text: &str, cx: &mut Context<'_>) {
    static PLUGIN: LazyLock<Regex> = LazyLock::new(|| {
        re(
            r#"(?m)^\s*(?:id\s*\(?\s*["']([^"']+)["']\s*\)?|kotlin\(\s*"([^"]+)"\s*\)|alias\(\s*libs\.plugins\.([\w.]+)\s*\)|`([\w-]+)`)(?:\s+version\s+["']([^"']+)["'])?"#,
        )
    });
    static APPLY: LazyLock<Regex> = LazyLock::new(|| re(r#"(?m)^\s*apply\s*\(?\s*plugin\s*[:=]\s*["']([^"']+)["']"#));
    static DEP: LazyLock<Regex> = LazyLock::new(|| {
        re(
            r#"(?m)^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|testCompileOnly|kapt|ksp|annotationProcessor|classpath|androidTestImplementation|debugImplementation|releaseImplementation|testFixturesImplementation|compile|testCompile)\s*\(?\s*(?:platform\(\s*)?["']([^"']+)["']"#,
        )
    });
    static PROJECT: LazyLock<Regex> = LazyLock::new(|| re(r#"project\(\s*(?:path\s*[:=]\s*)?["'](:[^"']*)["']"#));
    static CATALOG: LazyLock<Regex> = LazyLock::new(|| {
        re(
            r"(?m)^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|kapt|ksp)\s*\(?\s*libs\.([\w.]+)",
        )
    });
    static PROP: LazyLock<Regex> = LazyLock::new(|| {
        re(r#"(?m)^\s*(group|version|description|namespace|applicationId|rootProject\.name)\s*=\s*["']([^"']+)["']"#)
    });
    static SDK: LazyLock<Regex> =
        LazyLock::new(|| re(r"(?m)^\s*(compileSdk|minSdk|targetSdk)(?:Version)?\s*=?\s*(\d+)"));
    static JAVA: LazyLock<Regex> = LazyLock::new(|| {
        re(
            r"JavaLanguageVersion\.of\(\s*(\d+)\s*\)|jvmToolchain\(\s*(\d+)\s*\)|sourceCompatibility\s*=\s*(?:JavaVersion\.VERSION_)?['\x22]?([\d._]+)",
        )
    });
    static MAVEN: LazyLock<Regex> = LazyLock::new(|| {
        re(r#"maven\s*\{[^}]*?url\s*=?\s*(?:uri\()?\s*["']([^"']+)["']|maven\(\s*(?:url\s*=\s*)?["']([^"']+)["']\s*\)"#)
    });

    let mut props: BTreeMap<String, String> = BTreeMap::new();
    for c in PROP.captures_iter(text) {
        props.entry(c[1].to_string()).or_insert_with(|| c[2].to_string());
    }
    let name = props.get("rootProject.name").or_else(|| props.get("namespace")).or_else(|| props.get("group")).cloned();
    Package {
        ecosystem: "gradle",
        name: name.as_deref(),
        version: props.get("version").map(String::as_str),
        description: props.get("description").map(String::as_str),
        license: None,
        authors: Vec::new(),
        repository: None,
    }
    .write(cx);
    for (k, out) in [("group", "group"), ("namespace", "android_namespace"), ("applicationId", "application_id")] {
        if let Some(v) = props.get(k) {
            cx.format_set(out, v.as_str());
        }
    }
    let mut plugins: Vec<String> = PLUGIN
        .captures_iter(text)
        .filter_map(|c| {
            let id = c
                .get(1)
                .map(|m| m.as_str().to_string())
                .or_else(|| c.get(2).map(|m| format!("org.jetbrains.kotlin.{}", m.as_str())))
                .or_else(|| c.get(3).map(|m| format!("libs.plugins.{}", m.as_str())))
                .or_else(|| c.get(4).map(|m| m.as_str().to_string()))?;
            Some(match c.get(5) {
                Some(v) => format!("{id} {}", v.as_str()),
                None => id,
            })
        })
        .collect();
    plugins.extend(APPLY.captures_iter(text).map(|c| c[1].to_string()));
    // Core plugins named bare inside `plugins { }`: `application`, `java`.
    if let Some(block) = bracketed(text, "plugins", '{', '}') {
        let bare = block
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
        plugins.extend(bare.map(str::to_string));
    }
    if !plugins.is_empty() {
        cx.format_set("plugins", json!(plugins));
    }
    let (mut main, mut testing) = (Vec::new(), Vec::new());
    let mut configurations: BTreeMap<String, u64> = BTreeMap::new();
    for c in DEP.captures_iter(text) {
        let coord = &c[2];
        let mut parts = coord.splitn(3, ':');
        let (g, a, v) = (parts.next().unwrap_or(""), parts.next(), parts.next());
        let (dep, version) = match a {
            Some(a) => (format!("{g}:{a}"), v.unwrap_or("*").to_string()),
            None => (coord.to_string(), "*".into()),
        };
        *configurations.entry(c[1].to_string()).or_default() += 1;
        if TEST_CONFIGURATIONS.contains(&&c[1]) { testing.push((dep, version)) } else { main.push((dep, version)) }
    }
    for c in CATALOG.captures_iter(text) {
        *configurations.entry(c[1].to_string()).or_default() += 1;
        let dep = (format!("libs.{}", &c[2]), "catalog".to_string());
        if TEST_CONFIGURATIONS.contains(&&c[1]) { testing.push(dep) } else { main.push(dep) }
    }
    put_pairs(cx, "dependencies", main);
    put_pairs(cx, "dev_dependencies", testing);
    if !configurations.is_empty() {
        cx.format_set("configurations", json!(configurations));
    }
    let projects: Vec<&str> = PROJECT.captures_iter(text).filter_map(|c| c.get(1)).map(|m| m.as_str()).collect();
    if !projects.is_empty() {
        cx.format_set("project_dependencies", json!(projects));
    }
    // settings.gradle: `include(":app", ":core")`.
    let modules: Vec<String> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("include"))
        .flat_map(quoted)
        .filter(|m| m.starts_with(':'))
        .collect();
    if !modules.is_empty() {
        cx.format_set("modules", json!(modules));
    }
    let sdks: Map<String, Value> =
        SDK.captures_iter(text).map(|c| (super::snake(&c[1]), json!(c[2].parse::<u32>().unwrap_or(0)))).collect();
    if !sdks.is_empty() {
        cx.format_set("android", Value::Object(sdks));
    }
    if let Some(c) = JAVA.captures(text) {
        let v = c.get(1).or_else(|| c.get(2)).or_else(|| c.get(3)).map_or("", |m| m.as_str());
        cx.format_set("java_version", v.replace('_', "."));
    }
    let mut repos: Vec<String> = ["mavenCentral()", "google()", "gradlePluginPortal()", "mavenLocal()"]
        .iter()
        .filter(|r| text.contains(**r))
        .map(|r| r.trim_end_matches("()").to_string())
        .collect();
    for c in MAVEN.captures_iter(text) {
        let url = c.get(1).or_else(|| c.get(2)).map_or("", |m| m.as_str());
        let url = redact_secrets(url).into_owned();
        if !["repo.maven.apache.org", "repo1.maven.org", "maven.google.com", "plugins.gradle.org"]
            .iter()
            .any(|k| url.contains(k))
        {
            cx.security().risk("custom_package_index", Some(url.clone()));
        }
        repos.push(url);
    }
    if !repos.is_empty() {
        cx.format_set("repositories", json!(repos));
    }
}

fn composer(v: &Value, cx: &mut Context<'_>) {
    let license = v.get("license").and_then(|l| l.as_str().or_else(|| l.as_array()?.first()?.as_str()));
    let authors = v.get("authors").and_then(Value::as_array).into_iter().flatten().filter_map(person).collect();
    Package {
        ecosystem: "composer",
        name: s(v, &["name"]),
        version: s(v, &["version"]),
        description: s(v, &["description"]),
        license,
        authors,
        repository: s(v, &["support", "source"]).or_else(|| s(v, &["homepage"])),
    }
    .write(cx);
    copy(cx, v, &[("type", "type"), ("minimum-stability", "minimum_stability")]);
    for (key, group) in [("require", "dependencies"), ("require-dev", "dev_dependencies")] {
        let (mut listed, mut n) = deps(v.get(key));
        if let Some(php) = listed.remove("php") {
            cx.format_set("requires_php", php);
            n -= 1;
        }
        let exts: Vec<String> = listed.keys().filter(|k| k.starts_with("ext-")).cloned().collect();
        for e in &exts {
            listed.remove(e);
            n -= 1;
        }
        if !exts.is_empty() && group == "dependencies" {
            cx.format_set("php_extensions", json!(exts.iter().map(|e| &e[4..]).collect::<Vec<_>>()));
        }
        put_deps(cx, group, (listed, n));
    }
    if let Some(Value::Object(psr4)) = v.pointer("/autoload/psr-4") {
        cx.format_set("namespaces", json!(psr4.keys().collect::<Vec<_>>()));
    }
    set_keys(cx, "scripts", v.get("scripts"));
    for r in v.get("repositories").and_then(Value::as_array).into_iter().flatten() {
        if let Some(url) = s(r, &["url"]).filter(|u| !u.contains("packagist.org")) {
            cx.security().risk("custom_package_index", Some(redact_secrets(url).into_owned()));
        }
    }
    if let Some(k) = v.get("keywords").and_then(Value::as_array) {
        for kw in k.iter().filter_map(Value::as_str) {
            cx.content().source("composer.keywords").keyword(kw);
        }
    }
}

fn composer_lock(v: &Value, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "composer");
    let mut total = 0;
    for (key, group) in [("packages", "packages"), ("packages-dev", "dev_packages")] {
        let list = v.get(key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
        total += list.len();
        put_pairs(
            cx,
            group,
            list.iter()
                .filter_map(|p| Some((s(p, &["name"])?.to_string(), s(p, &["version"]).unwrap_or("*").to_string()))),
        );
    }
    cx.format_set("resolved_packages", total);
    copy(cx, v, &[("plugin-api-version", "plugin_api_version"), ("minimum-stability", "minimum_stability")]);
    if v.get("content-hash").is_some() {
        cx.format_set("content_hash", true);
    }
}

fn pubspec(v: &Value, cx: &mut Context<'_>) {
    Package {
        ecosystem: "pub",
        name: s(v, &["name"]),
        version: s(v, &["version"]),
        description: s(v, &["description"]),
        license: None,
        authors: Vec::new(),
        repository: s(v, &["repository"]).or_else(|| s(v, &["homepage"])),
    }
    .write(cx);
    if let Some(sdk) = s(v, &["environment", "sdk"]) {
        cx.format_set("dart_sdk", sdk);
    }
    if let Some(f) = s(v, &["environment", "flutter"]) {
        cx.format_set("flutter_sdk", f);
    }
    if v.get("flutter").is_some() || v.pointer("/dependencies/flutter").is_some() {
        cx.format_set("framework", "flutter");
    }
    if s(v, &["publish_to"]) == Some("none") {
        cx.format_set("private", true);
    }
    put_deps(cx, "dependencies", deps(v.get("dependencies")));
    put_deps(cx, "dev_dependencies", deps(v.get("dev_dependencies")));
    if let Some(Value::Object(o)) = v.get("dependency_overrides") {
        cx.format_set("dependency_overrides", o.len());
    }
}

fn pubspec_lock(v: &Value, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "pub");
    let Some(Value::Object(packages)) = v.get("packages") else { return };
    let mut sources: BTreeMap<String, u64> = BTreeMap::new();
    let mut direct: BTreeMap<String, u64> = BTreeMap::new();
    for p in packages.values() {
        *sources.entry(s(p, &["source"]).unwrap_or("?").to_string()).or_default() += 1;
        *direct.entry(s(p, &["dependency"]).unwrap_or("?").replace(' ', "_")).or_default() += 1;
    }
    cx.format_set("resolved_packages", packages.len());
    cx.format_set("sources", json!(sources));
    cx.format_set("dependency_kinds", json!(direct));
    put_pairs(cx, "packages", packages.iter().map(|(k, p)| (k.clone(), s(p, &["version"]).unwrap_or("*").to_string())));
    if let Some(sdks) = v.get("sdks") {
        cx.format_set("sdks", sdks.clone());
    }
}

fn mix(text: &str, cx: &mut Context<'_>) {
    static APP: LazyLock<Regex> = LazyLock::new(|| re(r"app:\s*:(\w+)"));
    static VERSION: LazyLock<Regex> = LazyLock::new(|| re(r#"(?m)^\s*version:\s*"([^"]+)""#));
    static ELIXIR: LazyLock<Regex> = LazyLock::new(|| re(r#"elixir:\s*"([^"]+)""#));
    static DESC: LazyLock<Regex> = LazyLock::new(|| re(r#"description:\s*"([^"]+)""#));
    static SOURCE: LazyLock<Regex> = LazyLock::new(|| re(r#"source_url:\s*"([^"]+)""#));
    static DEP: LazyLock<Regex> = LazyLock::new(|| {
        re(r#"\{\s*:(\w+)\s*,\s*(?:"([^"]+)"|(git|github|path|in_umbrella):\s*"?([^",}]+)"?)([^}]*)\}"#)
    });
    let app = first(&APP, text);
    let version = first(&VERSION, text);
    Package {
        ecosystem: "hex",
        name: app,
        version,
        description: first(&DESC, text),
        license: bracketed(text, "licenses:", '[', ']').and_then(|l| quoted(l).into_iter().next()).as_deref(),
        authors: Vec::new(),
        repository: first(&SOURCE, text),
    }
    .write(cx);
    if let Some(e) = first(&ELIXIR, text) {
        cx.format_set("elixir_version", e);
    }
    let Some(deps_block) = bracketed(text, "defp deps", '[', ']') else { return };
    let (mut main, mut dev) = (Vec::new(), Vec::new());
    for c in DEP.captures_iter(deps_block) {
        let version = c.get(2).map_or_else(|| format!("{}: {}", &c[3], c[4].trim()), |m| m.as_str().to_string());
        let opts = c.get(5).map_or("", |m| m.as_str());
        let only_dev =
            opts.contains("only:") && !opts.contains(":prod") && (opts.contains(":dev") || opts.contains(":test"));
        if only_dev { dev.push((c[1].to_string(), version)) } else { main.push((c[1].to_string(), version)) }
    }
    put_pairs(cx, "dependencies", main);
    put_pairs(cx, "dev_dependencies", dev);
}

fn mix_lock(text: &str, cx: &mut Context<'_>) {
    static ENTRY: LazyLock<Regex> = LazyLock::new(|| re(r#"(?m)^\s*"([\w-]+)":\s*\{:(\w+),\s*(?::\w+,\s*)?"([^"]+)""#));
    let mut sources: BTreeMap<String, u64> = BTreeMap::new();
    let mut packages = Vec::new();
    for c in ENTRY.captures_iter(text) {
        *sources.entry(c[2].to_string()).or_default() += 1;
        let version = if &c[2] == "hex" { c[3].to_string() } else { c[2].to_string() };
        packages.push((c[1].to_string(), version));
    }
    cx.format_set("ecosystem", "hex");
    cx.format_set("resolved_packages", packages.len());
    cx.format_set("sources", json!(sources));
    put_pairs(cx, "packages", packages);
}

/// `base >=4.14 && <5, text ^>=2.0` → pairs.
fn constraint_list(list: &str) -> Vec<(String, String)> {
    list.split(',')
        .filter_map(|d| {
            let d = d.trim();
            let at = d.find(|c: char| c.is_whitespace() || "<>=^".contains(c)).unwrap_or(d.len());
            let name = d[..at].trim();
            let version = d[at..].split_whitespace().collect::<Vec<_>>().join(" ");
            (!name.is_empty()).then(|| (name.to_string(), if version.is_empty() { "*".into() } else { version }))
        })
        .collect()
}

fn cabal(text: &str, cx: &mut Context<'_>) {
    let mut top: BTreeMap<String, String> = BTreeMap::new();
    let mut components: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut deps: BTreeMap<String, String> = BTreeMap::new();
    let mut current: Option<(usize, String, String)> = None;
    let flush = |cur: Option<(usize, String, String)>,
                 top: &mut BTreeMap<String, String>,
                 deps: &mut BTreeMap<String, String>| {
        let Some((indent, key, value)) = cur else { return };
        if key == "build-depends" {
            for (n, v) in constraint_list(&value) {
                deps.entry(n).or_insert(v);
            }
        } else if indent == 0 {
            top.entry(key).or_insert(value);
        }
    };
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("--") {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if let Some((_, _, value)) = current.as_mut().filter(|(i, _, _)| indent > *i) {
            value.push(' ');
            value.push_str(t);
            continue;
        }
        flush(current.take(), &mut top, &mut deps);
        let word = t.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
        if indent == 0
            && matches!(
                word.as_str(),
                "library"
                    | "executable"
                    | "test-suite"
                    | "benchmark"
                    | "foreign-library"
                    | "common"
                    | "flag"
                    | "source-repository"
            )
        {
            let name = t.split_whitespace().nth(1).unwrap_or("default").to_string();
            components.entry(word).or_default().push(name);
        } else if let Some((k, v)) = t.split_once(':') {
            current = Some((indent, k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    flush(current.take(), &mut top, &mut deps);
    let get = |k: &str| top.get(k).map(String::as_str);
    let authors = get("author")
        .map(|a| {
            a.split(',')
                .map(|x| x.split('<').next().unwrap_or(x).trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    Package {
        ecosystem: "hackage",
        name: get("name"),
        version: get("version"),
        description: get("synopsis"),
        license: get("license"),
        authors,
        repository: get("homepage"),
    }
    .write(cx);
    for (k, out) in [
        ("cabal-version", "cabal_version"),
        ("build-type", "build_type"),
        ("category", "category"),
        ("tested-with", "tested_with"),
    ] {
        if let Some(v) = get(k) {
            cx.format_set(out, v);
        }
    }
    // A bare e-mail address is personal data: only a name is reported.
    if let Some(m) =
        get("maintainer").map(|m| m.split('<').next().unwrap_or(m).trim()).filter(|m| !m.is_empty() && !m.contains('@'))
    {
        cx.format_set("maintainer", m);
    }

    if !components.is_empty() {
        cx.format_set("components", json!(components));
    }
    put_pairs(cx, "dependencies", deps);
}

fn stack(v: &Value, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "hackage");
    if let Some(r) = s(v, &["snapshot"]).or_else(|| s(v, &["resolver"])) {
        cx.format_set("snapshot", r);
    }
    if let Some(p) = v.get("packages").and_then(Value::as_array) {
        cx.format_set("packages", p.len());
    }
    if let Some(e) = v.get("extra-deps").and_then(Value::as_array) {
        let pairs = e.iter().filter_map(Value::as_str).map(|d| match d.rsplit_once('-') {
            Some((n, ver)) if ver.starts_with(|c: char| c.is_ascii_digit()) => {
                (n.to_string(), ver.split('@').next().unwrap_or(ver).to_string())
            }
            _ => (d.to_string(), "*".into()),
        });
        put_pairs(cx, "extra_dependencies", pairs);
    }
    set_keys(cx, "flags", v.get("flags"));
}

fn conan(text: &str, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "conan");
    let reference = |r: &str| -> (String, String) {
        let r = r.trim();
        match r.split_once('/') {
            Some((n, v)) => (n.to_string(), v.split('@').next().unwrap_or(v).to_string()),
            None => (r.to_string(), "*".into()),
        }
    };
    if text.contains("ConanFile") {
        // conanfile.py
        static ATTR: LazyLock<Regex> =
            LazyLock::new(|| re(r#"(?m)^\s{4}(name|version|license|url|description|homepage)\s*=\s*["']([^"']+)["']"#));
        static CALL: LazyLock<Regex> =
            LazyLock::new(|| re(r#"self\.(requires|tool_requires|build_requires|test_requires)\(\s*["']([^"']+)["']"#));
        let attrs: BTreeMap<String, String> =
            ATTR.captures_iter(text).map(|c| (c[1].to_string(), c[2].to_string())).collect();
        let get = |k: &str| attrs.get(k).map(String::as_str);
        Package {
            ecosystem: "conan",
            name: get("name"),
            version: get("version"),
            description: get("description"),
            license: get("license"),
            authors: Vec::new(),
            repository: get("url").or_else(|| get("homepage")),
        }
        .write(cx);
        let mut main: Vec<(String, String)> = text
            .lines()
            .find(|l| l.trim_start().starts_with("requires ="))
            .map(|l| quoted(l).iter().map(|r| reference(r)).collect())
            .unwrap_or_default();
        let mut tools = Vec::new();
        for c in CALL.captures_iter(text) {
            if &c[1] == "requires" { main.push(reference(&c[2])) } else { tools.push(reference(&c[2])) }
        }
        put_pairs(cx, "dependencies", main);
        put_pairs(cx, "tool_dependencies", tools);
        cx.format_set("kind", "conanfile.py");
        return;
    }
    let sections = ini_sections(text);
    let entries = |name: &str| -> Vec<String> {
        sections
            .iter()
            .filter(|(n, _)| n == name)
            .flat_map(|(_, e)| e.iter().map(|(k, v)| if v.is_empty() { k.clone() } else { format!("{k}={v}") }))
            .collect()
    };
    put_pairs(cx, "dependencies", entries("requires").iter().map(|r| reference(r)));
    let tools: Vec<String> = entries("tool_requires").into_iter().chain(entries("build_requires")).collect();
    put_pairs(cx, "tool_dependencies", tools.iter().map(|r| reference(r)));
    for (section, key) in [("generators", "generators"), ("options", "options"), ("layout", "layout")] {
        let list = entries(section);
        if !list.is_empty() {
            cx.format_set(key, json!(list));
        }
    }
    cx.format_set("kind", "conanfile.txt");
}

fn vcpkg(v: &Value, cx: &mut Context<'_>) {
    let version = ["version", "version-string", "version-semver", "version-date"].iter().find_map(|k| s(v, &[k]));
    let description = v.get("description").and_then(|d| d.as_str().or_else(|| d.as_array()?.first()?.as_str()));
    Package {
        ecosystem: "vcpkg",
        name: s(v, &["name"]),
        version,
        description,
        license: s(v, &["license"]),
        authors: Vec::new(),
        repository: s(v, &["homepage"]),
    }
    .write(cx);
    let pairs = v.get("dependencies").and_then(Value::as_array).into_iter().flatten().filter_map(|d| {
        if let Some(n) = d.as_str() {
            return Some((n.to_string(), "*".to_string()));
        }
        let n = s(d, &["name"])?;
        Some((n.to_string(), s(d, &["version>="]).map_or_else(|| "*".to_string(), |x| format!(">= {x}"))))
    });
    put_pairs(cx, "dependencies", pairs);
    if let Some(b) = s(v, &["builtin-baseline"]) {
        cx.format_set("builtin_baseline", b);
    }
    set_keys(cx, "features", v.get("features"));
    if let Some(o) = v.get("overrides").and_then(Value::as_array) {
        cx.format_set("overrides", o.len());
    }
}

fn deno(v: &Value, cx: &mut Context<'_>) {
    Package {
        ecosystem: "deno",
        name: s(v, &["name"]),
        version: s(v, &["version"]),
        description: None,
        license: s(v, &["license"]),
        authors: Vec::new(),
        repository: None,
    }
    .write(cx);
    if let Some(Value::Object(imports)) = v.get("imports") {
        let pairs = imports.iter().map(|(k, t)| (k.clone(), t.as_str().unwrap_or("?").to_string()));
        put_pairs(cx, "imports", pairs);
        let mut registries: BTreeMap<&str, u64> = BTreeMap::new();
        for t in imports.values().filter_map(Value::as_str) {
            let r = if t.starts_with("jsr:") {
                "jsr"
            } else if t.starts_with("npm:") {
                "npm"
            } else if t.starts_with("http") {
                "url"
            } else {
                "local"
            };
            *registries.entry(r).or_default() += 1;
        }
        cx.format_set("import_sources", json!(registries));
    }
    set_keys(cx, "tasks", v.get("tasks"));
    copy(
        cx,
        v,
        &[("exports", "exports"), ("workspace", "workspace"), ("nodeModulesDir", "node_modules_dir"), ("lock", "lock")],
    );
    set_keys(cx, "compiler_options", v.get("compilerOptions"));
}

fn julia_project(v: &Value, cx: &mut Context<'_>) {
    let authors = v.get("authors").and_then(Value::as_array).into_iter().flatten().filter_map(person).collect();
    Package {
        ecosystem: "julia",
        name: s(v, &["name"]),
        version: s(v, &["version"]),
        description: None,
        license: None,
        authors,
        repository: None,
    }
    .write(cx);
    if let Some(u) = s(v, &["uuid"]) {
        cx.format_set("uuid", u);
    }
    let compat = v.get("compat");
    if let Some(j) = compat.and_then(|c| c.get("julia")).and_then(Value::as_str) {
        cx.format_set("requires_julia", j);
    }
    let with_compat = |table: &str| -> Vec<(String, String)> {
        let Some(Value::Object(o)) = v.get(table) else { return Vec::new() };
        o.keys()
            .map(|k| (k.clone(), compat.and_then(|c| c.get(k)).and_then(Value::as_str).unwrap_or("*").to_string()))
            .collect()
    };
    put_pairs(cx, "dependencies", with_compat("deps"));
    put_pairs(cx, "weak_dependencies", with_compat("weakdeps"));
    put_pairs(cx, "extras", with_compat("extras"));
    set_keys(cx, "extensions", v.get("extensions"));
}

fn julia_manifest(v: &Value, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "julia");
    copy(cx, v, &[("julia_version", "julia_version"), ("manifest_format", "manifest_format")]);
    // Format 2 nests packages under `[deps]`; format 1 has them at the top.
    let table = v.get("deps").and_then(Value::as_object).or_else(|| v.as_object());
    let Some(t) = table else { return };
    let pairs: Vec<(String, String)> = t
        .iter()
        .filter_map(|(k, entries)| {
            let e = entries.as_array()?.first()?;
            Some((k.clone(), s(e, &["version"]).unwrap_or("stdlib").to_string()))
        })
        .collect();
    cx.format_set("resolved_packages", pairs.len());
    put_pairs(cx, "packages", pairs);
}

fn cff(v: &Value, cx: &mut Context<'_>) {
    let authors: Vec<String> = v
        .get("authors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|a| match (s(a, &["given-names"]), s(a, &["family-names"]), s(a, &["name"])) {
            (Some(g), Some(f), _) => Some(format!("{g} {f}")),
            (None, Some(f), _) => Some(f.to_string()),
            (_, _, Some(n)) => Some(n.to_string()),
            _ => None,
        })
        .collect();
    let n_authors = authors.len();
    let license = v.get("license").and_then(|l| l.as_str().or_else(|| l.as_array()?.first()?.as_str()));
    Package {
        ecosystem: "citation",
        name: s(v, &["title"]),
        version: v
            .get("version")
            .and_then(|x| x.as_str().map(str::to_string).or_else(|| x.as_f64().map(|f| f.to_string())))
            .as_deref(),
        description: s(v, &["abstract"]),
        license,
        authors,
        repository: s(v, &["repository-code"]).or_else(|| s(v, &["url"])),
    }
    .write(cx);
    cx.format_set("authors_count", n_authors);
    copy(cx, v, &[("cff-version", "cff_version"), ("type", "type"), ("doi", "doi"), ("message", "message")]);
    if let Some((d, tz)) = v.get("date-released").and_then(|d| d.as_str()).and_then(parse_date) {
        cx.temporal().content_date(DateField::Published, d, tz);
    }
    if let Some(ids) = v.get("identifiers").and_then(Value::as_array) {
        cx.format_set("identifiers", ids.len());
    }
    if let Some(p) = v.get("preferred-citation") {
        cx.format_set("preferred_citation", json!({ "type": s(p, &["type"]), "title": s(p, &["title"]), "journal": s(p, &["journal"]), "year": p.get("year") }));
    }
    if let Some(r) = v.get("references").and_then(Value::as_array) {
        cx.format_set("references", r.len());
    }
    if let Some(k) = v.get("keywords").and_then(Value::as_array) {
        for kw in k.iter().filter_map(Value::as_str) {
            cx.content().source("cff.keywords").keyword(kw);
        }
    }
}

/// Flake outputs worth naming.
const FLAKE_OUTPUTS: &[&str] = &[
    "packages",
    "devShells",
    "apps",
    "checks",
    "formatter",
    "overlays",
    "nixosModules",
    "nixosConfigurations",
    "darwinConfigurations",
    "homeConfigurations",
    "templates",
    "lib",
    "legacyPackages",
    "hydraJobs",
];

fn flake(text: &str, cx: &mut Context<'_>) {
    static OUTPUT: LazyLock<Regex> = LazyLock::new(|| re(r#"(?m)^\s*(\w+)(?:\.[\w${}."-]+)*\s*="#));
    static DESC: LazyLock<Regex> = LazyLock::new(|| re(r#"(?m)^\s*description\s*=\s*"([^"]*)""#));
    static INPUT: LazyLock<Regex> = LazyLock::new(|| re(r#"(?m)^\s*(?:inputs\.)?([\w-]+)\.url\s*=\s*"([^"]+)""#));
    static INPUT_SET: LazyLock<Regex> =
        LazyLock::new(|| re(r#"(?m)^\s*(?:inputs\.)?([\w-]+)\s*=\s*\{\s*url\s*=\s*"([^"]+)""#));
    static SYSTEM: LazyLock<Regex> =
        LazyLock::new(|| re(r#""((?:x86_64|aarch64|i686|armv7l|riscv64)-(?:linux|darwin))""#));
    let description = first(&DESC, text);
    Package {
        ecosystem: "nix",
        name: None,
        version: None,
        description,
        license: None,
        authors: Vec::new(),
        repository: None,
    }
    .write(cx);
    let inputs: Vec<(String, String)> = INPUT
        .captures_iter(text)
        .chain(INPUT_SET.captures_iter(text))
        .map(|c| (c[1].to_string(), c[2].to_string()))
        .collect();
    put_pairs(cx, "inputs", inputs);
    let follows = text.matches(".follows").count();
    if follows > 0 {
        cx.format_set("follows", follows);
    }
    let assigned: std::collections::BTreeSet<&str> =
        OUTPUT.captures_iter(text).filter_map(|c| c.get(1)).map(|m| m.as_str()).collect();
    let outputs: Vec<&str> = FLAKE_OUTPUTS.iter().copied().filter(|o| assigned.contains(o)).collect();
    if !outputs.is_empty() {
        cx.format_set("outputs", json!(outputs));
    }
    let systems: std::collections::BTreeSet<&str> =
        SYSTEM.captures_iter(text).filter_map(|c| c.get(1)).map(|m| m.as_str()).collect();
    if !systems.is_empty() {
        cx.format_set("systems", json!(systems));
    }
}

fn flake_lock(v: &Value, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "nix");
    copy(cx, v, &[("version", "lockfile_version")]);
    let root = s(v, &["root"]).unwrap_or("root");
    let Some(Value::Object(nodes)) = v.get("nodes") else { return };
    let mut inputs = Vec::new();
    let mut newest = 0i64;
    for (name, node) in nodes.iter().filter(|(k, _)| *k != root).take(MAX_DEPS) {
        let Some(locked) = node.get("locked") else { continue };
        let kind = s(locked, &["type"]).unwrap_or("?");
        let source = match (s(locked, &["owner"]), s(locked, &["repo"])) {
            (Some(o), Some(r)) => format!("{kind}:{o}/{r}"),
            _ => s(locked, &["url"]).map_or_else(|| kind.to_string(), |u| redact_secrets(u).into_owned()),
        };
        let mut e = Map::new();
        e.insert("name".into(), json!(name));
        e.insert("source".into(), json!(source));
        if let Some(rev) = s(locked, &["rev"]) {
            e.insert("rev".into(), json!(&rev[..rev.len().min(12)]));
        }
        if let Some(t) = locked.get("lastModified").and_then(Value::as_i64) {
            newest = newest.max(t);
            if let Some(d) = super::super::super::archive::unix_time(t) {
                e.insert("last_modified".into(), json!(d));
            }
        }
        inputs.push(Value::Object(e));
    }
    cx.format_set("resolved_inputs", nodes.len().saturating_sub(1));
    cx.format_set("inputs", Value::Array(inputs));
    if let Some(d) = super::super::super::archive::unix_time(newest).filter(|_| newest > 0) {
        cx.temporal().content_date(DateField::Modified, d, true);
    }
}

fn bazel_module(text: &str, cx: &mut Context<'_>) {
    static MODULE: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)module\(([^)]*)\)"));
    static KW: LazyLock<Regex> = LazyLock::new(|| re(r#"(\w+)\s*=\s*(?:"([^"]*)"|(\d+))"#));
    static DEP: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)bazel_dep\(([^)]*)\)"));
    let kw = |args: &str| -> BTreeMap<String, String> {
        KW.captures_iter(args)
            .map(|c| (c[1].to_string(), c.get(2).or_else(|| c.get(3)).map_or("", |m| m.as_str()).to_string()))
            .collect()
    };
    let module = MODULE.captures(text).map(|c| kw(&c[1])).unwrap_or_default();
    Package {
        ecosystem: "bazel",
        name: module.get("name").map(String::as_str),
        version: module.get("version").map(String::as_str),
        description: None,
        license: None,
        authors: Vec::new(),
        repository: None,
    }
    .write(cx);
    if let Some(l) = module.get("compatibility_level") {
        cx.format_set("compatibility_level", l.parse::<u64>().map_or_else(|_| json!(l), |n| json!(n)));
    }
    let (mut main, mut dev) = (Vec::new(), Vec::new());
    for c in DEP.captures_iter(text) {
        let args = &c[1];
        let k = kw(args);
        let Some(n) = k.get("name") else { continue };
        let pair = (n.clone(), k.get("version").cloned().unwrap_or_else(|| "*".into()));
        if args.contains("dev_dependency = True") || args.contains("dev_dependency=True") {
            dev.push(pair);
        } else {
            main.push(pair);
        }
    }
    put_pairs(cx, "dependencies", main);
    put_pairs(cx, "dev_dependencies", dev);
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for call in [
        "use_extension(",
        "use_repo(",
        "register_toolchains(",
        "archive_override(",
        "git_override(",
        "local_path_override(",
        "single_version_override(",
        "multiple_version_override(",
    ] {
        let n = text.matches(call).count();
        if n > 0 {
            counts.insert(call.trim_end_matches('('), n);
        }
    }
    if !counts.is_empty() {
        cx.format_set("calls", json!(counts));
    }
}

fn terraform_lock(text: &str, cx: &mut Context<'_>) {
    let mut providers: Vec<(String, String)> = Vec::new();
    let mut constraints = Map::new();
    let mut current: Option<String> = None;
    let mut hashes = 0u64;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("provider ") {
            current = quoted(rest).into_iter().next();
        } else if let Some(p) = &current {
            if let Some(v) = t.strip_prefix("version").and_then(|r| quoted(r).into_iter().next()) {
                providers.push((p.clone(), v));
            } else if let Some(c) = t.strip_prefix("constraints").and_then(|r| quoted(r).into_iter().next()) {
                constraints.insert(p.clone(), json!(c));
            } else if t.starts_with("\"h1:") || t.starts_with("\"zh:") {
                hashes += 1;
            } else if t == "}" {
                current = None;
            }
        }
    }
    cx.format_set("ecosystem", "terraform");
    cx.format_set("resolved_packages", providers.len());
    put_pairs(cx, "providers", providers);
    if !constraints.is_empty() {
        cx.format_set("constraints", Value::Object(constraints));
    }
    cx.format_set("hashes", hashes);
}

fn snapcraft(v: &Value, cx: &mut Context<'_>) {
    let license = s(v, &["license"]);
    Package {
        ecosystem: "snap",
        name: s(v, &["name"]),
        version: s(v, &["version"]).or_else(|| s(v, &["adopt-info"])),
        description: s(v, &["summary"]),
        license,
        authors: Vec::new(),
        repository: None,
    }
    .write(cx);
    copy(cx, v, &[("base", "base"), ("grade", "grade"), ("confinement", "confinement")]);
    if let Some(d) = s(v, &["description"]) {
        cx.emit_text(crate::plugin::TextRole::Body, d);
    }
    set_keys(cx, "apps", v.get("apps"));
    if let Some(Value::Object(apps)) = v.get("apps") {
        let daemons = apps.values().filter(|a| a.get("daemon").is_some()).count();
        if daemons > 0 {
            cx.format_set("daemons", daemons);
        }
        let mut plugs: std::collections::BTreeSet<&str> =
            apps.values().filter_map(|a| a.get("plugs")?.as_array()).flatten().filter_map(Value::as_str).collect();
        plugs.extend(v.get("plugs").and_then(Value::as_object).into_iter().flat_map(|o| o.keys().map(String::as_str)));
        if !plugs.is_empty() {
            cx.format_set("plugs", json!(plugs));
        }
    }
    if let Some(Value::Object(parts)) = v.get("parts") {
        let mut plugins: BTreeMap<&str, u64> = BTreeMap::new();
        for p in parts.values() {
            *plugins.entry(s(p, &["plugin"]).unwrap_or("?")).or_default() += 1;
        }
        cx.format_set("parts", json!(parts.keys().collect::<Vec<_>>()));
        cx.format_set("part_plugins", json!(plugins));
    }
    if let Some(a) = v.get("architectures").or_else(|| v.get("platforms")) {
        cx.format_set("architectures", keys(Some(a)).unwrap_or_else(|| a.clone()));
    }
}

fn flatpak(v: &Value, cx: &mut Context<'_>) {
    let id = s(v, &["app-id"]).or_else(|| s(v, &["id"]));
    Package {
        ecosystem: "flatpak",
        name: id,
        version: None,
        description: None,
        license: None,
        authors: Vec::new(),
        repository: None,
    }
    .write(cx);
    copy(
        cx,
        v,
        &[
            ("runtime", "runtime"),
            ("runtime-version", "runtime_version"),
            ("sdk", "sdk"),
            ("base", "base"),
            ("command", "command"),
        ],
    );
    if let Some(args) = v.get("finish-args").and_then(Value::as_array) {
        let list: Vec<&str> = args.iter().filter_map(Value::as_str).collect();
        cx.format_set("permissions", json!(list));
        let broad: Vec<&str> = list
            .iter()
            .copied()
            .filter(|a| {
                matches!(
                    *a,
                    "--filesystem=host"
                        | "--filesystem=home"
                        | "--device=all"
                        | "--talk-name=org.freedesktop.Flatpak"
                        | "--socket=system-bus"
                )
            })
            .collect();
        if !broad.is_empty() {
            cx.format_set("broad_permissions", json!(broad));
        }
    }
    let mut names = Vec::new();
    let mut sources: BTreeMap<String, u64> = BTreeMap::new();
    let mut stack: Vec<&Value> =
        v.get("modules").and_then(Value::as_array).map(|m| m.iter().collect()).unwrap_or_default();
    while let Some(m) = stack.pop() {
        if names.len() >= MAX_DEPS {
            break;
        }
        if let Some(n) = s(m, &["name"]) {
            names.push(n.to_string());
        }
        for src in m.get("sources").and_then(Value::as_array).into_iter().flatten() {
            *sources.entry(s(src, &["type"]).unwrap_or("?").to_string()).or_default() += 1;
        }
        stack.extend(m.get("modules").and_then(Value::as_array).into_iter().flatten());
    }
    if !names.is_empty() {
        cx.format_set("modules", json!(names));
    }
    if !sources.is_empty() {
        cx.format_set("source_types", json!(sources));
    }
}

fn opam(text: &str, cx: &mut Context<'_>) {
    static FIELD: LazyLock<Regex> = LazyLock::new(|| re(r#"(?m)^([\w-]+):\s*"([^"]*)""#));
    static DEP: LazyLock<Regex> = LazyLock::new(|| re(r#""([^"]+)"\s*(\{[^}]*\})?"#));
    let fields: BTreeMap<String, String> =
        FIELD.captures_iter(text).map(|c| (c[1].to_string(), c[2].to_string())).collect();
    let get = |k: &str| fields.get(k).map(String::as_str);
    let list = |key: &str| -> Vec<String> {
        match bracketed(text, &format!("\n{key}:"), '[', ']') {
            Some(b)
                if text[text.find(&format!("\n{key}:")).unwrap_or(0)..]
                    .lines()
                    .next()
                    .is_some_and(|l| l.contains('[')) =>
            {
                quoted(b)
            }
            _ => get(key).map(|v| vec![v.to_string()]).unwrap_or_default(),
        }
    };
    let authors: Vec<String> =
        list("authors").iter().map(|a| a.split('<').next().unwrap_or(a).trim().to_string()).collect();
    let license = list("license").into_iter().next();
    Package {
        ecosystem: "opam",
        name: get("name"),
        version: get("version"),
        description: get("synopsis"),
        license: license.as_deref(),
        authors,
        repository: get("dev-repo").or_else(|| get("homepage")),
    }
    .write(cx);
    copy(cx, &json!(fields), &[("opam-version", "opam_version"), ("bug-reports", "bug_reports")]);
    if let Some(d) = bracketed(text, "\ndepends:", '[', ']') {
        let pairs = DEP.captures_iter(d).map(|c| {
            (c[1].to_string(), c.get(2).map_or("*", |m| m.as_str().trim_matches(['{', '}']).trim()).replace('"', ""))
        });
        put_pairs(cx, "dependencies", pairs);
    }
}

fn cpan(v: &Value, cx: &mut Context<'_>) {
    let authors = v.get("author").and_then(Value::as_array).into_iter().flatten().filter_map(person).collect();
    let license = v.get("license").and_then(|l| l.as_array()?.first()?.as_str());
    let version = v.get("version").map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_string));
    Package {
        ecosystem: "cpan",
        name: s(v, &["name"]),
        version: version.as_deref(),
        description: s(v, &["abstract"]),
        license,
        authors,
        repository: s(v, &["resources", "repository", "url"]).or_else(|| s(v, &["resources", "repository", "web"])),
    }
    .write(cx);
    copy(cx, v, &[("release_status", "release_status"), ("generated_by", "generated_by")]);
    if let Some(m) = v.pointer("/meta-spec/version") {
        cx.format_set("meta_spec", m.clone());
    }
    for (phase, group) in [
        ("runtime", "dependencies"),
        ("build", "build_dependencies"),
        ("configure", "configure_dependencies"),
        ("test", "test_dependencies"),
        ("develop", "dev_dependencies"),
    ] {
        if let Some(r) = v.pointer(&format!("/prereqs/{phase}/requires")) {
            let (mut listed, mut n) = deps(Some(r));
            if let Some(perl) = listed.remove("perl") {
                if phase == "runtime" {
                    cx.format_set("requires_perl", perl);
                }
                n -= 1;
            }
            put_deps(cx, group, (listed, n));
        }
    }
}

fn rebar(text: &str, cx: &mut Context<'_>) {
    static DEP: LazyLock<Regex> =
        LazyLock::new(|| re(r#"\{\s*(\w+)\s*,\s*(?:"([^"]+)"|\{\s*(git|hg|pkg)\s*,\s*"?([^",}]+))"#));
    static RELEASE: LazyLock<Regex> = LazyLock::new(|| re(r#"\{\s*release\s*,\s*\{\s*(\w+)\s*,\s*"([^"]+)""#));
    static OTP: LazyLock<Regex> = LazyLock::new(|| re(r#"\{\s*minimum_otp_vsn\s*,\s*"([^"]+)""#));
    cx.format_set("ecosystem", "hex");
    if let Some(block) = bracketed(text, "{deps,", '[', ']') {
        let mut pairs: Vec<(String, String)> = DEP
            .captures_iter(block)
            .filter(|c| !matches!(&c[1], "tag" | "branch" | "ref"))
            .map(|c| {
                (c[1].to_string(), c.get(2).map_or_else(|| format!("{}: {}", &c[3], &c[4]), |m| m.as_str().to_string()))
            })
            .collect();
        // Bare atoms: the latest version from Hex.
        for atom in block
            .split([',', '\n'])
            .map(str::trim)
            .filter(|a| !a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        {
            if !pairs.iter().any(|(n, _)| n == atom) {
                pairs.push((atom.to_string(), "*".into()));
            }
        }
        put_pairs(cx, "dependencies", pairs);
    }
    if let Some(c) = RELEASE.captures(text) {
        cx.format_set("release", json!({ "name": &c[1], "version": &c[2] }));
    }
    if let Some(o) = first(&OTP, text) {
        cx.format_set("minimum_otp_version", o);
    }
    if let Some(p) = bracketed(text, "{plugins,", '[', ']') {
        let names: Vec<&str> = p
            .split([',', '{', '}', '\n'])
            .map(str::trim)
            .filter(|a| !a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
            .collect();
        if !names.is_empty() {
            cx.format_set("plugins", json!(names));
        }
    }
}

fn elm(v: &Value, cx: &mut Context<'_>) {
    Package {
        ecosystem: "elm",
        name: s(v, &["name"]),
        version: s(v, &["version"]),
        description: s(v, &["summary"]),
        license: s(v, &["license"]),
        authors: Vec::new(),
        repository: None,
    }
    .write(cx);
    copy(cx, v, &[("type", "type"), ("elm-version", "elm_version")]);
    let d = v.get("dependencies");
    match d.and_then(|d| d.get("direct")) {
        Some(direct) => {
            put_deps(cx, "dependencies", deps(Some(direct)));
            put_deps(cx, "indirect_dependencies", deps(d.and_then(|d| d.get("indirect"))));
        }
        None => put_deps(cx, "dependencies", deps(d)),
    }
    let td = v.get("test-dependencies");
    put_deps(cx, "test_dependencies", deps(td.and_then(|t| t.get("direct")).or(td)));
    if let Some(m) = v.get("exposed-modules") {
        let n = m.as_array().map_or_else(
            || m.as_object().map_or(0, |o| o.values().filter_map(Value::as_array).map(Vec::len).sum()),
            Vec::len,
        );
        cx.format_set("exposed_modules", n);
    }
}

fn gleam(v: &Value, cx: &mut Context<'_>) {
    let license = v.get("licences").and_then(|l| l.as_array()?.first()?.as_str());
    let repo = v
        .get("repository")
        .and_then(|r| Some(format!("{}:{}/{}", s(r, &["type"])?, s(r, &["user"])?, s(r, &["repo"])?)));
    Package {
        ecosystem: "hex",
        name: s(v, &["name"]),
        version: s(v, &["version"]),
        description: s(v, &["description"]),
        license,
        authors: Vec::new(),
        repository: repo.as_deref(),
    }
    .write(cx);
    copy(cx, v, &[("target", "target"), ("gleam", "gleam_version")]);
    put_deps(cx, "dependencies", deps(v.get("dependencies")));
    put_deps(cx, "dev_dependencies", deps(v.get("dev-dependencies").or_else(|| v.get("dev_dependencies"))));
}

/// Zig `build.zig.zon`: a Zig anonymous struct literal.
fn zon(text: &str, cx: &mut Context<'_>) {
    static FIELD: LazyLock<Regex> = LazyLock::new(|| {
        re(
            r#"(?m)^\s{4}\.(name|version|minimum_zig_version|fingerprint)\s*=\s*(?:"([^"]*)"|\.([\w@]+)|(0x[0-9a-fA-F]+))"#,
        )
    });
    static DEP: LazyLock<Regex> = LazyLock::new(|| re(r#"\.(@?"?[\w-]+"?)\s*=\s*\.\{([^}]*)\}"#));
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    for c in FIELD.captures_iter(text) {
        let v = c.get(2).or_else(|| c.get(3)).or_else(|| c.get(4)).map_or("", |m| m.as_str());
        fields.entry(c[1].to_string()).or_insert_with(|| v.to_string());
    }
    let get = |k: &str| fields.get(k).map(String::as_str);
    Package {
        ecosystem: "zig",
        name: get("name"),
        version: get("version"),
        description: None,
        license: None,
        authors: Vec::new(),
        repository: None,
    }
    .write(cx);
    if let Some(z) = get("minimum_zig_version") {
        cx.format_set("minimum_zig_version", z);
    }
    if let Some(block) = bracketed(text, ".dependencies", '{', '}') {
        let pairs = DEP.captures_iter(block).map(|c| {
            let body = &c[2];
            let at = if let Some(u) = body.split(".url").nth(1).and_then(|r| quoted(r).into_iter().next()) {
                redact_secrets(&u).into_owned()
            } else if let Some(p) = body.split(".path").nth(1).and_then(|r| quoted(r).into_iter().next()) {
                format!("path: {p}")
            } else {
                "*".into()
            };
            (c[1].trim_matches(['"', '@']).to_string(), at)
        });
        put_pairs(cx, "dependencies", pairs);
    }
    if let Some(p) = bracketed(text, ".paths", '{', '}') {
        cx.format_set("paths", quoted(p).len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constraints() {
        assert_eq!(
            constraint_list("base >=4.14 && <5, text"),
            [("base".into(), ">=4.14 && <5".into()), ("text".into(), "*".into())]
        );
    }

    #[test]
    fn custom_repositories_are_flagged() {
        let r = crate::plugin::testing::report_for(
            "build.gradle",
            b"repositories {\n  maven { url 'https://maven.example.test/releases' }\n}\n",
        );
        assert!(r.security.risks.iter().any(|x| x.kind == "custom_package_index"));
        let r = crate::plugin::testing::report_for("build.gradle", b"repositories { mavenCentral() }\n");
        assert_eq!(r.security.risks.len(), 0);
    }
}
