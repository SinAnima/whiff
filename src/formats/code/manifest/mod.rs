//! Package manifests and lockfiles across ecosystems: name, version,
//! licence, authors, repository, dependencies with versions (by group),
//! resolved-package counts and sources for lockfiles, scripts and build
//! targets. Install hooks and custom package indexes are flagged.
//!
//! npm, Cargo, `pyproject.toml`, `requirements.txt`, Go and Maven are
//! read here; the rest by ecosystem in the submodules: [`python`] (Pipfile,
//! Poetry, uv, setuptools), [`dotnet`] (`MSBuild` projects, NuGet, solutions),
//! [`apple_ruby`] (Bundler, CocoaPods, `SwiftPM`, Homebrew), [`ecosystems`]
//! (Composer, pub, Mix, Cabal, Stack, Conan, vcpkg, Deno, Julia, Elm,
//! Gleam, Zig, opam, CPAN, rebar3, Nix flakes, Bazel modules, Terraform
//! locks, Snapcraft, Flatpak, CITATION.cff), [`distro`] (R `DESCRIPTION`,
//! Debian `control` / `changelog` / `copyright`, `PKGBUILD`, RPM spec) and
//! [`sbom`] (SPDX, `CycloneDX`).

mod apple_ruby;
mod distro;
mod dotnet;
mod ecosystems;
mod python;
mod sbom;

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::plugin::{
    AnyValue, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, MAX_NESTING, Probe, Sniff, Source,
    TextRole, dotted_key_depth, nesting_depth, truncate_chars,
};

/// Extractor for package manifests.
pub struct Manifest;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, $parent:literal) => {
        spec!($id, $name, $mime, $parent, [])
    };
    ($id:literal, $name:literal, $mime:literal, $parent:literal, [$($ext:literal),*]) => {
        FormatSpec {
            id: $id,
            name: $name,
            family: "code.manifest",
            mimes: &[$mime],
            extensions: &[$($ext),*],
            magic: &[],
            parent: Some($parent),
        }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "code.manifest",
    version: 2,
    cost: Cost::Scan,
    priority: 10,
    formats: &[
        spec!("npm_package", "npm package.json", "application/json", "json"),
        spec!("npm_lockfile", "npm package-lock.json", "application/json", "json"),
        spec!("cargo_manifest", "Cargo manifest", "application/toml", "toml"),
        spec!("cargo_lockfile", "Cargo lockfile", "application/toml", "toml"),
        spec!("pyproject", "Python pyproject.toml", "application/toml", "toml"),
        spec!("pip_requirements", "pip requirements file", "text/plain", "text"),
        spec!("go_module", "Go module file", "text/plain", "text"),
        spec!("go_sum", "Go checksum database", "text/plain", "text"),
        spec!("maven_pom", "Maven POM", "application/xml", "xml"),
        spec!("pipfile", "Pipfile", "application/toml", "toml"),
        spec!("pipfile_lock", "Pipfile.lock", "application/json", "json"),
        spec!("poetry_lock", "Poetry lockfile", "application/toml", "toml"),
        spec!("uv_lock", "uv lockfile", "application/toml", "toml"),
        spec!("setup_py", "setuptools setup.py", "text/x-python", "python"),
        spec!("setup_cfg", "setuptools setup.cfg", "text/plain", "ini"),
        spec!("gradle_build", "Gradle build", "text/x-groovy", "groovy"),
        spec!("dotnet_project", ".NET project", "application/xml", "xml", ["csproj", "fsproj", "vbproj", "vcxproj"]),
        spec!("nuget_packages", "NuGet packages.config", "application/xml", "xml"),
        spec!("vs_solution", "Visual Studio solution", "text/plain", "text", ["sln"]),
        spec!("gemfile", "Ruby Gemfile", "text/x-ruby", "ruby"),
        spec!("gemfile_lock", "Bundler Gemfile.lock", "text/plain", "text"),
        spec!("podfile", "CocoaPods Podfile", "text/x-ruby", "ruby"),
        spec!("podfile_lock", "CocoaPods Podfile.lock", "application/yaml", "yaml"),
        spec!("swift_package", "SwiftPM Package.swift", "text/x-swift", "swift"),
        spec!("swift_package_resolved", "SwiftPM Package.resolved", "application/json", "json"),
        spec!("homebrew_formula", "Homebrew formula / cask", "text/x-ruby", "ruby"),
        spec!("brewfile", "Homebrew Brewfile", "text/x-ruby", "ruby"),
        spec!("composer_json", "Composer manifest", "application/json", "json"),
        spec!("composer_lock", "Composer lockfile", "application/json", "json"),
        spec!("pubspec", "Dart pubspec", "application/yaml", "yaml"),
        spec!("pubspec_lock", "Dart pubspec.lock", "application/yaml", "yaml"),
        spec!("mix_project", "Elixir mix.exs", "text/x-elixir", "elixir"),
        spec!("mix_lock", "Elixir mix.lock", "text/plain", "text"),
        spec!("cabal", "Haskell cabal file", "text/plain", "text", ["cabal"]),
        spec!("stack_yaml", "Haskell stack.yaml", "application/yaml", "yaml"),
        spec!("r_description", "R DESCRIPTION", "text/plain", "text"),
        spec!("conanfile", "Conan conanfile", "text/plain", "text"),
        spec!("vcpkg_json", "vcpkg manifest", "application/json", "json"),
        spec!("deno_config", "Deno config", "application/json", "json"),
        spec!("julia_project", "Julia Project.toml", "application/toml", "toml"),
        spec!("julia_manifest", "Julia Manifest.toml", "application/toml", "toml"),
        spec!("citation_cff", "CITATION.cff", "application/yaml", "yaml", ["cff"]),
        spec!("spdx", "SPDX SBOM", "text/spdx", "text", ["spdx"]),
        spec!("spdx_json", "SPDX SBOM (JSON)", "application/spdx+json", "json"),
        spec!("cyclonedx_json", "CycloneDX SBOM (JSON)", "application/vnd.cyclonedx+json", "json"),
        spec!("cyclonedx_xml", "CycloneDX SBOM (XML)", "application/vnd.cyclonedx+xml", "xml"),
        spec!("pkgbuild", "Arch PKGBUILD", "text/x-shellscript", "shell"),
        spec!("rpm_spec", "RPM spec file", "text/x-rpm-spec", "text", ["spec"]),
        spec!("debian_control", "Debian control file", "text/plain", "text"),
        spec!("debian_changelog", "Debian changelog", "text/plain", "text"),
        spec!("debian_copyright", "Debian copyright file", "text/plain", "text"),
        spec!("nix_flake", "Nix flake", "text/x-nix", "nix"),
        spec!("nix_flake_lock", "Nix flake.lock", "application/json", "json"),
        spec!("bazel_module", "Bazel MODULE.bazel", "text/x-starlark", "starlark"),
        spec!("terraform_lock", "Terraform dependency lock", "text/plain", "text"),
        spec!("snapcraft", "Snapcraft manifest", "application/yaml", "yaml"),
        spec!("flatpak_manifest", "Flatpak manifest", "application/json", "json"),
        spec!("opam", "opam package file", "text/plain", "text", ["opam"]),
        spec!("cpan_meta", "CPAN META.json", "application/json", "json"),
        spec!("rebar_config", "rebar3 config", "text/plain", "text"),
        spec!("elm_json", "Elm elm.json", "application/json", "json"),
        spec!("gleam_toml", "Gleam gleam.toml", "application/toml", "toml"),
        spec!("zig_zon", "Zig build.zig.zon", "text/plain", "text", ["zon"]),
    ],
};

/// Dependencies listed per group.
const MAX_DEPS: usize = 200;

impl Extractor for Manifest {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let name = probe.name?;
        let name = name.rsplit(['/', '\\']).next().unwrap_or(name);
        let head = std::str::from_utf8(&probe.head[..probe.head.len().min(2048)])
            .or_else(|e| std::str::from_utf8(&probe.head[..e.valid_up_to()]))
            .unwrap_or("");
        let format = by_name(name).or_else(|| by_content(name, head))?;
        // Above the generic JSON / YAML / INI / TOML sniffs (0.9 plus 0.05 for the extension).
        Some(Sniff { format, confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        cx.emit_text(TextRole::Data, &text);
        let id = cx.format_id().to_string();
        match id.as_str() {
            "npm_package" => npm(&parse_json(&text)?, cx),
            "npm_lockfile" => npm_lock(&parse_json(&text)?, cx),
            "cargo_manifest" => cargo(&parse_toml(&text)?, cx),
            "cargo_lockfile" => cargo_lock(&parse_toml(&text)?, cx),
            "pyproject" => pyproject(&parse_toml(&text)?, cx),
            "pip_requirements" => requirements(&text, cx),
            "go_module" => go_mod(&text, cx),
            "go_sum" => go_sum(&text, cx),
            "maven_pom" => maven(&text, cx),
            "pipfile" | "pipfile_lock" | "poetry_lock" | "uv_lock" | "setup_py" | "setup_cfg" => {
                python::extract(&id, &text, cx)?;
            }
            "dotnet_project" | "nuget_packages" | "vs_solution" => dotnet::extract(&id, &text, cx),
            "gemfile"
            | "gemfile_lock"
            | "podfile"
            | "podfile_lock"
            | "swift_package"
            | "swift_package_resolved"
            | "homebrew_formula"
            | "brewfile" => apple_ruby::extract(&id, &text, cx)?,
            "r_description" | "debian_control" | "debian_changelog" | "debian_copyright" | "pkgbuild" | "rpm_spec" => {
                distro::extract(&id, &text, cx);
            }
            "spdx" | "spdx_json" | "cyclonedx_json" | "cyclonedx_xml" => sbom::extract(&id, &text, cx)?,
            _ => ecosystems::extract(&id, &text, cx)?,
        }
        Ok(())
    }
}

crate::register_extractor!(Manifest);

/// Formats named by their file name alone.
fn by_name(name: &str) -> Option<&'static str> {
    Some(match name {
        "package.json" => "npm_package",
        "package-lock.json" | "npm-shrinkwrap.json" => "npm_lockfile",
        "Cargo.toml" => "cargo_manifest",
        "Cargo.lock" => "cargo_lockfile",
        "pyproject.toml" => "pyproject",
        "go.mod" => "go_module",
        "go.sum" => "go_sum",
        "pom.xml" => "maven_pom",
        "Pipfile" => "pipfile",
        "Pipfile.lock" => "pipfile_lock",
        "poetry.lock" => "poetry_lock",
        "uv.lock" => "uv_lock",
        "setup.py" => "setup_py",
        "setup.cfg" => "setup_cfg",
        "build.gradle" | "build.gradle.kts" | "settings.gradle" | "settings.gradle.kts" => "gradle_build",
        "Directory.Packages.props" | "Directory.Build.props" | "Directory.Build.targets" => "dotnet_project",
        "packages.config" => "nuget_packages",
        "Gemfile" | "gems.rb" => "gemfile",
        "Gemfile.lock" | "gems.locked" => "gemfile_lock",
        "Podfile" => "podfile",
        "Podfile.lock" => "podfile_lock",
        "Package.swift" => "swift_package",
        "Package.resolved" => "swift_package_resolved",
        "Brewfile" => "brewfile",
        "composer.json" => "composer_json",
        "composer.lock" => "composer_lock",
        "pubspec.yaml" => "pubspec",
        "pubspec.lock" => "pubspec_lock",
        "mix.exs" => "mix_project",
        "mix.lock" => "mix_lock",
        "stack.yaml" => "stack_yaml",
        "DESCRIPTION" => "r_description",
        "conanfile.txt" | "conanfile.py" => "conanfile",
        "vcpkg.json" => "vcpkg_json",
        "deno.json" | "deno.jsonc" => "deno_config",
        "Project.toml" | "JuliaProject.toml" => "julia_project",
        "Manifest.toml" | "JuliaManifest.toml" => "julia_manifest",
        "PKGBUILD" => "pkgbuild",
        "flake.nix" => "nix_flake",
        "flake.lock" => "nix_flake_lock",
        "MODULE.bazel" => "bazel_module",
        ".terraform.lock.hcl" => "terraform_lock",
        "snapcraft.yaml" | ".snapcraft.yaml" => "snapcraft",
        "opam" => "opam",
        "META.json" => "cpan_meta",
        "rebar.config" => "rebar_config",
        "elm.json" => "elm_json",
        "gleam.toml" => "gleam_toml",
        "build.zig.zon" => "zig_zon",
        "bom.json" => "cyclonedx_json",
        "bom.xml" => "cyclonedx_xml",
        n if n.starts_with("requirements") && has_extension(n, "txt") => "pip_requirements",
        n if has_extension(n, "pom") => "maven_pom",
        n if n.starts_with("Manifest-v") && has_extension(n, "toml") => "julia_manifest",
        n if n.ends_with(".spdx.json") => "spdx_json",
        n if n.ends_with(".cdx.json") => "cyclonedx_json",
        n if n.ends_with(".cdx.xml") => "cyclonedx_xml",
        _ => return None,
    })
}

/// Formats recognised by a file name plus the first lines.
fn by_content(name: &str, head: &str) -> Option<&'static str> {
    let first = head.trim_start_matches('\u{feff}').lines().next().unwrap_or("");
    let line_starts = |w: &str| head.lines().any(|l| l.trim_start().starts_with(w));
    Some(match name {
        "control" if first.starts_with("Source:") || first.starts_with("Package:") => "debian_control",
        "changelog" if distro::is_debian_changelog_line(first) => "debian_changelog",
        "copyright" if first.starts_with("Format:") && head.contains("copyright-format") => "debian_copyright",
        n if has_extension(n, "hcl")
            && first.starts_with("# This file is maintained automatically by \"terraform init\"") =>
        {
            "terraform_lock"
        }
        n if has_extension(n, "rb") && (head.contains("< Formula") || line_starts("cask \"")) => "homebrew_formula",
        n if has_extension(n, "json") && head.contains("\"bomFormat\"") && head.contains("CycloneDX") => {
            "cyclonedx_json"
        }
        n if has_extension(n, "json") && head.contains("\"spdxVersion\"") => "spdx_json",
        n if has_extension(n, "xml") && head.contains("cyclonedx.org/schema/bom") => "cyclonedx_xml",
        n if (has_extension(n, "json") || has_extension(n, "yml") || has_extension(n, "yaml"))
            && head.contains("app-id")
            && head.contains("runtime") =>
        {
            "flatpak_manifest"
        }
        _ => return None,
    })
}

fn has_extension(name: &str, ext: &str) -> bool {
    std::path::Path::new(name).extension().is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

/// The first YAML document of `text`.
fn parse_yaml(text: &str) -> Result<Value, ExtractError> {
    super::super::data::yaml::first_document(text).ok_or_else(|| ExtractError::malformed("not YAML"))
}

/// JSON, JSON with comments or JSON5.
fn parse_jsonc(text: &str) -> Result<Value, ExtractError> {
    super::super::data::json::parse(text.trim_start_matches('\u{feff}'), false)
        .map(|(v, _)| v)
        .map_err(|e| ExtractError::malformed(truncate_chars(&e, 300)))
}

/// `(name, version)` pairs as a dependency group (`{name: version}` plus its size).
fn put_pairs(cx: &mut Context<'_>, group: &str, pairs: impl IntoIterator<Item = (String, String)>) {
    let mut listed = Map::new();
    let mut n = 0;
    for (name, version) in pairs {
        n += 1;
        if listed.len() < MAX_DEPS {
            listed.insert(name, json!(version));
        }
    }
    put_deps(cx, group, (listed, n));
}

/// Strings in single or double quotes, in order.
fn quoted(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find(['"', '\'']) {
        let q = rest.as_bytes()[i] as char;
        let tail = &rest[i + 1..];
        let Some(j) = tail.find(q) else { break };
        out.push(tail[..j].to_string());
        rest = &tail[j + 1..];
    }
    out
}

/// The text between `open` (inclusive, the first after `key`) and its matching close bracket.
fn bracketed<'t>(text: &'t str, key: &str, open: char, close: char) -> Option<&'t str> {
    let at = text.find(key)? + key.len();
    let start = at + text[at..].find(open)?;
    let mut depth = 0usize;
    for (i, c) in text[start..].char_indices() {
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(&text[start + 1..start + i]);
            }
        }
    }
    None
}

fn parse_json(text: &str) -> Result<Value, ExtractError> {
    serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| ExtractError::malformed(e.to_string()))
}

pub(crate) fn parse_toml(text: &str) -> Result<Value, ExtractError> {
    if nesting_depth(text) > MAX_NESTING || dotted_key_depth(text) > MAX_NESTING {
        return Err(ExtractError::malformed("nested too deeply"));
    }
    toml::from_str::<AnyValue>(text)
        .map(|v| v.0)
        .map_err(|e| ExtractError::malformed(truncate_chars(&e.to_string(), 300)))
}

fn s<'v>(v: &'v Value, path: &[&str]) -> Option<&'v str> {
    path.iter().try_fold(v, |v, k| v.get(*k)).and_then(Value::as_str)
}

/// Write the common package facts.
struct Package<'a> {
    ecosystem: &'static str,
    name: Option<&'a str>,
    version: Option<&'a str>,
    description: Option<&'a str>,
    license: Option<&'a str>,
    authors: Vec<String>,
    repository: Option<&'a str>,
}

impl Package<'_> {
    fn write(&self, cx: &mut Context<'_>) {
        let src = format!("{}.manifest", self.ecosystem);
        if let Some(n) = self.name {
            let title = match self.version {
                Some(v) => format!("{n} {v}"),
                None => n.to_string(),
            };
            cx.content().source(src.clone()).title(title);
        }
        if let Some(d) = self.description {
            cx.content().source(src.clone()).description(d);
            cx.emit_text(TextRole::Body, d);
        }
        if let Some(l) = self.license {
            cx.rights().source(src.clone()).license(Some(l), None);
        }
        for a in &self.authors {
            cx.content().source(src.clone()).author(a.clone());
            cx.rights().source(src.clone()).creator(a.clone());
        }
        let f = cx.format();
        f.insert("ecosystem".into(), json!(self.ecosystem));
        for (k, v) in
            [("name", self.name), ("version", self.version), ("license", self.license), ("repository", self.repository)]
        {
            if let Some(v) = v {
                f.insert(k.into(), json!(v));
            }
        }
    }
}

/// `"Ada <ada@x> (https://…)"` or `{ "name": "Ada" }` → `Ada`.
fn person(v: &Value) -> Option<String> {
    let raw = match v {
        Value::String(s) => s.as_str(),
        Value::Object(o) => o.get("name")?.as_str()?,
        _ => return None,
    };
    let name = raw.split(['<', '(']).next().unwrap_or(raw).trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// A dependency table (`{name: version | {version: …}}`) as `{name: version}` plus its size.
fn deps(v: Option<&Value>) -> (Map<String, Value>, usize) {
    let Some(Value::Object(o)) = v else { return (Map::new(), 0) };
    let listed = o
        .iter()
        .take(MAX_DEPS)
        .map(|(k, d)| {
            let version = match d {
                Value::String(s) => json!(s),
                Value::Object(spec) => spec
                    .get("version")
                    .cloned()
                    .or_else(|| spec.get("git").map(|g| json!(format!("git: {}", g.as_str().unwrap_or("?")))))
                    .or_else(|| spec.get("path").map(|p| json!(format!("path: {}", p.as_str().unwrap_or("?")))))
                    .unwrap_or_else(|| json!("*")),
                other => other.clone(),
            };
            (k.clone(), version)
        })
        .collect();
    (listed, o.len())
}

fn put_deps(cx: &mut Context<'_>, group: &str, (listed, n): (Map<String, Value>, usize)) {
    if n > 0 {
        cx.format_set(group, Value::Object(listed));
        cx.format_set(&format!("{group}_count"), n);
    }
}

pub(crate) fn npm(v: &Value, cx: &mut Context<'_>) {
    let authors: Vec<String> = v
        .get("author")
        .into_iter()
        .chain(v.get("contributors").and_then(Value::as_array).into_iter().flatten())
        .filter_map(person)
        .collect();
    let repo = v.get("repository").and_then(|r| r.as_str().or_else(|| s(r, &["url"])));
    let license = v.get("license").and_then(|l| l.as_str().or_else(|| s(l, &["type"])));
    Package {
        ecosystem: "npm",
        name: s(v, &["name"]),
        version: s(v, &["version"]),
        description: s(v, &["description"]),
        license,
        authors,
        repository: repo,
    }
    .write(cx);
    for group in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] {
        put_deps(cx, &snake(group), deps(v.get(group)));
    }
    if let Some(Value::Object(scripts)) = v.get("scripts") {
        cx.format_set("scripts", json!(scripts.keys().collect::<Vec<_>>()));
        let hooks: Vec<&String> = scripts
            .keys()
            .filter(|k| matches!(k.as_str(), "preinstall" | "install" | "postinstall" | "prepare"))
            .collect();
        if !hooks.is_empty() {
            let detail = hooks.iter().map(|h| h.as_str()).collect::<Vec<_>>().join(", ");
            cx.security().active_content("install_scripts").risk("install_script", Some(detail));
        }
    }
    for key in ["main", "module", "types", "type", "private", "engines", "workspaces", "bin", "packageManager"] {
        if let Some(x) = v.get(key) {
            cx.format_set(&snake(key), x.clone());
        }
    }
    if let Some(k) = v.get("keywords").and_then(Value::as_array) {
        for kw in k.iter().filter_map(Value::as_str) {
            cx.content().source("npm.keywords").keyword(kw);
        }
    }
}

fn snake(k: &str) -> String {
    let mut out = String::new();
    for c in k.chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn npm_lock(v: &Value, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "npm");
    if let Some(n) = s(v, &["name"]) {
        cx.format_set("name", n);
    }
    cx.format_set("lockfile_version", v.get("lockfileVersion").cloned().unwrap_or(Value::Null));
    let packages = match v.get("packages").and_then(Value::as_object) {
        Some(p) => p.keys().filter(|k| !k.is_empty()).count(),
        None => v.get("dependencies").and_then(Value::as_object).map_or(0, Map::len),
    };
    cx.format_set("resolved_packages", packages);
}

pub(crate) fn cargo(v: &Value, cx: &mut Context<'_>) {
    let pkg = v.get("package").unwrap_or(&Value::Null);
    let authors: Vec<String> =
        pkg.get("authors").and_then(Value::as_array).into_iter().flatten().filter_map(person).collect();
    Package {
        ecosystem: "cargo",
        name: s(pkg, &["name"]),
        version: s(pkg, &["version"]),
        description: s(pkg, &["description"]),
        license: s(pkg, &["license"]),
        authors,
        repository: s(pkg, &["repository"]),
    }
    .write(cx);
    for key in ["edition", "rust-version", "homepage", "documentation"] {
        if let Some(x) = pkg.get(key) {
            cx.format_set(&key.replace('-', "_"), x.clone());
        }
    }
    for group in ["dependencies", "dev-dependencies", "build-dependencies"] {
        put_deps(cx, &group.replace('-', "_"), deps(v.get(group)));
    }
    if let Some(Value::Object(f)) = v.get("features") {
        cx.format_set("features", json!(f.keys().collect::<Vec<_>>()));
    }
    if let Some(m) = v.get("workspace").and_then(|w| w.get("members")) {
        cx.format_set("workspace_members", m.clone());
    }
    for target in ["bin", "example", "test", "bench"] {
        if let Some(Value::Array(a)) = v.get(target) {
            cx.format_set(&format!("{target}_targets"), a.len());
        }
    }
    if pkg.get("build").is_some_and(|b| b != &Value::Bool(false)) {
        cx.format_set("build_script", true);
    }
    if let Some(k) = pkg.get("keywords").and_then(Value::as_array) {
        for kw in k.iter().filter_map(Value::as_str) {
            cx.content().source("cargo.keywords").keyword(kw);
        }
    }
}

fn cargo_lock(v: &Value, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "cargo");
    let packages = v.get("package").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    let mut sources: BTreeMap<&str, u64> = BTreeMap::new();
    for p in packages {
        let kind = match s(p, &["source"]) {
            Some(src) if src.starts_with("registry+") => "registry",
            Some(src) if src.starts_with("git+") => "git",
            Some(_) => "other",
            None => "local",
        };
        *sources.entry(kind).or_default() += 1;
    }
    cx.format_set("lockfile_version", v.get("version").cloned().unwrap_or(Value::Null));
    cx.format_set("resolved_packages", packages.len());
    cx.format_set("sources", json!(sources));
}

fn pyproject(v: &Value, cx: &mut Context<'_>) {
    let project = v.get("project");
    let poetry = v.get("tool").and_then(|t| t.get("poetry"));
    let p = project.or(poetry).unwrap_or(&Value::Null);
    let license = p.get("license").and_then(|l| l.as_str().or_else(|| s(l, &["text"])));
    let authors: Vec<String> =
        p.get("authors").and_then(Value::as_array).into_iter().flatten().filter_map(person).collect();
    let repo = s(p, &["urls", "Repository"]).or_else(|| s(p, &["urls", "Source"])).or_else(|| s(p, &["repository"]));
    Package {
        ecosystem: "python",
        name: s(p, &["name"]),
        version: s(p, &["version"]),
        description: s(p, &["description"]),
        license,
        authors,
        repository: repo,
    }
    .write(cx);
    if let Some(r) = s(p, &["requires-python"]) {
        cx.format_set("requires_python", r);
    }
    match p.get("dependencies") {
        Some(Value::Array(a)) => {
            let list: Vec<&str> = a.iter().filter_map(Value::as_str).take(MAX_DEPS).collect();
            cx.format_set("dependencies", json!(list));
            cx.format_set("dependencies_count", a.len());
        }
        other => put_deps(cx, "dependencies", deps(other)),
    }
    if let Some(Value::Object(groups)) = p.get("optional-dependencies") {
        cx.format_set("optional_dependency_groups", json!(groups.keys().collect::<Vec<_>>()));
    }
    if let Some(Value::Object(scripts)) = p.get("scripts") {
        cx.format_set("scripts", json!(scripts.keys().collect::<Vec<_>>()));
    }
    if let Some(b) = s(v, &["build-system", "build-backend"]) {
        cx.format_set("build_backend", b);
    }
    if let Some(Value::Object(tools)) = v.get("tool") {
        cx.format_set("tools", json!(tools.keys().collect::<Vec<_>>()));
    }
    if let Some(k) = p.get("keywords").and_then(Value::as_array) {
        for kw in k.iter().filter_map(Value::as_str) {
            cx.content().source("python.keywords").keyword(kw);
        }
    }
}

fn requirements(text: &str, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "python");
    let mut reqs = Vec::new();
    let (mut pinned, mut editable, mut hashes, mut includes) = (0u64, 0u64, false, Vec::new());
    for line in text.lines() {
        let line = line.split(" #").next().unwrap_or(line).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(index) = ["--index-url", "-i ", "--extra-index-url"].iter().find(|o| line.starts_with(**o)) {
            let url = line[index.len()..].trim_start_matches(['=', ' ']);
            cx.security().risk("custom_package_index", Some(crate::plugin::redact_secrets(url).into_owned()));
            continue;
        }
        if let Some(f) = line.strip_prefix("-r ").or_else(|| line.strip_prefix("--requirement ")) {
            includes.push(f.trim().to_string());
            continue;
        }
        if line.starts_with("-e ") || line.starts_with("--editable") {
            editable += 1;
            continue;
        }
        if line.starts_with('-') {
            continue;
        }
        hashes |= line.contains("--hash=");
        let spec = line.split(" --").next().unwrap_or(line).split(';').next().unwrap_or(line).trim();
        pinned += u64::from(spec.contains("=="));
        if reqs.len() < MAX_DEPS {
            reqs.push(spec.to_string());
        }
    }
    cx.format_set("requirements", json!(reqs));
    cx.format_set("dependencies_count", reqs.len());
    cx.format_set("pinned", pinned);
    if editable > 0 {
        cx.format_set("editable", editable);
    }
    if hashes {
        cx.format_set("hash_checking", true);
    }
    if !includes.is_empty() {
        cx.format_set("includes", json!(includes));
    }
}

fn go_mod(text: &str, cx: &mut Context<'_>) {
    let mut module = None;
    let mut go = None;
    let mut requires = Map::new();
    let (mut direct, mut indirect) = (0u64, 0u64);
    let mut replaces = Vec::new();
    let mut block: Option<String> = None;
    for raw in text.lines() {
        let line = raw.split("//").next().unwrap_or(raw).trim();
        let indirect_mark = raw.contains("// indirect");
        if line.is_empty() {
            continue;
        }
        if line == ")" {
            block = None;
            continue;
        }
        let (directive, rest) = if let Some(b) = &block {
            (b.as_str(), line)
        } else {
            let (d, r) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            if r.trim() == "(" {
                block = Some(d.to_string());
                continue;
            }
            (d, r.trim())
        };
        match directive {
            "module" => module = Some(rest.trim_matches('"').to_string()),
            "go" => go = Some(rest.to_string()),
            "toolchain" => cx.format_set("toolchain", rest),
            "require" => {
                let mut parts = rest.split_whitespace();
                if let (Some(m), Some(v)) = (parts.next(), parts.next()) {
                    if indirect_mark {
                        indirect += 1;
                    } else {
                        direct += 1;
                    }
                    if requires.len() < MAX_DEPS {
                        requires.insert(m.to_string(), json!(v));
                    }
                }
            }
            "replace" => replaces.push(rest.to_string()),
            _ => {}
        }
    }
    Package {
        ecosystem: "go",
        name: module.as_deref(),
        version: None,
        description: None,
        license: None,
        authors: Vec::new(),
        repository: None,
    }
    .write(cx);
    if let Some(g) = go {
        cx.format_set("go_version", g);
    }
    cx.format_set("dependencies", Value::Object(requires));
    cx.format_set("dependencies_count", direct + indirect);
    cx.format_set("indirect_dependencies", indirect);
    if !replaces.is_empty() {
        cx.format_set("replace", json!(replaces.iter().take(50).collect::<Vec<_>>()));
    }
}

fn go_sum(text: &str, cx: &mut Context<'_>) {
    let modules: std::collections::BTreeSet<(&str, &str)> = text
        .lines()
        .filter_map(|l| {
            let mut p = l.split_whitespace();
            let (m, v) = (p.next()?, p.next()?);
            (!v.ends_with("/go.mod")).then_some((m, v))
        })
        .collect();
    cx.format_set("ecosystem", "go");
    cx.format_set("resolved_packages", modules.len());
}

/// Maven POM: coordinates, licences, dependencies, modules, plugins.
fn maven(text: &str, cx: &mut Context<'_>) {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(text);
    reader.config_mut().check_end_names = false;
    let mut path: Vec<String> = Vec::new();
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut deps = Vec::new();
    let mut dep: BTreeMap<String, String> = BTreeMap::new();
    let (mut modules, mut plugins, mut licenses) = (Vec::new(), Vec::new(), Vec::new());
    let mut text_buf = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                path.push(e.local_name().as_ref().to_string());
                text_buf.clear();
            }
            Ok(Event::Text(t)) => text_buf.push_str(&t.xml10_content()),
            Ok(Event::End(_)) => {
                let p = path.join("/");
                let value = text_buf.trim().to_string();
                match p.as_str() {
                    "project/dependencies/dependency" => {
                        if deps.len() < MAX_DEPS {
                            let coord = format!(
                                "{}:{}",
                                dep.get("groupId").map_or("?", String::as_str),
                                dep.get("artifactId").map_or("?", String::as_str)
                            );
                            deps.push(json!({ "coordinate": coord, "version": dep.get("version"), "scope": dep.get("scope") }));
                        }
                        dep.clear();
                    }
                    "project/modules/module" => modules.push(value.clone()),
                    "project/build/plugins/plugin/artifactId" => plugins.push(value.clone()),
                    "project/licenses/license/name" => licenses.push(value.clone()),
                    _ => {}
                }
                if let Some(field) = p.strip_prefix("project/dependencies/dependency/") {
                    dep.insert(field.to_string(), value.clone());
                } else if path.len() <= 3 && !value.is_empty() && fields.len() < 100 {
                    fields.insert(p.clone(), value);
                }
                path.pop();
                text_buf.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    let get = |k: &str| fields.get(k).map(String::as_str);
    let group = get("project/groupId").or_else(|| get("project/parent/groupId"));
    let artifact = get("project/artifactId");
    let coord = match (group, artifact) {
        (Some(g), Some(a)) => Some(format!("{g}:{a}")),
        (None, Some(a)) => Some(a.to_string()),
        _ => None,
    };
    Package {
        ecosystem: "maven",
        name: coord.as_deref(),
        version: get("project/version").or_else(|| get("project/parent/version")),
        description: get("project/description"),
        license: licenses.first().map(String::as_str),
        authors: Vec::new(),
        repository: get("project/scm/url").or_else(|| get("project/url")),
    }
    .write(cx);
    if let Some(n) = get("project/name") {
        cx.content().source("maven.name").title(n);
    }
    if let Some(p) = get("project/packaging") {
        cx.format_set("packaging", p);
    }
    if let Some(p) = get("project/parent/artifactId") {
        cx.format_set("parent", format!("{}:{p}", get("project/parent/groupId").unwrap_or("?")));
    }
    let props: Map<String, Value> = fields
        .iter()
        .filter_map(|(k, v)| k.strip_prefix("project/properties/").map(|p| (p.to_string(), json!(v))))
        .take(50)
        .collect();
    if !props.is_empty() {
        cx.format_set("properties", Value::Object(props));
    }
    cx.format_set("dependencies_count", deps.len());
    cx.format_set("dependencies", Value::Array(deps));
    if !modules.is_empty() {
        cx.format_set("modules", json!(modules));
    }
    if !plugins.is_empty() {
        cx.format_set("plugins", json!(plugins));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(person(&json!("Ada Lovelace <ada@example.org> (https://ada.dev)")).as_deref(), Some("Ada Lovelace"));
        assert_eq!(snake("devDependencies"), "dev_dependencies");
        let (m, n) = deps(Some(&json!({ "serde": "1", "x": { "git": "https://g/x" }, "y": { "path": "../y" } })));
        assert_eq!((m["x"].clone(), n), (json!("git: https://g/x"), 3));
    }

    crate::fixture_tests!(
        "npm_package",
        "npm_lockfile",
        "cargo_manifest",
        "cargo_lockfile",
        "pyproject",
        "pip_requirements",
        "go_module",
        "go_sum",
        "maven_pom",
        "pipfile",
        "pipfile_lock",
        "poetry_lock",
        "uv_lock",
        "setup_py",
        "setup_cfg",
        "gradle_build",
        "dotnet_project",
        "nuget_packages",
        "vs_solution",
        "gemfile",
        "gemfile_lock",
        "podfile",
        "podfile_lock",
        "swift_package",
        "swift_package_resolved",
        "homebrew_formula",
        "brewfile",
        "composer_json",
        "composer_lock",
        "pubspec",
        "pubspec_lock",
        "mix_project",
        "mix_lock",
        "cabal",
        "stack_yaml",
        "r_description",
        "conanfile",
        "vcpkg_json",
        "deno_config",
        "julia_project",
        "julia_manifest",
        "citation_cff",
        "spdx",
        "spdx_json",
        "cyclonedx_json",
        "cyclonedx_xml",
        "pkgbuild",
        "rpm_spec",
        "debian_control",
        "debian_changelog",
        "debian_copyright",
        "nix_flake",
        "nix_flake_lock",
        "bazel_module",
        "terraform_lock",
        "snapcraft",
        "flatpak_manifest",
        "opam",
        "cpan_meta",
        "rebar_config",
        "elm_json",
        "gleam_toml",
        "zig_zon"
    );
}
