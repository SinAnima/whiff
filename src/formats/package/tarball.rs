//! Packages that are tar archives, usually compressed: npm tarballs
//! (`package/package.json`), Rust crates (`Cargo.toml`, VCS info), Python
//! source distributions (`PKG-INFO`), Ruby gems (`metadata.gz` around
//! `data.tar.gz`), Helm charts (`Chart.yaml`), Arch Linux and Alpine
//! packages (`.PKGINFO`, install scripts, Alpine signatures), conda
//! packages (`info/index.json`, `about.json`; `.tar.bz2` and the `.conda`
//! ZIP of zstd tarballs), FreeBSD packages (`+COMPACT_MANIFEST` /
//! `+MANIFEST`: origin, ABI, licences, dependencies, scripts), Slackware
//! packages (`install/slack-desc`, `install/doinst.sh`; name and version
//! from the file name), Unity asset packages (one `<guid>/` folder per
//! asset with its `pathname`: asset count, paths, kinds and top folders)
//! and Docker / OCI image tarballs (`manifest.json`,
//! `index.json`, the image config: platform, entry point, environment,
//! ports, labels, layers). The payload is listed and handed on.
//!
//! Specifications: npm `package.json`; Cargo `package` layout; PyPA core
//! metadata 2.4 and sdist format; RubyGems package format; Helm chart
//! format v2; `PKGINFO(5)` (pacman) and Alpine's apk v2 format; `pkg(8)`
//! manifests (FreeBSD); Slackware's `makepkg(8)`; conda
//! package specification; OCI image layout and image spec 1.1, Docker
//! image specification v1.2 (`docker save`).

use serde_json::Value;

use super::manifest;
use super::yaml::first_document;
use super::{Package, Tarball, bare, codec_of, ext_is, gunzip_head, person, tar_names, text, unwrap};
use crate::plugin::{
    Codec, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, Zip,
    redact_secrets, zip_names,
};

/// Extractor for tar-based packages.
pub struct Tarballs;

macro_rules! spec {
    ($id:literal, $name:literal, [$($mime:literal),*], [$($ext:literal),*]) => {
        FormatSpec {
            id: $id,
            name: $name,
            family: "package",
            mimes: &[$($mime),*],
            extensions: &[$($ext),*],
            magic: &[],
            parent: None,
        }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "package.tarball",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!("npm_tarball", "npm package tarball", ["application/gzip"], []),
        spec!("crate", "Rust crate", ["application/gzip"], ["crate"]),
        spec!("python_sdist", "Python source distribution", ["application/gzip"], []),
        spec!("gem", "Ruby gem", ["application/x-tar"], ["gem"]),
        spec!("helm_chart", "Helm chart archive", ["application/gzip"], []),
        spec!("arch_package", "Arch Linux package", ["application/x-tar"], ["pkg.tar.zst"]),
        spec!("alpine_package", "Alpine package", ["application/gzip"], ["apk"]),
        spec!("conda_package", "conda package", ["application/zip"], ["conda"]),
        spec!("freebsd_package", "FreeBSD package", ["application/x-tar"], ["pkg"]),
        spec!("slackware_package", "Slackware package", ["application/gzip"], []),
        spec!("docker_image", "Docker / OCI image tarball", ["application/x-tar"], []),
        spec!("unity_package", "Unity asset package", ["application/gzip"], ["unitypackage"]),
    ],
};

/// Which package the entry names say this is (`ext`: the file's extension).
fn kind_from_names(names: &[String], ext: Option<&str>) -> Option<&'static str> {
    let depth2 =
        |file: &str| names.iter().any(|n| n.split_once('/').is_some_and(|(top, rest)| !top.is_empty() && rest == file));
    let has = |n: &str| names.iter().any(|x| bare(x) == n);
    Some(if names.iter().any(|n| unity_pathname(bare(n))) {
        "unity_package"
    } else if names.iter().any(|n| n == "package/package.json") {
        "npm_tarball"
    } else if has("metadata.gz") && has("data.tar.gz")
        || ext == Some("gem") && (has("metadata.gz") || has("data.tar.gz") || has("checksums.yaml.gz"))
    {
        "gem"
    } else if has(".PKGINFO") || names.iter().any(|n| n.starts_with(".SIGN.")) {
        if ext == Some("apk") || names.iter().any(|n| n.starts_with(".SIGN.")) {
            "alpine_package"
        } else {
            "arch_package"
        }
    } else if has("info/index.json") {
        "conda_package"
    } else if has("+COMPACT_MANIFEST") || has("+MANIFEST") {
        "freebsd_package"
    } else if has("install/slack-desc") {
        "slackware_package"
    } else if has("manifest.json") && has("repositories")
        || has("oci-layout")
        || names.first().is_some_and(|n| n == "blobs/")
    {
        "docker_image"
    } else if depth2("Cargo.toml.orig") || ext == Some("crate") && depth2("Cargo.toml") {
        "crate"
    } else if depth2("Chart.yaml") {
        "helm_chart"
    } else if depth2("PKG-INFO") {
        "python_sdist"
    } else {
        return None;
    })
}

impl Extractor for Tarballs {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let name = probe.name.map(str::to_ascii_lowercase).unwrap_or_default();
        if probe.head.starts_with(b"PK\x03\x04") {
            if probe.extension != Some("conda") {
                return None;
            }
            let names = zip_names(probe, 64);
            let conda = names.iter().any(|n| n == "metadata.json") && names.iter().any(|n| n.starts_with("info-"));
            return conda.then_some(Sniff { format: "conda_package", confidence: 0.95 });
        }
        // Arch packages are named `<name>-<ver>-<rel>-<arch>.pkg.tar.<zst|xz|gz>`.
        if [".pkg.tar.zst", ".pkg.tar.xz", ".pkg.tar.gz"].iter().any(|e| name.ends_with(e))
            && codec_of(probe.head).is_some()
        {
            return Some(Sniff { format: "arch_package", confidence: 0.95 });
        }
        // FreeBSD's `.pkg` is a compressed tar (macOS's is a XAR archive).
        if probe.extension == Some("pkg") && !probe.head.starts_with(b"\x1f\x8b") && codec_of(probe.head).is_some() {
            return Some(Sniff { format: "freebsd_package", confidence: 0.9 });
        }
        let inflated;
        let tar = if probe.head.starts_with(b"\x1f\x8b") {
            // What the head window inflates to (bounded): metadata files
            // often follow a few large ones.
            inflated = gunzip_head(probe.head, 1 << 20)?;
            &inflated[..]
        } else {
            probe.head
        };
        let names = tar_names(tar);
        if let Some(format) = kind_from_names(&names, probe.extension) {
            return Some(Sniff { format, confidence: 0.95 });
        }
        // npm packs everything under `package/`; a crate is named `.crate`.
        if !names.is_empty() && names.iter().all(|n| n.starts_with("package/")) {
            return Some(Sniff { format: "npm_tarball", confidence: 0.92 });
        }
        (probe.extension == Some("crate") && probe.head.starts_with(b"\x1f\x8b"))
            .then_some(Sniff { format: "crate", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let size = src.len();
        if cx.format_id() == "conda_package" && src.head().starts_with(b"PK") {
            return conda_v2(src, cx);
        }
        let (raw, _) = cx.read_bytes(src)?;
        let (tar, codec, cut) = unwrap(cx, raw)?;
        let format = cx.format_id().to_string();
        let mut pkg = match format.as_str() {
            "npm_tarball" => Package::new("npm"),
            "crate" => Package::new("cargo"),
            "python_sdist" => Package::new("pypi"),
            "gem" => Package::new("rubygems"),
            "helm_chart" => Package::new("helm"),
            "arch_package" => Package::new("arch"),
            "alpine_package" => Package::new("alpine"),
            "conda_package" => Package::new("conda"),
            "freebsd_package" => Package::new("freebsd"),
            "slackware_package" => Package::new("slackware"),
            "unity_package" => Package::new("unity"),
            _ => Package::new("oci"),
        };
        if let Some(c) = codec {
            pkg.set("compression", c);
        }
        if cut {
            pkg.set("payload_truncated", true);
        }
        let mut assets = 0u64;
        let mut ball = Tarball::read(cx, "package.tar", tar, |p| {
            let w = wanted(&format, bare(p));
            assets += u64::from(w && format == "unity_package");
            w
        })?;
        match format.as_str() {
            "npm_tarball" => {
                // The manifest mapping is shared with `code.manifest`.
                if let Some(v) = ball.file(|p| p == "package/package.json").and_then(json) {
                    manifest::npm(&v, cx);
                }
            }
            "crate" => {
                if let Some(v) =
                    ball.file(|p| depth2(p, "Cargo.toml")).and_then(|d| manifest::parse_toml(&text(d)).ok())
                {
                    manifest::cargo(&v, cx);
                }
                if let Some(v) = ball.file(|p| depth2(p, ".cargo_vcs_info.json")).and_then(json) {
                    pkg.set("vcs", v);
                }
            }
            "python_sdist" => {
                if let Some(d) = ball.file(|p| depth2(p, "PKG-INFO")) {
                    super::python_metadata(&text(d), &mut pkg);
                }
            }
            "gem" => return gem(cx, ball, pkg, size),
            "helm_chart" => {
                if let Some(v) = ball.file(|p| depth2(p, "Chart.yaml")).and_then(|d| first_document(&text(d))) {
                    helm(&v, &mut pkg);
                }
            }
            "arch_package" | "alpine_package" => pkginfo(&ball, &mut pkg),
            "conda_package" => conda_info(&ball, &mut pkg),
            "freebsd_package" => {
                freebsd(&ball, &mut pkg);
                // Entries are the installed paths: absolute by design.
                ball.inventory.allow_absolute();
            }
            "slackware_package" => slackware(&ball, src.name_hint(), &mut pkg),
            "unity_package" => unity(&ball, assets, &mut pkg),
            _ => docker(cx, &ball, &mut pkg),
        }
        if matches!(format.as_str(), "npm_tarball" | "crate") {
            // The manifest mapping wrote the package facts; add the rest.
            let f = cx.format();
            for (k, v) in pkg.extra {
                f.insert(k, v);
            }
        } else {
            pkg.write(cx);
        }
        ball.finish(cx, size)
    }
}

crate::register_extractor!(Tarballs);

/// Whether `path` is `<top>/<file>`.
fn depth2(path: &str, file: &str) -> bool {
    path.split_once('/').is_some_and(|(top, rest)| !top.is_empty() && rest == file)
}

/// The metadata files a format reads.
fn wanted(format: &str, p: &str) -> bool {
    match format {
        "npm_tarball" => p == "package/package.json",
        "crate" => depth2(p, "Cargo.toml") || depth2(p, ".cargo_vcs_info.json"),
        "python_sdist" => depth2(p, "PKG-INFO"),
        "gem" => matches!(p, "metadata.gz" | "data.tar.gz") || ext_is(p, "sig"),
        "helm_chart" => depth2(p, "Chart.yaml"),
        "arch_package" | "alpine_package" => {
            p == ".PKGINFO" || p.starts_with(".SIGN.") || p == ".INSTALL" || alpine_script(p)
        }
        "conda_package" => matches!(p, "info/index.json" | "info/about.json" | "info/paths.json"),
        "freebsd_package" => matches!(p, "+COMPACT_MANIFEST" | "+MANIFEST"),
        "slackware_package" => matches!(p, "install/slack-desc" | "install/doinst.sh"),
        "unity_package" => unity_pathname(p),
        _ => {
            matches!(p, "manifest.json" | "index.json" | "repositories")
                || p.starts_with("blobs/") && !p.ends_with('/')
                || ext_is(p, "json")
        }
    }
}

/// `<32 hex digits>/pathname`: where a Unity package names an asset.
fn unity_pathname(p: &str) -> bool {
    p.split_once('/').is_some_and(|(guid, rest)| {
        rest == "pathname" && guid.len() == 32 && guid.bytes().all(|b| b.is_ascii_hexdigit())
    })
}

/// Paths listed from a Unity package.
const MAX_ASSET_PATHS: usize = 50;

/// A Unity package's assets: their project paths (the first line of each
/// `pathname`), kinds by extension and top folders.
fn unity(ball: &Tarball, assets: u64, pkg: &mut Package) {
    use std::collections::BTreeMap;
    let mut paths: Vec<String> = ball
        .files
        .iter()
        .filter(|(p, _)| unity_pathname(bare(p)))
        .filter_map(|(_, d)| text(d).lines().next().map(|l| crate::plugin::truncate_chars(l.trim(), 300)))
        .filter(|l| !l.is_empty())
        .collect();
    paths.sort();
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let mut folders: BTreeMap<String, u64> = BTreeMap::new();
    for p in &paths {
        let file = p.rsplit('/').next().unwrap_or(p);
        let kind = file.rsplit_once('.').map_or("(folder or none)", |(_, e)| e).to_ascii_lowercase();
        *kinds.entry(kind).or_default() += 1;
        let mut parts = p.split('/');
        let top = match (parts.next(), parts.next()) {
            (Some(a), Some(b)) if parts.next().is_some() => format!("{a}/{b}"),
            (Some(a), _) => a.to_string(),
            _ => continue,
        };
        *folders.entry(top).or_default() += 1;
    }
    pkg.set("assets", assets);
    if (paths.len() as u64) < assets {
        pkg.set("asset_paths_read", paths.len());
    }
    if !kinds.is_empty() {
        pkg.set("asset_kinds", serde_json::json!(kinds));
    }
    if !folders.is_empty() {
        pkg.set("folders", serde_json::json!(folders));
    }
    paths.truncate(MAX_ASSET_PATHS);
    if !paths.is_empty() {
        pkg.set("asset_paths", paths);
    }
}

/// Alpine's install scripts: dot-files next to `.PKGINFO`.
fn alpine_script(p: &str) -> bool {
    [".pre-", ".post-", ".trigger"].iter().any(|x| p.starts_with(x))
}

fn json(data: &[u8]) -> Option<Value> {
    serde_json::from_slice(data).ok()
}

fn s<'v>(v: &'v Value, key: &str) -> Option<&'v str> {
    v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn strs(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect()
}

/// A Ruby gem: `metadata.gz` (the YAML specification) and the payload in
/// `data.tar.gz`; `*.sig` members are signatures.
fn gem(cx: &mut Context<'_>, outer: Tarball, mut pkg: Package, size: u64) -> Result<(), ExtractError> {
    let sigs: Vec<String> = outer.files.iter().filter(|(p, _)| ext_is(p, "sig")).map(|(p, _)| p.clone()).collect();
    pkg.signed = Some(!sigs.is_empty());
    if let Some(m) = outer.file(|p| p == "metadata.gz") {
        let d = cx.decompress(m, Codec::Gzip, 4 << 20)?;
        if let Some(v) = first_document(&text(&d.data)) {
            gemspec(&v, &mut pkg);
        }
    }
    pkg.write(cx);
    let Some(data) = outer.file(|p| p == "data.tar.gz").map(<[u8]>::to_vec) else {
        return outer.finish(cx, size);
    };
    let (tar, _, _) = unwrap(cx, data)?;
    Tarball::read(cx, "data.tar", tar, |_| false)?.finish(cx, size)
}

/// The fields of a gem specification (YAML with Ruby object tags, which
/// read as plain mappings).
fn gemspec(v: &Value, pkg: &mut Package) {
    let version =
        |x: Option<&Value>| x.and_then(|x| x.get("version").or(Some(x))).and_then(Value::as_str).map(str::to_string);
    pkg.name = s(v, "name").map(str::to_string);
    pkg.version = version(v.get("version"));
    pkg.summary = s(v, "summary").map(str::to_string);
    pkg.description = s(v, "description").map(str::to_string);
    pkg.license = Some(strs(v.get("licenses")).join(" AND ")).filter(|l| !l.is_empty());
    pkg.authors = strs(v.get("authors"));
    pkg.homepage = s(v, "homepage").map(str::to_string);
    pkg.architecture = s(v, "platform").map(str::to_string);
    for d in v.get("dependencies").and_then(Value::as_array).into_iter().flatten() {
        if s(d, "type") == Some(":development") {
            continue;
        }
        let reqs = d.pointer("/requirement/requirements").and_then(Value::as_array);
        let constraint: Vec<String> = reqs
            .into_iter()
            .flatten()
            .filter_map(|r| Some(format!("{} {}", r.get(0)?.as_str()?, version(r.get(1))?)))
            .collect();
        pkg.depend(s(d, "name").unwrap_or(""), &constraint.join(", "));
    }
    // Native extensions are built (code run) when the gem is installed.
    for e in strs(v.get("extensions")) {
        pkg.scripts.push(e);
    }
    if let Some(m) = s(v, "post_install_message") {
        pkg.set("post_install_message", m);
    }
    if let Some(e) = strs(v.get("executables")).into_iter().next().map(|_| strs(v.get("executables"))) {
        pkg.set("executables", e);
    }
    if let Some(r) = v
        .pointer("/required_ruby_version/requirements/0")
        .and_then(|r| Some(format!("{} {}", r.get(0)?.as_str()?, version(r.get(1))?)))
    {
        pkg.set("required_ruby_version", r);
    }
    if let Some(n) = v.get("files").and_then(Value::as_array) {
        pkg.set("listed_files", n.len());
    }
}

fn helm(v: &Value, pkg: &mut Package) {
    pkg.name = s(v, "name").map(str::to_string);
    pkg.version = s(v, "version").map(str::to_string);
    pkg.description = s(v, "description").map(str::to_string);
    pkg.homepage = s(v, "home").map(str::to_string);
    pkg.repository = strs(v.get("sources")).into_iter().next();
    pkg.license = v
        .pointer("/annotations/artifacthub.io~1license")
        .or_else(|| v.pointer("/annotations/licenses"))
        .and_then(Value::as_str)
        .map(str::to_string);
    for m in v.get("maintainers").and_then(Value::as_array).into_iter().flatten() {
        pkg.authors.extend(s(m, "name").map(str::to_string));
    }
    for d in v.get("dependencies").and_then(Value::as_array).into_iter().flatten() {
        pkg.depend(s(d, "name").unwrap_or(""), s(d, "version").unwrap_or(""));
    }
    for (key, out) in [
        ("appVersion", "app_version"),
        ("apiVersion", "api_version"),
        ("type", "chart_type"),
        ("kubeVersion", "kube_version"),
    ] {
        if let Some(x) = v.get(key).filter(|x| !x.is_null()) {
            pkg.set(out, x.clone());
        }
    }
}

/// `.PKGINFO` (`key = value` lines) of Arch and Alpine packages.
fn pkginfo(ball: &Tarball, pkg: &mut Package) {
    let alpine = pkg.ecosystem == "alpine";
    let mut sigs: Vec<String> = Vec::new();
    for (p, _) in &ball.files {
        if let Some(k) = p.strip_prefix(".SIGN.") {
            sigs.push(k.split('.').next().unwrap_or(k).to_ascii_lowercase());
        }
    }
    if alpine {
        pkg.signed = Some(!sigs.is_empty());
        pkg.signatures = sigs;
    }
    if ball.file(|p| p == ".INSTALL").is_some() {
        pkg.scripts.push(".INSTALL".into());
    }
    let Some(info) = ball.file(|p| p == ".PKGINFO").map(text) else { return };
    let mut provides = Vec::new();
    let mut conflicts = Vec::new();
    for line in info.lines() {
        let Some((k, v)) = line.split_once(" = ") else {
            if let Some(tool) = line.strip_prefix("# Generated by ") {
                pkg.set("generator", tool.trim());
            }
            continue;
        };
        let v = v.trim();
        match k.trim() {
            "pkgname" => pkg.name = Some(v.to_string()),
            "pkgver" => pkg.version = Some(v.to_string()),
            "pkgdesc" => pkg.summary = Some(v.to_string()),
            "url" => pkg.homepage = Some(v.to_string()),
            "arch" => pkg.architecture = Some(v.to_string()),
            "license" => {
                pkg.license = Some(match pkg.license.take() {
                    Some(l) => format!("{l} AND {v}"),
                    None => v.to_string(),
                });
            }
            "packager" | "maintainer" => {
                if let Some(p) = person(v).filter(|p| !pkg.authors.contains(p)) {
                    pkg.authors.push(p);
                }
            }
            "depend" => {
                let (n, c) = v.find(['<', '>', '=', '~']).map_or((v, ""), |i| v.split_at(i));
                pkg.depend(n, c);
            }
            "provides" => provides.push(v.to_string()),
            "conflict" => conflicts.push(v.to_string()),
            "size" => {
                if let Ok(n) = v.parse::<u64>() {
                    pkg.set("installed_size_bytes", n);
                }
            }
            "builddate" => {
                if let Some(t) = v.parse::<i64>().ok().and_then(super::archive::unix_time) {
                    pkg.set("build_time", t);
                }
            }
            "origin" | "pkgbase" if pkg.name.as_deref() != Some(v) => pkg.set("base", v),
            "commit" => pkg.set("commit", v),
            _ => {}
        }
    }
    if alpine {
        for (p, _) in &ball.files {
            if alpine_script(bare(p)) {
                pkg.scripts.push(bare(p).to_string());
            }
        }
    }
    if !provides.is_empty() {
        pkg.set("provides", provides);
    }
    if !conflicts.is_empty() {
        pkg.set("conflicts", conflicts);
    }
}

fn conda_info(ball: &Tarball, pkg: &mut Package) {
    if let Some(v) = ball.file(|p| p == "info/index.json").and_then(json) {
        pkg.name = s(&v, "name").map(str::to_string);
        pkg.version = s(&v, "version").map(str::to_string);
        pkg.license = s(&v, "license").map(str::to_string);
        pkg.architecture = s(&v, "subdir").or_else(|| s(&v, "arch")).map(str::to_string);
        for d in strs(v.get("depends")) {
            let (n, c) = d.split_once(' ').unwrap_or((&d, ""));
            pkg.depend(n, c);
        }
        if let Some(b) = s(&v, "build") {
            pkg.release = Some(b.to_string());
        }
        if let Some(t) = v.get("timestamp").and_then(Value::as_i64).and_then(|t| super::archive::unix_time(t / 1000)) {
            pkg.set("build_time", t);
        }
    }
    if let Some(v) = ball.file(|p| p == "info/about.json").and_then(json) {
        pkg.summary = s(&v, "summary").map(str::to_string);
        pkg.description = s(&v, "description").map(str::to_string);
        pkg.homepage = s(&v, "home").map(str::to_string);
        pkg.repository = s(&v, "dev_url").map(str::to_string);
        if pkg.license.is_none() {
            pkg.license = s(&v, "license").map(str::to_string);
        }
    }
    if let Some(v) = ball.file(|p| p == "info/paths.json").and_then(json) {
        let paths = v.get("paths").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
        pkg.set("listed_files", paths.len());
        // `post-link` / `pre-unlink` scripts run when the package is linked into an environment.
        for p in paths.iter().filter_map(|p| s(p, "_path")) {
            let n = p.rsplit('/').next().unwrap_or(p);
            if n.starts_with('.') && ["-post-link.", "-pre-link.", "-pre-unlink."].iter().any(|x| n.contains(x)) {
                pkg.scripts.push(p.to_string());
            }
        }
    }
}

/// A FreeBSD package's manifest (JSON in `+COMPACT_MANIFEST`; `+MANIFEST`
/// adds the scripts and the file list).
fn freebsd(ball: &Tarball, pkg: &mut Package) {
    let full = ball.file(|p| p == "+MANIFEST").and_then(json);
    let Some(m) = ball.file(|p| p == "+COMPACT_MANIFEST").and_then(json).or_else(|| full.clone()) else { return };
    pkg.name = s(&m, "name").map(str::to_string);
    pkg.version = s(&m, "version").map(str::to_string);
    pkg.summary = s(&m, "comment").map(str::to_string);
    pkg.description = s(&m, "desc").map(str::to_string);
    pkg.homepage = s(&m, "www").map(str::to_string);
    pkg.architecture = s(&m, "abi").or_else(|| s(&m, "arch")).map(str::to_string);
    pkg.authors.extend(s(&m, "maintainer").and_then(person));
    let licenses = strs(m.get("licenses"));
    if !licenses.is_empty() {
        let joiner = if s(&m, "licenselogic") == Some("or") { " OR " } else { " AND " };
        pkg.license = Some(licenses.join(joiner));
    }
    if let Some(Value::Object(deps)) = m.get("deps") {
        for (n, d) in deps {
            pkg.depend(n, s(d, "version").unwrap_or(""));
        }
    }
    for (key, out) in [("origin", "origin"), ("prefix", "prefix")] {
        if let Some(v) = s(&m, key) {
            pkg.set(out, v);
        }
    }
    if let Some(n) = m.get("flatsize").and_then(Value::as_u64) {
        pkg.set("installed_size_bytes", n);
    }
    let categories = strs(m.get("categories"));
    if !categories.is_empty() {
        pkg.set("categories", categories);
    }
    if let Some(Value::Object(scripts)) = full.as_ref().and_then(|f| f.get("scripts")) {
        pkg.scripts.extend(scripts.keys().cloned());
    }
    if let Some(Value::Object(files)) = full.as_ref().and_then(|f| f.get("files")) {
        pkg.set("listed_files", files.len());
    }
}

/// A Slackware package: `install/slack-desc` (`name: text` lines) and an
/// `install/doinst.sh` script; name, version, architecture and build come
/// from the file name (`<name>-<version>-<arch>-<build>.txz`).
fn slackware(ball: &Tarball, file: Option<&str>, pkg: &mut Package) {
    if let Some(stem) = file.map(|f| f.rsplit(['/', '\\']).next().unwrap_or(f)) {
        let stem = [".txz", ".tgz", ".tlz", ".tbz", ".tar"].iter().fold(stem, |s, x| s.strip_suffix(x).unwrap_or(s));
        let parts: Vec<&str> = stem.rsplitn(4, '-').collect();
        if let [build, arch, version, name] = parts[..] {
            pkg.name = Some(name.to_string());
            pkg.version = Some(version.to_string());
            pkg.architecture = Some(arch.to_string());
            pkg.release = Some(build.to_string());
        }
    }
    if let Some(desc) = ball.file(|p| p == "install/slack-desc").map(text) {
        if pkg.name.is_none() {
            pkg.name = desc
                .lines()
                .filter(|l| !l.starts_with('#'))
                .find_map(|l| l.split_once(':').map(|(n, _)| n.trim().to_string()));
        }
        let lines: Vec<&str> = desc
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once(':'))
            .filter(|(n, _)| pkg.name.as_deref() == Some(*n))
            .map(|(_, t)| t.trim())
            .collect();
        if let Some((first, rest)) = lines.split_first() {
            pkg.summary = Some((*first).to_string());
            let body = rest.iter().copied().filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" ");
            pkg.description = Some(body).filter(|b| !b.is_empty());
        }
    }
    if ball.file(|p| p == "install/doinst.sh").is_some() {
        pkg.scripts.push("install/doinst.sh".into());
    }
}

/// A `.conda` package: a ZIP of `info-*.tar.zst` (metadata) and
/// `pkg-*.tar.zst` (payload).
fn conda_v2(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let zip = Zip::open(src, 64)?;
    let mut pkg = Package::new("conda");
    pkg.set("compression", "zstd");
    let mut payload: Option<Vec<u8>> = None;
    for e in &zip.entries {
        let is_info = e.name.starts_with("info-") && e.name.ends_with(".tar.zst");
        if !(is_info || e.name.starts_with("pkg-") && e.name.ends_with(".tar.zst")) {
            continue;
        }
        let raw = zip.read(src, e, cx, cx.parse_limit())?;
        let (tar, _, _) = unwrap(cx, raw)?;
        if is_info {
            let info = Tarball::read(cx, &e.name, tar, |p| wanted("conda_package", p))?;
            conda_info(&info, &mut pkg);
        } else {
            payload = Some(tar);
        }
    }
    pkg.write(cx);
    match payload {
        Some(tar) => Tarball::read(cx, "pkg.tar", tar, |_| false)?.finish(cx, src.len()),
        None => Ok(()),
    }
}

/// A `docker save` / OCI image layout tarball.
fn docker(cx: &mut Context<'_>, ball: &Tarball, pkg: &mut Package) {
    let blob = |digest: &str| {
        let path = format!("blobs/{}", digest.replacen(':', "/", 1));
        ball.file(|p| p == path || p == digest)
    };
    let manifest = ball.file(|p| p == "manifest.json").and_then(json);
    let first = manifest.as_ref().and_then(|m| m.get(0));
    let mut config_path = first.and_then(|m| s(m, "Config")).map(str::to_string);
    let mut layers = first.map_or(0, |m| strs(m.get("Layers")).len());
    let tags = first.map(|m| strs(m.get("RepoTags"))).unwrap_or_default();
    if let Some(index) = ball.file(|p| p == "index.json").and_then(json) {
        pkg.set("oci_layout", true);
        // The first image manifest, then its config.
        if config_path.is_none()
            && let Some(m) = index.pointer("/manifests/0/digest").and_then(Value::as_str).and_then(blob).and_then(json)
        {
            config_path = m
                .pointer("/config/digest")
                .and_then(Value::as_str)
                .map(|d| format!("blobs/{}", d.replacen(':', "/", 1)));
            layers = m.get("layers").and_then(Value::as_array).map_or(0, Vec::len);
        }
    }
    if let Some(t) = tags.first() {
        let (name, version) = t.rsplit_once(':').filter(|(n, _)| !n.ends_with('/')).unwrap_or((t, ""));
        pkg.name = Some(name.to_string());
        pkg.version = Some(version.to_string()).filter(|v| !v.is_empty());
    }
    if !tags.is_empty() {
        pkg.set("tags", tags);
    }
    pkg.set("layers", layers);
    let Some(config) = config_path.as_deref().and_then(|p| ball.file(|x| x == p)).and_then(json) else { return };
    pkg.architecture = s(&config, "architecture").map(|a| match s(&config, "variant") {
        Some(v) => format!("{a}/{v}"),
        None => a.to_string(),
    });
    if let Some(os) = s(&config, "os") {
        pkg.set("os", os);
    }
    if let Some(t) = s(&config, "created") {
        pkg.set("created", t);
        cx.temporal().content_date(DateField::Created, t, true);
    }
    let c = config.get("config").cloned().unwrap_or(Value::Null);
    let labels = c.get("Labels").and_then(Value::as_object);
    let label = |k: &str| labels.and_then(|l| l.get(k)).and_then(Value::as_str).map(str::to_string);
    pkg.summary = label("org.opencontainers.image.title").or_else(|| label("org.opencontainers.image.description"));
    pkg.description = label("org.opencontainers.image.description");
    pkg.license = label("org.opencontainers.image.licenses");
    pkg.homepage = label("org.opencontainers.image.url");
    pkg.repository = label("org.opencontainers.image.source");
    pkg.authors.extend(label("org.opencontainers.image.authors").or_else(|| label("org.opencontainers.image.vendor")));
    if pkg.version.is_none() {
        pkg.version = label("org.opencontainers.image.version");
    }
    for (key, out) in [("Entrypoint", "entrypoint"), ("Cmd", "cmd")] {
        let v = strs(c.get(key));
        if !v.is_empty() {
            pkg.set(out, v);
        }
    }
    let env: Vec<String> = strs(c.get("Env")).iter().map(|e| redact_secrets(e).into_owned()).collect();
    if !env.is_empty() {
        pkg.set("env", env);
    }
    if let Some(p) = c.get("ExposedPorts").and_then(Value::as_object) {
        pkg.set("exposed_ports", p.keys().cloned().collect::<Vec<_>>());
    }
    if let Some(l) = labels.filter(|l| !l.is_empty()) {
        pkg.set("labels", Value::Object(l.clone()));
    }
    for (key, out) in [("WorkingDir", "working_dir"), ("User", "user")] {
        if let Some(v) = s(&c, key) {
            pkg.set(out, v);
        }
    }
    let user = s(&c, "User").unwrap_or("");
    if user.is_empty() || user == "root" || user == "0" || user.starts_with("0:") || user.starts_with("root:") {
        cx.security().risk("runs_as_root", Some(if user.is_empty() { "no USER set".into() } else { user.to_string() }));
    }
    if let Some(h) = config.get("history").and_then(Value::as_array) {
        pkg.set("history_steps", h.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn kinds() {
        assert_eq!(
            kind_from_names(&names(&["package/index.js", "package/package.json"]), Some("tgz")),
            Some("npm_tarball")
        );
        assert_eq!(kind_from_names(&names(&["metadata.gz", "data.tar.gz"]), None), Some("gem"));
        assert_eq!(
            kind_from_names(&names(&["t-1/Cargo.lock", "t-1/Cargo.toml", "t-1/Cargo.toml.orig"]), None),
            Some("crate")
        );
        assert_eq!(kind_from_names(&names(&["x-1/", "x-1/PKG-INFO"]), None), Some("python_sdist"));
        assert_eq!(kind_from_names(&names(&["c/Chart.yaml"]), None), Some("helm_chart"));
        assert_eq!(kind_from_names(&names(&[".SIGN.RSA.k.pub"]), None), Some("alpine_package"));
        assert_eq!(kind_from_names(&names(&[".PKGINFO", ".BUILDINFO"]), None), Some("arch_package"));
        assert_eq!(kind_from_names(&names(&["blobs/", "blobs/sha256/"]), None), Some("docker_image"));
        assert_eq!(kind_from_names(&names(&["harbour/notes.txt"]), None), None);
    }

    crate::fixture_tests!(
        "npm_tarball",
        "crate",
        "python_sdist",
        "gem",
        "helm_chart",
        "arch_package",
        "alpine_package",
        "conda_package",
        "freebsd_package",
        "slackware_package",
        "docker_image"
    );
}
