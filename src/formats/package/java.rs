//! Java archives: JAR, WAR (web application), EAR (enterprise application)
//! and AAR (Android library). `META-INF/MANIFEST.MF` gives the title,
//! version and vendor (`Implementation-*`, `Specification-*`, OSGi
//! `Bundle-*`), main class, class path, module name, multi-release flag,
//! Java agents and the JDK that built it; Maven's `pom.properties` gives
//! the coordinates; `META-INF/*.SF` with `*.RSA` / `*.DSA` / `*.EC` are
//! JAR signatures. Classes are counted and the first one's version gives
//! the Java release targeted. WAR: `WEB-INF/web.xml` and bundled
//! libraries; EAR: the modules of `application.xml`; AAR: the package and
//! SDK levels of its `AndroidManifest.xml`. Entries (nested JARs among
//! them) are listed and handed on.
//!
//! Specifications: JAR File Specification (Java SE 21); Maven
//! `pom.properties`; OSGi Core R8 §3.2; Jakarta Servlet 6 / Jakarta EE 10
//! deployment descriptors; Android AAR format.

use super::xml::{Ev, Flow, walk};
use super::{Package, ext_is, field, fields, person, zip_payload};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, Zip, zip_names,
};

/// Extractor for Java archives.
pub struct Java;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, $ext:literal) => {
        FormatSpec {
            id: $id,
            name: $name,
            family: "package",
            mimes: &[$mime],
            extensions: &[$ext],
            magic: &[],
            parent: Some("zip"),
        }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "package.java",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!("jar", "Java archive", "application/java-archive", "jar"),
        spec!("war", "Java web application archive", "application/java-archive", "war"),
        spec!("ear", "Java enterprise application archive", "application/java-archive", "ear"),
        spec!("aar", "Android library archive", "application/vnd.android.aar", "aar"),
    ],
};

const MAX_ENTRIES: usize = 1 << 16;

/// Which Java archive the names (and extension) say this is.
fn kind(names: &[String], ext: Option<&str>) -> Option<(&'static str, f64)> {
    let has = |n: &str| names.iter().any(|x| x == n);
    let starts = |p: &str| names.iter().any(|x| x.starts_with(p));
    if has("AndroidManifest.xml") {
        return has("classes.jar").then_some(("aar", 0.95));
    }
    let manifest = has("META-INF/MANIFEST.MF") || has("META-INF/");
    let classes = names.iter().any(|n| ext_is(n, "class")) || starts("META-INF/maven/");
    let by_ext = match ext {
        Some("war") => Some("war"),
        Some("ear") => Some("ear"),
        Some("jar") => Some("jar"),
        _ => None,
    };
    if starts("WEB-INF/") && (manifest || by_ext == Some("war")) {
        return Some(("war", 0.93));
    }
    if has("META-INF/application.xml") {
        return Some(("ear", 0.93));
    }
    match (by_ext, manifest, classes) {
        (Some(k), true, _) => Some((k, 0.93)),
        (Some(k), false, true) => Some((k, 0.9)),
        (None, true, true) => Some(("jar", 0.88)),
        _ => None,
    }
}

/// The Java release a class-file major version targets (45 = 1.1 … 52 = 8).
pub(crate) fn java_release(major: u16) -> Option<String> {
    match major {
        45..=48 => Some(format!("1.{}", major - 44)),
        49..=99 => Some((major - 44).to_string()),
        _ => None,
    }
}

impl Extractor for Java {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if !probe.head.starts_with(b"PK\x03\x04") {
            return None;
        }
        let names = zip_names(probe, 4000);
        kind(&names, probe.extension).map(|(format, confidence)| Sniff { format, confidence })
    }

    #[allow(clippy::too_many_lines)] // manifest, coordinates, signatures, per-kind descriptors
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let zip = Zip::open(src, MAX_ENTRIES)?;
        zip.flag_duplicates(cx);
        let mut pkg = Package::new("maven");
        let main = match zip.read_text(src, "META-INF/MANIFEST.MF", cx, 1 << 20) {
            Some(Ok(t)) => t,
            _ => String::new(),
        };
        let (m, _) = fields(&main, "");
        let get = |k: &str| field(&m, k).map(str::to_string);
        pkg.name = get("Implementation-Title").or_else(|| get("Bundle-Name")).or_else(|| get("Bundle-SymbolicName"));
        pkg.version = get("Implementation-Version").or_else(|| get("Bundle-Version"));
        pkg.authors.extend(get("Implementation-Vendor").or_else(|| get("Bundle-Vendor")));
        pkg.description = get("Bundle-Description");
        pkg.license = get("Bundle-License").map(|l| l.split(';').next().unwrap_or(&l).trim().to_string());
        pkg.homepage = get("Bundle-DocURL");
        for (key, out) in [
            ("Manifest-Version", "manifest_version"),
            ("Main-Class", "main_class"),
            ("Automatic-Module-Name", "module_name"),
            ("Bundle-SymbolicName", "bundle_symbolic_name"),
            ("Created-By", "created_by"),
            ("Build-Jdk-Spec", "build_jdk"),
            ("Build-Jdk", "build_jdk"),
            ("Premain-Class", "agent_premain_class"),
            ("Agent-Class", "agent_class"),
            ("Launcher-Agent-Class", "launcher_agent_class"),
            ("Specification-Title", "specification_title"),
            ("Specification-Version", "specification_version"),
        ] {
            if let Some(v) = field(&m, key)
                && !pkg.extra.contains_key(out)
            {
                pkg.set(out, v);
            }
        }
        if let Some(cp) = field(&m, "Class-Path") {
            pkg.set("class_path", cp.split_whitespace().collect::<Vec<_>>());
        }
        if field(&m, "Multi-Release").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
            pkg.set("multi_release", true);
        }
        // Maven coordinates; a shaded JAR carries several.
        let poms: Vec<String> = zip
            .entries
            .iter()
            .filter(|e| e.name.starts_with("META-INF/maven/") && e.name.ends_with("/pom.properties"))
            .map(|e| e.name.clone())
            .collect();
        if let Some(first) = poms.first()
            && let Some(Ok(t)) = zip.read_text(src, first, cx, 64 << 10)
        {
            let prop = |k: &str| {
                t.lines().find_map(|l| l.strip_prefix(k)?.trim_start().strip_prefix('=').map(|v| v.trim().to_string()))
            };
            if let (Some(g), Some(a)) = (prop("groupId"), prop("artifactId")) {
                pkg.set("coordinates", format!("{g}:{a}"));
                pkg.name = pkg.name.or(Some(a));
            }
            if pkg.version.is_none() {
                pkg.version = prop("version");
            }
        }
        if poms.len() > 1 {
            pkg.set("bundled_maven_artifacts", poms.len());
        }
        // Signatures: a `.SF` signature file with its signature block.
        let signers: Vec<String> = zip
            .entries
            .iter()
            .filter_map(|e| e.name.strip_prefix("META-INF/")?.strip_suffix(".SF").map(str::to_string))
            .filter(|s| !s.contains('/'))
            .collect();
        let blocks = zip.entries.iter().any(|e| {
            e.name.starts_with("META-INF/")
                && [".RSA", ".DSA", ".EC"].iter().any(|x| e.name.to_ascii_uppercase().ends_with(x))
        });
        pkg.signed = Some(!signers.is_empty() && blocks);
        if !signers.is_empty() {
            pkg.signatures = signers;
        }
        // Classes and the release they target.
        let classes: Vec<&crate::plugin::ZipEntry> = zip.entries.iter().filter(|e| ext_is(&e.name, "class")).collect();
        if !classes.is_empty() {
            pkg.set("classes", classes.len());
            let sample = classes.iter().find(|e| !e.name.ends_with("module-info.class")).unwrap_or(&classes[0]);
            if let Ok(head) = zip.read(src, sample, cx, 1 << 20)
                && head.starts_with(b"\xca\xfe\xba\xbe")
                && head.len() >= 8
            {
                let major = u16::from_be_bytes([head[6], head[7]]);
                pkg.set("class_file_version", major);
                if let Some(r) = java_release(major) {
                    pkg.set("java_release", r);
                }
            }
        }
        if zip.entries.iter().any(|e| e.name == "module-info.class" || e.name.ends_with("/module-info.class")) {
            pkg.set("modular", true);
        }
        let nested = zip.entries.iter().filter(|e| ext_is(&e.name, "jar")).count();
        if nested > 0 {
            pkg.set("nested_jars", nested);
        }
        match cx.format_id() {
            "war" => {
                if let Some(Ok(xml)) = zip.read_text(src, "WEB-INF/web.xml", cx, 4 << 20) {
                    let names = elements(&xml, cx, &["servlet-class", "filter-class", "display-name"])?;
                    let servlets: Vec<&String> =
                        names.iter().filter(|(k, _)| k == "servlet-class").map(|(_, v)| v).collect();
                    pkg.set("servlets", servlets.iter().map(|s| s.as_str()).collect::<Vec<_>>());
                    if let Some((_, d)) = names.iter().find(|(k, _)| k == "display-name") {
                        pkg.name = pkg.name.or(Some(d.clone()));
                    }
                }
            }
            "ear" => {
                if let Some(Ok(xml)) = zip.read_text(src, "META-INF/application.xml", cx, 4 << 20) {
                    let names = elements(&xml, cx, &["web-uri", "ejb", "java", "connector", "display-name"])?;
                    let modules: Vec<String> =
                        names.iter().filter(|(k, _)| k != "display-name").map(|(_, v)| v.clone()).collect();
                    pkg.set("modules", modules);
                    if let Some((_, d)) = names.iter().find(|(k, _)| k == "display-name") {
                        pkg.name = pkg.name.or(Some(d.clone()));
                    }
                }
            }
            "aar" => {
                pkg.ecosystem = "android";
                if let Some(Ok(xml)) = zip.read_text(src, "AndroidManifest.xml", cx, 4 << 20) {
                    android_text_manifest(&xml, cx, &mut pkg)?;
                }
            }
            _ => {}
        }
        pkg.authors = pkg.authors.iter().filter_map(|a| person(a)).collect();
        pkg.write(cx);
        zip_payload(src, cx, &zip)
    }
}

crate::register_extractor!(Java);

/// The text of the given elements, in document order.
fn elements(xml: &str, cx: &mut Context<'_>, names: &[&str]) -> Result<Vec<(String, String)>, ExtractError> {
    let mut out = Vec::new();
    let mut open: Option<String> = None;
    walk(xml, cx, |ev| {
        match ev {
            Ev::Open(t, _) => open = names.contains(&t.name.as_str()).then(|| t.name.clone()),
            Ev::Text(s) => {
                if let Some(n) = open.take()
                    && out.len() < 1000
                {
                    out.push((n, s.trim().to_string()));
                }
            }
            Ev::Close(_) => open = None,
        }
        Flow::Continue
    })?;
    Ok(out)
}

/// An AAR's plain-text `AndroidManifest.xml`: package and SDK levels.
fn android_text_manifest(xml: &str, cx: &mut Context<'_>, pkg: &mut Package) -> Result<(), ExtractError> {
    walk(xml, cx, |ev| {
        if let Ev::Open(t, _) = ev {
            match t.name.as_str() {
                "manifest" => {
                    if let Some(p) = t.attr("package") {
                        pkg.set("package", p);
                        pkg.name = pkg.name.take().or_else(|| Some(p.to_string()));
                    }
                }
                "uses-sdk" => {
                    for (a, out) in [("minSdkVersion", "min_sdk"), ("targetSdkVersion", "target_sdk")] {
                        if let Some(v) = t.attr(a) {
                            pkg.set(out, v);
                        }
                    }
                }
                _ => {}
            }
        }
        Flow::Continue
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn kinds() {
        assert_eq!(kind(&names(&["META-INF/MANIFEST.MF", "a/B.class"]), None), Some(("jar", 0.88)));
        assert_eq!(kind(&names(&["META-INF/MANIFEST.MF", "WEB-INF/web.xml"]), Some("war")), Some(("war", 0.93)));
        assert_eq!(kind(&names(&["AndroidManifest.xml", "classes.jar"]), Some("aar")), Some(("aar", 0.95)));
        assert_eq!(kind(&names(&["AndroidManifest.xml", "classes.dex"]), Some("apk")), None);
        assert_eq!(kind(&names(&["META-INF/MANIFEST.MF", "manifest.json"]), Some("xpi")), None);
        assert_eq!(java_release(52).as_deref(), Some("8"));
        assert_eq!(java_release(61).as_deref(), Some("17"));
        assert_eq!(java_release(46).as_deref(), Some("1.2"));
    }

    crate::fixture_tests!("jar", "war", "ear", "aar");
}
