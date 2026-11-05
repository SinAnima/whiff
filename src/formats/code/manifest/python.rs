//! Python packaging beyond `pyproject.toml`: Pipfile and Pipfile.lock
//! (Pipenv), poetry.lock, uv.lock, setuptools `setup.py` (read as text,
//! never run) and `setup.cfg`.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::{Package, bracketed, deps, parse_json, parse_toml, put_deps, put_pairs, quoted, s};
use crate::plugin::{Context, ExtractError, redact_secrets};

pub(super) fn extract(id: &str, text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    match id {
        "pipfile" => pipfile(&parse_toml(text)?, cx),
        "pipfile_lock" => pipfile_lock(&parse_json(text)?, cx),
        "poetry_lock" | "uv_lock" => lock(id, &parse_toml(text)?, cx),
        "setup_py" => setup_py(text, cx),
        _ => setup_cfg(text, cx),
    }
    Ok(())
}

fn pipfile(v: &Value, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "python");
    let sources: Vec<String> = v
        .get("source")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|s| s.get("url")?.as_str())
        .map(|u| redact_secrets(u).into_owned())
        .collect();
    for url in &sources {
        if !url.contains("pypi.org") && !url.contains("pythonhosted.org") {
            cx.security().risk("custom_package_index", Some(url.clone()));
        }
    }
    if !sources.is_empty() {
        cx.format_set("sources", json!(sources));
    }
    put_deps(cx, "dependencies", deps(v.get("packages")));
    put_deps(cx, "dev_dependencies", deps(v.get("dev-packages")));
    if let Some(r) = s(v, &["requires", "python_version"]).or_else(|| s(v, &["requires", "python_full_version"])) {
        cx.format_set("requires_python", r);
    }
    if let Some(Value::Object(scripts)) = v.get("scripts") {
        cx.format_set("scripts", json!(scripts.keys().collect::<Vec<_>>()));
    }
}

fn pipfile_lock(v: &Value, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "python");
    let meta = v.get("_meta").unwrap_or(&Value::Null);
    if let Some(spec) = meta.get("pipfile-spec") {
        cx.format_set("pipfile_spec", spec.clone());
    }
    if let Some(r) = s(meta, &["requires", "python_version"]) {
        cx.format_set("requires_python", r);
    }
    if let Some(n) = meta.get("sources").and_then(Value::as_array) {
        cx.format_set("sources", n.len());
    }
    let mut total = 0;
    for (group, key) in [("dependencies", "default"), ("dev_dependencies", "develop")] {
        let Some(Value::Object(o)) = v.get(key) else { continue };
        total += o.len();
        let pairs = o.iter().map(|(k, d)| (k.clone(), s(d, &["version"]).unwrap_or("*").to_string()));
        put_pairs(cx, group, pairs);
    }
    cx.format_set("resolved_packages", total);
}

/// poetry.lock and uv.lock: `[[package]]` tables with a name, version and source.
fn lock(id: &str, v: &Value, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "python");
    cx.format_set("tool", if id == "uv_lock" { "uv" } else { "poetry" });
    let packages = v.get("package").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    let mut sources: BTreeMap<String, u64> = BTreeMap::new();
    for p in packages {
        let kind = match p.get("source") {
            // uv: `source = { registry = "…" }`, `{ git = … }`, `{ editable = "." }` …
            Some(Value::Object(o)) if id == "uv_lock" => o.keys().next().cloned().unwrap_or_default(),
            // Poetry: `[package.source] type = "git"` (none for PyPI).
            Some(src) => s(src, &["type"]).unwrap_or("other").to_string(),
            None => "registry".into(),
        };
        *sources.entry(kind).or_default() += 1;
    }
    cx.format_set("resolved_packages", packages.len());
    cx.format_set("sources", json!(sources));
    let pairs = packages
        .iter()
        .filter_map(|p| Some((s(p, &["name"])?.to_string(), s(p, &["version"]).unwrap_or("*").to_string())));
    put_pairs(cx, "packages", pairs);
    let meta = v.get("metadata").unwrap_or(&Value::Null);
    for (key, value) in [
        ("lock_version", meta.get("lock-version").or_else(|| v.get("version"))),
        ("requires_python", meta.get("python-versions").or_else(|| v.get("requires-python"))),
        ("revision", v.get("revision")),
    ] {
        if let Some(x) = value {
            cx.format_set(key, x.clone());
        }
    }
    if meta.get("content-hash").is_some() {
        cx.format_set("content_hash", true);
    }
}

/// `setup(name="…", …)`: string keyword arguments, `install_requires`, entry points.
fn setup_py(text: &str, cx: &mut Context<'_>) {
    let kw = |key: &str| -> Option<String> {
        let at = text.find(&format!("{key}=")).or_else(|| text.find(&format!("{key} =")))?;
        let rest = text[at + key.len()..].trim_start_matches([' ', '=']);
        rest.starts_with(['"', '\''])
            .then(|| quoted(rest.lines().next().unwrap_or("")))
            .and_then(|q| q.into_iter().next())
    };
    let (name, version, description, license, author, url) =
        (kw("name"), kw("version"), kw("description"), kw("license"), kw("author"), kw("url"));
    Package {
        ecosystem: "python",
        name: name.as_deref(),
        version: version.as_deref(),
        description: description.as_deref(),
        license: license.as_deref(),
        authors: author.into_iter().collect(),
        repository: url.as_deref(),
    }
    .write(cx);
    cx.format_set("build_tool", "setuptools");
    if let Some(r) = kw("python_requires") {
        cx.format_set("requires_python", r);
    }
    if let Some(list) = bracketed(text, "install_requires", '[', ']') {
        put_pairs(cx, "dependencies", quoted(list).iter().map(|r| split_requirement(r)));
    }
    if let Some(eps) = bracketed(text, "console_scripts", '[', ']') {
        let names: Vec<String> =
            quoted(eps).iter().filter_map(|e| Some(e.split('=').next()?.trim().to_string())).collect();
        cx.format_set("console_scripts", json!(names));
    }
    if text.contains("ext_modules") {
        cx.format_set("native_extensions", true);
    }
    // Custom commands run arbitrary code during `pip install`.
    if text.contains("cmdclass") {
        cx.security().active_content("install_scripts").risk("install_script", Some("setup.py cmdclass".into()));
    }
}

/// `requests>=2.31 ; python_version>"3.8"` → (`requests`, `>=2.31`).
fn split_requirement(req: &str) -> (String, String) {
    let spec = req.split(';').next().unwrap_or(req).trim();
    let at =
        spec.find(|c: char| !(c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '[' | ']'))).unwrap_or(spec.len());
    let version = spec[at..].trim();
    (spec[..at].to_string(), if version.is_empty() { "*".into() } else { version.to_string() })
}

/// INI sections with continuation lines (indented lines extend the previous value).
pub(super) fn ini_sections(text: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut out: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with(['#', ';']) {
            continue;
        }
        if let Some(name) = trimmed.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            out.push((name.trim().to_string(), Vec::new()));
            continue;
        }
        let Some((_, entries)) = out.last_mut() else { continue };
        if line.starts_with([' ', '\t'])
            && let Some((_, value)) = entries.last_mut()
        {
            value.push('\n');
            value.push_str(trimmed);
        } else if let Some((k, v)) = trimmed.split_once(['=', ':']) {
            entries.push((k.trim().to_string(), v.trim().to_string()));
        } else {
            entries.push((trimmed.to_string(), String::new()));
        }
    }
    out
}

fn setup_cfg(text: &str, cx: &mut Context<'_>) {
    let sections = ini_sections(text);
    let get = |section: &str, key: &str| -> Option<&str> {
        sections.iter().find(|(n, _)| n == section)?.1.iter().find(|(k, _)| k == key).map(|(_, v)| v.trim())
    };
    Package {
        ecosystem: "python",
        name: get("metadata", "name"),
        version: get("metadata", "version"),
        description: get("metadata", "description"),
        license: get("metadata", "license"),
        authors: get("metadata", "author").map(str::to_string).into_iter().collect(),
        repository: get("metadata", "url"),
    }
    .write(cx);
    cx.format_set("build_tool", "setuptools");
    cx.format_set("sections", json!(sections.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>()));
    if let Some(r) = get("options", "python_requires") {
        cx.format_set("requires_python", r);
    }
    if let Some(reqs) = get("options", "install_requires") {
        let lines = reqs.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'));
        put_pairs(cx, "dependencies", lines.map(split_requirement));
    }
    if let Some(c) = get("metadata", "classifiers") {
        cx.format_set("classifiers", c.lines().filter(|l| !l.trim().is_empty()).count());
    }
    if let Some(eps) = get("options.entry_points", "console_scripts") {
        let names: Vec<&str> =
            eps.lines().filter_map(|l| Some(l.split('=').next()?.trim())).filter(|n| !n.is_empty()).collect();
        cx.format_set("console_scripts", json!(names));
    }
    let extras: Vec<&str> = sections
        .iter()
        .find(|(n, _)| n == "options.extras_require")
        .map(|(_, e)| e.iter().map(|(k, _)| k.as_str()).collect())
        .unwrap_or_default();
    if !extras.is_empty() {
        cx.format_set("optional_dependency_groups", json!(extras));
    }
    if let Some(k) = get("metadata", "keywords") {
        for kw in k.split([',', '\n']).map(str::trim).filter(|k| !k.is_empty()) {
            cx.content().source("python.keywords").keyword(kw);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirement_split() {
        assert_eq!(split_requirement("requests>=2.31 ; python_version>'3.8'"), ("requests".into(), ">=2.31".into()));
        assert_eq!(split_requirement("click"), ("click".into(), "*".into()));
        let ini = ini_sections("[metadata]\nname = tide\n[options]\ninstall_requires =\n    a\n    b>=1\n");
        assert_eq!(ini[1].1[0], ("install_requires".into(), "\na\nb>=1".into()));
    }

    #[test]
    fn setup_py_cmdclass_is_flagged() {
        let r = crate::plugin::testing::report_for("setup.py", b"setup(name='x', cmdclass={'install': Custom})\n");
        assert_eq!(r.identification.format, "setup_py");
        assert!(r.security.risks.iter().any(|x| x.kind == "install_script"));
        let r =
            crate::plugin::testing::report_for("Pipfile", b"[[source]]\nurl = \"https://pkgs.example.test/simple\"\n");
        assert!(r.security.risks.iter().any(|x| x.kind == "custom_package_index"));
    }
}
