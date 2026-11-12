//! Software bills of materials: SPDX (tag-value and JSON) and `CycloneDX`
//! (JSON and XML). Document name, spec version, creation time, creator
//! tools, the described component, package / component counts by type,
//! licences, ecosystems (from package URLs), relationships and
//! vulnerabilities. People among the creators are counted, not listed.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::{parse_json, put_pairs, s};
use crate::plugin::xmlwalk::{Ev, attr, walk};
use crate::plugin::{Context, DateField, ExtractError, parse_date};

/// Licence ids and ecosystems listed at most.
const MAX_KEYS: usize = 50;

pub(super) fn extract(id: &str, text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let sbom = match id {
        "spdx" => spdx_tags(text),
        "spdx_json" => spdx_json(&parse_json(text)?),
        "cyclonedx_json" => cyclonedx_json(&parse_json(text)?),
        _ => cyclonedx_xml(text, cx)?,
    };
    sbom.report(cx);
    Ok(())
}

#[derive(Default)]
struct Sbom {
    format: &'static str,
    spec_version: Option<String>,
    name: Option<String>,
    serial: Option<String>,
    created: Option<String>,
    tools: Vec<String>,
    organisations: Vec<String>,
    persons: u64,
    primary: Option<(String, Option<String>)>,
    packages: Vec<(String, String)>,
    types: BTreeMap<String, u64>,
    licenses: BTreeMap<String, u64>,
    ecosystems: BTreeMap<String, u64>,
    files: u64,
    relationships: u64,
    vulnerabilities: u64,
}

impl Sbom {
    fn package(&mut self, name: &str, version: Option<&str>) {
        self.packages.push((name.to_string(), version.unwrap_or("*").to_string()));
    }

    fn license(&mut self, l: &str) {
        let l = l.trim();
        if !l.is_empty()
            && !matches!(l, "NOASSERTION" | "NONE")
            && (self.licenses.len() < MAX_KEYS || self.licenses.contains_key(l))
        {
            *self.licenses.entry(l.to_string()).or_default() += 1;
        }
    }

    /// `pkg:npm/%40scope/name@1.0` → `npm`.
    fn purl(&mut self, purl: &str) {
        if let Some(kind) = purl.strip_prefix("pkg:").and_then(|r| r.split('/').next())
            && (self.ecosystems.len() < MAX_KEYS || self.ecosystems.contains_key(kind))
        {
            *self.ecosystems.entry(kind.to_ascii_lowercase()).or_default() += 1;
        }
    }

    /// SPDX `Tool: name-1.0`, `Organization: X`, `Person: Y (y@x)`.
    fn creator(&mut self, c: &str) {
        if let Some(t) = c.strip_prefix("Tool:") {
            self.tools.push(t.trim().to_string());
        } else if let Some(o) = c.strip_prefix("Organization:") {
            self.organisations.push(o.split('(').next().unwrap_or(o).trim().to_string());
        } else if c.starts_with("Person:") {
            self.persons += 1;
        }
    }

    fn report(self, cx: &mut Context<'_>) {
        cx.format_set("sbom_format", self.format);
        if let Some(v) = &self.spec_version {
            cx.format_set("spec_version", v.as_str());
        }
        if let Some(n) = &self.name {
            cx.format_set("document_name", n.as_str());
            cx.content().source("sbom").title(n.as_str());
        }
        if let Some(s) = &self.serial {
            cx.format_set("serial_number", s.as_str());
        }
        if let Some((d, tz)) = self.created.as_deref().and_then(parse_date) {
            cx.temporal().content_date(DateField::Created, d, tz);
        }
        for (key, list) in [("tools", &self.tools), ("organisations", &self.organisations)] {
            if !list.is_empty() {
                cx.format_set(key, json!(list.iter().take(MAX_KEYS).collect::<Vec<_>>()));
            }
        }
        if self.persons > 0 {
            cx.format_set("person_creators", self.persons);
        }
        if let Some((n, v)) = &self.primary {
            cx.format_set("component", json!({ "name": n, "version": v }));
        }
        cx.format_set("package_count", self.packages.len());
        put_pairs(cx, "packages", self.packages);
        for (key, map) in
            [("package_types", &self.types), ("licenses", &self.licenses), ("ecosystems", &self.ecosystems)]
        {
            if !map.is_empty() {
                cx.format_set(key, json!(map));
            }
        }
        for (key, n) in
            [("files", self.files), ("relationships", self.relationships), ("vulnerabilities", self.vulnerabilities)]
        {
            if n > 0 {
                cx.format_set(key, n);
            }
        }
    }
}

/// SPDX tag-value: `Tag: value` lines, `<text>…</text>` spans skipped.
fn spdx_tags(text: &str) -> Sbom {
    let mut b = Sbom { format: "SPDX", ..Sbom::default() };
    let mut in_text = false;
    let mut current: Option<(String, Option<String>)> = None;
    let flush = |b: &mut Sbom, current: &mut Option<(String, Option<String>)>| {
        if let Some((n, v)) = current.take() {
            b.package(&n, v.as_deref());
        }
    };
    for line in text.lines() {
        if in_text {
            in_text = !line.contains("</text>");
            continue;
        }
        let Some((tag, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        if value.starts_with("<text>") && !value.contains("</text>") {
            in_text = true;
        }
        match tag.trim() {
            "SPDXVersion" => b.spec_version = Some(value.to_string()),
            "DocumentName" => b.name = Some(value.to_string()),
            "Creator" => b.creator(value),
            "Created" => b.created = Some(value.to_string()),
            "PackageName" => {
                flush(&mut b, &mut current);
                current = Some((value.to_string(), None));
                *b.types.entry("package".into()).or_default() += 1;
            }
            "PackageVersion" => {
                if let Some((_, v)) = current.as_mut() {
                    *v = Some(value.to_string());
                }
            }
            "PackageLicenseDeclared" => b.license(value),
            "ExternalRef" if value.contains(" purl ") => b.purl(value.rsplit(' ').next().unwrap_or("")),
            "FileName" => b.files += 1,
            "Relationship" => b.relationships += 1,
            _ => {}
        }
    }
    flush(&mut b, &mut current);
    b
}

fn spdx_json(v: &Value) -> Sbom {
    let mut b = Sbom {
        format: "SPDX",
        spec_version: s(v, &["spdxVersion"]).map(str::to_string),
        name: s(v, &["name"]).map(str::to_string),
        created: s(v, &["creationInfo", "created"]).map(str::to_string),
        ..Sbom::default()
    };
    for c in
        v.pointer("/creationInfo/creators").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str)
    {
        b.creator(c);
    }
    for p in v.get("packages").and_then(Value::as_array).into_iter().flatten() {
        let Some(name) = s(p, &["name"]) else { continue };
        b.package(name, s(p, &["versionInfo"]));
        *b.types.entry(s(p, &["primaryPackagePurpose"]).unwrap_or("package").to_ascii_lowercase()).or_default() += 1;
        if let Some(l) = s(p, &["licenseDeclared"]) {
            b.license(l);
        }
        for r in p.get("externalRefs").and_then(Value::as_array).into_iter().flatten() {
            if s(r, &["referenceType"]) == Some("purl") {
                b.purl(s(r, &["referenceLocator"]).unwrap_or(""));
            }
        }
    }
    b.files = v.get("files").and_then(Value::as_array).map_or(0, |f| f.len() as u64);
    b.relationships = v.get("relationships").and_then(Value::as_array).map_or(0, |r| r.len() as u64);
    b
}

fn cyclonedx_json(v: &Value) -> Sbom {
    let mut b = Sbom {
        format: "CycloneDX",
        spec_version: s(v, &["specVersion"]).map(str::to_string),
        serial: s(v, &["serialNumber"]).map(str::to_string),
        created: s(v, &["metadata", "timestamp"]).map(str::to_string),
        ..Sbom::default()
    };
    let meta = v.get("metadata").unwrap_or(&Value::Null);
    // 1.4: `tools: [{vendor, name, version}]`; 1.5+: `tools: {components: […]}`.
    let tools = meta.get("tools").and_then(|t| t.as_array().or_else(|| t.get("components").and_then(Value::as_array)));
    for t in tools.into_iter().flatten() {
        if let Some(n) = s(t, &["name"]) {
            b.tools.push(match s(t, &["version"]) {
                Some(ver) => format!("{n} {ver}"),
                None => n.to_string(),
            });
        }
    }
    b.persons = meta.get("authors").and_then(Value::as_array).map_or(0, |a| a.len() as u64);
    if let Some(m) = meta.get("manufacturer").or_else(|| meta.get("supplier")).and_then(|m| s(m, &["name"])) {
        b.organisations.push(m.to_string());
    }
    if let Some(c) = meta.get("component")
        && let Some(n) = s(c, &["name"])
    {
        b.primary = Some((n.to_string(), s(c, &["version"]).map(str::to_string)));
        b.name = Some(n.to_string());
    }
    let mut stack: Vec<&Value> =
        v.get("components").and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default();
    while let Some(c) = stack.pop() {
        if b.packages.len() >= 100_000 {
            break;
        }
        if let Some(n) = s(c, &["name"]) {
            b.package(n, s(c, &["version"]));
        }
        *b.types.entry(s(c, &["type"]).unwrap_or("component").to_string()).or_default() += 1;
        if let Some(p) = s(c, &["purl"]) {
            b.purl(p);
        }
        for l in c.get("licenses").and_then(Value::as_array).into_iter().flatten() {
            if let Some(id) =
                s(l, &["license", "id"]).or_else(|| s(l, &["license", "name"])).or_else(|| s(l, &["expression"]))
            {
                b.license(id);
            }
        }
        stack.extend(c.get("components").and_then(Value::as_array).into_iter().flatten());
    }
    b.relationships = v.get("dependencies").and_then(Value::as_array).map_or(0, |d| d.len() as u64);
    b.vulnerabilities = v.get("vulnerabilities").and_then(Value::as_array).map_or(0, |d| d.len() as u64);
    b
}

fn cyclonedx_xml(text: &str, cx: &mut Context<'_>) -> Result<Sbom, ExtractError> {
    let mut b = Sbom { format: "CycloneDX", ..Sbom::default() };
    let mut path: Vec<String> = Vec::new();
    let mut component: Option<(Option<String>, Option<String>)> = None;
    let mut primary: (Option<String>, Option<String>) = (None, None);
    walk(text, cx, 1_000_000, |_, ev| match ev {
        Ev::Start(name, a) => {
            if name == "bom" && path.is_empty() {
                b.serial = attr(a, "serialNumber").map(str::to_string);
            }
            if name == "component" && path.last().is_some_and(|p| p == "components") {
                *b.types.entry(attr(a, "type").unwrap_or("component").to_string()).or_default() += 1;
                component = Some((None, None));
            }
            match (path.last().map(String::as_str), name) {
                (Some("dependencies"), "dependency") => b.relationships += 1,
                (Some("vulnerabilities"), "vulnerability") => b.vulnerabilities += 1,
                _ => {}
            }
            path.push(name.to_string());
        }
        Ev::Text(t) => {
            let p = path.join("/");
            let leaf = path.last().map_or("", String::as_str);
            if p == "bom/metadata/timestamp" {
                b.created = Some(t.to_string());
            } else if p.starts_with("bom/metadata/tools/") && leaf == "name" {
                b.tools.push(t.to_string());
            } else if p == "bom/metadata/component/name" {
                primary.0 = Some(t.to_string());
            } else if p == "bom/metadata/component/version" {
                primary.1 = Some(t.to_string());
            } else if let Some((n, v)) = component.as_mut()
                && path.len() >= 2
                && path[path.len() - 2] == "component"
            {
                match leaf {
                    "name" if n.is_none() => *n = Some(t.to_string()),
                    "version" if v.is_none() => *v = Some(t.to_string()),
                    "purl" => b.purl(t),
                    _ => {}
                }
            } else if matches!(leaf, "id" | "expression") && p.contains("/licenses/") && component.is_some() {
                b.license(t);
            }
        }
        Ev::End(name) => {
            path.pop();
            if name == "component"
                && path.last().is_some_and(|p| p == "components")
                && let Some((Some(n), v)) = component.take()
            {
                b.package(&n, v.as_deref());
            }
        }
    })?;
    if let Some(ns) = text.split("cyclonedx.org/schema/bom/").nth(1) {
        b.spec_version = ns.split(['"', '\'']).next().map(str::to_string);
    }
    if let (Some(n), v) = primary {
        b.name = Some(n.clone());
        b.primary = Some((n, v));
    }
    Ok(b)
}
