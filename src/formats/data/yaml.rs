//! YAML: documents, anchors and aliases, inferred schema, and known schemas
//! (Kubernetes, Docker Compose, GitHub Actions, `OpenAPI`, Ansible, Helm,
//! `CloudFormation`, GitLab CI, conda).
//!
//! Parsed with `serde-saphyr`, which is panic-free and enforces budgets on
//! depth, aliases and document size.
//!
//! Specification: <https://yaml.org/spec/1.2.2/>

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use super::known;
use super::schema::{Schema, top_level};
use crate::plugin::{
    AnyValue, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole,
    truncate_chars,
};

/// Extractor for YAML.
pub struct Yaml;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.yaml",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "yaml",
        name: "YAML",
        family: "data.yaml",
        mimes: &["application/yaml"],
        extensions: &["yaml", "yml"],
        magic: &[],
        parent: Some("text"),
    }],
};

impl Extractor for Yaml {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // Only for files without an extension: `---` also opens Markdown front matter.
        if probe.extension.is_some() {
            return None;
        }
        let head = std::str::from_utf8(&probe.head[..probe.head.len().min(2048)]).ok()?;
        if head.starts_with("%YAML") {
            return Some(Sniff { format: "yaml", confidence: 0.8 });
        }
        let k8s = head.lines().any(|l| l.starts_with("apiVersion:")) && head.lines().any(|l| l.starts_with("kind:"));
        k8s.then_some(Sniff { format: "yaml", confidence: 0.7 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        cx.emit_text(TextRole::Data, &text);
        let name = src.name_hint().map(str::to_string);
        cx.format_set("anchors", ANCHOR.find_iter(&text).count());
        cx.format_set("aliases", ALIAS.find_iter(&text).count());
        let docs: Vec<Value> = match serde_saphyr::from_multiple_with_options::<AnyValue>(&text, yaml_options()) {
            Ok(docs) => docs.into_iter().map(|d| d.0).filter(|d| !d.is_null()).collect(),
            Err(e) => {
                cx.format_set("valid", false);
                cx.format_set("error", truncate_chars(&e.to_string(), 300));
                return Ok(());
            }
        };
        cx.checkpoint()?;
        cx.format_set("valid", true);
        cx.format_set("documents", docs.len());
        if let Some(first) = docs.first() {
            cx.format_set("top_level", top_level(first));
        }
        let mut schema = Schema::default();
        for d in docs.iter().take(1000) {
            schema.add(d);
        }
        let known = known::detect(&docs, name.as_deref(), cx);
        cx.format_set("schema", known::schema_for(schema.to_json(), known.as_ref(), cx));
        if let Some(k) = known {
            cx.format_set("known_schema", k);
        }
        Ok(())
    }
}

crate::register_extractor!(Yaml);

/// The first document of `text`, for formats that carry YAML metadata
/// (Helm charts, Ruby gem specifications); `None` when it does not parse.
pub(crate) fn first_document(text: &str) -> Option<Value> {
    let docs = serde_saphyr::from_multiple_with_options::<AnyValue>(text, yaml_options()).ok()?;
    docs.into_iter().map(|d| d.0).find(|d| !d.is_null())
}

/// YAML 1.2 booleans (`on`, `yes` stay strings: GitHub Actions' `on:` key),
/// and the last of duplicate keys wins instead of failing the document.
fn yaml_options() -> serde_saphyr::Options {
    let mut o = serde_saphyr::Options::default();
    o.strict_booleans = true;
    o.duplicate_keys = serde_saphyr::DuplicateKeyPolicy::LastWins;
    o
}

static ANCHOR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)(?:^|[\s\[{,:-])&[A-Za-z0-9_-]+").expect("valid"));
static ALIAS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)(?:^|[\s\[{,:-])\*[A-Za-z0-9_-]+").expect("valid"));

#[cfg(test)]
mod tests {
    crate::fixture_tests!("yaml");
}
