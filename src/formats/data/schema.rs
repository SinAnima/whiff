//! Schema inference over parsed documents (JSON, YAML, TOML, NDJSON
//! records): which paths exist, with which types, how often, and a few
//! example values.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::plugin::{Redactor, is_secret_key, truncate_chars};

/// Paths tracked; further paths are counted as dropped.
const MAX_PATHS: usize = 300;
/// Nesting below this depth is summarised by its parent.
const MAX_DEPTH: usize = 12;
/// Array elements sampled per array.
const MAX_ELEMENTS: usize = 200;
const MAX_EXAMPLES: usize = 3;

#[derive(Default)]
struct PathStats {
    types: BTreeMap<&'static str, u64>,
    count: u64,
    examples: Vec<Value>,
    min_items: Option<usize>,
    max_items: usize,
}

/// Accumulates the shape of one or more documents.
#[derive(Default)]
pub(crate) struct Schema {
    paths: BTreeMap<String, PathStats>,
    order: Vec<String>,
    dropped: u64,
    documents: u64,
    max_depth: usize,
    /// How example values are redacted.
    redactor: Redactor,
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

impl Schema {
    /// An empty schema whose examples are redacted as `redactor` says.
    pub(crate) fn with(redactor: Redactor) -> Self {
        Self { redactor, ..Self::default() }
    }

    /// Add one document.
    pub(crate) fn add(&mut self, doc: &Value) {
        self.documents += 1;
        let redactor = self.redactor;
        // Iterative walk: (path, value, depth, key the value sits under).
        let mut stack: Vec<(String, &Value, usize, Option<&str>)> = vec![("$".into(), doc, 0, None)];
        while let Some((path, v, depth, key)) = stack.pop() {
            self.max_depth = self.max_depth.max(depth);
            let Some(stats) = self.stats(&path) else { continue };
            stats.count += 1;
            *stats.types.entry(type_name(v)).or_default() += 1;
            match v {
                Value::Array(a) => {
                    stats.min_items = Some(stats.min_items.map_or(a.len(), |m| m.min(a.len())));
                    stats.max_items = stats.max_items.max(a.len());
                    if depth < MAX_DEPTH {
                        let child = format!("{path}[]");
                        for item in a.iter().take(MAX_ELEMENTS).rev() {
                            stack.push((child.clone(), item, depth + 1, key));
                        }
                    }
                }
                Value::Object(o) if depth < MAX_DEPTH => {
                    for (k, item) in o.iter().rev() {
                        stack.push((format!("{path}.{}", escape_key(k)), item, depth + 1, Some(k)));
                    }
                }
                Value::Object(_) | Value::Null => {}
                scalar => {
                    let sensitive = redactor.hides_secrets() && key.is_some_and(is_secret_key);
                    if !sensitive && stats.examples.len() < MAX_EXAMPLES {
                        let ex = example(scalar, redactor);
                        if !stats.examples.contains(&ex) {
                            stats.examples.push(ex);
                        }
                    }
                }
            }
        }
    }

    fn stats(&mut self, path: &str) -> Option<&mut PathStats> {
        if !self.paths.contains_key(path) {
            if self.paths.len() >= MAX_PATHS {
                self.dropped += 1;
                return None;
            }
            self.order.push(path.to_string());
        }
        Some(self.paths.entry(path.to_string()).or_default())
    }

    /// The schema as JSON: `{ "paths": { "$.a": { "types": …, "count": …, "examples": … } }, … }`.
    pub(crate) fn to_json(&self) -> Value {
        let mut paths = Map::new();
        for p in &self.order {
            let s = &self.paths[p];
            let mut m = Map::new();
            let types: Vec<&str> = s.types.keys().copied().collect();
            m.insert("types".into(), json!(types));
            m.insert("count".into(), json!(s.count));
            if let Some(min) = s.min_items {
                m.insert("items".into(), json!([min, s.max_items]));
            }
            if !s.examples.is_empty() {
                m.insert("examples".into(), json!(s.examples));
            }
            paths.insert(p.clone(), Value::Object(m));
        }
        let mut out = Map::new();
        out.insert("paths".into(), Value::Object(paths));
        out.insert("max_depth".into(), json!(self.max_depth));
        if self.documents > 1 {
            out.insert("documents".into(), json!(self.documents));
        }
        if self.dropped > 0 {
            out.insert("paths_dropped".into(), json!(self.dropped));
        }
        Value::Object(out)
    }
}

fn escape_key(k: &str) -> String {
    if k.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') && !k.is_empty() {
        k.to_string()
    } else {
        format!("[{}]", serde_json::to_string(k).unwrap_or_default())
    }
}

fn example(v: &Value, r: Redactor) -> Value {
    match v {
        Value::String(s) => json!(truncate_chars(&r.sensitive(s), 60)),
        other => other.clone(),
    }
}

/// `object`, `array`, … of a document's top level.
pub(crate) fn top_level(v: &Value) -> &'static str {
    type_name(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infers_paths() {
        let mut s = Schema::default();
        s.add(&json!({ "name": "a", "tags": ["x", "y"], "n": 1, "password": "hunter2", "who": "bob@example.com" }));
        s.add(&json!({ "name": "b", "tags": [], "n": 2.5, "odd key": true }));
        let j = s.to_json();
        let p = &j["paths"];
        assert_eq!(p["$.name"]["count"], 2);
        assert_eq!(p["$.name"]["examples"], json!(["a", "b"]));
        assert_eq!(p["$.n"]["types"], json!(["integer", "number"]));
        assert_eq!(p["$.tags"]["items"], json!([0, 2]));
        assert_eq!(p["$.tags[]"]["count"], 2);
        assert!(p["$.password"].get("examples").is_none());
        assert_eq!(p["$.who"]["examples"], json!(["[redacted:email]"]));
        assert!(p.get("$.[\"odd key\"]").is_some());
        assert_eq!(j["documents"], 2);
    }

    #[test]
    fn caps_paths() {
        let mut big = Map::new();
        for i in 0..1000 {
            big.insert(format!("k{i}"), json!(i));
        }
        let mut s = Schema::default();
        s.add(&Value::Object(big));
        assert_eq!(s.to_json()["paths"].as_object().map(Map::len), Some(MAX_PATHS));
        assert!(s.to_json()["paths_dropped"].as_u64() > Some(0));
    }
}
