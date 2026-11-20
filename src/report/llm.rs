//! The compact, token-budgeted view of a report for language models.

use serde_json::{Map as JsonMap, Value, json};

use super::Report;

/// Rough token estimate for JSON text: one token per four bytes.
fn tokens(v: &Value) -> usize {
    serde_json::to_string(v).map_or(0, |s| s.len().div_ceil(4))
}

impl Report {
    /// A compact JSON view for language models: what the file is, what it is
    /// about, who made it, rights and risks, and the most useful
    /// format-specific details, shrunk step by step until it fits
    /// `max_tokens` (estimated at four bytes per token of JSON).
    ///
    /// Over budget, parts are dropped in this order: `metadata`, then the
    /// longer `details` and `outline`, a shorter `excerpt`, `details`,
    /// `keywords`, the `excerpt`, a shorter `summary`, `embedded` names, and
    /// last the dates, physical properties, summary and outline. What the
    /// file is (`format`, `mime`) always stays, so a very small budget can
    /// still be exceeded. 800 is the CLI's default (`--max-tokens`).
    ///
    /// ```
    /// let text = "# Saltmere tides\n\n".to_string() + &"The bell rings at high water. ".repeat(80);
    /// let report = whiff::Engine::new().extract_bytes(Some("tides.md"), text.into_bytes());
    ///
    /// let view = report.llm_view(800);
    /// assert!(view["excerpt"].is_string());
    ///
    /// // A tight budget drops the excerpt but keeps what the file is.
    /// let tight = report.llm_view(60);
    /// assert!(tight.get("excerpt").is_none());
    /// assert!(serde_json::to_string(&tight)?.contains("markdown"));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    pub fn llm_view(&self, max_tokens: usize) -> Value {
        let mut parts = Parts::from(self);
        let mut view = parts.render();
        for step in 0.. {
            if tokens(&view) <= max_tokens || !parts.shrink(step) {
                break;
            }
            view = parts.render();
        }
        view
    }
}

/// The view's pieces, kept separately so they can be trimmed.
struct Parts {
    head: JsonMap<String, Value>,
    outline: Vec<String>,
    keywords: Vec<String>,
    summary: Option<String>,
    excerpt: Option<String>,
    details: Option<JsonMap<String, Value>>,
    metadata: Option<JsonMap<String, Value>>,
    embedded: Vec<String>,
}

fn put(map: &mut JsonMap<String, Value>, key: &str, value: Value) {
    let empty = match &value {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    };
    if !empty {
        map.insert(key.to_string(), value);
    }
}

impl From<&Report> for Parts {
    fn from(r: &Report) -> Self {
        let id = &r.identification;
        let mut head = JsonMap::new();
        put(&mut head, "file", json!(r.source.name));
        put(&mut head, "format", json!(format!("{} ({})", id.name, id.format)));
        put(&mut head, "mime", json!(id.mime));
        put(&mut head, "encoding", json!(id.encoding));
        put(&mut head, "size_bytes", json!(r.system.size_bytes));
        put(&mut head, "modified", json!(r.temporal.filesystem.modified));
        let c = &r.content;
        put(&mut head, "title", json!(c.title));
        put(&mut head, "description", json!(c.description));
        put(&mut head, "authors", json!(c.authors));
        put(&mut head, "language", json!(c.language.as_ref().map(|l| &l.code)));
        let dates: Vec<Value> = r
            .temporal
            .content
            .iter()
            .take(4)
            .map(|d| json!(format!("{}: {}", format!("{:?}", d.field).to_lowercase(), d.value)))
            .collect();
        put(&mut head, "dates", Value::Array(dates));

        let p = &r.physical;
        let mut physical = JsonMap::new();
        if let Some(t) = &p.text {
            put(&mut physical, "lines", json!(t.lines));
            put(&mut physical, "words", json!(t.words));
        }
        if let Some(i) = &p.image {
            put(&mut physical, "pixels", json!(format!("{}x{}", i.width, i.height)));
        }
        if let Some(m) = &p.media {
            put(&mut physical, "duration_s", json!(m.duration_s));
        }
        if let Some(d) = &p.document {
            put(&mut physical, "pages", json!(d.pages));
        }
        if let Some(k) = &p.container {
            put(&mut physical, "entries", json!(k.entries));
        }
        put(&mut head, "physical", Value::Object(physical));

        let rights = &r.rights;
        let mut rmap = JsonMap::new();
        put(&mut rmap, "copyright", json!(rights.copyright));
        put(&mut rmap, "license", json!(rights.license.as_ref().and_then(|l| l.name.clone().or(l.url.clone()))));
        put(&mut rmap, "creators", json!(rights.creators));
        put(&mut head, "rights", Value::Object(rmap));

        let s = &r.security;
        let mut smap = JsonMap::new();
        put(&mut smap, "risk_level", json!(s.risk_level.map(super::Severity::as_str)));
        // Most severe first, as `kind (severity)`.
        let mut risks: Vec<&super::Risk> = s.risks.iter().collect();
        risks.sort_by_key(|r| std::cmp::Reverse(r.severity));
        put(
            &mut smap,
            "risks",
            json!(risks.iter().map(|r| format!("{} ({})", r.kind, r.severity.as_str())).collect::<Vec<_>>()),
        );
        put(&mut smap, "embedded_risks", json!(s.embedded_risks.keys().collect::<Vec<_>>()));
        put(&mut smap, "encrypted", json!(s.encrypted.filter(|e| *e)));
        put(&mut smap, "active_content", json!(s.active_content));
        put(&mut smap, "secrets", json!(s.secrets.keys().collect::<Vec<_>>()));
        put(&mut head, "security", Value::Object(smap));

        let indent = |level: u8| "  ".repeat(usize::from(level.saturating_sub(1)));
        Self {
            head,
            outline: c.outline.iter().map(|h| format!("{}{}", indent(h.level), h.text)).collect(),
            keywords: if c.keywords.is_empty() { c.tags.clone() } else { c.keywords.clone() },
            summary: c.summary.clone(),
            excerpt: c.excerpt.clone(),
            details: r.format.get(&id.format).and_then(Value::as_object).cloned().filter(|m| !m.is_empty()),
            metadata: Some(r.metadata.clone()).filter(|m| !m.is_empty()),
            embedded: r.embedded.iter().filter_map(|e| e.source.name.clone()).collect(),
        }
    }
}

impl Parts {
    fn render(&self) -> Value {
        let mut m = self.head.clone();
        put(&mut m, "keywords", json!(self.keywords));
        put(&mut m, "summary", json!(self.summary));
        put(&mut m, "outline", json!(self.outline));
        put(&mut m, "excerpt", json!(self.excerpt));
        if let Some(d) = &self.details {
            put(&mut m, "details", Value::Object(d.clone()));
        }
        if let Some(md) = &self.metadata {
            put(&mut m, "metadata", Value::Object(md.clone()));
        }
        if !self.embedded.is_empty() {
            let n = self.embedded.len();
            let names: Vec<&String> = self.embedded.iter().take(10).collect();
            put(&mut m, "embedded", json!({ "count": n, "names": names }));
        }
        Value::Object(m)
    }

    /// Apply shrink step `step`; `false` when nothing is left to shrink.
    fn shrink(&mut self, step: usize) -> bool {
        match step {
            0 => self.metadata = None,
            1 => truncate_map(self.details.as_mut(), 12),
            2 => self.outline.truncate(24),
            3 => shorten(&mut self.excerpt, 200),
            4 => self.details = None,
            5 => self.outline.truncate(10),
            6 => self.keywords.truncate(6),
            7 => self.excerpt = None,
            8 => shorten(&mut self.summary, 300),
            9 => self.embedded.truncate(3),
            10 => self.outline.truncate(4),
            11 => {
                self.head.remove("dates");
                self.head.remove("physical");
            }
            12 => {
                self.summary = None;
                self.outline.clear();
            }
            _ => return false,
        }
        true
    }
}

fn truncate_map(map: Option<&mut JsonMap<String, Value>>, keep: usize) {
    if let Some(m) = map {
        let keys: Vec<String> = m.keys().skip(keep).cloned().collect();
        for k in keys {
            m.remove(&k);
        }
        for v in m.values_mut() {
            match v {
                Value::Array(a) if a.len() > 5 => a.truncate(5),
                Value::String(s) if s.len() > 200 => *s = crate::text::truncate_chars(s, 200),
                _ => {}
            }
        }
    }
}

fn shorten(s: &mut Option<String>, max: usize) {
    if let Some(t) = s {
        *t = crate::text::truncate_chars(t, max);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Heading;

    #[test]
    fn fits_the_budget() {
        let mut r = Report::default();
        r.source.name = Some("notes.md".into());
        r.identification.format = "markdown".into();
        r.identification.name = "Markdown".into();
        r.content.title = Some("Notes".into());
        r.content.excerpt = Some("word ".repeat(400));
        r.content.outline = (0..100).map(|i| Heading { level: 2, text: format!("Section {i}") }).collect();
        let big = r.llm_view(10_000);
        assert_eq!(big["outline"].as_array().map(Vec::len), Some(100));
        let small = r.llm_view(150);
        assert!(tokens(&small) <= 150, "{small}");
        assert_eq!(small["title"], "Notes");
        assert_eq!(small["format"], "Markdown (markdown)");
    }
}
