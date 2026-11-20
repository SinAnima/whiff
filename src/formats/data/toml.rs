//! TOML: tables, inferred schema and known schemas.
//!
//! `toml` has no nesting limit, so nesting is checked before parsing.
//!
//! Specification: <https://toml.io/en/v1.0.0>

use serde_json::Value;

use super::known;
use super::schema::Schema;
use crate::plugin::{
    AnyValue, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, MAX_NESTING, Source, TextRole,
    dotted_key_depth, nesting_depth, truncate_chars,
};

/// Extractor for TOML.
pub struct Toml;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.toml",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "toml",
        name: "TOML",
        family: "data.toml",
        mimes: &["application/toml"],
        extensions: &["toml"],
        magic: &[],
        parent: Some("text"),
    }],
};

impl Extractor for Toml {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        cx.emit_text(TextRole::Data, &text);
        if nesting_depth(&text) > MAX_NESTING || dotted_key_depth(&text) > MAX_NESTING {
            cx.format_set("valid", false);
            cx.format_set("error", format!("nested deeper than {MAX_NESTING} levels; not parsed"));
            return Ok(());
        }
        let value = match toml::from_str::<AnyValue>(&text) {
            Ok(v) => v.0,
            Err(e) => {
                cx.format_set("valid", false);
                cx.format_set("error", truncate_chars(&e.to_string(), 300));
                return Ok(());
            }
        };
        cx.format_set("valid", true);
        if let Value::Object(o) = &value {
            let tables: Vec<&String> = o.iter().filter(|(_, v)| v.is_object()).map(|(k, _)| k).take(50).collect();
            cx.format_set("tables", serde_json::json!(tables));
            cx.format_set("top_level_keys", o.len());
        }
        let mut schema = Schema::with(cx.redactor());
        schema.add(&value);
        cx.format_set("schema", schema.to_json());
        let name = src.name_hint().map(str::to_string);
        if let Some(k) = known::detect(std::slice::from_ref(&value), name.as_deref(), cx) {
            cx.format_set("known_schema", k);
        }
        Ok(())
    }
}

crate::register_extractor!(Toml);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("toml");
}
