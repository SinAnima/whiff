//! A small JSON Schema validator for the keywords the `whiff/1` report schema
//! uses (`schemars` output, draft 2020-12): `type`, `format` (the integer
//! widths and floats), `minimum` / `maximum`, `const`, `enum`, `properties`,
//! `additionalProperties`, `required`, `items`, `prefixItems`, `minItems` /
//! `maxItems`, `anyOf` / `oneOf` / `allOf` and local `$ref`s. A keyword it
//! does not know is an error, so a schema that starts using one fails the
//! conformance run instead of being skipped.

use serde_json::{Map, Value};

/// Keywords that only document the schema.
const DOCS: &[&str] = &["$schema", "$id", "title", "description", "default", "examples", "deprecated", "readOnly"];

/// Errors from checking `value` against `schema` (whose `$defs` resolve
/// `$ref`s), as `path: problem`. Empty when the value is valid.
pub(crate) fn validate(schema: &Value, value: &Value) -> Vec<String> {
    let mut errs = Vec::new();
    check(schema, schema, value, "", &mut errs);
    errs
}

fn check(root: &Value, schema: &Value, value: &Value, path: &str, errs: &mut Vec<String>) {
    let s = match schema {
        Value::Bool(true) => return,
        Value::Bool(false) => return errs.push(format!("{path}: no value is allowed here")),
        Value::Object(s) => s,
        _ => return errs.push(format!("{path}: schema node is not an object")),
    };
    for (key, rule) in s {
        match key.as_str() {
            "$ref" => match resolve(root, rule) {
                Some(target) => check(root, target, value, path, errs),
                None => errs.push(format!("{path}: unresolved $ref {rule}")),
            },
            "type" => {
                let names: Vec<&str> = match rule {
                    Value::String(t) => vec![t.as_str()],
                    Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                    _ => Vec::new(),
                };
                if !names.iter().any(|t| has_type(value, t)) {
                    errs.push(format!("{path}: {} is not of type {}", kind(value), names.join(" or ")));
                }
            }
            "format" => check_format(rule.as_str().unwrap_or(""), value, path, errs),
            "minimum" => {
                if let (Some(v), Some(min)) = (value.as_f64(), rule.as_f64())
                    && v < min
                {
                    errs.push(format!("{path}: {v} is below the minimum {min}"));
                }
            }
            "maximum" => {
                if let (Some(v), Some(max)) = (value.as_f64(), rule.as_f64())
                    && v > max
                {
                    errs.push(format!("{path}: {v} is above the maximum {max}"));
                }
            }
            "const" => {
                if value != rule {
                    errs.push(format!("{path}: {value} is not {rule}"));
                }
            }
            "enum" => {
                if !rule.as_array().is_some_and(|a| a.contains(value)) {
                    errs.push(format!("{path}: {value} is not one of {rule}"));
                }
            }
            "anyOf" | "oneOf" | "allOf" => {
                let passing = rule
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|alt| {
                        let mut e = Vec::new();
                        check(root, alt, value, path, &mut e);
                        e.is_empty()
                    })
                    .count();
                let total = rule.as_array().map_or(0, Vec::len);
                let ok = match key.as_str() {
                    "anyOf" => passing > 0,
                    "oneOf" => passing == 1,
                    _ => passing == total,
                };
                if !ok {
                    errs.push(format!("{path}: {passing} of {total} `{key}` alternatives match"));
                }
            }
            // Checked below, by the value's kind, or holding `$ref` targets.
            "properties"
            | "additionalProperties"
            | "required"
            | "items"
            | "prefixItems"
            | "minItems"
            | "maxItems"
            | "$defs"
            | "definitions" => {}
            other if DOCS.contains(&other) => {}
            other => errs.push(format!("{path}: keyword `{other}` is not supported by this checker")),
        }
    }
    if let Value::Object(obj) = value {
        check_object(root, s, obj, path, errs);
    }
    if let Value::Array(items) = value {
        check_array(root, s, items, path, errs);
    }
}

fn check_object(root: &Value, s: &Map<String, Value>, obj: &Map<String, Value>, path: &str, errs: &mut Vec<String>) {
    let props = s.get("properties").and_then(Value::as_object);
    for name in s.get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
        if !obj.contains_key(name) {
            errs.push(format!("{path}: required `{name}` is missing"));
        }
    }
    for (name, v) in obj {
        let at = format!("{path}/{name}");
        match props.and_then(|p| p.get(name)) {
            Some(sub) => check(root, sub, v, &at, errs),
            None => {
                if let Some(extra) = s.get("additionalProperties") {
                    check(root, extra, v, &at, errs);
                }
            }
        }
    }
}

fn check_array(root: &Value, s: &Map<String, Value>, items: &[Value], path: &str, errs: &mut Vec<String>) {
    let len = items.len() as u64;
    if let Some(min) = s.get("minItems").and_then(Value::as_u64)
        && len < min
    {
        errs.push(format!("{path}: {len} items, fewer than {min}"));
    }
    if let Some(max) = s.get("maxItems").and_then(Value::as_u64)
        && len > max
    {
        errs.push(format!("{path}: {len} items, more than {max}"));
    }
    let prefix = s.get("prefixItems").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
    for (i, v) in items.iter().enumerate() {
        let at = format!("{path}/{i}");
        if let Some(sub) = prefix.get(i) {
            check(root, sub, v, &at, errs);
        } else if let Some(sub) = s.get("items") {
            check(root, sub, v, &at, errs);
        }
    }
}

fn resolve<'a>(root: &'a Value, reference: &Value) -> Option<&'a Value> {
    let pointer = reference.as_str()?.strip_prefix('#')?;
    root.pointer(pointer)
}

fn has_type(v: &Value, t: &str) -> bool {
    match t {
        "null" => v.is_null(),
        "boolean" => v.is_boolean(),
        "string" => v.is_string(),
        "array" => v.is_array(),
        "object" => v.is_object(),
        "number" => v.is_number(),
        "integer" => v.is_i64() || v.is_u64(),
        _ => false,
    }
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_f64() => "number",
        Value::Number(_) => "integer",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// `schemars` integer widths and float names. Other formats (`date-time`,
/// `uri`…) are annotations here.
fn check_format(format: &str, v: &Value, path: &str, errs: &mut Vec<String>) {
    let range: Option<(i128, i128)> = match format {
        "uint8" => Some((0, u8::MAX.into())),
        "uint16" => Some((0, u16::MAX.into())),
        "uint32" => Some((0, u32::MAX.into())),
        "uint64" | "uint" => Some((0, u64::MAX.into())),
        "int8" => Some((i8::MIN.into(), i8::MAX.into())),
        "int16" => Some((i16::MIN.into(), i16::MAX.into())),
        "int32" => Some((i32::MIN.into(), i32::MAX.into())),
        "int64" | "int" => Some((i64::MIN.into(), i64::MAX.into())),
        _ => None,
    };
    let Some((lo, hi)) = range else { return };
    let n = v.as_i64().map(i128::from).or_else(|| v.as_u64().map(i128::from));
    match n {
        Some(n) if (lo..=hi).contains(&n) => {}
        Some(n) => errs.push(format!("{path}: {n} does not fit {format}")),
        // A non-integer is reported by `type`.
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::validate;

    #[test]
    fn the_checker_rejects_what_the_schema_forbids() {
        let schema = json!({
            "type": "object",
            "properties": {
                "size": { "type": "integer", "format": "uint8", "minimum": 0 },
                "kind": { "oneOf": [{ "const": "file" }, { "const": "dir" }] },
                "tags": { "type": "array", "items": { "$ref": "#/$defs/Tag" }, "maxItems": 2 },
                "when": { "type": ["string", "null"] }
            },
            "required": ["kind"],
            "additionalProperties": false,
            "$defs": { "Tag": { "type": "string" } }
        });
        let valid = validate(&schema, &json!({ "kind": "dir", "size": 7, "tags": ["a"], "when": null }));
        assert_eq!(valid, [] as [String; 0]);
        let mut errs = validate(&schema, &json!({ "size": 300, "tags": ["a", 2, "c"], "extra": 1 }));
        errs.sort();
        assert_eq!(
            errs,
            [
                "/extra: no value is allowed here",
                "/size: 300 does not fit uint8",
                "/tags/1: integer is not of type string",
                "/tags: 3 items, more than 2",
                ": required `kind` is missing",
            ]
        );
        assert_eq!(validate(&schema, &json!({ "kind": "link" })), ["/kind: 0 of 2 `oneOf` alternatives match"]);
        assert_eq!(validate(&json!({ "if": {} }), &json!(1)), [": keyword `if` is not supported by this checker"]);
    }
}
