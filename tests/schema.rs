//! The committed JSON Schema must match the report model. Changing the model
//! therefore shows up in review; regenerate with
//! `UPDATE_SCHEMA=1 cargo test --test schema`.

use std::path::Path;

#[test]
fn committed_schema_is_current() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/schema/whiff-1.schema.json");
    let generated = serde_json::to_string_pretty(&schemars::schema_for!(whiff::Report)).unwrap() + "\n";
    if std::env::var_os("UPDATE_SCHEMA").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &generated).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == generated,
        "docs/schema/whiff-1.schema.json is out of date; run `UPDATE_SCHEMA=1 cargo test --test schema` \
         and check the change is additive (renames/removals need schema whiff/2)"
    );
}

/// Keys that document a schema without constraining reports.
const DOCS: [&str; 4] = ["description", "default", "examples", "title"];

/// The documentation-free form of a schema node, for comparing alternatives.
fn bare(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => {
            m.iter().filter(|(k, _)| !DOCS.contains(&k.as_str())).map(|(k, v)| (k.clone(), bare(v))).collect()
        }
        serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(bare).collect()),
        other => other.clone(),
    }
}

/// Whether `cur` still accepts every report `base` describes and keeps every
/// field, type and value `base` promises (it may add properties, `$defs`,
/// enum values and alternatives). Differences are pushed to `errs`.
fn covers(base: &serde_json::Value, cur: &serde_json::Value, path: &str, errs: &mut Vec<String>) {
    use serde_json::Value;
    let (Value::Object(b), Value::Object(c)) = (base, cur) else {
        if bare(base) != bare(cur) {
            errs.push(format!("{path}: changed"));
        }
        return;
    };
    for (key, bv) in b {
        if DOCS.contains(&key.as_str()) {
            continue;
        }
        let at = format!("{path}/{key}");
        let Some(cv) = c.get(key) else {
            errs.push(format!("{at}: removed"));
            continue;
        };
        match key.as_str() {
            "properties" | "$defs" => {
                for (name, bp) in bv.as_object().into_iter().flatten() {
                    match cv.get(name) {
                        Some(cp) => covers(bp, cp, &format!("{at}/{name}"), errs),
                        None => errs.push(format!("{at}/{name}: removed")),
                    }
                }
            }
            "required" | "enum" => {
                let have: Vec<&Value> = cv.as_array().map(|a| a.iter().collect()).unwrap_or_default();
                for x in bv.as_array().into_iter().flatten() {
                    if !have.contains(&x) {
                        errs.push(format!("{at}: {x} no longer listed"));
                    }
                }
            }
            "oneOf" | "anyOf" => {
                let have: Vec<Value> = cv.as_array().map(|a| a.iter().map(bare).collect()).unwrap_or_default();
                for x in bv.as_array().into_iter().flatten() {
                    if !have.contains(&bare(x)) {
                        errs.push(format!("{at}: alternative {} no longer accepted", bare(x)));
                    }
                }
            }
            _ => covers(bv, cv, &at, errs),
        }
    }
}

/// The report schema frozen at 1.0 (`docs/schema/whiff-1-baseline.schema.json`)
/// must stay covered: 1.x may add to `whiff/1`, never remove or change what
/// it promised. Renames, removals and type changes need schema `whiff/2`.
#[test]
fn schema_only_grows_from_the_1_0_baseline() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let base: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("docs/schema/whiff-1-baseline.schema.json")).unwrap())
            .unwrap();
    let cur = serde_json::to_value(schemars::schema_for!(whiff::Report)).unwrap();
    let mut errs = Vec::new();
    covers(&base, &cur, "", &mut errs);
    assert!(errs.is_empty(), "the report schema no longer covers the 1.0 baseline:\n  {}", errs.join("\n  "));
}

#[test]
fn baseline_check_catches_removals() {
    let base =
        serde_json::json!({"properties": {"a": {"type": "string"}, "b": {"type": "integer"}}, "required": ["a"]});
    let mut errs = Vec::new();
    covers(
        &base,
        &serde_json::json!({"properties": {"a": {"type": "string"}, "c": {}}, "required": ["a"]}),
        "",
        &mut errs,
    );
    assert_eq!(errs, vec!["/properties/b: removed"]);
    errs.clear();
    covers(
        &base,
        &serde_json::json!({"properties": {"a": {"type": ["string", "null"]}, "b": {"type": "integer"}}}),
        "",
        &mut errs,
    );
    assert_eq!(errs.len(), 2, "{errs:?}"); // type widened to nullable, `a` no longer required
}
