//! Apple Watch faces shared as `.watchface` files: a ZIP holding the face
//! description (`face.json`), its metadata (`metadata.json`), snapshots and
//! complication data. Reports the face type and version, the complication
//! slots and the apps that fill them, customisations and the snapshots.
//!
//! There is no published specification; the layout follows files written
//! by watchOS 7 and later.

use serde_json::{Map, Value, json};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, Zip, zip_names,
};

/// Extractor for Apple Watch faces.
pub struct WatchFace;

static META: ExtractorMeta = ExtractorMeta {
    id: "apple.watchface",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "watchface",
        name: "Apple Watch face",
        family: "apple",
        // Not `application/zip`: the detector's MIME fallback must keep
        // choosing the ZIP reader for plain archives.
        mimes: &["application/x-apple-watchface"],
        extensions: &["watchface"],
        magic: &[],
        parent: None,
    }],
};

impl Extractor for WatchFace {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if !probe.head.starts_with(b"PK\x03\x04") {
            return None;
        }
        let names = zip_names(probe, 500);
        let has = |n: &str| names.iter().any(|x| x.rsplit('/').next() == Some(n));
        (has("face.json")
            && (has("metadata.json") || probe.extension.is_some_and(|e| e.eq_ignore_ascii_case("watchface"))))
        .then_some(Sniff { format: "watchface", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let zip = Zip::open(src, 10_000)?;
        let json_of = |src: &mut dyn Source, cx: &mut Context<'_>, name: &str| -> Option<Value> {
            let e = zip.entries.iter().find(|e| e.name.rsplit('/').next() == Some(name))?.clone();
            serde_json::from_slice(&zip.read(src, &e, cx, 4 << 20).ok()?).ok()
        };
        let face = json_of(src, cx, "face.json").unwrap_or(Value::Null);
        let meta = json_of(src, cx, "metadata.json").unwrap_or(Value::Null);
        let s =
            |v: &Value, keys: &[&str]| keys.iter().find_map(|k| v.get(*k).and_then(Value::as_str)).map(str::to_string);
        if let Some(t) = s(&face, &["face type", "faceType", "type"]) {
            cx.format_set("face_type", t);
        }
        if let Some(v) = face.get("version").filter(|v| !v.is_null()) {
            cx.format_set("version", v.clone());
        }
        // Slot → app: the metadata's names, else the face's complication entries.
        let mut slots = Map::new();
        if let Some(m) = meta.get("complications_names").and_then(Value::as_object) {
            for (slot, app) in m {
                slots.insert(slot.clone(), app.clone());
            }
        }
        if let Some(m) = face.get("complications").and_then(Value::as_object) {
            for (slot, c) in m {
                slots.entry(slot.clone()).or_insert_with(|| {
                    json!(s(c, &["app", "bundle id", "bundleId"]).unwrap_or_else(|| "(set)".into()))
                });
            }
        }
        cx.format_set("complications", Value::Object(slots));
        if let Some(c) = face.get("customization").and_then(Value::as_object) {
            cx.format_set("customizations", c.keys().cloned().collect::<Vec<_>>());
        }
        let snapshots: Vec<String> = zip
            .entries
            .iter()
            .map(|e| e.name.rsplit('/').next().unwrap_or(&e.name).to_string())
            .filter(|n| n.ends_with("snapshot.png"))
            .collect();
        cx.format_set("snapshots", snapshots);
        cx.format_set("entries", zip.entries.len());
        let photos = zip.entries.iter().filter(|e| e.name.starts_with("Resources/") && !e.name.ends_with('/')).count();
        if photos > 0 {
            cx.format_set("resources", photos);
        }
        Ok(())
    }
}

crate::register_extractor!(WatchFace);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("watchface");
}
