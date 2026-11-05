//! Unity text-serialised assets and their `.meta` files:
//! * scenes, prefabs, materials, animations … (`%TAG !u! tag:unity3d.com`):
//!   objects, the class histogram (by Unity class ID, named for the common
//!   ones), GameObject names, MonoBehaviour scripts and the other assets
//!   referenced by GUID;
//! * `.meta`: format version, the asset's GUID, its importer, asset bundle.
//!
//! Specification: Unity Manual "Format of Text Serialized files" and the
//! "YAML Class ID Reference".

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole, truncate_chars,
};

/// Extractor for Unity YAML assets.
pub struct Unity;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.unity",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "unity_yaml",
            name: "Unity YAML asset",
            family: "data.binser",
            mimes: &[],
            extensions: &["unity", "prefab", "asset", "mat", "anim", "controller", "physicmaterial"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "unity_meta",
            name: "Unity asset metadata",
            family: "data.binser",
            mimes: &[],
            extensions: &["meta"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

/// Names of common Unity class IDs.
pub(crate) fn class_name(id: u32) -> Option<&'static str> {
    Some(match id {
        1 => "GameObject",
        4 => "Transform",
        20 => "Camera",
        21 => "Material",
        23 => "MeshRenderer",
        28 => "Texture2D",
        29 => "OcclusionCullingSettings",
        33 => "MeshFilter",
        43 => "Mesh",
        48 => "Shader",
        54 => "Rigidbody",
        64 => "MeshCollider",
        65 => "BoxCollider",
        74 => "AnimationClip",
        81 => "AudioListener",
        82 => "AudioSource",
        83 => "AudioClip",
        91 => "AnimatorController",
        95 => "Animator",
        104 => "RenderSettings",
        108 => "Light",
        111 => "Animation",
        114 => "MonoBehaviour",
        115 => "MonoScript",
        135 => "SphereCollider",
        136 => "CapsuleCollider",
        137 => "SkinnedMeshRenderer",
        157 => "LightmapSettings",
        196 => "NavMeshSettings",
        198 => "ParticleSystem",
        199 => "ParticleSystemRenderer",
        212 => "SpriteRenderer",
        222 => "CanvasRenderer",
        223 => "Canvas",
        224 => "RectTransform",
        1001 => "PrefabInstance",
        1101 => "AnimatorStateTransition",
        1102 => "AnimatorState",
        1107 => "AnimatorStateMachine",
        1_660_057_539 => "SceneRoots",
        _ => return None,
    })
}

fn histogram(m: BTreeMap<String, u64>, top: usize) -> Value {
    let mut v: Vec<(String, u64)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Value::Object(v.into_iter().take(top).map(|(k, n)| (k, n.into())).collect::<Map<_, _>>())
}

/// The 32-hex GUID after `guid: ` in a line.
fn guid(line: &str) -> Option<&str> {
    let i = line.find("guid: ")? + 6;
    let g = line.get(i..i + 32)?;
    g.bytes().all(|c| c.is_ascii_hexdigit()).then_some(g)
}

impl Extractor for Unity {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = &probe.head[..probe.head.len().min(256)];
        let has = |n: &[u8]| h.windows(n.len()).any(|w| w == n);
        if has(b"%TAG !u! tag:unity3d.com") {
            return Some(Sniff { format: "unity_yaml", confidence: 0.97 });
        }
        (h.starts_with(b"fileFormatVersion:") && has(b"\nguid: "))
            .then_some(Sniff { format: "unity_meta", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        cx.emit_text(TextRole::Data, &text);
        if cx.format_id() == "unity_meta" {
            meta(&text, cx);
            return Ok(());
        }
        let mut classes: BTreeMap<String, u64> = BTreeMap::new();
        let mut names: Vec<String> = Vec::new();
        let mut scripts: BTreeSet<&str> = BTreeSet::new();
        let mut refs: BTreeSet<&str> = BTreeSet::new();
        let (mut objects, mut stripped) = (0u64, 0u64);
        let mut current = 0u32;
        let mut version = None;
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("%YAML ") {
                version = Some(v.trim());
            }
            if let Some(rest) = line.strip_prefix("--- !u!") {
                objects += 1;
                if rest.ends_with(" stripped") {
                    stripped += 1;
                }
                current = rest.split([' ', '&']).next().and_then(|n| n.parse().ok()).unwrap_or(0);
                let name = class_name(current).map_or_else(|| format!("class_{current}"), str::to_string);
                *classes.entry(name).or_default() += 1;
                continue;
            }
            let t = line.trim_start();
            if current == 1
                && let Some(n) = t.strip_prefix("m_Name: ")
                && names.len() < 100
            {
                names.push(truncate_chars(n.trim(), 100));
            }
            if let Some(g) = guid(t) {
                if t.starts_with("m_Script:") {
                    scripts.insert(g);
                } else {
                    refs.insert(g);
                }
            }
        }
        if objects == 0 {
            return Err(ExtractError::malformed("no Unity objects"));
        }
        if let Some(v) = version {
            cx.format_set("yaml_version", v);
        }
        cx.format_set("objects", objects);
        if stripped > 0 {
            cx.format_set("stripped_objects", stripped);
        }
        cx.format_set("classes", histogram(classes, 40));
        if !names.is_empty() {
            cx.format_set("game_objects", names);
        }
        cx.format_set("scripts", scripts.len());
        cx.format_set("referenced_assets", refs.len());
        Ok(())
    }
}

fn meta(text: &str, cx: &mut Context<'_>) {
    let mut importer = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("fileFormatVersion: ") {
            cx.format_set("file_format_version", v.trim());
        } else if let Some(g) = line.strip_prefix("guid: ") {
            cx.format_set("guid", truncate_chars(g.trim(), 40));
        } else if importer.is_none() && !line.starts_with([' ', '-', '#']) && line.trim_end().ends_with("Importer:") {
            importer = Some(line.trim_end().trim_end_matches(':').to_string());
        } else if let Some(b) = line.trim_start().strip_prefix("assetBundleName: ")
            && !b.trim().is_empty()
        {
            cx.format_set("asset_bundle", truncate_chars(b.trim(), 200));
        } else if line.starts_with("folderAsset: yes") {
            cx.format_set("folder", true);
        }
    }
    if let Some(i) = importer {
        cx.format_set("importer", truncate_chars(&i, 100));
    }
}

crate::register_extractor!(Unity);

#[cfg(test)]
mod tests {
    use crate::plugin::testing::report_for;

    #[test]
    fn scene_classes() {
        let t = "%YAML 1.1\n%TAG !u! tag:unity3d.com,2011:\n--- !u!1 &100\nGameObject:\n  m_Name: Buoy\n\
            --- !u!4 &101\nTransform:\n  m_GameObject: {fileID: 100}\n--- !u!114 &102\nMonoBehaviour:\n  \
            m_Script: {fileID: 11500000, guid: 0123456789abcdef0123456789abcdef, type: 3}\n";
        let r = report_for("Harbour.unity", t.as_bytes());
        let f = &r.format["unity_yaml"];
        assert_eq!(f["objects"], 3);
        assert_eq!(f["classes"]["MonoBehaviour"], 1);
        assert_eq!((f["game_objects"][0].as_str(), f["scripts"].as_u64()), (Some("Buoy"), Some(1)));
        let m = report_for(
            "Buoy.cs.meta",
            b"fileFormatVersion: 2\nguid: 0123456789abcdef0123456789abcdef\nMonoImporter:\n  serializedVersion: 2\n",
        );
        assert_eq!(m.format["unity_meta"]["importer"], "MonoImporter");
    }

    crate::fixture_tests!("unity_yaml", "unity_meta");
}
