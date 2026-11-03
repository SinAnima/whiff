//! glTF 2.0 (`.gltf` JSON and `.glb` binary) and VRM avatars:
//! * the asset (generator, version, copyright), scenes, nodes, meshes and
//!   primitives, vertices and triangles, materials, textures, images
//!   (embedded or external), samplers, animations, skins, cameras,
//!   extensions used and required, buffers (embedded, external, GLB), and
//!   the bounds of the positions (mesh space: node transforms not applied);
//! * VRM 0.x (`VRM`) and 1.0 (`VRMC_vrm`) metadata: title, version,
//!   authors, contact, licence and the usage permissions, into `rights`.
//!
//! Specifications: Khronos glTF 2.0 (2021); VRM 0.0 and VRM 1.0
//! (`VRMC_vrm` meta).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{Box3, hist};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, truncate_chars,
};

/// Extractor for glTF and VRM.
pub struct Gltf;

static META: ExtractorMeta = ExtractorMeta {
    id: "cad.gltf",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "gltf",
            name: "glTF / GLB",
            family: "3d",
            mimes: &["model/gltf+json"],
            extensions: &["gltf"],
            magic: &[],
            parent: Some("json"),
        },
        FormatSpec {
            id: "glb",
            name: "glTF binary",
            family: "3d",
            mimes: &["model/gltf-binary"],
            extensions: &["glb"],
            magic: &[Magic::at(0, b"glTF")],
            parent: None,
        },
        FormatSpec {
            id: "vrm",
            name: "VRM avatar",
            family: "3d",
            mimes: &[],
            extensions: &["vrm"],
            magic: &[Magic::at(0, b"glTF")],
            parent: Some("glb"),
        },
    ],
};

fn len_of(v: &Value, key: &str) -> usize {
    v.get(key).and_then(Value::as_array).map_or(0, Vec::len)
}

#[allow(clippy::too_many_lines)] // one block per top-level array
fn describe(cx: &mut Context<'_>, v: &Value, glb_bin: Option<usize>) {
    let asset = v.get("asset").cloned().unwrap_or(Value::Null);
    for (k, out) in [
        ("version", "gltf_version"),
        ("generator", "generator"),
        ("minVersion", "min_version"),
        ("copyright", "copyright"),
    ] {
        if let Some(s) = asset.get(k).and_then(Value::as_str) {
            cx.format_set(out, truncate_chars(s, 200));
        }
    }
    if let Some(c) = asset.get("copyright").and_then(Value::as_str) {
        cx.rights().source("gltf.asset.copyright").copyright(truncate_chars(c, 300));
    }
    let mut counts = Map::new();
    for k in [
        "scenes",
        "nodes",
        "meshes",
        "materials",
        "textures",
        "images",
        "samplers",
        "animations",
        "skins",
        "cameras",
        "accessors",
        "bufferViews",
        "buffers",
    ] {
        let n = len_of(v, k);
        if n > 0 {
            counts.insert(k.into(), n.into());
        }
    }
    cx.format_set("counts", Value::Object(counts));
    if let Some(n) = v.pointer("/scenes/0/name").and_then(Value::as_str) {
        cx.format_set("scene", truncate_chars(n, 100));
    }
    // Vertices, triangles and bounds from the POSITION accessors.
    let accessors = v.get("accessors").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    let (mut vertices, mut triangles, mut primitives) = (0u64, 0u64, 0u64);
    let mut modes: BTreeMap<String, u64> = BTreeMap::new();
    let mut b = Box3::default();
    for m in v.get("meshes").and_then(Value::as_array).into_iter().flatten().take(100_000) {
        for p in m.get("primitives").and_then(Value::as_array).into_iter().flatten().take(10_000) {
            primitives += 1;
            let mode = p.get("mode").and_then(Value::as_u64).unwrap_or(4);
            let name = match mode {
                0 => "points",
                1 => "lines",
                2 => "line_loop",
                3 => "line_strip",
                4 => "triangles",
                5 => "triangle_strip",
                6 => "triangle_fan",
                _ => "unknown",
            };
            *modes.entry(name.into()).or_default() += 1;
            let pos = p
                .pointer("/attributes/POSITION")
                .and_then(Value::as_u64)
                .and_then(|i| accessors.get(usize::try_from(i).ok()?));
            let count = pos.and_then(|a| a.get("count")).and_then(Value::as_u64).unwrap_or(0);
            vertices += count;
            if let Some(a) = pos {
                let g = |k: &str| {
                    a.get(k).and_then(Value::as_array).map(|x| x.iter().filter_map(Value::as_f64).collect::<Vec<_>>())
                };
                if let (Some(lo), Some(hi)) = (g("min"), g("max"))
                    && lo.len() == 3
                    && hi.len() == 3
                {
                    b.add([lo[0], lo[1], lo[2]]);
                    b.add([hi[0], hi[1], hi[2]]);
                }
            }
            let idx = p
                .get("indices")
                .and_then(Value::as_u64)
                .and_then(|i| accessors.get(usize::try_from(i).ok()?))
                .and_then(|a| a.get("count"))
                .and_then(Value::as_u64);
            let n = idx.unwrap_or(count);
            triangles += match mode {
                4 => n / 3,
                5 | 6 => n.saturating_sub(2),
                _ => 0,
            };
        }
    }
    cx.format_set("primitives", primitives);
    cx.format_set("primitive_modes", hist(modes));
    cx.format_set("vertices", vertices);
    cx.format_set("triangles", triangles);
    b.points = b.points.min(vertices);
    b.report(cx, "bounds");
    // Images: embedded (buffer views, data URIs) or external files.
    let (mut embedded, mut external) = (0u64, Vec::new());
    for i in v.get("images").and_then(Value::as_array).into_iter().flatten() {
        match i.get("uri").and_then(Value::as_str) {
            Some(u) if !u.starts_with("data:") => {
                if external.len() < 100 {
                    external.push(truncate_chars(u, 200));
                }
            }
            _ => embedded += 1,
        }
    }
    cx.format_set("embedded_images", embedded);
    if !external.is_empty() {
        cx.format_set("external_images", external);
    }
    let buffers: Vec<String> = v
        .get("buffers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|b| b.get("uri").and_then(Value::as_str))
        .filter(|u| !u.starts_with("data:"))
        .take(100)
        .map(|u| truncate_chars(u, 200))
        .collect();
    if !buffers.is_empty() {
        cx.format_set("external_buffers", buffers);
    }
    if let Some(n) = glb_bin {
        cx.format_set("glb_binary_bytes", n);
    }
    for (k, out) in [("extensionsUsed", "extensions_used"), ("extensionsRequired", "extensions_required")] {
        let e: Vec<String> = v
            .get(k)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .take(100)
            .map(|s| truncate_chars(s, 80))
            .collect();
        if !e.is_empty() {
            cx.format_set(out, e);
        }
    }
    vrm(cx, v);
}

/// VRM 0.x / 1.0 metadata: identity, licence and permissions.
fn vrm(cx: &mut Context<'_>, v: &Value) {
    let (meta, spec) = if let Some(m) = v.pointer("/extensions/VRMC_vrm/meta") {
        (m, v.pointer("/extensions/VRMC_vrm/specVersion").and_then(Value::as_str).unwrap_or("1.0"))
    } else if let Some(m) = v.pointer("/extensions/VRM/meta") {
        (m, v.pointer("/extensions/VRM/specVersion").and_then(Value::as_str).unwrap_or("0.0"))
    } else {
        return;
    };
    cx.format_set("vrm_version", truncate_chars(spec, 10));
    let s = |k: &str| meta.get(k).and_then(Value::as_str).map(|x| truncate_chars(x, 300));
    let mut m = Map::new();
    for (k, v) in meta.as_object().into_iter().flatten().take(40) {
        if let Some(x) = v.as_str().filter(|x| !x.is_empty()) {
            m.insert(k.clone(), truncate_chars(x, 300).into());
        } else if let Some(a) = v.as_array() {
            m.insert(
                k.clone(),
                a.iter().filter_map(Value::as_str).take(20).map(|x| truncate_chars(x, 100)).collect::<Vec<_>>().into(),
            );
        } else if v.is_boolean() {
            m.insert(k.clone(), v.clone());
        }
    }
    cx.format_set("vrm_meta", Value::Object(m));
    if let Some(t) = s("name").or_else(|| s("title")) {
        cx.content().source("vrm.meta").title(t);
    }
    let authors: Vec<String> = meta
        .get("authors")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .or_else(|| s("author").map(|a| vec![a]))
        .unwrap_or_default();
    for a in authors.iter().take(20) {
        cx.content().source("vrm.meta").author(a.clone());
    }
    if let Some(c) = s("copyrightInformation") {
        cx.rights().source("vrm.meta").copyright(c);
    }
    let licence = s("licenseName").or_else(|| s("licenseUrl"));
    let url = s("licenseUrl").or_else(|| s("otherLicenseUrl"));
    if licence.is_some() || url.is_some() {
        cx.rights().source("vrm.meta").license(licence.as_deref(), url.as_deref());
    }
}

/// The JSON and binary chunks of a GLB.
fn glb_chunks(b: &[u8]) -> Option<(Value, Option<usize>)> {
    let u32_at = |i: usize| Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?));
    if b.get(..4)? != b"glTF" || u32_at(4)? != 2 {
        return None;
    }
    let jlen = usize::try_from(u32_at(12)?).ok()?;
    if u32_at(16)? != 0x4E4F_534A {
        return None;
    }
    let json: Value = serde_json::from_slice(b.get(20..20 + jlen)?).ok()?;
    let bin_at = 20 + jlen;
    let bin = (u32_at(bin_at + 4) == Some(0x004E_4942))
        .then(|| u32_at(bin_at))
        .flatten()
        .and_then(|n| usize::try_from(n).ok());
    Some((json, bin))
}

impl Extractor for Gltf {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let has = |n: &[u8]| h.windows(n.len()).any(|w| w == n);
        if h.starts_with(b"glTF") {
            let vrm = has(b"\"VRMC_vrm\"") || has(b"\"VRM\"");
            return Some(Sniff { format: if vrm { "vrm" } else { "glb" }, confidence: 0.98 });
        }
        let json = h.iter().find(|c| !c.is_ascii_whitespace()) == Some(&b'{');
        (json
            && has(b"\"asset\"")
            && has(b"\"version\"")
            && (has(b"\"meshes\"") || has(b"\"scenes\"") || has(b"\"nodes\""))
            && !has(b"\"geometricError\""))
        .then_some(Sniff { format: "gltf", confidence: 0.96 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "gltf" {
            let text = cx.read_text(src)?.text;
            let v: Value = serde_json::from_str(&text).map_err(|e| ExtractError::malformed(format!("JSON: {e}")))?;
            describe(cx, &v, None);
            return Ok(());
        }
        // The JSON chunk only: the binary chunk holds the data.
        let h = src.read_vec(0, 20).map_err(|_| ExtractError::malformed("GLB header"))?;
        let jlen = h.get(12..16).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize);
        if jlen > 64 << 20 {
            return Err(ExtractError::malformed("GLB JSON chunk length"));
        }
        let b = src.read_vec(0, 28 + jlen).map_err(|_| ExtractError::malformed("GLB chunks"))?;
        let (json, bin) = glb_chunks(&b).ok_or_else(|| ExtractError::malformed("GLB chunks"))?;
        cx.format_set("glb_length", u32::from_le_bytes([h[8], h[9], h[10], h[11]]));
        describe(cx, &json, bin);
        Ok(())
    }
}

crate::register_extractor!(Gltf);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glb_layout() {
        let json = br#"{"asset":{"version":"2.0"}}  "#;
        let mut b = b"glTF".to_vec();
        b.extend(2u32.to_le_bytes());
        b.extend(u32::try_from(20 + json.len()).unwrap().to_le_bytes());
        b.extend(u32::try_from(json.len()).unwrap().to_le_bytes());
        b.extend(0x4E4F_534Au32.to_le_bytes());
        b.extend(json);
        let (v, bin) = glb_chunks(&b).unwrap();
        assert_eq!(v.pointer("/asset/version").and_then(Value::as_str), Some("2.0"));
        assert_eq!(bin, None);
        assert!(glb_chunks(b"glTF\x01\0\0\0").is_none());
    }

    crate::fixture_tests!("gltf", "glb", "vrm");
}
