//! Autodesk Fusion documents:
//!
//! * Fusion designs (`.f3d`, a ZIP): the document manifest (manifest
//!   version, document type, display name, description, document ID,
//!   whether it was saved offline or carries a cloud lineage), the
//!   document structure from `Properties.dat` (part or assembly design,
//!   its subtype), the asset folders and their asset types, B-rep streams
//!   and their encoding, mesh bodies, T-spline forms, configuration tables,
//!   previews, and the documents it references (`RedirectionsStream.dat`);
//! * Fusion archives (`.f3z`, a ZIP of designs and drawings): the root
//!   member, the design description (name, current version, the service
//!   that created it and when) and its design objects.
//!
//! Geometry is not decoded. Cloud lineage and version URNs are given only
//! with `--privacy off`.
//!
//! Specification: the cadmpeg project's Fusion `.f3d` format notes
//! (CC-BY-4.0), sections 1.2 – 1.5.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use super::{bump, hist};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, Zip, ZipEntry, zip_names,
};

/// Extractor for Fusion documents.
pub struct Fusion;

static META: ExtractorMeta = ExtractorMeta {
    id: "cad.fusion",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "fusion_design",
            name: "Autodesk Fusion design",
            family: "cad",
            mimes: &["application/x-autodesk-fusion-design"],
            extensions: &["f3d"],
            magic: &[],
            parent: Some("zip"),
        },
        FormatSpec {
            id: "fusion_archive",
            name: "Autodesk Fusion archive",
            family: "cad",
            mimes: &["application/x-autodesk-fusion-archive"],
            extensions: &["f3z"],
            magic: &[],
            parent: Some("zip"),
        },
    ],
};

/// Names listed.
const MAX_LISTED: usize = 100;
/// Bytes read from a manifest or JSON entry.
const MAX_ENTRY: usize = 4 << 20;

impl Extractor for Fusion {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if !probe.head.starts_with(b"PK\x03\x04") {
            return None;
        }
        let names = zip_names(probe, 4000);
        let has = |n: &str| names.iter().any(|x| x == n);
        if has("Manifest.dat")
            && (has("Properties.dat") || names.iter().any(|n| n.contains(".BlobParts/") || n.contains("[Active]/")))
        {
            return Some(Sniff { format: "fusion_design", confidence: 0.95 });
        }
        if has("Manifest.json")
            && has("DesignDescription.json")
            && names.iter().any(|n| n.to_ascii_lowercase().ends_with(".f3d"))
        {
            return Some(Sniff { format: "fusion_archive", confidence: 0.95 });
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let zip = Zip::open(src, 100_000)?;
        cx.format_set("entries", zip.entries.len());
        if cx.format_id() == "fusion_archive" {
            archive(&zip, src, cx);
            Ok(())
        } else {
            design(&zip, src, cx)
        }
    }
}

crate::register_extractor!(Fusion);

/// Reads of `u32`-length-prefixed fields (ASCII byte counts, UTF-16LE
/// code-unit counts).
struct Lp<'a> {
    b: &'a [u8],
    at: usize,
}

impl Lp<'_> {
    fn len(&mut self) -> Option<usize> {
        let s = self.b.get(self.at..self.at + 4)?;
        self.at += 4;
        let n = u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize;
        (n <= 1 << 20).then_some(n)
    }

    fn ascii(&mut self) -> Option<String> {
        let n = self.len()?;
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(String::from_utf8_lossy(s).into_owned())
    }

    fn utf16(&mut self) -> Option<String> {
        let n = self.len()?;
        let s = self.b.get(self.at..self.at.checked_add(n * 2)?)?;
        self.at += n * 2;
        let units: Vec<u16> = s.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        Some(String::from_utf16_lossy(&units))
    }
}

/// UTF-16LE `needle` somewhere in `b`.
fn has_utf16(b: &[u8], needle: &str) -> bool {
    let n: Vec<u8> = needle.encode_utf16().flat_map(u16::to_le_bytes).collect();
    b.windows(n.len()).any(|w| w == n.as_slice())
}

/// The last `urn:` string (UTF-16LE, length-prefixed) in `b`.
fn last_urn(b: &[u8]) -> Option<String> {
    let n: Vec<u8> = "urn:".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let at = b.windows(n.len()).rposition(|w| w == n.as_slice())?;
    Lp { b, at: at.checked_sub(4)? }.utf16()
}

/// The extension of an entry name (after the last dot of its last component).
fn extension(name: &str) -> &str {
    name.rsplit('/').next().and_then(|n| n.rsplit_once('.')).map_or("", |(_, e)| e)
}

fn read(zip: &Zip, src: &mut dyn Source, cx: &mut Context<'_>, e: &ZipEntry) -> Option<Vec<u8>> {
    match zip.read(src, e, cx, MAX_ENTRY) {
        Ok(b) => Some(b),
        Err(err) => {
            cx.warn(format!("{}: {err}", e.name));
            None
        }
    }
}

/// The top-level `Manifest.dat`.
fn manifest(cx: &mut Context<'_>, b: &[u8]) {
    let mut r = Lp { b, at: 0 };
    let Some(version) = r.ascii() else { return };
    cx.format_set("manifest_version", version);
    if r.ascii().as_deref() != Some("FusionDocType") {
        return;
    }
    if let Some(t) = r.utf16() {
        cx.format_set("document_type", t);
    }
    if let Some(name) = r.utf16().filter(|n| !n.is_empty()) {
        cx.content().source("fusion.Manifest").title(&name);
        cx.format_set("display_name", name);
    }
    if let Some(d) = r.utf16().filter(|d| !d.is_empty()) {
        cx.content().source("fusion.Manifest").description(&d);
        cx.format_set("description", d);
    }
    if let Some(g) = r.utf16().filter(|g| !g.is_empty()) {
        cx.format_set("document_id", g);
    }
    if has_utf16(b, "NA_OFFLINESAVE") {
        cx.format_set("saved_offline", true);
    } else if has_utf16(b, "NA_EXPORT") {
        cx.format_set("exported", true);
    }
    if let Some(urn) = last_urn(b) {
        cx.format_set("cloud_lineage", if cx.privacy_strict() { json!(true) } else { json!(urn) });
    }
}

/// A per-asset `Manifest.dat`: base name, two GUIDs, the asset type.
fn asset_type(b: &[u8]) -> Option<String> {
    let mut r = Lp { b, at: 0 };
    r.utf16()?;
    r.utf16()?;
    r.utf16()?;
    r.ascii().filter(|t| !t.is_empty())
}

fn design(zip: &Zip, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    if let Some(e) = zip.find("Manifest.dat").cloned()
        && let Some(b) = read(zip, src, cx, &e)
    {
        manifest(cx, &b);
    }
    // Properties.dat: a u32 byte count, then JSON with `docstruct`.
    if let Some(e) = zip.find("Properties.dat").cloned()
        && let Some(b) = read(zip, src, cx, &e)
        && let Some(json) = b.get(4..)
        && let Ok(v) = serde_json::from_slice::<Value>(json)
        && let Some(d) = v.get("docstruct")
    {
        for (key, out) in [("type", "design_type"), ("subtype", "design_subtype"), ("version", "docstruct_version")] {
            if let Some(s) = d.get(key).and_then(Value::as_str) {
                cx.format_set(out, s);
            }
        }
    }
    cx.checkpoint()?;
    let mut folders = BTreeSet::new();
    let mut roles: BTreeMap<String, u64> = BTreeMap::new();
    let mut asset_types: BTreeMap<String, u64> = BTreeMap::new();
    let mut brep_header = None;
    let entries: Vec<ZipEntry> = zip.entries.iter().filter(|e| !e.is_dir()).cloned().collect();
    for e in &entries {
        let name = e.name.as_str();
        let lower = name.to_ascii_lowercase();
        if let Some((folder, rest)) = name.split_once('/') {
            folders.insert(folder.trim_end_matches("[Active]").to_string());
            if rest == "Manifest.dat"
                && let Some(b) = read(zip, src, cx, e)
                && let Some(t) = asset_type(&b)
            {
                bump(&mut asset_types, &t, 50);
            }
        }
        let role = if name.contains("Breps.BlobParts/") {
            if brep_header.is_none() && matches!(extension(&lower), "smb" | "smbh") {
                brep_header = zip
                    .read_prefix(src, e, cx, 64)
                    .ok()
                    .map(|(b, _)| {
                        b.iter()
                            .take_while(|c| c.is_ascii_graphic() || **c == b' ')
                            .map(|&c| char::from(c))
                            .collect::<String>()
                    })
                    .filter(|s| s.len() >= 4);
            }
            "brep_streams"
        } else if extension(&lower) == "paramesh" {
            "mesh_bodies"
        } else if extension(&lower) == "tsm" {
            "tspline_forms"
        } else if extension(&lower) == "protein" {
            "appearance_assets"
        } else if extension(&lower) == "dsgcfg" {
            "configuration_tables"
        } else if name.contains("/Previews/") || name.contains("Images.BlobParts/") {
            "images"
        } else if name.ends_with("/BulkStream.dat") {
            "design_segments"
        } else {
            continue;
        };
        *roles.entry(role.to_string()).or_insert(0) += 1;
    }
    cx.format_set("asset_folders", folders.len());
    if !asset_types.is_empty() {
        cx.format_set("asset_types", hist(asset_types));
    }
    cx.format_set("parts_by_role", hist(roles));
    if let Some(h) = brep_header {
        cx.format_set("brep_encoding", h);
    }
    if let Some(e) = zip.find("RedirectionsStream.dat").cloned()
        && let Some(b) = read(zip, src, cx, &e)
        && let Ok(v) = serde_json::from_slice::<Value>(&b)
    {
        let designs = v.get("designs").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
        if let Some(fv) = designs.first().and_then(|d| d.get("file-version")).and_then(Value::as_i64) {
            cx.format_set("file_version", fv);
        }
        let refs: Vec<&str> = designs
            .iter()
            .skip(1)
            .filter_map(|d| d.get("targetFileName").or_else(|| d.get("displayName")).and_then(Value::as_str))
            .take(MAX_LISTED)
            .collect();
        cx.format_set("references", designs.len().saturating_sub(1));
        if !refs.is_empty() {
            cx.format_set("referenced_documents", json!(refs));
        }
    }
    Ok(())
}

fn archive(zip: &Zip, src: &mut dyn Source, cx: &mut Context<'_>) {
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    for e in zip.entries.iter().filter(|e| !e.is_dir()) {
        let ext = e.name.rsplit_once('.').map_or("", |(_, x)| x).to_ascii_lowercase();
        bump(&mut kinds, &ext, 20);
    }
    cx.format_set("members_by_extension", hist(kinds));
    if let Some(e) = zip.find("Manifest.json").cloned()
        && let Some(b) = read(zip, src, cx, &e)
        && let Ok(v) = serde_json::from_slice::<Value>(&b)
        && let Some(root) = v.get("root").and_then(Value::as_str)
    {
        cx.format_set("root", root);
    }
    let Some(e) = zip.find("DesignDescription.json").cloned() else { return };
    let Some(b) = read(zip, src, cx, &e) else { return };
    let Ok(v) = serde_json::from_slice::<Value>(&b) else {
        cx.warn("DesignDescription.json: not JSON");
        return;
    };
    let Some(d) = v.get("designDescription") else { return };
    if let Some(n) = d.get("name").and_then(Value::as_str) {
        cx.content().source("fusion.DesignDescription").title(n);
        cx.format_set("name", n);
    }
    if let Some(cv) = d.get("currentVersion") {
        cx.format_set("current_version", cv.clone());
    }
    let graphs = d.get("designGraphs").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
    let mut objects = Vec::new();
    for g in graphs {
        for o in g.get("designObjects").and_then(Value::as_array).into_iter().flatten() {
            let mut m = Map::new();
            for (key, out) in [("friendlyName", "name"), ("relativePath", "member"), ("contentType", "content_type")] {
                if let Some(s) = o.get(key).and_then(Value::as_str) {
                    m.insert(out.into(), json!(s));
                }
            }
            if objects.len() < MAX_LISTED {
                objects.push(Value::Object(m));
            }
        }
        if let Some(s) = g.get("creatingService").and_then(Value::as_str) {
            cx.format_set("creating_service", s);
        }
        if let Some(t) = g.get("creationDate").and_then(Value::as_str) {
            cx.format_set("created", t);
        }
    }
    cx.format_set("design_graphs", graphs.len());
    cx.format_set("design_objects", objects);
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("fusion_design", "fusion_archive");

    #[test]
    fn length_prefixed_fields() {
        let mut b = Vec::new();
        b.extend_from_slice(&7u32.to_le_bytes());
        b.extend_from_slice(b"3-2-0-0");
        b.extend_from_slice(&4u32.to_le_bytes());
        b.extend("tide".encode_utf16().flat_map(u16::to_le_bytes));
        let mut r = Lp { b: &b, at: 0 };
        assert_eq!(r.ascii().as_deref(), Some("3-2-0-0"));
        assert_eq!(r.utf16().as_deref(), Some("tide"));
        assert!(r.ascii().is_none());
        assert!(has_utf16(&b, "ide"));
    }
}
