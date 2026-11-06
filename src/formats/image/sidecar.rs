//! Standalone metadata files, handed to the shared `whiff::meta` decoders:
//! * XMP sidecars (`.xmp`, as written next to raw files by Lightroom,
//!   Capture One, darktable…): the packet itself, plus the namespaces used
//!   and how many Camera Raw (`crs:`) develop settings it carries;
//! * ICC colour profiles (`.icc`, `.icm`);
//! * exiv2 metadata containers (`.exv`): the EXIF, XMP, IPTC (Photoshop
//!   resources), ICC and comment segments of a JPEG without the image;
//! * raw EXIF dumps (`.exif`): a TIFF structure, with or without the
//!   `Exif\0\0` APP1 header;
//! * VRA Core 4 XML records: every work, image and collection with its
//!   element sets (title, agent, date, subject, rights…), into
//!   `metadata.vra`;
//! * RawTherapee processing profiles (`.pp3`): the version that wrote it,
//!   the tool sections and the main develop settings.
//!
//! References: Adobe XMP Specification Part 3 (sidecar files); ICC.1:2022
//! §7; exiv2 `exv` file layout (JPEG segments after `FF 01 "Exiv2"`); VRA
//! Core 4.0 schema; RawTherapee "Sidecar files – processing profiles".

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::plugin::xmlwalk::{Ev, attr, walk, xml_root};
use crate::plugin::{
    BlockKind, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    latin1_or_utf8, truncate_chars,
};

/// Extractor for standalone metadata files.
pub struct Sidecar;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.sidecar",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "xmp",
            name: "XMP sidecar",
            family: "meta.xmp",
            mimes: &["application/rdf+xml", "application/xmp+xml"],
            extensions: &["xmp"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "icc",
            name: "ICC colour profile",
            family: "meta.icc",
            mimes: &["application/vnd.iccprofile"],
            extensions: &["icc", "icm"],
            magic: &[Magic::at(36, b"acsp")],
            parent: None,
        },
        FormatSpec {
            id: "exv",
            name: "Exiv2 metadata container",
            family: "meta.exif",
            mimes: &["image/x-exv"],
            extensions: &["exv"],
            magic: &[Magic::prefix(b"\xff\x01Exiv2")],
            parent: None,
        },
        FormatSpec {
            id: "exif",
            name: "EXIF metadata dump",
            family: "meta.exif",
            mimes: &[],
            extensions: &["exif"],
            magic: &[Magic::prefix(b"Exif\0\0II*\0"), Magic::prefix(b"Exif\0\0MM\0*")],
            parent: None,
        },
        FormatSpec {
            id: "vra",
            name: "VRA Core 4 record",
            family: "meta.vra",
            mimes: &["application/xml"],
            extensions: &[],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "pp3",
            name: "RawTherapee processing profile",
            family: "meta.xmp",
            mimes: &[],
            extensions: &["pp3"],
            magic: &[Magic::prefix(b"[Version]\nAppVersion="), Magic::prefix(b"[Version]\r\nAppVersion=")],
            parent: Some("ini"),
        },
    ],
};

const MAX_LISTED: usize = 100;
const MAX_EVENTS: usize = 200_000;

impl Extractor for Sidecar {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if probe.extension == Some("exif") && matches!(h.get(..4), Some(b"II*\0" | b"MM\0*")) {
            return Some(Sniff { format: "exif", confidence: 0.97 });
        }
        let (root, tag) = xml_root(h)?;
        let text = String::from_utf8_lossy(&h[..h.len().min(4096)]);
        if root == "xmpmeta" || root == "xapmeta" || (root == "RDF" && text.contains("ns.adobe.com/")) {
            return Some(Sniff { format: "xmp", confidence: 0.97 });
        }
        (root == "vra" && tag.contains("vraweb.org")).then_some(Sniff { format: "vra", confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, truncated) = cx.read_bytes(src)?;
        if truncated {
            cx.warn("file cut at the parse limit");
        }
        match cx.format_id() {
            "xmp" => {
                xmp(&data, cx);
                Ok(())
            }
            "icc" => {
                let declared = data.get(..4).map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                if declared as usize != data.len() {
                    cx.warn(format!("header says {declared} bytes, file has {}", data.len()));
                }
                cx.emit_block(BlockKind::ICC, data);
                Ok(())
            }
            "exv" => {
                exv(&data, cx);
                Ok(())
            }
            "exif" => {
                cx.emit_block(BlockKind::EXIF, data);
                Ok(())
            }
            "vra" => vra(&data, cx),
            "pp3" => pp3(&latin1_or_utf8(&data), cx),
            other => Err(ExtractError::Unsupported(format!("format {other}"))),
        }
    }
}

crate::register_extractor!(Sidecar);

// ---- XMP --------------------------------------------------------------------

fn xmp(data: &[u8], cx: &mut Context<'_>) {
    let text = String::from_utf8_lossy(data);
    let mut namespaces = BTreeSet::new();
    let mut rest = text.as_ref();
    while let Some(i) = rest.find("xmlns") {
        rest = &rest[i + 5..];
        let Some(after) = rest
            .trim_start_matches(|c: char| c == ':' || c.is_alphanumeric() || c == '_' || c == '-')
            .strip_prefix('=')
        else {
            continue;
        };
        let Some(q) = after.chars().next().filter(|c| *c == '"' || *c == '\'') else { continue };
        if let Some(end) = after[1..].find(q)
            && namespaces.len() < MAX_LISTED
        {
            namespaces.insert(after[1..=end].to_string());
        }
    }
    cx.format_set("packet_wrapper", text.contains("<?xpacket"));
    // Camera Raw develop settings: `crs:` attributes and elements (closing tags excluded).
    let develop = text.matches("crs:").count().saturating_sub(text.matches("</crs:").count());
    if develop > 0 {
        cx.format_set("camera_raw_settings", develop);
    }
    if !namespaces.is_empty() {
        cx.format_set("namespaces", json!(namespaces.into_iter().collect::<Vec<_>>()));
    }
    cx.emit_block(BlockKind::XMP, data.to_vec());
}

// ---- exiv2 .exv ---------------------------------------------------------------

fn exv(data: &[u8], cx: &mut Context<'_>) {
    let mut at = 7;
    let mut segments = Vec::new();
    while at + 4 <= data.len() && data[at] == 0xff {
        let marker = data[at + 1];
        if marker == 0xd9 {
            break;
        }
        let len = usize::from(u16::from_be_bytes([data[at + 2], data[at + 3]]));
        let Some(body) = data.get(at + 4..at + 2 + len).filter(|_| len >= 2) else {
            cx.warn(format!("segment at {at} runs past the end"));
            break;
        };
        let name = match marker {
            0xe1 if body.starts_with(b"Exif\0\0") => {
                cx.emit_block(BlockKind::EXIF, body.to_vec());
                "exif"
            }
            0xe1 if body.starts_with(b"http://ns.adobe.com/xap/1.0/\0") => {
                cx.emit_block(BlockKind::XMP, body[29..].to_vec());
                "xmp"
            }
            0xed if body.starts_with(b"Photoshop 3.0\0") => {
                cx.emit_block(BlockKind::PHOTOSHOP_IRB, body[14..].to_vec());
                "photoshop"
            }
            0xe2 if body.starts_with(b"ICC_PROFILE\0") && body.len() > 14 => {
                cx.emit_block(BlockKind::ICC, body[14..].to_vec());
                "icc"
            }
            0xfe => {
                cx.format_set("comment", truncate_chars(&latin1_or_utf8(body), 2000));
                "comment"
            }
            _ => "other",
        };
        if segments.len() < MAX_LISTED {
            segments.push(name);
        }
        at += 2 + len;
    }
    cx.format_set("segments", json!(segments));
}

// ---- VRA Core 4 ----------------------------------------------------------------

#[derive(Default)]
struct Record {
    kind: String,
    id: Option<String>,
    fields: Map<String, Value>,
}

fn vra(data: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let text = String::from_utf8_lossy(data);
    let mut records: Vec<Record> = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut depth_of_record = None;
    walk(&text, cx, MAX_EVENTS, |_, ev| match ev {
        Ev::Start(name, attrs) => {
            if depth_of_record.is_none() && matches!(name, "work" | "image" | "collection") {
                depth_of_record = Some(path.len());
                if records.len() < MAX_LISTED {
                    records.push(Record {
                        kind: name.to_string(),
                        id: attr(attrs, "id").map(str::to_string),
                        ..Record::default()
                    });
                }
            }
            path.push(name.to_string());
        }
        Ev::End(_) => {
            path.pop();
            if depth_of_record == Some(path.len()) {
                depth_of_record = None;
            }
        }
        Ev::Text(t) => {
            let (Some(d), Some(rec)) = (depth_of_record, records.last_mut()) else { return };
            if let Some(key) = field_key(&path[d + 1..]) {
                let list = rec.fields.entry(key).or_insert_with(|| json!([]));
                if let Value::Array(l) = list
                    && l.len() < MAX_LISTED
                {
                    l.push(json!(truncate_chars(t, 2000)));
                }
            }
        }
    })?;
    if records.is_empty() {
        return Err(ExtractError::malformed("no work, image or collection record"));
    }
    let first =
        |key: &str| records.iter().find_map(|r| r.fields.get(key)?.as_array()?.first()?.as_str().map(str::to_string));
    if let Some(t) = first("title") {
        cx.content().source("vra.title").title(truncate_chars(&t, 300));
    }
    if let Some(d) = first("description") {
        cx.content().source("vra.description").description(truncate_chars(&d, 1000));
    }
    for r in &records {
        for (key, set) in [("agent.name", 0), ("subject.term", 1)] {
            for v in r.fields.get(key).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                if set == 0 {
                    cx.content().source("vra.agent").author(v);
                } else {
                    cx.content().source("vra.subject").keyword(v);
                }
            }
        }
    }
    if let Some(r) = first("rights.text") {
        cx.rights().source("vra.rights").copyright(r);
    }
    let out: Vec<Value> = records
        .into_iter()
        .map(|r| {
            let mut m = Map::new();
            m.insert("kind".into(), json!(r.kind));
            if let Some(id) = r.id {
                m.insert("id".into(), json!(id));
            }
            m.extend(r.fields);
            Value::Object(m)
        })
        .collect();
    cx.format_set("records", out.len());
    cx.metadata_set("vra", "records", Value::Array(out));
    Ok(())
}

/// `titleSet/title` → `title`, `titleSet/display` → `title.display`,
/// `agentSet/agent/name` → `agent.name`; `notes` elements are skipped.
fn field_key(rel: &[String]) -> Option<String> {
    let (set, rest) = rel.split_first()?;
    let base = set.strip_suffix("Set")?;
    let rest = match rest.split_first() {
        Some((f, r)) if f == base => r,
        _ => rest,
    };
    if rest.iter().any(|p| p == "notes") {
        return None;
    }
    Some(std::iter::once(base).chain(rest.iter().map(String::as_str)).collect::<Vec<_>>().join("."))
}

// ---- RawTherapee .pp3 -------------------------------------------------------------

/// Develop settings reported as `section/key`.
const PP3_KEYS: &[(&str, &str)] = &[
    ("Exposure", "Compensation"),
    ("Exposure", "Auto"),
    ("White Balance", "Setting"),
    ("White Balance", "Temperature"),
    ("White Balance", "Green"),
    ("Crop", "Enabled"),
    ("Rotation", "Degree"),
    ("Color Management", "OutputProfile"),
    ("Sharpening", "Enabled"),
    ("Directional Pyramid Denoising", "Enabled"),
];

fn pp3(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut section = String::new();
    let mut sections = Vec::new();
    let mut settings = 0u64;
    let mut develop = Map::new();
    for line in text.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.to_string();
            if sections.len() < MAX_LISTED {
                sections.push(section.clone());
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        settings += 1;
        match (section.as_str(), k) {
            ("Version", "AppVersion") => cx.format_set("app_version", v),
            ("Version", "Version") => cx.format_set("profile_version", v.parse::<u64>().map_or(json!(v), |n| json!(n))),
            ("General", "Rank") => cx.format_set("rank", v.parse::<i64>().map_or(json!(v), |n| json!(n))),
            ("General", "ColorLabel") => cx.format_set("color_label", v.parse::<i64>().map_or(json!(v), |n| json!(n))),
            _ => {
                if PP3_KEYS.contains(&(section.as_str(), k)) && !v.is_empty() {
                    develop.insert(format!("{section}/{k}"), json!(v));
                }
            }
        }
    }
    if sections.first().map(String::as_str) != Some("Version") {
        return Err(ExtractError::malformed("no [Version] section"));
    }
    cx.format_set("sections", json!(sections));
    cx.format_set("settings", settings);
    if !develop.is_empty() {
        cx.format_set("develop", Value::Object(develop));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vra_keys() {
        let p = |s: &[&str]| s.iter().map(|x| (*x).to_string()).collect::<Vec<_>>();
        assert_eq!(field_key(&p(&["titleSet", "title"])).as_deref(), Some("title"));
        assert_eq!(field_key(&p(&["titleSet", "display"])).as_deref(), Some("title.display"));
        assert_eq!(field_key(&p(&["agentSet", "agent", "name"])).as_deref(), Some("agent.name"));
        assert_eq!(field_key(&p(&["agentSet", "notes"])), None);
        assert_eq!(field_key(&p(&["image"])), None);
    }

    crate::fixture_tests!("xmp", "icc", "exv", "exif", "vra", "pp3");
}
