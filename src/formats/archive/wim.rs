//! Windows Imaging (WIM, and its split `.swm` and solid `.esd` forms): the
//! 208-byte header (version, compression, chunk size, GUID, part number,
//! image count, boot image) and the XML resource, which is never compressed:
//! per image its name, description, folder and file counts, size, times and,
//! for Windows images, the edition, architecture, build and languages.
//!
//! Specification: Microsoft's *Windows Imaging File Format (WIM)* and the
//! wimlib sources (`wimlib/header.h`, `xml.c`).

use crate::plugin::{
    ByteReader, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, filetime,
    xmlwalk,
};

/// Extractor for WIM, SWM and ESD files.
pub struct Wim;

static META: ExtractorMeta = ExtractorMeta {
    id: "archive.wim",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "wim",
        name: "Windows Imaging (WIM / SWM / ESD)",
        family: "archive",
        mimes: &["application/x-ms-wim"],
        extensions: &["wim", "swm", "esd"],
        // `WLPWM`: wimlib's pipable WIMs.
        magic: &[Magic::prefix(b"MSWIM\0\0\0"), Magic::prefix(b"WLPWM\0\0\0")],
        parent: None,
    }],
};

/// Images described.
const MAX_IMAGES: usize = 256;
/// XML events read.
const MAX_EVENTS: usize = 200_000;

impl Extractor for Wim {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let h = src.read_vec(0, 208)?;
        let mut r = ByteReader::new(&h).skip(8)?;
        let header_len = r.le_u32()?;
        let version = r.le_u32()?;
        let flags = r.le_u32()?;
        let chunk = r.le_u32()?;
        let guid = r.bytes(16)?;
        let (part, parts) = (r.le_u16()?, r.le_u16()?);
        let images = r.le_u32()?;
        if header_len < 148 {
            return Err(ExtractError::malformed("WIM header size"));
        }
        cx.format_set("version", format!("{}.{}", version >> 16, (version >> 8) & 0xff));
        if h.starts_with(b"WLPWM") {
            cx.format_set("pipable", true);
        }
        let compression = match flags & 0x00ff_0000 {
            0 if flags & 2 == 0 => "none",
            0x0002_0000 => "XPRESS",
            0x0004_0000 => "LZX",
            0x0008_0000 => "LZMS",
            0x0020_0000 => "XPRESS (new)",
            _ => "other",
        };
        cx.format_set("compression", compression);
        if flags & 2 != 0 {
            cx.format_set("chunk_bytes", chunk);
        }
        cx.format_set(
            "guid",
            guid.iter().fold(String::new(), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            }),
        );
        cx.format_set("part", format!("{part}/{parts}"));
        cx.format_set("images", images);
        for (bit, name) in [
            (0x8, "spanned"),
            (0x10, "resource_only"),
            (0x20, "metadata_only"),
            (0x40, "write_in_progress"),
            (0x80, "relative_path_fix"),
        ] {
            if flags & bit != 0 {
                cx.format_set(name, true);
            }
        }
        // Resource headers: a 7-byte stored size, flags, offset, original size.
        let mut xml_header = ByteReader::new(&h).skip(72)?;
        let stored = xml_header.bytes(7)?.iter().rev().fold(0u64, |acc, &byte| (acc << 8) | u64::from(byte));
        xml_header.u8()?;
        let at = xml_header.le_u64()?;
        let size = xml_header.le_u64()?;
        let boot = ByteReader::new(&h).skip(120)?.le_u32()?;
        if boot > 0 {
            cx.format_set("boot_image", boot);
        }
        let n = size.max(stored).min(cx.parse_limit() as u64);
        if at == 0 || n < 2 || at >= src.len() {
            // Parts after the first of a split set carry no XML.
            return Ok(());
        }
        let raw = src.read_vec(at, usize::try_from(n.min(src.len() - at)).unwrap_or(0))?;
        let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        let xml = String::from_utf16_lossy(&units);
        let xml = xml.trim_start_matches('\u{feff}');
        images_xml(cx, xml)
    }
}

crate::register_extractor!(Wim);

/// A FILETIME split in `HIGHPART` / `LOWPART` hex strings.
fn hex_time(high: &str, low: &str) -> Option<String> {
    let p = |s: &str| u64::from_str_radix(s.trim().trim_start_matches("0x").trim_start_matches("0X"), 16).ok();
    filetime((p(high)? << 32) | p(low)?)
}

#[allow(clippy::too_many_lines)] // one walk over the image list
fn images_xml(cx: &mut Context<'_>, xml: &str) -> Result<(), ExtractError> {
    use serde_json::{Map, Value};
    let mut images: Vec<Map<String, Value>> = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let (mut high, mut low) = (String::new(), String::new());
    let mut windows: Map<String, Value> = Map::new();
    let mut version: [Option<u64>; 4] = [None; 4];
    let mut languages: Vec<Value> = Vec::new();
    xmlwalk::walk(xml, cx, MAX_EVENTS, |_, ev| match ev {
        xmlwalk::Ev::Start(name, attrs) => {
            if name == "IMAGE" && images.len() < MAX_IMAGES {
                let mut m = Map::new();
                if let Some(i) = xmlwalk::attr(attrs, "INDEX").and_then(|v| v.parse::<u64>().ok()) {
                    m.insert("index".into(), i.into());
                }
                images.push(m);
                windows = Map::new();
                version = [None; 4];
                languages.clear();
            }
            path.push(name.to_string());
        }
        xmlwalk::Ev::End(name) => {
            path.pop();
            let Some(img) = images.last_mut().filter(|_| path.iter().any(|p| p == "IMAGE") || name == "IMAGE") else {
                return;
            };
            match name {
                "CREATIONTIME" | "LASTMODIFICATIONTIME" if path.last().is_some_and(|p| p == "IMAGE") => {
                    let key = if name == "CREATIONTIME" { "created" } else { "modified" };
                    if let Some(t) = hex_time(&high, &low) {
                        img.insert(key.into(), t.into());
                    }
                }
                "IMAGE" => {
                    if let [Some(a), Some(b), Some(c), sp] = version {
                        let v = match sp {
                            Some(s) if s > 0 => format!("{a}.{b}.{c}.{s}"),
                            _ => format!("{a}.{b}.{c}"),
                        };
                        windows.insert("version".into(), v.into());
                    }
                    if !languages.is_empty() {
                        windows.insert("languages".into(), Value::Array(languages.clone()));
                    }
                    if !windows.is_empty() {
                        img.insert("windows".into(), Value::Object(windows.clone()));
                    }
                }
                _ => {}
            }
        }
        xmlwalk::Ev::Text(t) => {
            let (Some(tag), Some(img)) = (path.last().map(String::as_str), images.last_mut()) else { return };
            let parent = path.len().checked_sub(2).map(|i| path[i].as_str());
            match (parent, tag) {
                (Some("IMAGE"), "NAME" | "DESCRIPTION" | "DISPLAYNAME" | "FLAGS") => {
                    let key = match tag {
                        "NAME" => "name",
                        "DESCRIPTION" => "description",
                        "DISPLAYNAME" => "display_name",
                        _ => "edition_flags",
                    };
                    img.insert(key.into(), t.into());
                }
                (Some("IMAGE"), "DIRCOUNT" | "FILECOUNT" | "TOTALBYTES") => {
                    let key = match tag {
                        "DIRCOUNT" => "directories",
                        "FILECOUNT" => "files",
                        _ => "total_bytes",
                    };
                    if let Ok(n) = t.parse::<u64>() {
                        img.insert(key.into(), n.into());
                    }
                }
                (_, "HIGHPART") => high = t.to_string(),
                (_, "LOWPART") => low = t.to_string(),
                (Some("WINDOWS"), "ARCH") => {
                    let arch = match t {
                        "0" => "x86",
                        "5" => "ARM",
                        "6" => "IA-64",
                        "9" => "x64",
                        "12" => "ARM64",
                        other => other,
                    };
                    windows.insert("architecture".into(), arch.into());
                }
                (Some("WINDOWS"), "PRODUCTNAME" | "EDITIONID" | "INSTALLATIONTYPE" | "PRODUCTTYPE") => {
                    let key = match tag {
                        "PRODUCTNAME" => "product",
                        "EDITIONID" => "edition",
                        "INSTALLATIONTYPE" => "installation_type",
                        _ => "product_type",
                    };
                    windows.insert(key.into(), t.into());
                }
                (Some("VERSION"), "MAJOR") => version[0] = t.parse().ok(),
                (Some("VERSION"), "MINOR") => version[1] = t.parse().ok(),
                (Some("VERSION"), "BUILD") => version[2] = t.parse().ok(),
                (Some("VERSION"), "SPBUILD") => version[3] = t.parse().ok(),
                (Some("LANGUAGES"), "LANGUAGE") => languages.push(t.into()),
                _ => {}
            }
        }
    })?;
    if let Some(name) = images.first().and_then(|i| i.get("name")).and_then(Value::as_str) {
        cx.content().title(name.to_string());
    }
    let created: Vec<String> = images.iter().filter_map(|i| i.get("created")?.as_str().map(str::to_string)).collect();
    if let Some(first) = created.iter().min() {
        cx.temporal().content_date(DateField::Created, first.clone(), true);
    }
    let files: u64 = images.iter().filter_map(|i| i.get("files")?.as_u64()).sum();
    if files > 0 {
        cx.physical().entries(files);
    }
    cx.format_set("image_list", Value::Array(images.into_iter().map(Value::Object).collect()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("wim");

    #[test]
    fn filetimes() {
        assert_eq!(hex_time("0x01DC1B37", "0xF1A4A520").as_deref(), Some("2025-09-01T12:00:00Z"));
        assert_eq!(hex_time("zz", "0"), None);
    }
}
