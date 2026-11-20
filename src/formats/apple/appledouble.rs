//! AppleDouble (`._name` files that carry a file's Mac metadata on other
//! file systems and in archives) and AppleSingle: the entries present,
//! the original name, Finder type and creator, resource fork size, file
//! dates, and the extended attributes macOS stores in the Finder info
//! entry (names and sizes; the quarantine agent and the download URLs of
//! `kMDItemWhereFroms` are decoded).
//!
//! Specifications: RFC 1740 (AppleSingle / AppleDouble version 2); the
//! `ATTR` extended-attribute header of Apple's `copyfile.c`.

use serde_json::{Map, Value};

use super::unix_time;
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, proplist,
    truncate_chars,
};

/// Extractor for AppleDouble and AppleSingle files.
pub struct AppleDouble;

static META: ExtractorMeta = ExtractorMeta {
    id: "apple.appledouble",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "appledouble",
            name: "AppleDouble resource forks / xattr dumps",
            family: "apple",
            mimes: &["multipart/appledouble"],
            extensions: &[],
            magic: &[Magic::at(0, b"\x00\x05\x16\x07")],
            parent: None,
        },
        FormatSpec {
            id: "applesingle",
            name: "AppleSingle file",
            family: "apple",
            mimes: &["application/applefile"],
            extensions: &["as"],
            magic: &[Magic::at(0, b"\x00\x05\x16\x00")],
            parent: None,
        },
    ],
};

/// Seconds from 1970 to 2000-01-01, the AppleSingle date epoch.
const AS_EPOCH: i64 = 946_684_800;
/// Extended attributes listed.
const MAX_ATTRS: usize = 64;

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn be_usize(b: &[u8], at: usize) -> Option<usize> {
    usize::try_from(be32(b, at)?).ok()
}

fn entry_name(id: u32) -> &'static str {
    match id {
        1 => "data_fork",
        2 => "resource_fork",
        3 => "real_name",
        4 => "comment",
        5 => "icon_bw",
        6 => "icon_color",
        8 => "file_dates",
        9 => "finder_info",
        10 => "mac_file_info",
        11 => "prodos_file_info",
        12 => "msdos_file_info",
        13 => "afp_short_name",
        14 => "afp_file_info",
        15 => "afp_directory_id",
        _ => "other",
    }
}

/// A four-character code, when printable.
fn four_cc(b: &[u8]) -> Option<String> {
    (b.len() == 4 && b.iter().all(|c| (0x20..0x7f).contains(c)) && b != b"    ")
        .then(|| String::from_utf8_lossy(b).into_owned())
}

impl Extractor for AppleDouble {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    #[allow(clippy::too_many_lines)] // entries, then the attributes
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, _) = cx.read_bytes(src)?;
        let count = data.get(24..26).map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])));
        let count = count.ok_or_else(|| ExtractError::malformed("AppleDouble header"))?;
        cx.format_set("version", format!("{}", be32(&data, 4).unwrap_or(0) >> 16));
        let filler = String::from_utf8_lossy(&data[8..24]).trim_matches([' ', '\0']).to_string();
        if !filler.is_empty() {
            cx.format_set("home_file_system", truncate_chars(&filler, 16));
        }
        let mut entries = Map::new();
        let mut attrs: Vec<(String, usize)> = Vec::new();
        let mut where_froms: Vec<String> = Vec::new();
        let mut quarantine = None;
        for i in 0..count.min(64) {
            let base = 26 + 12 * i;
            let (Some(id), Some(off), Some(len)) =
                (be32(&data, base), be_usize(&data, base + 4), be_usize(&data, base + 8))
            else {
                break;
            };
            let body = data.get(off..off.saturating_add(len)).unwrap_or_default();
            entries.insert(entry_name(id).into(), len.into());
            match id {
                3 => cx.format_set("real_name", truncate_chars(&String::from_utf8_lossy(body), 255)),
                8 if body.len() >= 16 => {
                    for (k, at, field) in [("created", 0, DateField::Created), ("modified", 4, DateField::Modified)] {
                        let secs = i32::from_be_bytes(body[at..at + 4].try_into().unwrap_or_default());
                        if let Some(t) = unix_time(i64::from(secs) + AS_EPOCH) {
                            cx.format_set(k, t.clone());
                            cx.temporal().content_date(field, t, true);
                        }
                    }
                }
                9 if body.len() >= 32 => {
                    if let Some(t) = four_cc(&body[0..4]) {
                        cx.format_set("file_type", t);
                    }
                    if let Some(c) = four_cc(&body[4..8]) {
                        cx.format_set("creator", c);
                    }
                    let flags = u16::from_be_bytes([body[8], body[9]]);
                    if flags & 0x4000 != 0 {
                        cx.format_set("invisible", true);
                    }
                    if flags & 0x0400 != 0 {
                        cx.format_set("custom_icon", true);
                    }
                    let h = body.get(34..).unwrap_or_default();
                    if h.starts_with(b"ATTR") {
                        // magic, debug tag, total size, data start, data length,
                        // 3 reserved words, flags, then the attribute count.
                        let n = h.get(34..36).map_or(0, |b| usize::from(u16::from_be_bytes([b[0], b[1]])));
                        let mut at = 36;
                        for _ in 0..n.min(MAX_ATTRS) {
                            let (Some(aoff), Some(alen), Some(&nl)) =
                                (be_usize(h, at), be_usize(h, at + 4), h.get(at + 10))
                            else {
                                break;
                            };
                            let Some(raw) = h.get(at + 11..at + 11 + usize::from(nl)) else { break };
                            let name = String::from_utf8_lossy(raw.strip_suffix(b"\0").unwrap_or(raw)).into_owned();
                            // Attribute offsets count from the start of the file.
                            let value = data.get(aoff..aoff.saturating_add(alen)).unwrap_or_default();
                            match name.as_str() {
                                "com.apple.quarantine" => {
                                    let v = String::from_utf8_lossy(value);
                                    quarantine = v.split(';').nth(2).filter(|a| !a.is_empty()).map(str::to_string);
                                }
                                "com.apple.metadata:kMDItemWhereFroms" => {
                                    if let Some((p, _)) = proplist::parse(value) {
                                        let urls =
                                            p.as_array().into_iter().flatten().filter_map(plist::Value::as_string);
                                        where_froms
                                            .extend(urls.take(4).map(|u| truncate_chars(&cx.redact_secrets(u), 500)));
                                    }
                                }
                                _ => {}
                            }
                            attrs.push((name, alen));
                            at = (at + 11 + usize::from(nl) + 3) & !3;
                        }
                    }
                }
                _ => {}
            }
        }
        cx.format_set("entries", Value::Object(entries));
        if !attrs.is_empty() {
            let m: Map<String, Value> = attrs.into_iter().map(|(n, l)| (truncate_chars(&n, 200), l.into())).collect();
            cx.format_set("extended_attributes", Value::Object(m));
        }
        if let Some(q) = quarantine {
            cx.format_set("quarantine_agent", truncate_chars(&q, 100));
        }
        if !where_froms.is_empty() {
            cx.format_set("where_froms", where_froms);
        }
        Ok(())
    }
}

crate::register_extractor!(AppleDouble);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_names() {
        assert_eq!(four_cc(b"TEXT").as_deref(), Some("TEXT"));
        assert_eq!(four_cc(b"\0\0\0\0"), None);
        assert_eq!(entry_name(2), "resource_fork");
    }

    crate::fixture_tests!("appledouble", "applesingle");
}
