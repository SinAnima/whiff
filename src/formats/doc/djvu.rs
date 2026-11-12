//! DjVu documents (`.djvu`, `.djv`): single pages, bundled and indirect
//! multi-page documents. Reports the kind, page count, the first page's
//! size, resolution, version and rotation, the chunk histogram, whether a
//! hidden text layer, annotations and bookmarks are present, and the
//! metadata of uncompressed annotations (`ANTa`: title, author, …).
//!
//! Compressed chunks (`TXTz`, `ANTz`, `NAVM`) use the BZZ coder and are
//! only counted.
//!
//! Reference: "DjVu3 Specification" (Lizardtech, 2005), sections 4–8.

use std::collections::BTreeMap;

use serde_json::json;

use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, truncate_chars};

/// Extractor for DjVu.
pub struct Djvu;

static META: ExtractorMeta = ExtractorMeta {
    id: "doc.djvu",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "djvu",
        name: "DjVu document",
        family: "doc.other",
        mimes: &["image/vnd.djvu"],
        extensions: &["djvu", "djv"],
        magic: &[Magic::prefix(b"AT&TFORM")],
        parent: None,
    }],
};

/// Bytes walked at most.
const MAX_FILE: u64 = 256 << 20;
const MAX_CHUNKS: usize = 200_000;

impl Extractor for Djvu {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let n = usize::try_from(src.len().min(MAX_FILE)).unwrap_or(0);
        let d = src.read_vec(0, n)?;
        let form = d.get(12..16).ok_or(ExtractError::Truncated { offset: 12, needed: 4 })?;
        let kind = match form {
            b"DJVU" => "single page",
            b"DJVM" => "multi-page",
            b"DJVI" => "shared data",
            b"THUM" => "thumbnails",
            _ => return Err(ExtractError::malformed(format!("FORM type {}", String::from_utf8_lossy(form)))),
        };
        let mut w = Walk::default();
        w.walk(&d[16..], cx, 0)?;
        if form == b"DJVM" {
            cx.format_set("bundled", w.bundled.unwrap_or(false));
            if let Some(n) = w.dir_files {
                cx.format_set("directory_files", n);
            }
        }
        cx.format_set("kind", kind);
        let pages = if form == b"DJVU" { 1 } else { w.pages };
        cx.physical().pages(pages);
        if let Some((width, height, dpi, version, rotation)) = w.info {
            let mut img = cx.physical().image(u32::from(width), u32::from(height));
            if dpi > 0 {
                img.dpi(f64::from(dpi), f64::from(dpi));
            }
            cx.format_set("version", version);
            cx.format_set("rotation", rotation);
        }
        cx.format_set("text_layer", w.counts.contains_key("TXTz") || w.counts.contains_key("TXTa"));
        cx.format_set("annotations", w.counts.contains_key("ANTz") || w.counts.contains_key("ANTa"));
        cx.format_set("bookmarks", w.counts.contains_key("NAVM"));
        cx.format_set("chunks", json!(w.counts));
        Ok(())
    }
}

crate::register_extractor!(Djvu);

#[derive(Default)]
struct Walk {
    counts: BTreeMap<String, u64>,
    pages: u64,
    /// Width, height, dpi, version, rotation of the first page.
    info: Option<(u16, u16, u16, String, u16)>,
    bundled: Option<bool>,
    dir_files: Option<u16>,
    chunks: usize,
}

impl Walk {
    fn walk(&mut self, d: &[u8], cx: &mut Context<'_>, depth: usize) -> Result<(), ExtractError> {
        let mut at = 0;
        while at + 8 <= d.len() && depth < 8 {
            self.chunks += 1;
            if self.chunks > MAX_CHUNKS {
                cx.warn("chunk limit reached");
                return Ok(());
            }
            let id = String::from_utf8_lossy(&d[at..at + 4]).into_owned();
            let len = u32::from_be_bytes([d[at + 4], d[at + 5], d[at + 6], d[at + 7]]) as usize;
            let body = d.get(at + 8..at + 8 + len).unwrap_or(&d[at + 8..]);
            if id == "FORM" && body.len() >= 4 {
                let sub = String::from_utf8_lossy(&body[..4]).into_owned();
                if sub == "DJVU" {
                    self.pages += 1;
                }
                *self.counts.entry(format!("FORM:{sub}")).or_default() += 1;
                self.walk(&body[4..], cx, depth + 1)?;
            } else {
                match id.as_str() {
                    "INFO" if self.info.is_none() && body.len() >= 10 => {
                        let w = u16::from_be_bytes([body[0], body[1]]);
                        let h = u16::from_be_bytes([body[2], body[3]]);
                        let (minor, major) = (body[4], body[5]);
                        let dpi = u16::from_le_bytes([body[6], body[7]]);
                        let rotation = match body[9] & 7 {
                            6 => 90,
                            2 => 180,
                            5 => 270,
                            _ => 0,
                        };
                        self.info = Some((w, h, dpi, format!("{major}.{minor}"), rotation));
                    }
                    "DIRM" if body.len() >= 3 => {
                        self.bundled = Some(body[0] & 0x80 != 0);
                        self.dir_files = Some(u16::from_be_bytes([body[1], body[2]]));
                    }
                    "ANTa" => annotations(&String::from_utf8_lossy(body), cx),
                    _ => {}
                }
                *self.counts.entry(id).or_default() += 1;
            }
            at += 8 + len + (len & 1);
        }
        Ok(())
    }
}

/// `(metadata (Title "…") (Author "…") …)` in an uncompressed annotation chunk.
fn annotations(text: &str, cx: &mut Context<'_>) {
    let Some(i) = text.find("(metadata") else { return };
    let mut rest = &text[i + 9..];
    while let Some(open) = rest.find('(') {
        let after = &rest[open + 1..];
        let key: String = after.chars().take_while(|c| c.is_alphanumeric()).collect();
        let Some(q) = after.find('"') else { break };
        let val_start = &after[q + 1..];
        let Some(end) = val_start.find('"') else { break };
        let value = truncate_chars(&val_start[..end], 1000);
        match key.to_ascii_lowercase().as_str() {
            "title" => {
                cx.content().source("djvu.metadata.Title").title(value);
            }
            "author" => {
                cx.content().source("djvu.metadata.Author").author(value);
            }
            "subject" => {
                cx.content().source("djvu.metadata.Subject").description(value);
            }
            "keywords" => {
                for k in value.split([',', ';']).map(str::trim).filter(|k| !k.is_empty()) {
                    cx.content().source("djvu.metadata.Keywords").keyword(k);
                }
            }
            "year" => cx.format_set("year", value),
            _ => {}
        }
        rest = &val_start[end + 1..];
        if rest.trim_start().starts_with(')') && rest.trim_start()[1..].trim_start().starts_with(')') {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("djvu");
}
