//! Aseprite sprites (`.aseprite`, `.ase`): canvas size, colour mode,
//! palette size, pixel ratio, grid, frames and their total duration,
//! layers (names, kinds, groups, tilemaps), tags (frame ranges,
//! directions, repeats), slices, tilesets, cels, the colour profile,
//! external files and user-data text.
//!
//! Specification: Aseprite File Format (`.ase` / `.aseprite`), docs/ase-
//! file-specs.md in the Aseprite repository (v1.3).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{bump, hist};
use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole,
    truncate_chars,
};

/// Extractor for Aseprite files.
pub struct Sprite;

static META: ExtractorMeta = ExtractorMeta {
    id: "game.sprite",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "aseprite",
        name: "Aseprite sprite",
        family: "game",
        mimes: &["image/x-aseprite"],
        extensions: &["aseprite", "ase"],
        magic: &[],
        parent: None,
    }],
};

const MAX_FRAMES: usize = 100_000;
const MAX_CHUNKS: usize = 1_000_000;
const MAX_LIST: usize = 100;

fn string(r: &mut ByteReader<'_>) -> Result<String, ExtractError> {
    let n = usize::from(r.le_u16()?);
    Ok(truncate_chars(&String::from_utf8_lossy(r.bytes(n)?), 300))
}

#[allow(clippy::too_many_lines)] // one arm per chunk type
fn aseprite(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(b);
    r.advance(6)?;
    let frames = usize::from(r.le_u16()?);
    let (w, h) = (r.le_u16()?, r.le_u16()?);
    let depth = r.le_u16()?;
    r.advance(4 + 2 + 8)?;
    let transparent = r.u8()?;
    r.advance(3)?;
    let colors = r.le_u16()?;
    let (pw, ph) = (r.u8()?, r.u8()?);
    let (gx, gy, gw, gh) = (r.le_i16()?, r.le_i16()?, r.le_u16()?, r.le_u16()?);
    let mode = match depth {
        32 => "RGBA",
        16 => "grayscale",
        8 => "indexed",
        _ => "unknown",
    };
    cx.format_set("width", w);
    cx.format_set("height", h);
    cx.format_set("color_mode", mode);
    cx.format_set("frame_count", frames);
    if depth == 8 {
        cx.format_set("transparent_index", transparent);
    }
    if depth == 8 {
        // Zero means 256 in old files.
        cx.format_set("palette_colors", if colors == 0 { 256 } else { colors });
    }
    if pw > 0 && ph > 0 && pw != ph {
        cx.format_set("pixel_ratio", format!("{pw}:{ph}"));
    }
    if gw > 0 && gh > 0 {
        cx.format_set("grid", vec![i64::from(gx), i64::from(gy), i64::from(gw), i64::from(gh)]);
    }
    {
        let mut img = cx.physical().image(u32::from(w), u32::from(h));
        img.frames(u32::try_from(frames).unwrap_or(u32::MAX));
        img.color_space(mode);
        if depth == 32 {
            img.channels(4).bit_depth(8);
        }
    }
    r.seek(128)?;
    let mut duration = 0u64;
    let mut layers = Vec::new();
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let mut tags = Vec::new();
    let mut slices = Vec::new();
    let mut tilesets = Vec::new();
    let mut externals = Vec::new();
    let mut user_text = Vec::new();
    let (mut cels, mut chunks_seen) = (0u64, 0usize);
    let mut profile = None;
    for _ in 0..frames.min(MAX_FRAMES) {
        let start = r.position();
        let Ok(size) = r.le_u32() else { break };
        if r.le_u16()? != 0xF1FA {
            cx.warn("a frame without its magic number");
            break;
        }
        let old = usize::from(r.le_u16()?);
        duration += u64::from(r.le_u16()?);
        r.advance(2)?;
        let new = r.le_u32()? as usize;
        let count = if new == 0 { old } else { new };
        for _ in 0..count {
            chunks_seen += 1;
            if chunks_seen > MAX_CHUNKS {
                break;
            }
            let cstart = r.position();
            let csize = r.le_u32()? as usize;
            let ty = r.le_u16()?;
            if csize < 6 {
                break;
            }
            let body = r.bytes(csize - 6)?;
            let mut c = ByteReader::new(body);
            let parsed = (|| -> Result<(), ExtractError> {
                match ty {
                    0x2004 => {
                        let flags = c.le_u16()?;
                        let kind = match c.le_u16()? {
                            0 => "image",
                            1 => "group",
                            2 => "tilemap",
                            _ => "other",
                        };
                        let child = c.le_u16()?;
                        c.advance(2 + 2 + 2 + 1 + 3)?;
                        let name = string(&mut c)?;
                        bump(&mut kinds, kind, 10);
                        if layers.len() < MAX_LIST {
                            let mut l = Map::new();
                            l.insert("name".into(), name.into());
                            l.insert("kind".into(), kind.into());
                            if child > 0 {
                                l.insert("level".into(), child.into());
                            }
                            if flags & 1 == 0 {
                                l.insert("hidden".into(), true.into());
                            }
                            if flags & 64 != 0 {
                                l.insert("reference".into(), true.into());
                            }
                            layers.push(Value::Object(l));
                        }
                    }
                    0x2005 => cels += 1,
                    0x2007 => {
                        profile = Some(match c.le_u16()? {
                            0 => "none",
                            1 => "sRGB",
                            2 => "embedded ICC",
                            _ => "unknown",
                        });
                    }
                    0x2008 => {
                        let n = c.le_u32()?;
                        c.advance(8)?;
                        for _ in 0..n.min(1000) {
                            c.advance(4)?;
                            let kind = c.u8()?;
                            c.advance(7)?;
                            let name = string(&mut c)?;
                            if externals.len() < MAX_LIST {
                                let k = match kind {
                                    0 => "palette",
                                    1 => "tileset",
                                    2 => "properties",
                                    3 => "tile management",
                                    _ => "other",
                                };
                                externals.push(format!("{k}: {name}"));
                            }
                        }
                    }
                    0x2018 => {
                        let n = c.le_u16()?;
                        c.advance(8)?;
                        for _ in 0..n {
                            let (from, to) = (c.le_u16()?, c.le_u16()?);
                            let dir = match c.u8()? {
                                0 => "forward",
                                1 => "reverse",
                                2 => "ping-pong",
                                3 => "ping-pong reverse",
                                _ => "unknown",
                            };
                            let repeat = c.le_u16()?;
                            c.advance(6 + 3 + 1)?;
                            let name = string(&mut c)?;
                            if tags.len() < MAX_LIST {
                                let mut t = Map::new();
                                t.insert("name".into(), name.into());
                                t.insert("frames".into(), vec![from, to].into());
                                t.insert("direction".into(), dir.into());
                                if repeat > 0 {
                                    t.insert("repeat".into(), repeat.into());
                                }
                                tags.push(Value::Object(t));
                            }
                        }
                    }
                    0x2020 => {
                        let flags = c.le_u32()?;
                        if flags & 1 != 0 {
                            let t = string(&mut c)?;
                            if !t.is_empty() && user_text.len() < MAX_LIST {
                                user_text.push(t);
                            }
                        }
                    }
                    0x2022 => {
                        c.advance(12)?;
                        let name = string(&mut c)?;
                        if slices.len() < MAX_LIST {
                            slices.push(name);
                        }
                    }
                    0x2023 => {
                        c.advance(4)?;
                        let flags = c.le_u32()?;
                        let n = c.le_u32()?;
                        let (tw, th) = (c.le_u16()?, c.le_u16()?);
                        c.advance(2 + 14)?;
                        let name = string(&mut c)?;
                        if tilesets.len() < MAX_LIST {
                            let mut t = Map::new();
                            t.insert("name".into(), name.into());
                            t.insert("tiles".into(), n.into());
                            t.insert("tile_size".into(), vec![tw, th].into());
                            if flags & 1 != 0 {
                                t.insert("external".into(), true.into());
                            }
                            tilesets.push(Value::Object(t));
                        }
                    }
                    _ => {}
                }
                Ok(())
            })();
            if parsed.is_err() {
                cx.warn(format!("a malformed chunk 0x{ty:04x}"));
            }
            r.seek(cstart + csize)?;
        }
        r.seek(start + size as usize)?;
    }
    #[allow(clippy::cast_precision_loss)]
    let secs = duration as f64 / 1000.0;
    cx.format_set("duration_ms", duration);
    cx.physical().duration_s(secs);
    if !layers.is_empty() {
        cx.format_set("layer_count", kinds.values().sum::<u64>());
        cx.format_set("layer_kinds", hist(kinds));
        cx.format_set("layers", layers);
    }
    if !tags.is_empty() {
        cx.format_set("tags", tags);
    }
    if !slices.is_empty() {
        cx.format_set("slices", slices);
    }
    if !tilesets.is_empty() {
        cx.format_set("tilesets", tilesets);
    }
    if !externals.is_empty() {
        cx.format_set("external_files", externals);
    }
    cx.format_set("cel_count", cels);
    if let Some(p) = profile {
        cx.format_set("color_profile", p);
    }
    for t in &user_text {
        cx.emit_text(TextRole::Body, t);
    }
    if !user_text.is_empty() {
        cx.format_set("user_data", user_text);
    }
    Ok(())
}

impl Extractor for Sprite {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    // The header magic is two bytes at offset 4; the first frame's magic and
    // the declared file size make it certain.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let frame = h.get(132..134) == Some(&[0xFA, 0xF1]) || h.get(6..8) == Some(&[0, 0]);
        let size = h.get(..4).map(|s| u64::from(u32::from_le_bytes([s[0], s[1], s[2], s[3]])));
        (h.get(4..6) == Some(&[0xE0, 0xA5])
            && frame
            && (size == Some(probe.len) || matches!(probe.extension, Some("aseprite" | "ase"))))
        .then_some(Sniff { format: "aseprite", confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, _) = cx.read_bytes(src)?;
        aseprite(cx, &b)
    }
}

crate::register_extractor!(Sprite);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("aseprite");
}
