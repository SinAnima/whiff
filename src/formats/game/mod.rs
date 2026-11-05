//! `games` extractors (feature `games`): cartridge ROMs and console
//! packages, chiptunes, game archives (WAD, PAK, BSP, VPK, BSA / BA2,
//! RGSS, RPA), engine files (Unity, Unreal, Godot, `GameMaker`), Minecraft
//! worlds and schematics, Tiled maps, Aseprite sprites, Steam manifests,
//! interactive fiction and emulator save states.
//!
//! Shared here: fixed-width text fields, histograms and hex.

#![allow(clippy::many_single_char_names, clippy::similar_names)] // header fields and their offsets

pub(crate) mod archive;
pub(crate) mod chiptune;
pub(crate) mod console;
pub(crate) mod engine;
pub(crate) mod fiction;
pub(crate) mod minecraft;
pub(crate) mod rom;
pub(crate) mod save;
pub(crate) mod sprite;
pub(crate) mod steam;
pub(crate) mod tiled;

use std::collections::BTreeMap;

use serde_json::Value;

pub(crate) use super::archive::unix_time;
use crate::plugin::{latin1_or_utf8, truncate_chars};

/// A fixed-width text field: cut at the first NUL, trailing blanks and
/// padding (0xFF) removed; `None` when nothing printable is left.
pub(crate) fn fixed(b: &[u8]) -> Option<String> {
    let b = &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())];
    let end = b.iter().rposition(|&c| c != b' ' && c != 0xFF).map_or(0, |i| i + 1);
    let s = latin1_or_utf8(&b[..end]);
    let s = s.trim();
    (!s.is_empty() && s.chars().all(|c| !c.is_control())).then(|| truncate_chars(s, 200))
}

/// A histogram as a JSON object.
pub(crate) fn hist(m: BTreeMap<String, u64>) -> Value {
    Value::Object(m.into_iter().map(|(k, v)| (k, v.into())).collect())
}

/// Add one to `key` of a histogram that keeps at most `max` keys.
pub(crate) fn bump(m: &mut BTreeMap<String, u64>, key: &str, max: usize) {
    if let Some(n) = m.get_mut(key) {
        *n += 1;
    } else if m.len() < max {
        m.insert(key.to_string(), 1);
    }
}

/// Lowercase hex.
pub(crate) fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::with_capacity(b.len() * 2), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// The extension of an archive member name, lowercased (histogram key).
pub(crate) fn member_ext(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    match base.rsplit_once('.') {
        Some((stem, e)) if !stem.is_empty() && !e.is_empty() && e.len() <= 12 => e.to_ascii_lowercase(),
        _ => "(none)".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(fixed(b"ZELDA  \0junk").as_deref(), Some("ZELDA"));
        assert_eq!(fixed(b"\xff\xff\xff"), None);
        assert_eq!(member_ext("maps/E1M1.WAD"), "wad");
        assert_eq!(member_ext("README"), "(none)");
        assert_eq!(hex(&[0, 0xab]), "00ab");
    }
}
