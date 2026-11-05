//! Emulator save files:
//! * `RetroArch` save states (`RASTATE`, plain or in `RetroArch`'s RZIP
//!   container): version, compression, blocks (core memory,
//!   achievements, replay) and their sizes;
//! * Mednafen save states (`MDFNSVST`, plain or gzip): when it was saved,
//!   the Mednafen version, the preview size, sections;
//! * battery saves (`.srm`, `.sav` next to ROMs is left to SPSS): size,
//!   the likely kind by size, whether it is blank.
//!
//! Specifications: `RetroArch` `tasks/task_save.c` and
//! `libretro-common/streams/rzip_stream.c` (1.20); Mednafen `src/state.cpp`
//! (1.32).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::plugin::{
    Codec, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    truncate_chars,
};

/// Extractor for emulator save files.
pub struct Save;

static META: ExtractorMeta = ExtractorMeta {
    id: "game.save",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "retroarch_state",
            name: "RetroArch save state",
            family: "game",
            mimes: &[],
            extensions: &["state"],
            magic: &[Magic::prefix(b"RASTATE"), Magic::prefix(b"#RZIPv\x01#")],
            parent: None,
        },
        FormatSpec {
            id: "mednafen_state",
            name: "Mednafen save state",
            family: "game",
            mimes: &[],
            extensions: &["mc0", "mc1", "mc2", "mc3", "mc4", "mc5", "mc6", "mc7", "mc8", "mc9"],
            // Often gzip-compressed: sniffed.
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "battery_save",
            name: "Battery save (SRAM)",
            family: "game",
            mimes: &[],
            extensions: &["srm"],
            magic: &[],
            parent: None,
        },
    ],
};

/// Decompress a `RetroArch` RZIP stream: 20-byte header, then chunks of a
/// 32-bit size and zlib data.
fn rzip(cx: &mut Context<'_>, b: &[u8]) -> Result<Vec<u8>, ExtractError> {
    let chunk = u32::from_le_bytes(b.get(8..12).unwrap_or(&[0; 4]).try_into().unwrap_or_default());
    let total = u64::from_le_bytes(b.get(12..20).unwrap_or(&[0; 8]).try_into().unwrap_or_default());
    cx.format_set("compression", "RZIP");
    cx.format_set("chunk_size", chunk);
    cx.format_set("uncompressed_size", total);
    let max = usize::try_from(total).unwrap_or(usize::MAX).min(cx.parse_limit());
    let mut out = Vec::new();
    let mut at = 20usize;
    while out.len() < max {
        let Some(n) = b.get(at..at + 4) else { break };
        let n = u32::from_le_bytes([n[0], n[1], n[2], n[3]]) as usize;
        at += 4;
        let Some(d) = b.get(at..at.saturating_add(n)) else { break };
        at += n;
        let room = (chunk as usize).max(1).min(max - out.len());
        let part = cx.decompress(d, Codec::Zlib, room)?;
        out.extend_from_slice(&part.data);
        if n == 0 {
            break;
        }
    }
    Ok(out)
}

fn rastate(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let data = if b.starts_with(b"#RZIPv") { rzip(cx, b)? } else { b.to_vec() };
    if !data.starts_with(b"RASTATE") {
        // RZIP around a core's raw state (states before RetroArch 1.17).
        cx.format_set("raw_core_state", true);
        return Ok(());
    }
    if let Some(&v) = data.get(7) {
        cx.format_set("version", v);
    }
    let mut blocks = Vec::new();
    let mut at = 8usize;
    while let Some(h) = data.get(at..at + 8) {
        let tag = String::from_utf8_lossy(&h[..4]).trim_end().to_string();
        let size = u64::from(u32::from_le_bytes([h[4], h[5], h[6], h[7]]));
        let name = match tag.as_str() {
            "MEM" => "core memory",
            "ACHV" => "achievements",
            "RPLY" => "replay",
            "END" => "end",
            _ => "other",
        };
        if tag == "END" {
            break;
        }
        let mut m = Map::new();
        m.insert("block".into(), truncate_chars(&tag, 8).into());
        m.insert("kind".into(), name.into());
        m.insert("size".into(), size.into());
        blocks.push(Value::Object(m));
        // Blocks are padded to 8 bytes.
        at = at.saturating_add(8).saturating_add(usize::try_from(size.div_ceil(8) * 8).unwrap_or(usize::MAX));
        if blocks.len() >= 100 {
            break;
        }
    }
    cx.format_set("blocks", blocks);
    Ok(())
}

fn mednafen(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let data = if b.starts_with(&[0x1F, 0x8B]) {
        let max = cx.parse_limit();
        cx.format_set("compression", "gzip");
        cx.decompress(b, Codec::Gzip, max)?.data
    } else {
        b.to_vec()
    };
    let h = data.get(..32).ok_or(ExtractError::Malformed("short Mednafen state".into()))?;
    let le32 = |i: usize| u32::from_le_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]);
    let saved = i64::from_le_bytes(h[8..16].try_into().unwrap_or_default());
    if let Some(d) = super::unix_time(saved) {
        cx.temporal().content_date(DateField::Created, d.clone(), true);
        cx.format_set("saved", d);
    }
    // 0x00103201 is Mednafen 1.32.1: the major version from bit 20, the
    // minor and patch numbers as decimal digits in hex.
    let v = le32(16);
    cx.format_set("mednafen_version", format!("{:x}.{:x}.{:x}", v >> 20, (v >> 8) & 0xFFF, v & 0xFF));
    let len = le32(20);
    if len & 0x8000_0000 != 0 {
        cx.format_set("big_endian_host", true);
    }
    let (w, ht) = (le32(24), le32(28));
    let mut at = 32usize;
    if w > 0 && ht > 0 {
        cx.format_set("preview", vec![w, ht]);
        at = at.saturating_add(3usize.saturating_mul(w as usize).saturating_mul(ht as usize));
    }
    // Sections: a 32-byte name and a 32-bit size.
    let mut sections: BTreeMap<String, u64> = BTreeMap::new();
    let end = (len & 0x7FFF_FFFF) as usize;
    while let Some(s) = data.get(at..at + 36) {
        if at >= end.min(data.len()) || sections.len() >= 200 {
            break;
        }
        let name = super::fixed(&s[..32]).unwrap_or_default();
        let size = u32::from_le_bytes([s[32], s[33], s[34], s[35]]);
        if name.is_empty() {
            break;
        }
        sections.insert(name, u64::from(size));
        at = at.saturating_add(36).saturating_add(size as usize);
    }
    if !sections.is_empty() {
        cx.format_set("sections", super::hist(sections));
    }
    Ok(())
}

fn battery(cx: &mut Context<'_>, b: &[u8], len: u64) {
    let kind = match len {
        512 => Some("EEPROM (4 Kbit) or NES / Game Boy MBC2"),
        2048 => Some("2 KiB SRAM"),
        8192 => Some("8 KiB SRAM (most NES and Game Boy cartridges)"),
        32768 => Some("32 KiB SRAM (Game Boy MBC3 / MBC5, GBA SRAM)"),
        65536 => Some("64 KiB flash (GBA)"),
        131_072 => Some("128 KiB SRAM or flash"),
        _ => None,
    };
    if let Some(k) = kind {
        cx.format_set("likely_kind", k);
    }
    let blank = b.iter().all(|&c| c == 0) || b.iter().all(|&c| c == 0xFF);
    cx.format_set("blank", blank);
    #[allow(clippy::cast_precision_loss)]
    let used = b.iter().filter(|&&c| c != 0 && c != 0xFF).count() as f64 / b.len().max(1) as f64;
    cx.format_set("used_ratio", (used * 1000.0).round() / 1000.0);
}

impl Extractor for Save {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let ext = probe.extension.unwrap_or("");
        // Battery saves are raw memory: blank ones look like anything.
        if ext == "srm" {
            return Some(Sniff { format: "battery_save", confidence: 0.97 });
        }
        // Mednafen states, plain or gzip-compressed (`.mc0` … `.mc9`).
        let h = probe.head;
        let numbered = ext.len() == 3 && ext.starts_with("mc") && ext.as_bytes()[2].is_ascii_digit();
        (h.starts_with(b"MDFNSVST") || h.starts_with(b"MEDNAFENSVESTATE") || numbered && h.starts_with(&[0x1F, 0x8B]))
            .then_some(Sniff { format: "mednafen_state", confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let (b, _) = cx.read_bytes(src)?;
        match cx.format_id() {
            "retroarch_state" => rastate(cx, &b),
            "mednafen_state" => mednafen(cx, &b),
            _ => {
                battery(cx, &b, len);
                Ok(())
            }
        }
    }
}

crate::register_extractor!(Save);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("retroarch_state", "mednafen_state", "battery_save");
}
