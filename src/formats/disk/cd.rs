//! CD images: raw sector dumps (`.bin` / `.img` with 2352-byte sectors, as
//! cdrdao, CloneCD and most rippers write them) and CloneCD control files
//! (`.ccd`). A raw image reports its sector mode and count and is read
//! through its user data (2048 bytes per sector), so the ISO 9660 / UDF
//! volume on it is described and listed as for an `.iso`. A CloneCD
//! control file reports its sessions and tracks (mode, start), the TOC
//! entry count and whether data tracks are scrambled. CUE sheets are read
//! by the playlist extractor.
//!
//! Specifications: ECMA-130 (CD-ROM sectors: sync, header, modes 1 and 2);
//! the CloneCD control-file layout as documented by the `ccd2cue` and
//! libmirage projects.

use serde_json::{Map, Value, json};

use super::{Block, BlockMap, Virtual, iso};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, SourceError,
};

/// Extractor for CD images.
pub struct CdImage;

static META: ExtractorMeta = ExtractorMeta {
    id: "disk.cd",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "cd_bin",
            name: "Raw CD image (2352-byte sectors)",
            family: "disk",
            mimes: &["application/x-cd-image"],
            // `.bin` is detected by its sector sync, not the extension
            // (most `.bin` files are something else).
            extensions: &[],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "ccd",
            name: "CloneCD control file",
            family: "disk",
            mimes: &["text/x-clonecd"],
            extensions: &["ccd"],
            magic: &[],
            parent: None,
        },
    ],
};

const RAW: u64 = 2352;
/// [`RAW`] as a slice length.
const RAW_LEN: usize = 2352;
const SYNC: &[u8] = b"\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00";

/// Where the 2048 user-data bytes start in a raw sector of this mode.
fn data_offset(mode: u8) -> Option<u64> {
    match mode {
        1 => Some(16),
        // Mode 2 form 1 (CD-ROM XA): an 8-byte subheader first.
        2 => Some(24),
        _ => None,
    }
}

/// The mode of the sector holding the volume descriptor, if it is one.
fn volume_mode(head: &[u8]) -> Option<u8> {
    let at = 16 * RAW_LEN;
    let s = head.get(at..at + RAW_LEN)?;
    let mode = *s.get(15).filter(|_| s.starts_with(SYNC))?;
    let d = usize::try_from(data_offset(mode)?).ok()?;
    s.get(d + 1..d + 6).is_some_and(|m| m == b"CD001" || m == b"BEA01").then_some(mode)
}

struct Sectors {
    offset: u64,
}

impl BlockMap for Sectors {
    fn block_size(&self) -> u64 {
        2048
    }

    fn locate(&mut self, _: &mut dyn Source, n: u64) -> Result<Block, SourceError> {
        Ok(Block::At(super::offset(super::scaled(n, RAW)?, self.offset)?))
    }
}

impl Extractor for CdImage {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if probe.head.starts_with(b"[CloneCD]") {
            return Some(Sniff { format: "ccd", confidence: 0.97 });
        }
        (probe.head.starts_with(SYNC) && volume_mode(probe.head).is_some())
            .then_some(Sniff { format: "cd_bin", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "ccd" {
            return ccd(src, cx);
        }
        let mode = volume_mode(src.head()).ok_or_else(|| ExtractError::malformed("no data track volume descriptor"))?;
        let sectors = src.len() / RAW;
        cx.format_set("sector_mode", if mode == 1 { "mode1" } else { "mode2_form1" });
        cx.format_set("sectors", sectors);
        if !src.len().is_multiple_of(RAW) {
            cx.warn("the image is not a whole number of 2352-byte sectors");
        }
        let offset = data_offset(mode).unwrap_or(16);
        let mut v = Virtual::new(src, Sectors { offset }, sectors * 2048)?;
        iso::read(&mut v, cx)
    }
}

crate::register_extractor!(CdImage);

fn ccd(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let text = cx.read_text(src)?.text;
    let mut section = String::new();
    let mut tracks: Vec<Map<String, Value>> = Vec::new();
    let mut entries = 0u64;
    for line in text.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.to_string();
            if let Some(n) = name.strip_prefix("TRACK ").and_then(|n| n.trim().parse::<u32>().ok())
                && tracks.len() < 99
            {
                let mut m = Map::new();
                m.insert("number".into(), json!(n));
                tracks.push(m);
            }
            if name.starts_with("Entry ") {
                entries += 1;
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match (section.as_str(), k) {
            ("CloneCD", "Version") => cx.format_set("version", v.to_string()),
            ("Disc", "Sessions") => cx.format_set("sessions", v.parse::<u64>().unwrap_or(0)),
            ("Disc", "DataTracksScrambled") => cx.format_set("data_tracks_scrambled", v == "1"),
            ("Disc", "CDTextLength") if v != "0" => cx.format_set("cd_text", true),
            ("Disc", "CATALOG") => cx.format_set("catalog", v.to_string()),
            (s, "MODE") if s.starts_with("TRACK ") => {
                if let Some(t) = tracks.last_mut() {
                    let mode = match v {
                        "0" => "audio",
                        "1" => "mode1",
                        "2" => "mode2",
                        _ => "other",
                    };
                    t.insert("mode".into(), json!(mode));
                }
            }
            (s, "INDEX 1") if s.starts_with("TRACK ") => {
                if let (Some(t), Ok(lba)) = (tracks.last_mut(), v.parse::<u64>()) {
                    t.insert("start_sector".into(), json!(lba));
                }
            }
            (s, "ISRC") if s.starts_with("TRACK ") => {
                if let Some(t) = tracks.last_mut() {
                    t.insert("isrc".into(), json!(v));
                }
            }
            _ => {}
        }
    }
    cx.format_set("toc_entries", entries);
    let audio = tracks.iter().filter(|t| t.get("mode") == Some(&json!("audio"))).count();
    cx.format_set("audio_tracks", audio);
    cx.format_set("data_tracks", tracks.len() - audio);
    cx.format_set("tracks", tracks.into_iter().map(Value::Object).collect::<Vec<_>>());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes() {
        assert_eq!(data_offset(1), Some(16));
        assert_eq!(data_offset(2), Some(24));
        assert_eq!(data_offset(0), None);
        let mut head = vec![0u8; 17 * RAW_LEN];
        let at = 16 * RAW_LEN;
        head[at..at + 12].copy_from_slice(SYNC);
        head[at + 15] = 1;
        head[at + 17..at + 22].copy_from_slice(b"CD001");
        assert_eq!(volume_mode(&head), Some(1));
    }

    crate::fixture_tests!("cd_bin", "ccd");
}
