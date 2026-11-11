//! Audio workstation sessions in binary, application-private layouts:
//!
//! * Pro Tools sessions (`.ptx` for Pro Tools 10 and later, `.ptf` / `.pts`
//!   for 5 – 9): the XOR obfuscation is undone, then the block tree gives
//!   the Pro Tools version, byte order, sample rate, audio files, tracks
//!   (audio and MIDI), regions and plug-in entries;
//! * GarageBand and Logic Pro project data (`ProjectData` inside a `.band`
//!   or `.logicx` bundle): the format version and the chunks by kind (song,
//!   tracks, sequences, environment objects, audio units, styles). The
//!   bundle's `MetaData.plist` and `ProjectInformation.plist` are read by
//!   the property-list extractor (tempo, key, time signature, tracks, the
//!   GarageBand version that saved it).
//!
//! Audio file names are listed as names; Pro Tools stores no paths in this
//! list.
//!
//! Specifications: none published. Pro Tools' obfuscation and blocks as
//! read by ptformat (Damien Zammit, the Ardour importer); GarageBand's
//! chunk framing as GarageBand writes it.

use std::collections::BTreeMap;

use serde_json::json;

use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for the sessions above.
pub struct Sessions;

/// `\x03` and the bit string Pro Tools writes at the start of every session.
const PT_MAGIC: &[u8] = b"\x030010111100101011";
/// GarageBand / Logic project data.
const GB_MAGIC: &[u8] = b"\x23\x47\xc0\xab";

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.session",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "protools_session",
            name: "Pro Tools session",
            family: "audio",
            mimes: &["application/x-protools-session"],
            extensions: &["ptx", "ptf", "pts"],
            magic: &[Magic::prefix(PT_MAGIC)],
            parent: None,
        },
        FormatSpec {
            id: "garageband_project",
            name: "GarageBand / Logic Pro project data",
            family: "audio",
            mimes: &["application/x-garageband-project"],
            extensions: &[],
            magic: &[Magic::prefix(GB_MAGIC)],
            parent: None,
        },
    ],
};

/// Names listed.
const MAX_LISTED: usize = 200;
/// Blocks parsed at most.
const MAX_BLOCKS: usize = 200_000;
/// Block nesting followed.
const MAX_DEPTH: usize = 12;

impl Extractor for Sessions {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, cut) = cx.read_bytes(src)?;
        if cut {
            cx.format_set("truncated", true);
        }
        if cx.format_id() == "garageband_project" {
            garageband(cx, &b);
            return Ok(());
        }
        let plain = unxor(&b).ok_or_else(|| ExtractError::malformed("unknown Pro Tools obfuscation"))?;
        protools(cx, &plain)
    }
}

crate::register_extractor!(Sessions);

// --- Pro Tools --------------------------------------------------------------------------------

/// The session with its XOR key removed (bytes 0x14 on). Byte 0x12 picks
/// the scheme (1: Pro Tools 5 – 9, 5: 10 and later), byte 0x13 the key.
fn unxor(b: &[u8]) -> Option<Vec<u8>> {
    if b.len() < 0x14 {
        return None;
    }
    let (kind, value) = (b[0x12], b[0x13]);
    let (mul, negative) = match kind {
        1 => (53u16, false),
        5 => (11u16, true),
        _ => return None,
    };
    let delta = (0u16..256).find(|i| (i * mul) & 0xff == u16::from(value))?;
    #[allow(clippy::cast_possible_truncation)] // `delta` < 256
    let delta = if negative { (delta as u8).wrapping_neg() } else { delta as u8 };
    let key: Vec<u8> = (0u8..=255).map(|i| i.wrapping_mul(delta)).collect();
    let mut out = b.to_vec();
    for (i, c) in out.iter_mut().enumerate().skip(0x14) {
        let index = if kind == 1 { i & 0xff } else { (i >> 12) & 0xff };
        *c ^= key[index];
    }
    Some(out)
}

#[derive(Debug, Clone)]
struct Block {
    content: u16,
    /// Offset of the content type (block start + 7).
    offset: usize,
    size: usize,
    children: Vec<Block>,
}

struct Pt<'a> {
    b: &'a [u8],
    big: bool,
    blocks: usize,
}

impl Pt<'_> {
    fn u16(&self, at: usize) -> u16 {
        self.b
            .get(at..at + 2)
            .map_or(0, |s| if self.big { u16::from_be_bytes([s[0], s[1]]) } else { u16::from_le_bytes([s[0], s[1]]) })
    }

    fn u32(&self, at: usize) -> u32 {
        self.b.get(at..at + 4).map_or(0, |s| {
            let a = [s[0], s[1], s[2], s[3]];
            if self.big { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
        })
    }

    /// A string with a 32-bit length at `at`.
    fn string(&self, at: usize) -> Option<String> {
        let n = self.u32(at) as usize;
        let s = self.b.get(at + 4..(at + 4).checked_add(n)?)?;
        Some(String::from_utf8_lossy(s).into_owned())
    }

    /// The block at `pos` (marker `Z`, type, size, content type), with its
    /// children, when it fits inside `max`.
    fn block_at(&mut self, pos: usize, max: usize, depth: usize) -> Option<Block> {
        if self.b.get(pos) != Some(&0x5a) || self.blocks >= MAX_BLOCKS {
            return None;
        }
        let kind = self.u16(pos + 1);
        let size = self.u32(pos + 3) as usize;
        let offset = pos + 7;
        if kind & 0xff00 != 0 || offset.checked_add(size)? > max || offset + 2 > self.b.len() {
            return None;
        }
        self.blocks += 1;
        let mut block = Block { content: self.u16(pos + 7), offset, size, children: Vec::new() };
        if depth < MAX_DEPTH {
            let mut i = 1;
            while i < size && pos + i < offset + size {
                match self.block_at(pos + i, offset + size, depth + 1) {
                    Some(c) => {
                        i += c.size + 7;
                        block.children.push(c);
                    }
                    None => i += 1,
                }
            }
        }
        Some(block)
    }

    fn top_blocks(&mut self) -> Vec<Block> {
        let mut out = Vec::new();
        let mut i = 20;
        while i < self.b.len() && self.blocks < MAX_BLOCKS {
            match self.block_at(i, self.b.len(), 0) {
                Some(blk) => {
                    i += blk.size + 7;
                    out.push(blk);
                }
                None => i += 1,
            }
        }
        out
    }

    /// The Pro Tools version, as ptformat finds it.
    fn version(&mut self) -> Option<u32> {
        match self.block_at(0x1f, self.b.len(), MAX_DEPTH) {
            None => {
                let v = [0x40, 0x3d].iter().map(|&at| u32::from(*self.b.get(at).unwrap_or(&0))).find(|&v| v != 0);
                v.or_else(|| self.b.get(0x3a).map(|&v| u32::from(v) + 2)).filter(|&v| v != 0)
            }
            Some(blk) if blk.content == 0x0003 => {
                let skip = self.string(blk.offset + 3)?.len() + 8;
                Some(self.u32(blk.offset + 3 + skip))
            }
            Some(blk) if blk.content == 0x2067 => Some(2 + self.u32(blk.offset + 20)),
            Some(_) => None,
        }
    }
}

fn walk<'b>(blocks: &'b [Block], out: &mut Vec<&'b Block>) {
    for blk in blocks {
        out.push(blk);
        walk(&blk.children, out);
    }
}

fn protools(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let mut pt = Pt { b, big: b.get(0x11).is_some_and(|&v| v != 0), blocks: 0 };
    cx.format_set("byte_order", if pt.big { "big" } else { "little" });
    cx.format_set("obfuscation", if b[0x12] == 1 { "pro_tools_5_9" } else { "pro_tools_10_plus" });
    if let Some(v) = pt.version() {
        cx.format_set("pro_tools_version", v);
    }
    pt.blocks = 0;
    let top = pt.top_blocks();
    cx.checkpoint()?;
    let mut all = Vec::new();
    walk(&top, &mut all);
    cx.format_set("blocks", all.len());
    let version = pt.version().unwrap_or(0);
    let mut rate = None;
    let (mut files, mut tracks, mut midi_tracks, mut regions, mut plugins) =
        (Vec::<String>::new(), Vec::<String>::new(), Vec::<String>::new(), 0u64, 0u64);
    for blk in &top {
        match blk.content {
            0x1028 => rate = Some(pt.u32(blk.offset + 4)),
            0x1004 => {
                for c in blk.children.iter().filter(|c| c.content == 0x103a) {
                    files.extend(wav_names(&pt, c, version));
                }
            }
            0x1015 => {
                for c in blk.children.iter().filter(|c| c.content == 0x1014) {
                    if let Some(n) = pt.string(c.offset + 2)
                        && tracks.last() != Some(&n)
                    {
                        tracks.push(n);
                    }
                }
            }
            0x2519 => {
                for c in blk.children.iter().filter(|c| c.content == 0x251a) {
                    if let Some(n) = pt.string(c.offset + 4)
                        && !midi_tracks.contains(&n)
                    {
                        midi_tracks.push(n);
                    }
                }
            }
            0x100b | 0x262a => {
                regions += blk.children.iter().filter(|c| matches!(c.content, 0x1008 | 0x2629)).count() as u64;
            }
            _ => {}
        }
    }
    plugins += all.iter().filter(|blk| blk.content == 0x1017).count() as u64;
    if let Some(r) = rate.filter(|&r| r > 0) {
        cx.format_set("sample_rate", r);
    }
    // MIDI tracks are listed with the audio ones in the full track list.
    midi_tracks.retain(|n| !tracks.contains(n));
    cx.format_set("audio_files", files.len());
    cx.format_set("audio_tracks", tracks.len());
    cx.format_set("midi_tracks", midi_tracks.len());
    cx.format_set("regions", regions);
    if plugins > 0 {
        cx.format_set("plugin_entries", plugins);
    }
    let list = |v: &[String]| json!(v.iter().take(MAX_LISTED).collect::<Vec<_>>());
    if !files.is_empty() {
        cx.format_set("audio_file_names", list(&files));
    }
    if !tracks.is_empty() {
        cx.format_set("audio_track_names", list(&tracks));
    }
    if !midi_tracks.is_empty() {
        cx.format_set("midi_track_names", list(&midi_tracks));
    }
    Ok(())
}

/// Audio file names in a WAV-names block (folders, groups and fades skipped).
fn wav_names(pt: &Pt<'_>, c: &Block, version: u32) -> Vec<String> {
    const TYPES: [&[u8]; 6] = [b"WAVE", b"EVAW", b"AIFF", b"FFIA", b"fFXM", b"MXFf"];
    let mut out = Vec::new();
    let mut pos = c.offset + 11;
    let end = c.offset + c.size;
    while pos < end && out.len() < 100_000 {
        let Some(name) = pt.string(pos) else { break };
        pos += name.len() + 4;
        let kind = pt.b.get(pos..pos + 4).unwrap_or_default();
        pos += 9;
        if name.contains(".grp") || name.contains("Audio Files") || name.contains("Fade Files") {
            continue;
        }
        let typed = TYPES.iter().any(|t| kind.windows(4).any(|w| w == *t));
        let ok = if version < 10 || kind.first().is_some_and(|&k| k != 0) {
            typed
        } else {
            [".wav", ".aif", ".mxf"].iter().any(|e| name.contains(e))
        };
        if ok {
            out.push(name);
        }
    }
    out
}

// --- GarageBand / Logic --------------------------------------------------------------------

/// A chunk tag (stored reversed: `gnoS` is `Song`) as text.
fn tag_name(t: &[u8]) -> Option<String> {
    t.iter().all(u8::is_ascii_alphanumeric).then(|| t.iter().rev().map(|&c| char::from(c)).collect())
}

fn garageband(cx: &mut Context<'_>, b: &[u8]) {
    let le16 = |at: usize| b.get(at..at + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]));
    cx.format_set("format_version", le16(4));
    // Chunks: a 4-byte tag, 24 bytes, the data length (u64) at +28, data at +36.
    let Some(mut at) = (0x10..0x40).find(|&i| b.get(i..i + 4).and_then(tag_name).is_some()) else {
        return;
    };
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let mut chunks = 0u64;
    while let Some(tag) = b.get(at..at + 4).and_then(tag_name) {
        let Some(len) = b.get(at + 28..at + 36).map(|s| u64::from_le_bytes(s.try_into().unwrap_or([0; 8]))) else {
            break;
        };
        chunks += 1;
        if kinds.len() < 100 || kinds.contains_key(&tag) {
            *kinds.entry(tag).or_insert(0) += 1;
        }
        let Some(next) = usize::try_from(len).ok().and_then(|l| (at + 36).checked_add(l)) else { break };
        if next > b.len() || chunks >= 1_000_000 {
            break;
        }
        at = next;
    }
    cx.format_set("chunks", chunks);
    cx.format_set("chunks_by_kind", json!(kinds));
    if at < b.len() && chunks > 0 {
        cx.format_set("unread_bytes", b.len() - at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("protools_session", "garageband_project");

    #[test]
    fn unxor_round_trip() {
        // Scheme 1 with key value 53 (delta 1): byte i is XORed with i & 0xff.
        let mut b = PT_MAGIC.to_vec();
        b.extend_from_slice(&[0, 1, 53]);
        b.extend((0x14..0x40u8).map(|i| i ^ 0x5a));
        let plain = unxor(&b).unwrap();
        assert!(plain[0x14..].iter().all(|&c| c == 0x5a));
        assert_eq!(tag_name(b"gnoS").as_deref(), Some("Song"));
    }
}
