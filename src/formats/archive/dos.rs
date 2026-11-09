//! Older DOS-era archivers, listed from their headers; entries stored
//! without compression are handed on:
//!
//! * ARC (SEA ARC 5–7) and PAK (NoGate): a chain of 29-byte headers, each
//!   followed by its data;
//! * Zoo (Rahul Dhesi): an archive header and a chain of directory entries,
//!   with the long names and folders of Zoo 2;
//! * ACE (Marcel Lemke): CRC-checked main and file headers;
//! * ZPAQ (Matt Mahoney) journaling archives: the transactions, read from
//!   each one's uncompressed `c` block (the file list itself is compressed);
//! * KGB Archiver (PAQ6): the plain-text file list ahead of the data.
//!
//! Specifications: the ARC 5.21 and `nomarch` sources; `zoo.h` of Zoo 2.10;
//! the `acefile` module and the unace sources; the ZPAQ 1.0 specification
//! (level 2, journaling); the KGB Archiver 1.0b4 sources.

use super::{Entry, Inventory, Kind, Stored, dos_stamp, dos_time, stored_children, wanted};
use crate::plugin::{
    ByteReader, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff,
    Source, latin1_or_utf8,
};

/// Extractor for ARC, PAK, Zoo, ACE, ZPAQ and KGB archives.
pub struct Dos;

/// The 13-byte tag that starts every block of a ZPAQ archive written with
/// locators.
const ZPAQ_TAG: &[u8] = b"7kSt\xa0\x31\x83\xd3\x8c\xb2\x28\xb0\xd3";
const ZOO_TAG: u32 = 0xFDC4_A7DC;

static META: ExtractorMeta = ExtractorMeta {
    id: "archive.dos",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "arc",
            name: "ARC / PAK archive",
            family: "archive",
            mimes: &["application/x-arc"],
            // NoGate PAK files are ARC files too, but `.pak` is mostly
            // Quake's: content decides.
            extensions: &["arc", "ark"],
            // 0x1A and a method byte; `sniff` checks the name too.
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "zoo",
            name: "Zoo archive",
            family: "archive",
            mimes: &["application/x-zoo"],
            extensions: &["zoo"],
            magic: &[Magic::at(20, b"\xdc\xa7\xc4\xfd")],
            parent: None,
        },
        FormatSpec {
            id: "ace",
            name: "ACE archive",
            family: "archive",
            mimes: &["application/x-ace-compressed"],
            extensions: &["ace"],
            magic: &[Magic::at(7, b"**ACE**")],
            parent: None,
        },
        FormatSpec {
            id: "zpaq",
            name: "ZPAQ archive",
            family: "archive",
            mimes: &["application/x-zpaq"],
            extensions: &["zpaq"],
            magic: &[Magic::prefix(ZPAQ_TAG), Magic::prefix(b"zPQ")],
            parent: None,
        },
        FormatSpec {
            id: "kgb",
            name: "KGB Archiver archive",
            family: "archive",
            mimes: &["application/x-kgb"],
            extensions: &["kgb", "kge"],
            magic: &[Magic::prefix(b"KGB_arch")],
            parent: None,
        },
    ],
};

const MAX_ENTRIES: u64 = 1 << 20;

impl Extractor for Dos {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // A first entry with a valid date whose data fits in the file.
        let first = arc_header(probe.head)?;
        if first.method == 0 || dos_time(first.date, first.time).is_none() || first.len + first.packed > probe.len {
            return None;
        }
        let confidence = if matches!(probe.extension, Some("arc" | "ark" | "pak")) { 0.8 } else { 0.45 };
        Some(Sniff { format: "arc", confidence })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "arc" => arc(src, cx),
            "zoo" => zoo(src, cx),
            "ace" => ace(src, cx),
            "zpaq" => zpaq(src, cx),
            _ => kgb(src, cx),
        }
    }
}

crate::register_extractor!(Dos);

// --- ARC / PAK ---------------------------------------------------------------

/// One ARC header.
struct ArcHeader {
    method: u8,
    name: String,
    packed: u64,
    date: u16,
    time: u16,
    original: u64,
    /// Header length: the data follows.
    len: u64,
}

/// The ARC header at the start of `h`, `None` unless it looks like one.
fn arc_header(h: &[u8]) -> Option<ArcHeader> {
    if h.len() < 2 || h[0] != 0x1a {
        return None;
    }
    let method = h[1];
    if method == 0 {
        return Some(ArcHeader { method, name: String::new(), packed: 0, date: 0, time: 0, original: 0, len: 2 });
    }
    // 1–11: ARC and PAK methods; 20–29 (information records) and 30
    // (folders) were added by ARC 7 / PAK.
    if !(1..=11).contains(&method) && !(20..=30).contains(&method) {
        return None;
    }
    let name = h.get(2..15)?;
    let end = name.iter().position(|&b| b == 0)?;
    if end == 0 || !name[..end].iter().all(|&b| b.is_ascii_graphic()) {
        return None;
    }
    let mut r = ByteReader::new(h.get(15..)?);
    let packed = u64::from(r.le_u32().ok()?);
    let date = r.le_u16().ok()?;
    let time = r.le_u16().ok()?;
    r.le_u16().ok()?;
    // Method 1 (ARC 1) has no separate original size.
    let (original, len) = if method == 1 { (packed, 25) } else { (u64::from(r.le_u32().ok()?), 29) };
    Some(ArcHeader { method, name: latin1_or_utf8(&name[..end]), packed, date, time, original, len })
}

fn arc_method(m: u8) -> &'static str {
    match m {
        1 | 2 => "stored",
        3 => "packed",
        4 => "squeezed",
        5..=8 => "crunched",
        9 => "squashed",
        10 => "crushed",
        11 => "distilled",
        _ => "other",
    }
}

fn arc(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    let mut inv = Inventory::new();
    let mut stored: Vec<Stored> = Vec::new();
    let mut at = 0u64;
    let (mut ended, mut pak) = (false, false);
    let mut folders: Vec<String> = Vec::new();
    for i in 0..MAX_ENTRIES {
        if i % 1024 == 1023 {
            cx.checkpoint()?;
        }
        let h = src.read_vec(at, usize::try_from(len.saturating_sub(at).min(29)).unwrap_or(0))?;
        let Some(ArcHeader { method, name, packed, date, time, original, len: header }) = arc_header(&h) else {
            // PAK appends its own records after the end marker; anything
            // else is damage.
            if at < len {
                cx.warn(format!("no ARC header at offset {at}"));
                inv.truncated = true;
            }
            break;
        };
        if method == 0 {
            ended = true;
            break;
        }
        pak |= method >= 10;
        let data_at = at + header;
        at = data_at.saturating_add(packed);
        match method {
            // An information record (comment, attributes): not a file.
            20..=29 => continue,
            // A folder: its entries follow, up to an end marker.
            30 => {
                folders.push(name.clone());
                inv.push(Entry { path: folders.join("/"), kind: Kind::Dir, size: Some(0), ..Entry::default() });
                at = data_at;
                continue;
            }
            _ => {}
        }
        let path = if folders.is_empty() { name } else { format!("{}/{name}", folders.join("/")) };
        let e = Entry {
            path,
            kind: Kind::File,
            size: Some(original),
            compressed: Some(packed),
            modified: dos_time(date, time),
            method: Some(arc_method(method).to_string()),
            ..Entry::default()
        };
        if arc_method(method) == "stored" && wanted(&e) {
            stored.push((e.path.clone(), data_at, packed));
        }
        inv.push(e);
        if at >= len {
            inv.truncated = true;
            break;
        }
    }
    if pak {
        cx.format_set("variant", "PAK");
    }
    if !ended {
        cx.warn("no end-of-archive marker");
    }
    inv.report(cx, len);
    stored_children(src, cx, stored)
}

// --- Zoo ---------------------------------------------------------------------

#[allow(clippy::too_many_lines)] // the archive header and the entry chain in one walk
fn zoo(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    let h = src.read_vec(0, usize::try_from(len.min(42)).unwrap_or(0))?;
    let mut r = ByteReader::new(&h);
    let text = r.bytes(20)?;
    if r.le_u32()? != ZOO_TAG {
        return Err(ExtractError::malformed("Zoo tag"));
    }
    let text = latin1_or_utf8(text.split(|&b| b == 0x1a || b == 0).next().unwrap_or(&[]));
    if !text.trim().is_empty() {
        cx.format_set("header_text", text.trim());
    }
    let mut at = u64::from(r.le_u32()?);
    r.le_u32()?;
    let (major, minor) = (r.u8()?, r.u8()?);
    cx.format_set("version_needed", format!("{major}.{minor}"));
    if h.len() >= 42 && major >= 2 {
        let mut c = ByteReader::new(&h).skip(35)?;
        let (_, comment_len) = (c.le_u32()?, c.le_u16()?);
        if comment_len > 0 {
            cx.format_set("comment_bytes", comment_len);
        }
    }
    let mut inv = Inventory::new();
    let mut stored: Vec<Stored> = Vec::new();
    let mut deleted = 0u64;
    for i in 0..MAX_ENTRIES {
        if i % 1024 == 1023 {
            cx.checkpoint()?;
        }
        let d = src.read_vec(at, usize::try_from(len.saturating_sub(at).min(56 + 2 + 510)).unwrap_or(0))?;
        if d.len() < 51 {
            inv.truncated = true;
            break;
        }
        let mut r = ByteReader::new(&d);
        if r.le_u32()? != ZOO_TAG {
            cx.warn(format!("no Zoo directory entry at offset {at}"));
            inv.truncated = true;
            break;
        }
        let kind = r.u8()?;
        let method = r.u8()?;
        let next = u64::from(r.le_u32()?);
        let offset = u64::from(r.le_u32()?);
        let (date, time) = (r.le_u16()?, r.le_u16()?);
        r.le_u16()?;
        let original = u64::from(r.le_u32()?);
        let packed = u64::from(r.le_u32()?);
        r.advance(2)?;
        let is_deleted = r.u8()? != 0;
        r.advance(1 + 4 + 2)?;
        let short = r.bytes(13)?;
        // The last entry is empty: its `next` is 0.
        if next == 0 {
            break;
        }
        let mut path = latin1_or_utf8(short.split(|&b| b == 0).next().unwrap_or(&[]));
        if kind == 2 && d.len() >= 58 {
            let mut v = ByteReader::new(&d).skip(56)?;
            let (nlen, dlen) = (usize::from(v.u8()?), usize::from(v.u8()?));
            if let (Ok(long), Ok(dir)) = (v.bytes(nlen), v.bytes(dlen)) {
                let long = latin1_or_utf8(long.split(|&b| b == 0).next().unwrap_or(&[]));
                let dir = latin1_or_utf8(dir.split(|&b| b == 0).next().unwrap_or(&[]));
                if !long.is_empty() {
                    path = long;
                }
                if !dir.is_empty() {
                    path = format!("{}/{path}", dir.trim_end_matches(['/', '\\']));
                }
            }
        }
        if is_deleted {
            deleted += 1;
        } else {
            let e = Entry {
                path,
                kind: Kind::File,
                size: Some(original),
                compressed: Some(packed),
                modified: dos_time(date, time),
                method: Some(match method {
                    0 => "stored".into(),
                    1 => "LZW".into(),
                    2 => "LZH".into(),
                    m => format!("method {m}"),
                }),
                ..Entry::default()
            };
            if method == 0 && wanted(&e) {
                stored.push((e.path.clone(), offset, packed));
            }
            inv.push(e);
        }
        if next <= at || next >= len {
            if next >= len {
                inv.truncated = true;
            }
            break;
        }
        at = next;
    }
    if deleted > 0 {
        cx.format_set("deleted_entries", deleted);
    }
    inv.report(cx, len);
    stored_children(src, cx, stored)
}

// --- ACE ---------------------------------------------------------------------

fn ace_host(h: u8) -> &'static str {
    match h {
        0 => "MS-DOS",
        1 => "OS/2",
        2 => "Win32",
        3 => "Unix",
        4 => "Mac OS",
        5 => "Windows NT",
        6 => "PRIMOS",
        7 => "Apple GS",
        8 => "Atari",
        9 => "VAX VMS",
        10 => "Amiga",
        11 => "NeXT",
        12 => "Linux",
        _ => "other",
    }
}

/// One ACE block: type, flags, body, and the offset after the header.
type AceBlock = (u8, u16, Vec<u8>, u64);

/// The ACE block at `at`.
fn ace_block(src: &mut dyn Source, at: u64) -> Result<Option<AceBlock>, ExtractError> {
    if at + 4 > src.len() {
        return Ok(None);
    }
    let h = src.read_vec(at, 4)?;
    let size = u64::from(u16::from_le_bytes([h[2], h[3]]));
    if size < 3 {
        return Err(ExtractError::malformed("ACE header size"));
    }
    let body = src.read_vec(at + 4, usize::try_from(size).unwrap_or(0))?;
    Ok(Some((body[0], u16::from_le_bytes([body[1], body[2]]), body, at + 4 + size)))
}

fn ace(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    // Self-extracting archives keep a stub ahead of the main header.
    let head = src.read_vec(0, usize::try_from(len.min(64 * 1024)).unwrap_or(0))?;
    let start = head.windows(7).position(|w| w == b"**ACE**").and_then(|p| p.checked_sub(7)).unwrap_or(0) as u64;
    let Some((0, flags, main, mut at)) = ace_block(src, start)? else {
        return Err(ExtractError::malformed("ACE main header"));
    };
    let mut r = ByteReader::new(&main).skip(10)?;
    let (needed, created_by, host, volume) = (r.u8()?, r.u8()?, r.u8()?, r.u8()?);
    let stamp = r.le_u32()?;
    cx.format_set("version_needed", format!("{}.{}", needed / 10, needed % 10));
    cx.format_set("created_by_version", format!("{}.{}", created_by / 10, created_by % 10));
    cx.format_set("created_on", ace_host(host));
    if let Some(t) = dos_stamp(stamp) {
        cx.format_set("created", t);
    }
    for (bit, name) in [
        (0x0200, "self_extracting"),
        (0x0800, "multivolume"),
        (0x2000, "recovery_record"),
        (0x4000, "locked"),
        (0x8000, "solid"),
    ] {
        if flags & bit != 0 {
            cx.format_set(name, true);
        }
    }
    if flags & 0x0800 != 0 {
        cx.format_set("volume", volume);
    }
    let mut inv = Inventory::new();
    let mut stored: Vec<Stored> = Vec::new();
    for i in 0..MAX_ENTRIES {
        if i % 1024 == 1023 {
            cx.checkpoint()?;
        }
        let Some((kind, flags, body, data_at)) = ace_block(src, at)? else { break };
        // Recovery records and anything else carry an `addsize` too.
        let mut r = ByteReader::new(&body).skip(3)?;
        let wide = flags & 0x0004 != 0;
        let packed = if flags & 0x0001 == 0 {
            0
        } else if wide {
            r.le_u64()?
        } else {
            u64::from(r.le_u32()?)
        };
        if kind == 1 || kind == 3 {
            let original = if wide { r.le_u64()? } else { u64::from(r.le_u32()?) };
            let stamp = r.le_u32()?;
            let attributes = r.le_u32()?;
            r.le_u32()?;
            let method = r.u8()?;
            r.advance(1 + 2 + 2)?;
            let n = usize::from(r.le_u16()?);
            let name = latin1_or_utf8(r.bytes(n)?);
            let dir = attributes & 0x10 != 0;
            let e = Entry {
                path: name,
                kind: if dir { Kind::Dir } else { Kind::File },
                size: Some(if dir { 0 } else { original }),
                compressed: Some(packed),
                modified: dos_stamp(stamp),
                encrypted: flags & 0x4000 != 0,
                method: (!dir).then(|| {
                    match method {
                        0 => "stored",
                        1 => "LZ77",
                        2 => "blocked",
                        _ => "other",
                    }
                    .to_string()
                }),
                ..Entry::default()
            };
            // Stored, whole (not split across volumes) and not encrypted.
            if method == 0 && packed == original && flags & 0x3000 == 0 && wanted(&e) {
                stored.push((e.path.clone(), data_at, packed));
            }
            inv.push(e);
        }
        at = data_at.saturating_add(packed);
        if at >= len {
            break;
        }
    }
    inv.report(cx, len);
    stored_children(src, cx, stored)
}

// --- ZPAQ ----------------------------------------------------------------------

/// A block whose model is empty (`hsize` 7: no components): its first
/// segment's name, its data (the chunks joined, without the leading
/// post-processor byte, up to `cap` bytes) and the offset after the block.
/// `Ok(None)` for a block with a model (compressed data) or none at all.
fn zpaq_stored(src: &mut dyn Source, at: u64, cap: usize) -> Result<Option<(String, Vec<u8>, u64)>, ExtractError> {
    let len = src.len();
    let h = src.read_vec(at, usize::try_from(len.saturating_sub(at).min(512)).unwrap_or(0))?;
    let tag = if h.starts_with(ZPAQ_TAG) { ZPAQ_TAG.len() } else { 0 };
    let mut r = ByteReader::new(h.get(tag..).unwrap_or(&[]));
    if r.bytes(3).ok() != Some(b"zPQ".as_slice()) {
        return Ok(None);
    }
    let level = r.u8()?;
    if !(1..=2).contains(&level) || r.u8()? != 1 || r.le_u16()? != 7 || r.bytes(7)? != [0; 7] {
        return Ok(None);
    }
    if r.u8()? != 1 {
        return Ok(None);
    }
    let name = latin1_or_utf8(r.cstr()?);
    r.cstr()?;
    r.u8()?;
    // Chunks: a 4-byte big-endian length each, then a zero length.
    let mut pos = at + (tag + r.position()) as u64;
    let mut data = Vec::new();
    loop {
        let n = u64::from(ByteReader::new(&src.read_vec(pos, 4)?).be_u32()?);
        pos += 4;
        if n == 0 {
            break;
        }
        let room = cap.saturating_sub(data.len());
        let take = usize::try_from(n).unwrap_or(usize::MAX).min(room);
        if take > 0 {
            data.extend(src.read_vec(pos, take)?);
        }
        pos = pos.checked_add(n).filter(|&p| p <= len).ok_or_else(|| ExtractError::malformed("ZPAQ chunk"))?;
    }
    // An optional SHA-1, then the end of the block (one segment each).
    let end = src.read_vec(pos, 1)?;
    pos += if end[0] == 0xfd { 21 } else { 1 };
    if src.read_vec(pos, 1)? != [0xff] {
        return Err(ExtractError::malformed("ZPAQ block end"));
    }
    if !data.is_empty() {
        data.remove(0);
    }
    Ok(Some((name, data, pos + 1)))
}

/// `jDC` + `YYYYMMDDHHMMSS` → RFC 3339.
fn zpaq_date(name: &str) -> Option<String> {
    zpaq_stamp(name.get(3..17)?.parse().ok()?)
}

/// A date stored as the decimal number `YYYYMMDDHHMMSS` → RFC 3339.
fn zpaq_stamp(n: u64) -> Option<String> {
    let d = format!("{n:014}");
    (n >= 1_000_000_000_000 && d.len() == 14)
        .then(|| format!("{}-{}-{}T{}:{}:{}Z", &d[..4], &d[4..6], &d[6..8], &d[8..10], &d[10..12], &d[12..14]))
}

fn zpaq(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    let head = src.read_vec(0, usize::try_from(len.min(64)).unwrap_or(0))?;
    let level = head.windows(4).find(|w| &w[..3] == b"zPQ").map_or(0, |w| w[3]);
    cx.format_set("level", level);
    let journaling = zpaq_stored(src, 0, 0)?.is_some_and(|(first, ..)| first.starts_with("jDC"));
    cx.format_set("journaling", journaling);
    if !journaling {
        // A streaming archive: its blocks are compressed and not skipped
        // without decompressing them.
        return Ok(());
    }
    let cap = cx.parse_limit();
    let mut at = 0u64;
    let (mut dates, mut incomplete) = (Vec::new(), false);
    let (mut fragments, mut data_bytes, mut compressed) = (0u64, 0u64, 0u64);
    for i in 0..MAX_ENTRIES {
        if i % 256 == 255 {
            cx.checkpoint()?;
        }
        if at >= len {
            break;
        }
        let Some((name, data, end)) = zpaq_stored(src, at, cap)? else {
            // A compressed block (the index, or data after a damaged `c`
            // block): every block of a journaling archive starts with the
            // locator tag, so skip to the next one.
            match next_tag(src, at + 1)? {
                Some(next) => {
                    at = next;
                    continue;
                }
                None => break,
            }
        };
        match name.as_bytes().get(17) {
            Some(b'c') => {
                let size = ByteReader::new(&data).le_u64()?;
                dates.extend(zpaq_date(&name));
                if size == u64::MAX {
                    incomplete = true;
                    break;
                }
                compressed = compressed.saturating_add(size);
                // The compressed data (`d` blocks) follows; skip it.
                at = end.saturating_add(size);
                continue;
            }
            // Fragment table: the block size, then a SHA-1 and a size per
            // fragment (each fragment is stored once: deduplicated).
            Some(b'h') => {
                let mut r = ByteReader::new(&data).skip(4)?;
                while r.remaining() >= 24 {
                    r.advance(20)?;
                    fragments += 1;
                    data_bytes = data_bytes.saturating_add(u64::from(r.le_u32()?));
                }
            }
            _ => {}
        }
        at = end;
    }
    cx.format_set("transactions", dates.len());
    if let (Some(a), Some(b)) = (dates.first(), dates.last()) {
        cx.format_set("first_transaction", a.clone());
        cx.format_set("last_transaction", b.clone());
        cx.temporal().content_date(DateField::Created, a.clone(), true);
        cx.temporal().content_date(DateField::Modified, b.clone(), true);
    }
    cx.format_set("fragments", fragments);
    cx.format_set("deduplicated_bytes", data_bytes);
    cx.format_set("compressed_bytes", compressed);
    cx.physical().uncompressed_bytes(data_bytes);
    if incomplete {
        cx.format_set("incomplete_transaction", true);
    }
    Ok(())
}

/// The offset of the next ZPAQ locator tag at or after `from`.
fn next_tag(src: &mut dyn Source, mut from: u64) -> Result<Option<u64>, ExtractError> {
    const WINDOW: u64 = 64 * 1024;
    let len = src.len();
    while from < len {
        let buf = src.read_vec(from, usize::try_from((len - from).min(WINDOW)).unwrap_or(0))?;
        if let Some(p) = buf.windows(ZPAQ_TAG.len()).position(|w| w == ZPAQ_TAG) {
            return Ok(Some(from + p as u64));
        }
        if buf.len() < ZPAQ_TAG.len() {
            break;
        }
        from += (buf.len() - ZPAQ_TAG.len() + 1) as u64;
    }
    Ok(None)
}

// --- KGB -----------------------------------------------------------------------

fn kgb(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    let h = src.read_vec(0, usize::try_from(len.min(64 * 1024)).unwrap_or(0))?;
    let mut lines = h.split(|&b| b == b'\n');
    let first = lines.next().unwrap_or(&[]);
    let level = first.strip_prefix(b"KGB_arch -").and_then(|l| l.first()).filter(|b| b.is_ascii_digit());
    if let Some(l) = level {
        cx.format_set("compression_level", l - b'0');
    }
    let mut inv = Inventory::new();
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(tab) = line.iter().position(|&b| b == b'\t') else { break };
        let Ok(size) = std::str::from_utf8(&line[..tab]).unwrap_or("").parse::<u64>() else { break };
        inv.push(Entry {
            path: latin1_or_utf8(&line[tab + 1..]),
            kind: Kind::File,
            size: Some(size),
            method: Some("PAQ6".into()),
            ..Entry::default()
        });
    }
    inv.report(cx, len);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("arc", "zoo", "ace", "zpaq", "kgb");

    #[test]
    fn arc_headers() {
        let mut h = vec![0x1a, 2];
        h.extend(b"NOTES.TXT\0\0\0\0");
        h.extend(5u32.to_le_bytes());
        h.extend([0x21, 0x5b, 0, 0x60, 0, 0]);
        h.extend(5u32.to_le_bytes());
        let a = arc_header(&h).unwrap();
        assert_eq!((a.method, a.name.as_str(), a.packed, a.original), (2, "NOTES.TXT", 5, 5));
        assert!(arc_header(b"\x1a\x02\x01\x02garbage-garbage-garbage-garbage").is_none());
        assert!(arc_header(b"\x1a\x40NOTES").is_none());
        assert_eq!(arc_header(b"\x1a\0").unwrap().method, 0);
    }

    #[test]
    fn zpaq_dates() {
        assert_eq!(zpaq_date("jDC20250901120000c0000000001").as_deref(), Some("2025-09-01T12:00:00Z"));
        assert_eq!(zpaq_date("jDCx"), None);
        assert_eq!(zpaq_stamp(0), None);
    }
}
