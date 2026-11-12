//! Classic Mac OS wrappers, which carry a file's two forks and its Finder
//! information across systems that have neither:
//!
//! * StuffIt 1.5–4.5 archives (`SIT!` … `rLau`): 112-byte entry headers
//!   with names, Finder type and creator, dates and both forks' sizes and
//!   methods, folders as start / end entries;
//! * BinHex 4.0 (`.hqx`): 6-bit text, run-length encoded, then a header and
//!   both forks, each with a CRC;
//! * MacBinary I–III: a 128-byte header (CRC-checked from II on), then the
//!   forks.
//!
//! The data fork is handed on as a child (stored StuffIt entries; always for
//! BinHex and MacBinary); the resource fork's types are listed.
//!
//! Specifications: the StuffIt notes in macutils and The Unarchiver's
//! `XADStuffItParser`; *BinHex 4.0 Definition* (Peter N. Lewis, 1991); the
//! MacBinary II and III standards; *Inside Macintosh: More Macintosh
//! Toolbox* (resource forks).

use std::collections::BTreeMap;

use super::{Entry, Inventory, Kind, child, unix_time, wanted};
use crate::plugin::{
    ByteReader, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff,
    Source, latin1_or_utf8,
};

/// Extractor for StuffIt, BinHex and MacBinary files.
pub struct Mac;

static META: ExtractorMeta = ExtractorMeta {
    id: "archive.mac",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "stuffit",
            name: "StuffIt archive",
            family: "archive",
            mimes: &["application/x-stuffit"],
            extensions: &["sit"],
            magic: &[Magic::at(10, b"rLau")],
            parent: None,
        },
        FormatSpec {
            id: "binhex",
            name: "BinHex 4.0 file",
            family: "archive",
            mimes: &["application/mac-binhex40"],
            extensions: &["hqx"],
            magic: &[Magic::prefix(b"(This file must be converted")],
            parent: None,
        },
        FormatSpec {
            id: "macbinary",
            name: "MacBinary file",
            family: "archive",
            mimes: &["application/x-macbinary"],
            // Not `bin`: too many other formats use it; the header CRC finds
            // MacBinary files whatever their name.
            extensions: &["macbin"],
            // A zero version byte, and a header CRC `sniff` checks.
            magic: &[],
            parent: None,
        },
    ],
};

/// Seconds from 1904-01-01 to 1970-01-01.
const MAC_EPOCH: i64 = 2_082_844_800;
/// StuffIt entries read.
const MAX_ENTRIES: usize = 1 << 16;
/// Resource types listed.
const MAX_TYPES: usize = 64;

impl Extractor for Mac {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.len() < 128 || h[0] != 0 || h[74] != 0 || h[82] != 0 || !(1..=63).contains(&h[1]) {
            return None;
        }
        let crc = u16::from_be_bytes([h[124], h[125]]);
        (crc == crc16_xmodem(&h[..124]) || &h[102..106] == b"mBIN")
            .then_some(Sniff { format: "macbinary", confidence: 0.85 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "stuffit" => stuffit(src, cx),
            "binhex" => binhex(src, cx),
            _ => macbinary(src, cx),
        }
    }
}

crate::register_extractor!(Mac);

/// CRC-16/XMODEM (CCITT polynomial, initial value 0): MacBinary and BinHex.
fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// CRC-16 (ARC polynomial, initial value 0): StuffIt headers and forks.
fn crc16_arc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xA001 } else { crc >> 1 };
        }
    }
    crc
}

/// Seconds since 1904 in the local time of the Mac that wrote them: a civil
/// `YYYY-MM-DDTHH:MM:SS`.
fn mac_time(secs: u32) -> Option<String> {
    unix_time(i64::from(secs) - MAC_EPOCH).map(|t| t.trim_end_matches('Z').to_string())
}

/// A Finder type or creator: four printable Mac Roman characters.
fn four_cc(b: &[u8]) -> Option<String> {
    (b.len() == 4 && b.iter().any(|&c| c != 0) && b.iter().all(|&c| c >= 0x20 && c != 0x7f)).then(|| latin1_or_utf8(b))
}

/// The resource types of a resource fork, with their counts (`STR  ×2`).
fn resource_types(fork: &[u8]) -> Vec<String> {
    let be16 = |at: usize| fork.get(at..at + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let be32 = |at: usize| fork.get(at..at + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    let Some(map) = be32(4).and_then(|m| usize::try_from(m).ok()) else { return Vec::new() };
    let Some(types) = be16(map + 24).map(|t| map + usize::from(t)) else { return Vec::new() };
    let Some(n) = be16(types) else { return Vec::new() };
    (0..=usize::from(n))
        .take(MAX_TYPES)
        .map_while(|i| {
            let e = types + 2 + 8 * i;
            Some(format!("{} ×{}", four_cc(fork.get(e..e + 4)?)?, usize::from(be16(e + 4)?) + 1))
        })
        .collect()
}

/// The facts both forks wrappers share.
struct Forks<'a> {
    name: String,
    kind: Option<String>,
    creator: Option<String>,
    data_len: u64,
    rsrc_len: u64,
    rsrc: &'a [u8],
}

fn report_forks(cx: &mut Context<'_>, f: &Forks<'_>) {
    cx.format_set("name", f.name.clone());
    if let Some(t) = &f.kind {
        cx.format_set("file_type", t.clone());
    }
    if let Some(c) = &f.creator {
        cx.format_set("creator", c.clone());
    }
    cx.format_set("data_fork_bytes", f.data_len);
    cx.format_set("resource_fork_bytes", f.rsrc_len);
    let types = resource_types(f.rsrc);
    if !types.is_empty() {
        cx.format_set("resource_types", types);
    }
    cx.content().title(f.name.clone());
}

// --- StuffIt ---------------------------------------------------------------------

fn sit_method(m: u8) -> String {
    match m & 0x0f {
        0 => "stored".into(),
        1 => "RLE90".into(),
        2 => "LZW".into(),
        3 => "Huffman".into(),
        5 => "LZAH".into(),
        6 => "fixed Huffman".into(),
        8 => "MW".into(),
        13 => "LZ + Huffman".into(),
        14 => "installer".into(),
        15 => "Arsenic".into(),
        n => format!("method {n}"),
    }
}

fn stuffit(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    let h = src.read_vec(0, 22)?;
    let mut r = ByteReader::new(&h);
    let signature = latin1_or_utf8(r.bytes(4)?);
    let top = r.be_u16()?;
    let declared = u64::from(r.be_u32()?);
    r.advance(4)?;
    cx.format_set("signature", signature);
    cx.format_set("version", r.u8()?);
    cx.format_set("top_level_entries", top);
    if declared != len {
        cx.format_set("declared_bytes", declared);
    }
    let mut inv = Inventory::new();
    let mut folders: Vec<String> = Vec::new();
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let (mut rsrc_forks, mut bad_crc) = (0u64, false);
    let mut at = 22u64;
    for i in 0..MAX_ENTRIES {
        if i % 1024 == 1023 {
            cx.checkpoint()?;
        }
        if at + 112 > len {
            break;
        }
        let e = src.read_vec(at, 112)?;
        if u16::from_be_bytes([e[110], e[111]]) != crc16_arc(&e[..110]) {
            bad_crc = true;
            cx.warn(format!("StuffIt entry header CRC mismatch at offset {at}"));
            break;
        }
        let (r_method, d_method) = (e[0], e[1]);
        let name = latin1_or_utf8(&e[3..3 + usize::from(e[2].min(63))]);
        let mut r = ByteReader::new(&e).skip(66)?;
        let (kind, creator) = (four_cc(r.bytes(4)?), four_cc(r.bytes(4)?));
        r.be_u16()?;
        let (_created, modified) = (r.be_u32()?, r.be_u32()?);
        let (rlen, dlen) = (u64::from(r.be_u32()?), u64::from(r.be_u32()?));
        let (rsrc_packed, data_packed) = (u64::from(r.be_u32()?), u64::from(r.be_u32()?));
        let path =
            |name: &str| if folders.is_empty() { name.to_string() } else { format!("{}/{name}", folders.join("/")) };
        if r_method & 0x2f == 32 || d_method & 0x2f == 32 {
            inv.push(Entry {
                path: path(&name),
                kind: Kind::Dir,
                size: Some(0),
                modified: mac_time(modified),
                ..Entry::default()
            });
            folders.push(name);
            at += 112;
            continue;
        }
        if r_method & 0x2f == 33 || d_method & 0x2f == 33 {
            folders.pop();
            at += 112;
            continue;
        }
        if rlen > 0 {
            rsrc_forks += 1;
        }
        if let (Some(k), Some(c)) = (&kind, &creator) {
            *kinds.entry(format!("{k}/{c}")).or_default() += 1;
        }
        let entry = Entry {
            path: path(&name),
            kind: Kind::File,
            size: Some(dlen),
            compressed: Some(data_packed),
            modified: mac_time(modified),
            encrypted: (r_method | d_method) & 0x10 != 0,
            method: Some(sit_method(d_method)),
            ..Entry::default()
        };
        let data_at = at + 112 + rsrc_packed;
        if matches!(d_method & 0x1f, 0)
            && data_packed == dlen
            && wanted(&entry)
            && cx.child_room() > 0
            && data_at + data_packed <= len
        {
            let n = data_packed.min(cx.parse_limit() as u64);
            let data = src.read_vec(data_at, usize::try_from(n).unwrap_or(0))?;
            child(cx, &entry.path, data, n == data_packed)?;
        }
        inv.push(entry);
        at = data_at.saturating_add(data_packed);
    }
    if rsrc_forks > 0 {
        cx.format_set("resource_forks", rsrc_forks);
    }
    if !kinds.is_empty() {
        cx.format_set("type_creator", serde_json::json!(kinds));
    }
    inv.truncated |= bad_crc;
    inv.report(cx, len);
    Ok(())
}

// --- BinHex ----------------------------------------------------------------------

const HQX: &[u8; 64] = b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";

/// The bytes between the first `:` that starts a line and the closing `:`,
/// 6-bit decoded and run-length expanded, up to `cap` bytes.
fn hqx_decode(text: &[u8], cap: usize) -> Result<Vec<u8>, ExtractError> {
    let start = text
        .windows(2)
        .position(|w| matches!(w[0], b'\n' | b'\r') && w[1] == b':')
        .ok_or_else(|| ExtractError::malformed("BinHex data"))?
        + 2;
    let mut table = [255u8; 256];
    for (i, &c) in HQX.iter().enumerate() {
        table[usize::from(c)] = u8::try_from(i).unwrap_or(0);
    }
    let (mut packed, mut bits, mut acc) = (Vec::new(), 0u32, 0u32);
    for &c in &text[start..] {
        if c == b':' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = table[usize::from(c)];
        if v == 255 {
            return Err(ExtractError::malformed("BinHex character"));
        }
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            packed.push(u8::try_from((acc >> bits) & 0xff).unwrap_or(0));
        }
        if packed.len() > cap {
            break;
        }
    }
    // 0x90 n: repeat the previous byte n-1 more times; 0x90 0: a literal 0x90.
    let mut out = Vec::with_capacity(packed.len());
    let mut i = 0;
    while i < packed.len() && out.len() < cap {
        let b = packed[i];
        if b == 0x90 && i + 1 < packed.len() {
            let n = packed[i + 1];
            i += 2;
            if n == 0 {
                out.push(0x90);
            } else if let Some(&prev) = out.last() {
                let more = usize::from(n - 1).min(cap - out.len());
                out.extend(std::iter::repeat_n(prev, more));
            }
            continue;
        }
        out.push(b);
        i += 1;
    }
    Ok(out)
}

fn binhex(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    // 6 bits a character: the text is 4/3 of the data it holds.
    let cap = cx.parse_limit();
    let text = src.read_vec(0, usize::try_from(len.min((cap as u64).saturating_mul(2))).unwrap_or(0))?;
    let data = hqx_decode(&text, cap)?;
    let mut r = ByteReader::new(&data);
    let n = usize::from(r.u8()?);
    let name = latin1_or_utf8(r.bytes(n)?);
    r.u8()?;
    let (kind, creator) = (four_cc(r.bytes(4)?), four_cc(r.bytes(4)?));
    r.be_u16()?;
    let (dlen, rlen) = (u64::from(r.be_u32()?), u64::from(r.be_u32()?));
    let header_end = r.position();
    let crc = r.be_u16()?;
    if crc != crc16_xmodem(&data[..header_end]) {
        cx.warn("BinHex header CRC mismatch");
    }
    let fork = |at: usize, n: u64| {
        let end = at.saturating_add(usize::try_from(n).unwrap_or(usize::MAX)).min(data.len());
        data.get(at.min(end)..end).unwrap_or(&[])
    };
    let d_at = r.position();
    let r_at = d_at.saturating_add(usize::try_from(dlen).unwrap_or(usize::MAX)).saturating_add(2);
    let (dfork, rfork) = (fork(d_at, dlen), fork(r_at, rlen));
    if let (Some(c), true) = (data.get(d_at + dfork.len()..d_at + dfork.len() + 2), dfork.len() as u64 == dlen) {
        let ok = u16::from_be_bytes([c[0], c[1]]) == crc16_xmodem(dfork);
        cx.format_set("data_fork_crc_ok", ok);
    }
    report_forks(cx, &Forks { name: name.clone(), kind, creator, data_len: dlen, rsrc_len: rlen, rsrc: rfork });
    if dlen > 0 && cx.child_room() > 0 {
        child(cx, &name, dfork.to_vec(), dfork.len() as u64 == dlen)?;
    }
    Ok(())
}

// --- MacBinary -------------------------------------------------------------------

fn macbinary(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    let h = src.read_vec(0, 128)?;
    let name = latin1_or_utf8(&h[2..2 + usize::from(h[1].clamp(1, 63))]);
    let crc_ok = u16::from_be_bytes([h[124], h[125]]) == crc16_xmodem(&h[..124]);
    let version = if &h[102..106] == b"mBIN" {
        "III"
    } else if crc_ok {
        "II"
    } else {
        "I"
    };
    cx.format_set("macbinary_version", version);
    let mut r = ByteReader::new(&h).skip(83)?;
    let (dlen, rlen) = (u64::from(r.be_u32()?), u64::from(r.be_u32()?));
    let (created, modified) = (r.be_u32()?, r.be_u32()?);
    let secondary = u64::from(u16::from_be_bytes([h[120], h[121]]));
    let pad = |n: u64| n.div_ceil(128) * 128;
    let d_at = 128 + pad(secondary);
    let r_at = d_at + pad(dlen);
    let rsrc = if rlen > 0 && r_at < len {
        src.read_vec(r_at, usize::try_from(rlen.min(len - r_at).min(cx.parse_limit() as u64)).unwrap_or(0))?
    } else {
        Vec::new()
    };
    report_forks(
        cx,
        &Forks {
            name: name.clone(),
            kind: four_cc(&h[65..69]),
            creator: four_cc(&h[69..73]),
            data_len: dlen,
            rsrc_len: rlen,
            rsrc: &rsrc,
        },
    );
    if let Some(t) = mac_time(created) {
        cx.temporal().content_date(DateField::Created, t, false);
    }
    if let Some(t) = mac_time(modified) {
        cx.temporal().content_date(DateField::Modified, t, false);
    }
    if dlen > 0 && d_at < len && cx.child_room() > 0 {
        let n = dlen.min(len - d_at).min(cx.parse_limit() as u64);
        let data = src.read_vec(d_at, usize::try_from(n).unwrap_or(0))?;
        child(cx, &name, data, n == dlen)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("stuffit", "binhex", "macbinary");

    #[test]
    fn checksums() {
        assert_eq!(crc16_xmodem(b"123456789"), 0x31c3);
        assert_eq!(crc16_arc(b"123456789"), 0xbb3d);
    }

    #[test]
    fn binhex_run_lengths() {
        // "!!!!" is four zero 6-bit groups: three zero bytes.
        assert_eq!(hqx_decode(b"x\n:!!!!:", 64).unwrap(), [0, 0, 0]);
        assert!(hqx_decode(b"no data", 64).is_err());
        assert!(hqx_decode(b"x\n:~~~~:", 64).is_err());
    }
}
