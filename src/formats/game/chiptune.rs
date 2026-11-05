//! Chiptunes: music that runs on (emulated) console and computer sound
//! hardware, from their headers and tags:
//! * NSF and `NSFe` (NES): songs, start song, addresses, region, expansion
//!   chips, title, artist, copyright, ripper, track names and times;
//! * SPC (Super NES): ID666 tags (text and binary forms) and the extended
//!   `xid6` tags: song, game, artist, dumper, comments, OST title,
//!   publisher, copyright year, play and fade lengths;
//! * VGM and VGZ (gzip): version, the sound chips and their clocks, length
//!   and loop, the GD3 tags (track, game, system, author in English and
//!   Japanese, release date, converter, notes);
//! * SID (PSID, RSID; Commodore 64): version, songs, start song, clock,
//!   SID models and extra SID chips, title, author, release;
//! * GBS (Game Boy): songs, addresses, title, author, copyright.
//!
//! Specifications: `NESdev` wiki (NSF, `NSFe`, NSF2); the SPC and ID666
//! format notes (`SNESmusic.org`); VGM 1.71 specification and GD3 1.00
//! (`vgmrips`); HVSC `SID_file_format.txt` (PSID v1–v4); the GBS 1.00
//! specification.

use serde_json::{Map, Value};

use super::fixed;
use crate::plugin::{
    ByteReader, Codec, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    truncate_chars,
};

/// Extractor for chiptunes.
pub struct Chiptune;

static META: ExtractorMeta = ExtractorMeta {
    id: "game.chiptune",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "nsf",
            name: "NES Sound Format (NSF)",
            family: "game",
            mimes: &["audio/x-nsf"],
            extensions: &["nsf"],
            magic: &[Magic::prefix(b"NESM\x1a")],
            parent: None,
        },
        FormatSpec {
            id: "nsfe",
            name: "Extended NES Sound Format (NSFe)",
            family: "game",
            mimes: &[],
            extensions: &["nsfe"],
            magic: &[Magic::prefix(b"NSFE")],
            parent: None,
        },
        // `.spc` is also a PKCS#7 bundle: the signature decides.
        FormatSpec {
            id: "spc",
            name: "SNES SPC700 sound file",
            family: "game",
            mimes: &["audio/x-spc"],
            extensions: &[],
            magic: &[Magic::prefix(b"SNES-SPC700 Sound File Data")],
            parent: None,
        },
        FormatSpec {
            id: "vgm",
            name: "Video Game Music (VGM / VGZ)",
            family: "game",
            mimes: &["audio/x-vgm"],
            extensions: &["vgm", "vgz"],
            // VGZ is gzip-compressed: sniffed.
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "sid",
            name: "Commodore 64 SID tune (PSID / RSID)",
            family: "game",
            mimes: &["audio/prs.sid"],
            extensions: &["sid", "psid"],
            magic: &[Magic::prefix(b"PSID"), Magic::prefix(b"RSID")],
            parent: None,
        },
        // `.gbs` is also a Gerber layer: the signature decides.
        FormatSpec {
            id: "gbs",
            name: "Game Boy Sound System (GBS)",
            family: "game",
            mimes: &[],
            extensions: &[],
            magic: &[Magic::prefix(b"GBS\x01")],
            parent: None,
        },
    ],
};

/// Title, author and copyright into `content` and `rights`, and `format`.
fn tags(cx: &mut Context<'_>, title: Option<String>, author: Option<String>, copyright: Option<String>) {
    if let Some(t) = title {
        cx.content().title(t.clone());
        cx.format_set("title", t);
    }
    if let Some(a) = author {
        cx.content().author(a.clone());
        cx.format_set("author", a);
    }
    if let Some(c) = copyright {
        cx.rights().copyright(c.clone());
        cx.format_set("copyright", c);
    }
}

fn chips_nes(bits: u8) -> Vec<Value> {
    ["VRC6", "VRC7", "FDS", "MMC5", "Namco 163", "Sunsoft 5B", "VT02+"]
        .iter()
        .enumerate()
        .filter(|(i, _)| bits & (1 << i) != 0)
        .map(|(_, c)| (*c).into())
        .collect()
}

fn region_nes(bits: u8) -> &'static str {
    match bits & 3 {
        0 => "NTSC",
        1 => "PAL",
        _ => "NTSC and PAL",
    }
}

fn nsf(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let h = b.get(..0x80).ok_or(ExtractError::Malformed("short NSF header".into()))?;
    let le = |i: usize| u16::from_le_bytes([h[i], h[i + 1]]);
    cx.format_set("version", h[5]);
    cx.format_set("songs", h[6]);
    cx.format_set("start_song", h[7]);
    cx.format_set("load_address", format!("0x{:04x}", le(8)));
    cx.format_set("init_address", format!("0x{:04x}", le(0x0A)));
    cx.format_set("play_address", format!("0x{:04x}", le(0x0C)));
    cx.format_set("region", region_nes(h[0x7A]));
    cx.format_set("bankswitched", h[0x70..0x78].iter().any(|&c| c != 0));
    let chips = chips_nes(h[0x7B]);
    if !chips.is_empty() {
        cx.format_set("expansion_chips", chips);
    }
    tags(cx, fixed(&h[0x0E..0x2E]), fixed(&h[0x2E..0x4E]), fixed(&h[0x4E..0x6E]));
    Ok(())
}

/// NUL-terminated strings (the empty piece after the last NUL dropped).
fn strings0(b: &[u8], max: usize) -> Vec<String> {
    let b = b.strip_suffix(&[0]).unwrap_or(b);
    b.split(|&c| c == 0).take(max).map(|s| fixed(s).unwrap_or_default()).collect()
}

fn nsfe(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(b);
    r.tag(b"NSFE")?;
    let mut chunks = Vec::new();
    let (mut title, mut author, mut copyright) = (None, None, None);
    while r.remaining() >= 8 && chunks.len() < 1000 {
        let n = r.le_u32()? as usize;
        let id = r.array::<4>()?;
        let Ok(d) = r.bytes(n.min(r.remaining())) else { break };
        let name = String::from_utf8_lossy(&id).into_owned();
        match &id {
            b"INFO" if d.len() >= 8 => {
                let le = |i: usize| u16::from_le_bytes([d[i], d[i + 1]]);
                cx.format_set("load_address", format!("0x{:04x}", le(0)));
                cx.format_set("init_address", format!("0x{:04x}", le(2)));
                cx.format_set("play_address", format!("0x{:04x}", le(4)));
                cx.format_set("region", region_nes(d[6]));
                let chips = chips_nes(d[7]);
                if !chips.is_empty() {
                    cx.format_set("expansion_chips", chips);
                }
                if let Some(&n) = d.get(8) {
                    cx.format_set("songs", n);
                }
                if let Some(&s) = d.get(9) {
                    cx.format_set("start_song", u16::from(s) + 1);
                }
            }
            b"auth" => {
                let s = strings0(d, 4);
                let get = |i: usize| s.get(i).filter(|v| !v.is_empty()).cloned();
                (title, author, copyright) = (get(0), get(1), get(2));
                if let Some(r) = get(3) {
                    cx.format_set("ripper", r);
                }
            }
            b"tlbl" => {
                let labels: Vec<Value> = strings0(d, 256).into_iter().map(Value::from).collect();
                cx.format_set("track_titles", labels);
            }
            b"time" => {
                let ms: Vec<Value> = d
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .take(256)
                    .map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                    .map(|t| if t < 0 { Value::Null } else { (f64::from(t) / 1000.0).into() })
                    .collect();
                cx.format_set("track_seconds", ms);
            }
            b"NEND" => {
                chunks.push(name);
                break;
            }
            _ => {}
        }
        chunks.push(name);
    }
    cx.format_set("chunks", chunks);
    tags(cx, title, author, copyright);
    Ok(())
}

fn spc(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let h = b.get(..0x100).ok_or(ExtractError::Malformed("short SPC header".into()))?;
    cx.format_set("version", format!("0.{}", h[0x24]));
    let mut m = Map::new();
    let (mut title, mut author, mut copyright) = (None, None, None);
    if h[0x23] == 26 {
        title = fixed(&h[0x2E..0x4E]);
        if let Some(g) = fixed(&h[0x4E..0x6E]) {
            m.insert("game".into(), g.into());
        }
        if let Some(d) = fixed(&h[0x6E..0x7E]) {
            m.insert("dumper".into(), d.into());
        }
        if let Some(c) = fixed(&h[0x7E..0x9E]) {
            m.insert("comments".into(), c.into());
        }
        // The text form has decimal play and fade lengths; the binary form
        // puts the artist one byte earlier.
        let digits = |s: &[u8]| s.iter().all(|&c| c.is_ascii_digit() || c == 0 || c == b' ');
        let text = digits(&h[0xA9..0xB1]);
        let num = |s: &[u8]| std::str::from_utf8(s).ok().and_then(|t| t.trim_matches(['\0', ' ']).parse::<u64>().ok());
        let (secs, fade, artist) = if text {
            (num(&h[0xA9..0xAC]), num(&h[0xAC..0xB1]), fixed(&h[0xB1..0xD1]))
        } else {
            let secs = u64::from(h[0xA9]) | u64::from(h[0xAA]) << 8 | u64::from(h[0xAB]) << 16;
            let fade = u64::from(u32::from_le_bytes([h[0xAC], h[0xAD], h[0xAE], h[0xAF]]));
            (Some(secs), Some(fade), fixed(&h[0xB0..0xD0]))
        };
        m.insert("id666".into(), if text { "text" } else { "binary" }.into());
        if let Some(s) = secs.filter(|&s| s > 0) {
            m.insert("play_seconds".into(), s.into());
            #[allow(clippy::cast_precision_loss)]
            cx.physical().duration_s(s as f64);
        }
        if let Some(f) = fade.filter(|&f| f > 0) {
            m.insert("fade_ms".into(), f.into());
        }
        author = artist;
    }
    // Extended tags after the 64 KiB RAM image and DSP registers.
    if let Some(x) = b.get(0x10200..)
        && x.starts_with(b"xid6")
    {
        let n = u32::from_le_bytes(x.get(4..8).unwrap_or(&[0; 4]).try_into().unwrap_or_default()) as usize;
        let mut r = ByteReader::new(x.get(8..8 + n.min(x.len() - 8)).unwrap_or(&[]));
        while r.remaining() >= 4 {
            let (id, ty) = (r.u8()?, r.u8()?);
            let len = usize::from(r.le_u16()?);
            let data = if ty == 0 {
                &[][..]
            } else {
                let d = r.bytes(len.min(r.remaining()))?;
                let pad = (4 - len % 4) % 4;
                let _ = r.advance(pad.min(r.remaining()));
                d
            };
            let s = || fixed(data).map(|v| truncate_chars(&v, 300));
            match id {
                0x01 => title = s().or(title),
                0x02 => {
                    if let Some(v) = s() {
                        m.insert("game".into(), v.into());
                    }
                }
                0x03 => author = s().or(author),
                0x07 => {
                    if let Some(v) = s() {
                        m.insert("comments".into(), v.into());
                    }
                }
                0x10 => {
                    if let Some(v) = s() {
                        m.insert("ost_title".into(), v.into());
                    }
                }
                0x13 => {
                    if let Some(v) = s() {
                        m.insert("publisher".into(), v.into());
                    }
                }
                0x14 if ty == 0 => {
                    m.insert("copyright_year".into(), len.into());
                }
                _ => {}
            }
        }
        m.insert("extended_tags".into(), true.into());
        // The copyright: year and publisher.
        let year = m.get("copyright_year").and_then(Value::as_u64);
        let publisher = m.get("publisher").and_then(Value::as_str);
        copyright = match (year, publisher) {
            (Some(y), Some(p)) => Some(format!("{y} {p}")),
            (Some(y), None) => Some(y.to_string()),
            (None, Some(p)) => Some(p.to_string()),
            (None, None) => None,
        };
    }
    for (k, v) in m {
        cx.format_set(&k, v);
    }
    tags(cx, title, author, copyright);
    Ok(())
}

/// VGM header clocks: (offset, chip), in header order.
const VGM_CHIPS: [(usize, &str); 41] = [
    (0x0C, "SN76489"),
    (0x10, "YM2413"),
    (0x2C, "YM2612"),
    (0x30, "YM2151"),
    (0x38, "Sega PCM"),
    (0x40, "RF5C68"),
    (0x44, "YM2203"),
    (0x48, "YM2608"),
    (0x4C, "YM2610"),
    (0x50, "YM3812"),
    (0x54, "YM3526"),
    (0x58, "Y8950"),
    (0x5C, "YMF262"),
    (0x60, "YMF278B"),
    (0x64, "YMF271"),
    (0x68, "YMZ280B"),
    (0x6C, "RF5C164"),
    (0x70, "PWM"),
    (0x74, "AY8910"),
    (0x80, "Game Boy DMG"),
    (0x84, "NES APU"),
    (0x88, "MultiPCM"),
    (0x8C, "uPD7759"),
    (0x90, "OKIM6258"),
    (0x98, "OKIM6295"),
    (0x9C, "K051649"),
    (0xA0, "K054539"),
    (0xA4, "HuC6280"),
    (0xA8, "C140"),
    (0xAC, "K053260"),
    (0xB0, "Pokey"),
    (0xB4, "QSound"),
    (0xB8, "SCSP"),
    (0xC0, "WonderSwan"),
    (0xC4, "VSU"),
    (0xC8, "SAA1099"),
    (0xCC, "ES5503"),
    (0xD0, "ES5506"),
    (0xD8, "X1-010"),
    (0xDC, "C352"),
    (0xE0, "GA20"),
];

fn vgm(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let h = b.get(..0x40).ok_or(ExtractError::Malformed("short VGM header".into()))?;
    let le = |i: usize| b.get(i..i + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]));
    let v = le(8);
    let version = format!("{:x}.{:02x}", v >> 8, v & 0xFF);
    cx.format_set("version", version);
    // The header ends where the data starts (0x40 before 1.50).
    let data_at = if v >= 0x150 && le(0x34) != 0 { 0x34 + le(0x34) as usize } else { 0x40 };
    let mut chips = Map::new();
    for (at, name) in VGM_CHIPS {
        if at + 4 > data_at || (v < 0x110 && at >= 0x2C) || h.len() < 4 {
            continue;
        }
        let clock = le(at);
        // YM2413 clocks were shared with the YM2612 / YM2151 before 1.10.
        if clock & 0x3FFF_FFFF != 0 {
            let mut c = Map::new();
            c.insert("clock_hz".into(), (clock & 0x3FFF_FFFF).into());
            if clock & 0x4000_0000 != 0 {
                c.insert("dual".into(), true.into());
            }
            chips.insert(name.into(), c.into());
        }
    }
    cx.format_set("chips", chips);
    let samples = le(0x18);
    cx.format_set("samples", samples);
    cx.physical().duration_s((f64::from(samples) / 44100.0 * 1000.0).round() / 1000.0);
    if le(0x1C) != 0 {
        cx.format_set("loop_seconds", (f64::from(le(0x20)) / 44100.0 * 1000.0).round() / 1000.0);
    }
    let gd3 = le(0x14);
    if gd3 != 0
        && let Some(g) = b.get(0x14 + gd3 as usize..)
        && g.starts_with(b"Gd3 ")
    {
        let n = g.get(8..12).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize);
        let body = g.get(12..12 + n.min(g.len().saturating_sub(12))).unwrap_or(&[]);
        let units: Vec<u16> = body.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let fields: Vec<String> = units
            .split(|&u| u == 0)
            .take(11)
            .map(|s| truncate_chars(String::from_utf16_lossy(s).trim(), 500))
            .collect();
        let get = |i: usize| fields.get(i).filter(|s| !s.is_empty()).cloned();
        let mut m = Map::new();
        for (i, k) in [
            (1, "track_japanese"),
            (2, "game"),
            (3, "game_japanese"),
            (4, "system"),
            (5, "system_japanese"),
            (7, "author_japanese"),
            (8, "release_date"),
            (9, "converter"),
            (10, "notes"),
        ] {
            if let Some(s) = get(i) {
                m.insert(k.into(), s.into());
            }
        }
        cx.format_set("gd3", m);
        tags(cx, get(0).or_else(|| get(1)), get(6).or_else(|| get(7)), None);
    }
    Ok(())
}

fn sid(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let h = b.get(..0x76).ok_or(ExtractError::Malformed("short SID header".into()))?;
    let be = |i: usize| u16::from_be_bytes([h[i], h[i + 1]]);
    let version = be(4);
    cx.format_set("kind", if h[0] == b'R' { "RSID" } else { "PSID" });
    cx.format_set("version", version);
    let load = if be(8) == 0 {
        // The load address is then the first two bytes of the data.
        let at = usize::from(be(6));
        b.get(at..at + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
    } else {
        be(8)
    };
    cx.format_set("load_address", format!("0x{load:04x}"));
    cx.format_set("init_address", format!("0x{:04x}", be(0x0A)));
    cx.format_set("play_address", format!("0x{:04x}", be(0x0C)));
    cx.format_set("songs", be(0x0E));
    cx.format_set("start_song", be(0x10));
    if version >= 2
        && let Some(x) = b.get(0x76..0x7C)
    {
        let flags = u16::from_be_bytes([x[0], x[1]]);
        if flags & 1 != 0 {
            cx.format_set("compute_player", true);
        }
        let clock = match (flags >> 2) & 3 {
            1 => Some("PAL"),
            2 => Some("NTSC"),
            3 => Some("PAL and NTSC"),
            _ => None,
        };
        if let Some(c) = clock {
            cx.format_set("clock", c);
        }
        let model = |bits: u16| match bits & 3 {
            1 => Some("MOS 6581"),
            2 => Some("MOS 8580"),
            3 => Some("6581 and 8580"),
            _ => None,
        };
        let mut sids = vec![Value::from(model(flags >> 4).unwrap_or("unknown"))];
        let extra = |b: u8| (b & 1 == 0 && (0x42..=0xFE).contains(&b)).then(|| 0xD000 | u16::from(b) << 4);
        if version >= 3
            && let Some(a) = extra(x[4])
        {
            let mut s = Map::new();
            s.insert("address".into(), format!("0x{a:04x}").into());
            s.insert("model".into(), model(flags >> 6).unwrap_or("same").into());
            sids.push(s.into());
        }
        if version >= 4
            && let Some(a) = extra(x[5])
        {
            let mut s = Map::new();
            s.insert("address".into(), format!("0x{a:04x}").into());
            s.insert("model".into(), model(flags >> 8).unwrap_or("same").into());
            sids.push(s.into());
        }
        cx.format_set("sid_chips", sids);
    }
    tags(cx, fixed(&h[0x16..0x36]), fixed(&h[0x36..0x56]), fixed(&h[0x56..0x76]));
    Ok(())
}

fn gbs(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let h = b.get(..0x70).ok_or(ExtractError::Malformed("short GBS header".into()))?;
    let le = |i: usize| u16::from_le_bytes([h[i], h[i + 1]]);
    cx.format_set("version", h[3]);
    cx.format_set("songs", h[4]);
    cx.format_set("start_song", h[5]);
    cx.format_set("load_address", format!("0x{:04x}", le(6)));
    cx.format_set("init_address", format!("0x{:04x}", le(8)));
    cx.format_set("play_address", format!("0x{:04x}", le(0x0A)));
    // Timer control bit 2: songs driven by the timer, not the vertical blank.
    cx.format_set("timing", if h[0x0F] & 4 != 0 { "timer" } else { "vblank" });
    tags(cx, fixed(&h[0x10..0x30]), fixed(&h[0x30..0x50]), fixed(&h[0x50..0x70]));
    Ok(())
}

impl Extractor for Chiptune {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        (h.starts_with(b"Vgm ") || probe.extension == Some("vgz") && h.starts_with(&[0x1F, 0x8B]))
            .then_some(Sniff { format: "vgm", confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let id = cx.format_id().to_string();
        let (mut b, _) = cx.read_bytes(src)?;
        if id == "vgm" && b.starts_with(&[0x1F, 0x8B]) {
            let max = cx.parse_limit();
            b = cx.decompress(&b, Codec::Gzip, max)?.data;
            cx.format_set("compressed", "gzip");
        }
        match id.as_str() {
            "nsf" => nsf(cx, &b),
            "nsfe" => nsfe(cx, &b),
            "spc" => spc(cx, &b),
            "vgm" => vgm(cx, &b),
            "sid" => sid(cx, &b),
            _ => gbs(cx, &b),
        }
    }
}

crate::register_extractor!(Chiptune);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("nsf", "nsfe", "spc", "vgm", "sid", "gbs");
}
