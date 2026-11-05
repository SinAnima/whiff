//! Cartridge ROM images, from their headers:
//! * NES (iNES and NES 2.0): PRG / CHR sizes, mapper and submapper,
//!   mirroring, battery, trainer, console type, timing;
//! * Super NES: the internal header (`LoROM`, `HiROM`, `ExHiROM`; copier headers
//!   skipped): title, map mode and speed, chipset, ROM and RAM sizes,
//!   region, maker and game codes, version, checksum (verified);
//! * Game Boy and Game Boy Color: title, manufacturer and licensee codes,
//!   CGB and SGB flags, cartridge type, ROM and RAM sizes, region,
//!   version, header and global checksums (verified);
//! * Game Boy Advance: title, game and maker codes, region, version,
//!   header complement (verified);
//! * Nintendo 64 (`.z64`, byte-swapped `.v64`, word-swapped `.n64`): byte
//!   order, title, game code, region, version, CRCs, clock rate, entry
//!   point, libultra version;
//! * Sega Mega Drive / Genesis (and 32X, Pico): system, copyright and date,
//!   domestic and overseas titles, serial, devices, ROM and RAM ranges,
//!   regions, checksum (verified).
//!
//! Specifications: `NESdev` wiki (iNES, NES 2.0); `SNESdev` wiki and the
//! SNES Development Manual (cartridge header); Pan Docs (the cartridge
//! header); GBATEK (cartridge header); `n64brew` wiki (ROM header); the
//! Sega Genesis Software Manual and plutiedev (ROM header).

use serde_json::{Map, Value};

use super::fixed;
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source};

/// Extractor for cartridge ROMs.
pub struct Rom;

static META: ExtractorMeta = ExtractorMeta {
    id: "game.rom",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "nes_rom",
            name: "NES ROM (iNES / NES 2.0)",
            family: "game",
            mimes: &["application/x-nes-rom"],
            extensions: &["nes"],
            magic: &[Magic::prefix(b"NES\x1a")],
            parent: None,
        },
        // No signature: the internal header is sniffed with the extension.
        FormatSpec {
            id: "snes_rom",
            name: "Super NES ROM",
            family: "game",
            mimes: &["application/vnd.nintendo.snes.rom"],
            extensions: &["sfc", "smc"],
            magic: &[],
            parent: None,
        },
        // The first bytes of the boot logo every cartridge carries.
        FormatSpec {
            id: "gameboy_rom",
            name: "Game Boy / Game Boy Color ROM",
            family: "game",
            mimes: &["application/x-gameboy-rom", "application/x-gameboy-color-rom"],
            extensions: &["gb", "gbc", "sgb"],
            magic: &[Magic::at(0x104, &[0xCE, 0xED, 0x66, 0x66])],
            parent: None,
        },
        FormatSpec {
            id: "gba_rom",
            name: "Game Boy Advance ROM",
            family: "game",
            mimes: &["application/x-gba-rom"],
            extensions: &["gba", "agb"],
            magic: &[Magic::at(4, &[0x24, 0xFF, 0xAE, 0x51, 0x69, 0x9A])],
            parent: None,
        },
        FormatSpec {
            id: "n64_rom",
            name: "Nintendo 64 ROM",
            family: "game",
            mimes: &["application/x-n64-rom"],
            extensions: &["z64", "n64", "v64"],
            magic: &[
                Magic::prefix(&[0x80, 0x37, 0x12, 0x40]),
                Magic::prefix(&[0x37, 0x80, 0x40, 0x12]),
                Magic::prefix(&[0x40, 0x12, 0x37, 0x80]),
            ],
            parent: None,
        },
        // `.md` is Markdown: Mega Drive ROMs are found by their header.
        FormatSpec {
            id: "megadrive_rom",
            name: "Sega Mega Drive / Genesis ROM",
            family: "game",
            mimes: &["application/x-genesis-rom"],
            extensions: &["gen", "32x"],
            magic: &[Magic::at(0x100, b"SEGA")],
            parent: None,
        },
    ],
};

fn region_letter(c: u8) -> Option<&'static str> {
    Some(match c {
        b'J' => "Japan",
        b'E' => "North America",
        b'P' | b'X' | b'Y' => "Europe",
        b'D' => "Germany",
        b'F' => "France",
        b'I' => "Italy",
        b'S' => "Spain",
        b'U' => "Australia",
        b'A' => "Asia / all regions",
        b'K' => "Korea",
        b'C' => "China",
        b'H' => "Netherlands",
        b'W' => "Sweden / Scandinavia",
        b'N' => "Canada",
        b'B' => "Brazil",
        _ => return None,
    })
}

fn set_opt(m: &mut Map<String, Value>, k: &str, v: Option<impl Into<Value>>) {
    if let Some(v) = v {
        m.insert(k.into(), v.into());
    }
}

#[allow(clippy::too_many_lines)] // one field per header byte
fn nes(cx: &mut Context<'_>, b: &[u8], len: u64) -> Result<(), ExtractError> {
    let h = b.get(..16).ok_or(ExtractError::Malformed("short iNES header".into()))?;
    let nes2 = h[7] & 0x0C == 0x08;
    // Archaic headers have text ("DiskDude!") in bytes 7–15.
    let dirty = !nes2 && h[12..16].iter().any(|&c| c != 0);
    let mut mapper = u32::from(h[6] >> 4);
    if !dirty {
        mapper |= u32::from(h[7] & 0xF0);
    }
    let size = |lsb: u8, msb: u8, unit: u64| -> u64 {
        if msb == 0x0F {
            // Exponent-multiplier notation.
            let exp = u32::from(lsb >> 2);
            let mul = u64::from(lsb & 3) * 2 + 1;
            1u64.checked_shl(exp.min(62)).unwrap_or(0).saturating_mul(mul)
        } else {
            (u64::from(msb) << 8 | u64::from(lsb)) * unit
        }
    };
    let (prg, chr) = if nes2 {
        mapper |= u32::from(h[8] & 0x0F) << 8;
        (size(h[4], h[9] & 0x0F, 16384), size(h[5], h[9] >> 4, 8192))
    } else {
        (u64::from(h[4]) * 16384, u64::from(h[5]) * 8192)
    };
    let mut m = Map::new();
    m.insert("header".into(), if nes2 { "NES 2.0" } else { "iNES" }.into());
    m.insert("prg_rom_bytes".into(), prg.into());
    m.insert("chr_rom_bytes".into(), chr.into());
    if chr == 0 {
        m.insert("chr_ram".into(), true.into());
    }
    m.insert("mapper".into(), mapper.into());
    set_opt(&mut m, "mapper_name", mapper_name(mapper));
    if nes2 && h[8] >> 4 != 0 {
        m.insert("submapper".into(), (h[8] >> 4).into());
    }
    let mirroring = if h[6] & 0x08 != 0 {
        "four-screen"
    } else if h[6] & 1 != 0 {
        "vertical"
    } else {
        "horizontal"
    };
    m.insert("mirroring".into(), mirroring.into());
    m.insert("battery".into(), (h[6] & 2 != 0).into());
    let trainer = h[6] & 4 != 0;
    if trainer {
        m.insert("trainer".into(), true.into());
    }
    let console = match h[7] & 3 {
        0 => "NES / Famicom",
        1 => "Vs. System",
        2 => "PlayChoice-10",
        _ if nes2 => match h[13] & 0x0F {
            1 => "Vs. System",
            2 => "PlayChoice-10",
            3 => "Famiclone (decimal mode)",
            4 => "EPSM",
            5 => "VT01",
            6 => "VT02",
            7 => "VT03",
            8 => "VT09",
            9 => "VT32",
            10 => "VT369",
            11 => "UM6578",
            12 => "Famicom Network System",
            _ => "extended",
        },
        _ => "extended",
    };
    m.insert("console".into(), console.into());
    let timing = if nes2 {
        Some(["NTSC", "PAL", "multiple-region", "Dendy"][usize::from(h[12] & 3)])
    } else if !dirty {
        Some(if h[9] & 1 != 0 { "PAL" } else { "NTSC" })
    } else {
        None
    };
    set_opt(&mut m, "timing", timing);
    if nes2 {
        let ram = |shift: u8| if shift == 0 { 0 } else { 64u64 << shift };
        for (k, v) in [
            ("prg_ram_bytes", ram(h[10] & 0x0F)),
            ("prg_nvram_bytes", ram(h[10] >> 4)),
            ("chr_ram_bytes", ram(h[11] & 0x0F)),
            ("chr_nvram_bytes", ram(h[11] >> 4)),
        ] {
            if v > 0 {
                m.insert(k.into(), v.into());
            }
        }
    } else if !dirty && h[8] > 0 {
        m.insert("prg_ram_bytes".into(), (u64::from(h[8]) * 8192).into());
    }
    // NES 2.0 exponent sizes can be huge: saturate.
    let expected = (16u64 + if trainer { 512 } else { 0 }).saturating_add(prg).saturating_add(chr);
    let actual = len;
    if actual < expected {
        m.insert("truncated".into(), true.into());
    } else if actual > expected {
        m.insert("trailing_bytes".into(), (actual - expected).into());
    }
    for (k, v) in m {
        cx.format_set(&k, v);
    }
    Ok(())
}

fn mapper_name(m: u32) -> Option<&'static str> {
    Some(match m {
        0 => "NROM",
        1 => "MMC1",
        2 => "UxROM",
        3 => "CNROM",
        4 => "MMC3",
        5 => "MMC5",
        7 => "AxROM",
        9 => "MMC2",
        10 => "MMC4",
        11 => "Color Dreams",
        13 => "CPROM",
        19 => "Namco 163",
        24 | 26 => "VRC6",
        66 => "GxROM",
        69 => "Sunsoft FME-7",
        71 => "Camerica / Codemasters",
        85 => "VRC7",
        111 => "GTROM",
        _ => return None,
    })
}

/// Sum of a SNES ROM's bytes, the remainder past the largest power of two
/// mirrored up to it.
fn snes_sum(rom: &[u8]) -> u16 {
    let sum = |s: &[u8]| s.iter().fold(0u32, |a, &x| a.wrapping_add(u32::from(x)));
    if rom.is_empty() {
        return 0;
    }
    let base = 1usize << (usize::BITS - 1 - rom.len().leading_zeros());
    let mut total = sum(&rom[..base]);
    let rest = &rom[base..];
    if !rest.is_empty() {
        let part = sum(rest);
        let reps = u32::try_from(base / rest.len()).unwrap_or(u32::MAX);
        total = total.wrapping_add(part.wrapping_mul(reps));
    }
    (total & 0xFFFF) as u16
}

/// How plausible an SNES header at `at` is.
fn snes_score(rom: &[u8], at: usize, mode_hi: bool) -> i32 {
    let Some(h) = rom.get(at..at + 0x40) else { return -100 };
    let mut s = 0;
    let chk = u16::from_le_bytes([h[0x1E], h[0x1F]]);
    let cmp = u16::from_le_bytes([h[0x1C], h[0x1D]]);
    if chk ^ cmp == 0xFFFF {
        s += 4;
    }
    let map = h[0x15] & !0x10;
    if (map == 0x20 && !mode_hi) || (matches!(map, 0x21 | 0x25) && mode_hi) || map == 0x22 || map == 0x23 {
        s += 3;
    }
    if h[..21].iter().all(|&c| (0x20..0x7F).contains(&c) || c >= 0xA0) {
        s += 2;
    }
    if h[0x17] >= 7 && h[0x17] <= 13 {
        s += 1;
    }
    // The reset vector points into ROM.
    if u16::from_le_bytes([h[0x3C], h[0x3D]]) >= 0x8000 {
        s += 1;
    }
    s
}

fn snes(cx: &mut Context<'_>, b: &[u8], whole: bool) -> Result<(), ExtractError> {
    let copier = b.len() % 1024 == 512;
    let rom = if copier { &b[512..] } else { b };
    let (at, layout) = [(0x7FC0, "LoROM", false), (0xFFC0, "HiROM", true), (0x40_FFC0, "ExHiROM", true)]
        .into_iter()
        .map(|(at, name, hi)| (snes_score(rom, at, hi), at, name))
        .filter(|(s, ..)| *s >= 4)
        .max_by_key(|(s, at, _)| (*s, usize::MAX - at))
        .map(|(_, at, name)| (at, name))
        .ok_or(ExtractError::Malformed("no SNES internal header".into()))?;
    let h = &rom[at..at + 0x40];
    let mut m = Map::new();
    if copier {
        m.insert("copier_header".into(), true.into());
    }
    m.insert("layout".into(), layout.into());
    let title = fixed(&h[..21]);
    if let Some(t) = &title {
        cx.content().title(t.clone());
    }
    set_opt(&mut m, "title", title);
    let mode = h[0x15];
    m.insert("map_mode".into(), format!("0x{mode:02x}").into());
    m.insert("speed".into(), if mode & 0x10 != 0 { "FastROM" } else { "SlowROM" }.into());
    let ty = h[0x16];
    let chip = match ty {
        0x00 => "ROM".to_string(),
        0x01 => "ROM + RAM".to_string(),
        0x02 => "ROM + RAM + battery".to_string(),
        _ => {
            let co = match ty >> 4 {
                0 => "DSP",
                1 => "Super FX",
                2 => "OBC1",
                3 => "SA-1",
                4 => "S-DD1",
                5 => "S-RTC",
                0xE => "other",
                0xF => "custom",
                _ => "unknown",
            };
            let base = match ty & 0x0F {
                3 => "ROM + ",
                4 => "ROM + RAM + ",
                5 => "ROM + RAM + battery + ",
                6 => "ROM + battery + ",
                _ => "",
            };
            format!("{base}{co}")
        }
    };
    m.insert("chipset".into(), chip.into());
    if h[0x17] > 0 && h[0x17] < 16 {
        m.insert("declared_rom_bytes".into(), (1024u64 << h[0x17]).into());
    }
    if h[0x18] > 0 && h[0x18] < 16 {
        m.insert("ram_size_bytes".into(), (1024u64 << h[0x18]).into());
    }
    let region = [
        "Japan",
        "North America",
        "Europe",
        "Sweden / Scandinavia",
        "Finland",
        "Denmark",
        "France",
        "Netherlands",
        "Spain",
        "Germany",
        "Italy",
        "China",
        "Indonesia",
        "Korea",
        "international",
        "Canada",
        "Brazil",
        "Australia",
    ]
    .get(usize::from(h[0x19]));
    set_opt(&mut m, "region", region.copied());
    // Developer ID 0x33: the extended header precedes the standard one.
    if h[0x1A] == 0x33 && at >= 0x10 {
        let x = &rom[at - 0x10..at];
        set_opt(&mut m, "maker_code", fixed(&x[..2]));
        set_opt(&mut m, "game_code", fixed(&x[2..6]));
    } else {
        m.insert("maker_code".into(), format!("{:02X}", h[0x1A]).into());
    }
    m.insert("version".into(), format!("1.{}", h[0x1B]).into());
    let chk = u16::from_le_bytes([h[0x1E], h[0x1F]]);
    m.insert("checksum".into(), format!("{chk:04x}").into());
    if whole {
        m.insert("checksum_valid".into(), (snes_sum(rom) == chk).into());
    }
    for (k, v) in m {
        cx.format_set(&k, v);
    }
    Ok(())
}

fn gameboy(cx: &mut Context<'_>, b: &[u8], whole: bool) -> Result<(), ExtractError> {
    let h = b.get(0x100..0x150).ok_or(ExtractError::Malformed("short Game Boy header".into()))?;
    let mut m = Map::new();
    let cgb = h[0x43];
    // Titles shrink to 15 characters with the CGB flag and to 11 with a
    // manufacturer code (four capital letters).
    let manufacturer = &h[0x3F..0x43];
    let (title, maker) = if cgb & 0x80 != 0 && manufacturer.iter().all(u8::is_ascii_uppercase) {
        (fixed(&h[0x34..0x3F]), fixed(manufacturer))
    } else if cgb & 0x80 != 0 {
        (fixed(&h[0x34..0x43]), None)
    } else {
        (fixed(&h[0x34..0x44]), None)
    };
    if let Some(t) = &title {
        cx.content().title(t.clone());
    }
    set_opt(&mut m, "title", title);
    set_opt(&mut m, "manufacturer_code", maker);
    let platform = match cgb {
        0xC0 => "Game Boy Color only",
        0x80 => "Game Boy Color enhanced",
        _ => "Game Boy",
    };
    m.insert("platform".into(), platform.into());
    if h[0x46] == 0x03 {
        m.insert("super_game_boy".into(), true.into());
    }
    let ty = h[0x47];
    m.insert("cartridge_type".into(), gb_cart(ty).map_or_else(|| format!("0x{ty:02x}"), str::to_string).into());
    if h[0x48] <= 8 {
        m.insert("declared_rom_bytes".into(), (32768u64 << h[0x48]).into());
    }
    let ram = match h[0x49] {
        2 => Some(8192u64),
        3 => Some(32768),
        4 => Some(131_072),
        5 => Some(65536),
        _ => None,
    };
    set_opt(&mut m, "ram_size_bytes", ram);
    m.insert("region".into(), if h[0x4A] == 0 { "Japan" } else { "overseas" }.into());
    let licensee = if h[0x4B] == 0x33 { fixed(&h[0x44..0x46]) } else { Some(format!("{:02X}", h[0x4B])) };
    set_opt(&mut m, "licensee_code", licensee);
    m.insert("version".into(), h[0x4C].into());
    let hsum = h[0x34..0x4D].iter().fold(0u8, |x, &c| x.wrapping_sub(c).wrapping_sub(1));
    m.insert("header_checksum_valid".into(), (hsum == h[0x4D]).into());
    let global = u16::from_be_bytes([h[0x4E], h[0x4F]]);
    let sum = b
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 0x14E && *i != 0x14F)
        .fold(0u16, |a, (_, &x)| a.wrapping_add(u16::from(x)));
    m.insert("global_checksum".into(), format!("{global:04x}").into());
    if whole {
        m.insert("global_checksum_valid".into(), (sum == global).into());
    }
    for (k, v) in m {
        cx.format_set(&k, v);
    }
    Ok(())
}

fn gb_cart(t: u8) -> Option<&'static str> {
    Some(match t {
        0x00 => "ROM only",
        0x01 => "MBC1",
        0x02 => "MBC1 + RAM",
        0x03 => "MBC1 + RAM + battery",
        0x05 => "MBC2",
        0x06 => "MBC2 + battery",
        0x08 => "ROM + RAM",
        0x09 => "ROM + RAM + battery",
        0x0B => "MMM01",
        0x0C => "MMM01 + RAM",
        0x0D => "MMM01 + RAM + battery",
        0x0F => "MBC3 + timer + battery",
        0x10 => "MBC3 + timer + RAM + battery",
        0x11 => "MBC3",
        0x12 => "MBC3 + RAM",
        0x13 => "MBC3 + RAM + battery",
        0x19 => "MBC5",
        0x1A => "MBC5 + RAM",
        0x1B => "MBC5 + RAM + battery",
        0x1C => "MBC5 + rumble",
        0x1D => "MBC5 + rumble + RAM",
        0x1E => "MBC5 + rumble + RAM + battery",
        0x20 => "MBC6",
        0x22 => "MBC7 + sensor + rumble + RAM + battery",
        0xFC => "Pocket Camera",
        0xFD => "Bandai TAMA5",
        0xFE => "HuC3",
        0xFF => "HuC1 + RAM + battery",
        _ => return None,
    })
}

fn gba(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let h = b.get(..0xC0).ok_or(ExtractError::Malformed("short GBA header".into()))?;
    let mut m = Map::new();
    let title = fixed(&h[0xA0..0xAC]);
    if let Some(t) = &title {
        cx.content().title(t.clone());
    }
    set_opt(&mut m, "title", title);
    let code = fixed(&h[0xAC..0xB0]);
    if let Some(c) = &code {
        set_opt(&mut m, "region", c.as_bytes().get(3).copied().and_then(region_letter));
    }
    set_opt(&mut m, "game_code", code);
    set_opt(&mut m, "maker_code", fixed(&h[0xB0..0xB2]));
    m.insert("version".into(), h[0xBC].into());
    let chk = h[0xA0..0xBD].iter().fold(0u8, |a, &x| a.wrapping_sub(x)).wrapping_sub(0x19);
    m.insert("header_checksum_valid".into(), (chk == h[0xBD] && h[0xB2] == 0x96).into());
    for (k, v) in m {
        cx.format_set(&k, v);
    }
    Ok(())
}

fn n64(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let raw = b.get(..0x40).ok_or(ExtractError::Malformed("short N64 header".into()))?;
    // Normalise to big-endian (.z64).
    let (order, h): (&str, Vec<u8>) = match raw[..4] {
        [0x80, ..] => ("big-endian (z64)", raw.to_vec()),
        [0x37, ..] => ("byte-swapped (v64)", raw.as_chunks::<2>().0.iter().flat_map(|c| [c[1], c[0]]).collect()),
        _ => ("little-endian (n64)", raw.as_chunks::<4>().0.iter().flat_map(|c| [c[3], c[2], c[1], c[0]]).collect()),
    };
    let be = |i: usize| u32::from_be_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]);
    let mut m = Map::new();
    m.insert("byte_order".into(), order.into());
    let title = fixed(&h[0x20..0x34]);
    if let Some(t) = &title {
        cx.content().title(t.clone());
    }
    set_opt(&mut m, "title", title);
    let media = match h[0x3B] {
        b'N' => Some("cartridge"),
        b'D' => Some("64DD disk"),
        b'C' => Some("cartridge with 64DD expansion"),
        b'E' => Some("64DD expansion"),
        b'Z' => Some("Aleck64"),
        _ => None,
    };
    set_opt(&mut m, "media", media);
    if let Some(code) = fixed(&h[0x3B..0x3F]).filter(|c| c.len() == 4 && c.bytes().all(|c| c.is_ascii_alphanumeric())) {
        m.insert("game_code".into(), code.into());
    }
    set_opt(&mut m, "region", region_letter(h[0x3E]));
    m.insert("version".into(), h[0x3F].into());
    m.insert("crc1".into(), format!("{:08x}", be(0x10)).into());
    m.insert("crc2".into(), format!("{:08x}", be(0x14)).into());
    let clock = be(0x04) & 0xFFFF_FFF0;
    if clock != 0 {
        m.insert("clock_rate".into(), clock.into());
    }
    m.insert("entry_point".into(), format!("0x{:08x}", be(0x08)).into());
    // libultra: 0x0000_144B is release 2.0K (major in the third byte, the
    // revision letter in the fourth).
    let lib = be(0x0C);
    if lib >> 16 == 0 && (lib >> 8) & 0xFF > 0 && ((lib & 0xFF) as u8).is_ascii_uppercase() {
        let major = (lib >> 8) & 0xFF;
        m.insert("libultra".into(), format!("{}.{}{}", major / 10, major % 10, char::from((lib & 0xFF) as u8)).into());
    }
    for (k, v) in m {
        cx.format_set(&k, v);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // one field per header field
fn megadrive(cx: &mut Context<'_>, b: &[u8], whole: bool) -> Result<(), ExtractError> {
    let h = b.get(0x100..0x200).ok_or(ExtractError::Malformed("short Mega Drive header".into()))?;
    let mut m = Map::new();
    let system = fixed(&h[..0x10]).unwrap_or_default();
    let platform = if system.contains("32X") {
        "32X"
    } else if system.contains("PICO") {
        "Pico"
    } else if system.contains("GENESIS") {
        "Genesis"
    } else {
        "Mega Drive"
    };
    m.insert("system".into(), system.into());
    m.insert("platform".into(), platform.into());
    let copyright = fixed(&h[0x10..0x20]);
    if let Some(c) = &copyright {
        // "(C)SEGA 1991.APR": the publisher's code, the release year and month.
        let body = c.trim_start_matches("(C)").trim();
        if let Some((who, date)) = body.split_once(' ').or_else(|| body.split_at_checked(4)) {
            let who = who.trim();
            if !who.is_empty() {
                m.insert("publisher_code".into(), who.into());
            }
            let date = date.trim();
            if date.len() >= 4 && date[..4].bytes().all(|c| c.is_ascii_digit()) {
                m.insert("release".into(), date.replace('.', " ").into());
            }
        }
        cx.rights().copyright(c.clone());
    }
    set_opt(&mut m, "copyright", copyright);
    let domestic = fixed(&h[0x20..0x50]).map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "));
    let overseas = fixed(&h[0x50..0x80]).map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "));
    if let Some(t) = overseas.as_ref().or(domestic.as_ref()) {
        cx.content().title(t.clone());
    }
    set_opt(&mut m, "domestic_title", domestic);
    set_opt(&mut m, "overseas_title", overseas);
    set_opt(&mut m, "serial", fixed(&h[0x80..0x8E]));
    let be32 = |i: usize| u32::from_be_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]);
    let devices: Vec<Value> = h[0x90..0xA0]
        .iter()
        .filter_map(|&c| {
            Some(match c {
                b'J' => "3-button controller",
                b'6' => "6-button controller",
                b'0' => "Master System controller",
                b'A' => "analog joystick",
                b'4' => "multitap",
                b'G' => "light gun",
                b'L' => "Activator",
                b'M' => "mouse",
                b'B' => "trackball",
                b'T' => "tablet",
                b'V' => "paddle",
                b'K' => "keyboard",
                b'R' => "serial port",
                b'P' => "printer",
                b'C' => "CD-ROM",
                b'F' => "floppy drive",
                b'D' => "download",
                _ => return None,
            })
        })
        .map(Value::from)
        .collect();
    if !devices.is_empty() {
        m.insert("devices".into(), devices.into());
    }
    m.insert("rom_range".into(), format!("0x{:06x}-0x{:06x}", be32(0xA0), be32(0xA4)).into());
    m.insert("ram_range".into(), format!("0x{:06x}-0x{:06x}", be32(0xA8), be32(0xAC)).into());
    if &h[0xB0..0xB2] == b"RA" {
        m.insert("extra_memory".into(), format!("0x{:06x}-0x{:06x}", be32(0xB4), be32(0xB8)).into());
    }
    let reg = fixed(&h[0xF0..0xF3]).unwrap_or_default();
    let regions: Vec<Value> = if reg.len() == 1 && reg.as_bytes()[0].is_ascii_hexdigit() && !"JUE".contains(&reg) {
        // The newer form: a hex digit, bit 0 Japan, 2 Americas, 3 Europe.
        let v = u8::from_str_radix(&reg, 16).unwrap_or(0);
        [(1, "Japan"), (4, "Americas"), (8, "Europe")]
            .into_iter()
            .filter(|(bit, _)| v & bit != 0)
            .map(|(_, r)| r.into())
            .collect()
    } else {
        reg.chars()
            .filter_map(|c| match c {
                'J' => Some("Japan"),
                'U' => Some("Americas"),
                'E' => Some("Europe"),
                _ => None,
            })
            .map(Value::from)
            .collect()
    };
    if !regions.is_empty() {
        m.insert("regions".into(), regions.into());
    }
    let chk = u16::from_be_bytes([h[0x8E], h[0x8F]]);
    let sum = b
        .get(0x200..)
        .unwrap_or(&[])
        .chunks(2)
        .fold(0u16, |a, w| a.wrapping_add(u16::from_be_bytes([w[0], w.get(1).copied().unwrap_or(0)])));
    m.insert("checksum".into(), format!("{chk:04x}").into());
    if whole {
        m.insert("checksum_valid".into(), (sum == chk).into());
    }
    for (k, v) in m {
        cx.format_set(&k, v);
    }
    Ok(())
}

impl Extractor for Rom {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or("");
        // SNES: no signature; a plausible internal header in the head.
        if matches!(ext, "sfc" | "smc" | "swc" | "fig") {
            let rom = if probe.len % 1024 == 512 { h.get(512..)? } else { h };
            let best = [(0x7FC0, false), (0xFFC0, true)].iter().map(|&(at, hi)| snes_score(rom, at, hi)).max()?;
            return (best >= 7).then_some(Sniff { format: "snes_rom", confidence: 0.97 });
        }
        // Mega Drive: "SEGA" plus a known system name, so a stray "SEGA" at
        // 0x100 is not enough without the extension.
        if h.get(0x100..0x104) == Some(b"SEGA")
            && (matches!(ext, "gen" | "md" | "smd" | "bin" | "32x")
                || h.get(0x104..0x110).is_some_and(|s| s.starts_with(b" MEGA") || s.starts_with(b" GENESIS")))
        {
            return Some(Sniff { format: "megadrive_rom", confidence: 0.97 });
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let id = cx.format_id().to_string();
        let len = src.len();
        // Checksums need the whole ROM; past the read limit they are left out.
        let (b, cut) = cx.read_bytes(src)?;
        cx.format_set("rom_size_bytes", len);
        match id.as_str() {
            "nes_rom" => nes(cx, &b, len),
            "snes_rom" => snes(cx, &b, !cut),
            "gameboy_rom" => gameboy(cx, &b, !cut),
            "gba_rom" => gba(cx, &b),
            "n64_rom" => n64(cx, &b),
            _ => megadrive(cx, &b, !cut),
        }
    }
}

crate::register_extractor!(Rom);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snes_checksum_mirrors_the_remainder() {
        // 3 bytes: the 2-byte power-of-two part plus the last byte twice.
        assert_eq!(snes_sum(&[1, 2, 3]), 1 + 2 + 3 + 3);
        assert_eq!(snes_sum(&[0xFF; 4]), 0x3FC);
    }

    crate::fixture_tests!("nes_rom", "snes_rom", "gameboy_rom", "gba_rom", "n64_rom", "megadrive_rom");
}
