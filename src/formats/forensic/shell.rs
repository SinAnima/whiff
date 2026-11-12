//! Windows shell artefacts:
//! * shortcuts (`.lnk`): target (from the link info or the shell item
//!   list), arguments, working directory, icon, the target's times, size
//!   and attributes, the volume (drive type, serial, label) or network
//!   share, the tracker's machine ID and droid times, known folder; a
//!   shortcut that starts a command interpreter with arguments is a risk;
//! * jump lists (`automaticDestinations-ms`, a compound file of shortcuts
//!   with a `DestList` index; `customDestinations-ms`): entry and pinned
//!   counts, the shortcuts' targets;
//! * Recycle Bin `$I` files: original path, size and deletion time;
//! * Windows Vista–11 thumbnail caches (`thumbcache_*.db`, `CMMM`, and the
//!   `IMMM` index): Windows version, thumbnail size class, entries with
//!   their image type and pixel size;
//! * Prefetch (`.pf`, Windows XP to 11, LZXPRESS-compressed since 8): the
//!   executable, hash, run count, last run times, volumes, how many files
//!   it loaded.
//!
//! User names in paths are hidden when privacy is strict.
//!
//! Specifications: Microsoft "MS-SHLLINK"; libyal "Windows Explorer
//! Thumbnail Cache database format"; libyal "Windows Jump List",
//! "Windows Shell Item" and "Windows Prefetch File (PF) format".

use serde_json::{Map, Value, json};

use super::{asciiz, filetime, filetime_at, le, le_usize, user_path, utf16z, xpress};
use crate::plugin::{
    Cfb, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, guid,
};

/// Extractor for shell artefacts.
pub struct Shell;

static META: ExtractorMeta = ExtractorMeta {
    id: "forensic.shell",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "lnk",
            name: "Windows shortcut",
            family: "forensic",
            mimes: &["application/x-ms-shortcut"],
            extensions: &["lnk"],
            magic: &[Magic::prefix(
                b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46",
            )],
            parent: None,
        },
        FormatSpec {
            id: "jump_list",
            name: "Windows jump list",
            family: "forensic",
            mimes: &[],
            extensions: &["automaticdestinations-ms"],
            magic: &[],
            parent: Some("cfb"),
        },
        FormatSpec {
            id: "custom_jump_list",
            name: "Windows custom jump list",
            family: "forensic",
            mimes: &[],
            extensions: &["customdestinations-ms"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "recycle_bin_info",
            name: "Windows Recycle Bin $I file",
            family: "forensic",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "prefetch",
            name: "Windows Prefetch",
            family: "forensic",
            mimes: &[],
            extensions: &["pf"],
            magic: &[Magic::at(4, b"SCCA"), Magic::prefix(b"MAM\x04"), Magic::prefix(b"MAM\x84")],
            parent: None,
        },
        FormatSpec {
            id: "thumbcache",
            name: "Windows thumbnail cache (thumbcache)",
            family: "forensic",
            mimes: &[],
            extensions: &["db"],
            magic: &[Magic::prefix(b"CMMM"), Magic::prefix(b"IMMM")],
            parent: None,
        },
    ],
};

/// Shortcut targets listed from one jump list.
const MAX_TARGETS: usize = 64;

/// Programs whose shortcuts with arguments run scripts or commands.
const INTERPRETERS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msiexec.exe",
    "forfiles.exe",
    "conhost.exe",
    "curl.exe",
];

fn u32_at(b: &[u8], at: usize) -> usize {
    b.get(at..at + 4).map_or(0, le_usize)
}

fn u16_at(b: &[u8], at: usize) -> usize {
    b.get(at..at + 2).map_or(0, le_usize)
}

fn drive_type(t: usize) -> &'static str {
    match t {
        1 => "no_root_dir",
        2 => "removable",
        3 => "fixed",
        4 => "remote",
        5 => "cdrom",
        6 => "ramdisk",
        _ => "unknown",
    }
}

fn attributes(a: usize) -> Vec<&'static str> {
    [
        (0x1, "read_only"),
        (0x2, "hidden"),
        (0x4, "system"),
        (0x10, "directory"),
        (0x20, "archive"),
        (0x80, "normal"),
        (0x100, "temporary"),
        (0x800, "compressed"),
        (0x1000, "offline"),
        (0x4000, "encrypted"),
    ]
    .into_iter()
    .filter(|&(bit, _)| a & bit != 0)
    .map(|(_, n)| n)
    .collect()
}

/// A path from a shell item list: volume and file entry names.
fn idlist_path(items: &[u8]) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut at = 0;
    while at + 2 <= items.len() {
        let size = u16_at(items, at);
        if size == 0 {
            break;
        }
        let item = items.get(at..at + size)?;
        let kind = *item.get(2)?;
        match kind & 0x70 {
            0x20 => {
                let v = asciiz(item.get(3..)?);
                parts.push(v.trim_end_matches('\\').to_string());
            }
            0x30 => {
                // Short name, then (in the extension block) the long name.
                let short = asciiz(item.get(14..)?);
                let long = item
                    .windows(4)
                    .position(|w| w == [0x04, 0x00, 0xef, 0xbe])
                    .and_then(|sig| {
                        let ext = sig.checked_sub(4)?;
                        let version = u16_at(item, ext + 2);
                        let name_at = match version {
                            3 => 18,
                            7 => 26,
                            8 => 30,
                            9 => 46,
                            _ => return None,
                        };
                        Some(utf16z(item.get(ext + name_at..)?))
                    })
                    .filter(|s| !s.is_empty());
                parts.push(long.unwrap_or(short));
            }
            _ => {}
        }
        at += size;
    }
    (!parts.is_empty()).then(|| parts.join("\\"))
}

/// A shortcut's facts, its target and its arguments.
type Shortcut = (Map<String, Value>, Option<String>, Option<String>);

/// A shortcut's facts, from a buffer holding one shell link.
#[allow(clippy::too_many_lines)] // header, ID list, link info, strings, extra data
fn shortcut(b: &[u8], cx: &mut Context<'_>) -> Option<Shortcut> {
    if b.len() < 0x4c || u32_at(b, 0) != 0x4c {
        return None;
    }
    let flags = u32_at(b, 20);
    let unicode = flags & 0x80 != 0;
    let mut m = Map::new();
    let attrs = attributes(u32_at(b, 24));
    if !attrs.is_empty() {
        m.insert("target_attributes".into(), json!(attrs));
    }
    for (at, key) in [(28, "target_created"), (36, "target_accessed"), (44, "target_modified")] {
        if let Some(t) = filetime_at(b, at) {
            m.insert(key.into(), t.into());
        }
    }
    m.insert("target_size".into(), u32_at(b, 52).into());
    m.insert(
        "show_command".into(),
        match u32_at(b, 60) {
            3 => "maximized",
            7 => "minimized",
            _ => "normal",
        }
        .into(),
    );
    let mut at = 0x4c;
    let mut target: Option<String> = None;
    if flags & 0x1 != 0 {
        let n = u16_at(b, at);
        target = b.get(at + 2..at + 2 + n).and_then(idlist_path);
        at += 2 + n;
    }
    if flags & 0x2 != 0 && flags & 0x100 == 0 {
        let li = b.get(at..at + u32_at(b, at))?;
        let hsize = u32_at(li, 4);
        let lflags = u32_at(li, 8);
        let cstr = |off: usize| li.get(off..).map(asciiz).filter(|s| !s.is_empty());
        let wstr = |off: usize| li.get(off..).map(utf16z).filter(|s| !s.is_empty());
        if lflags & 1 != 0 {
            let v = u32_at(li, 12);
            if let Some(vol) = li.get(v..) {
                let mut vm = Map::new();
                vm.insert("drive_type".into(), drive_type(u32_at(vol, 4)).into());
                vm.insert("serial".into(), format!("{:08X}", u32_at(vol, 8)).into());
                let label_off = u32_at(vol, 12);
                let label = if label_off == 0x14 {
                    vol.get(u32_at(vol, 16)..).map(utf16z)
                } else {
                    vol.get(label_off..).map(asciiz)
                };
                if let Some(l) = label.filter(|l| !l.is_empty()) {
                    vm.insert("label".into(), l.into());
                }
                m.insert("volume".into(), Value::Object(vm));
            }
            let base = if hsize >= 0x24 { wstr(u32_at(li, 28)) } else { None }.or_else(|| cstr(u32_at(li, 16)));
            let suffix = if hsize >= 0x24 { wstr(u32_at(li, 32)) } else { None }.or_else(|| cstr(u32_at(li, 24)));
            if let Some(p) = base {
                target = Some(format!("{p}{}", suffix.unwrap_or_default()));
            }
        }
        if lflags & 2 != 0 {
            let n = u32_at(li, 20);
            if let Some(net) = li.get(n..) {
                let name_off = u32_at(net, 8);
                let share = if name_off > 0x14 {
                    net.get(u32_at(net, 20)..).map(utf16z)
                } else {
                    net.get(name_off..).map(asciiz)
                };
                if let Some(s) = share.filter(|s| !s.is_empty()) {
                    let suffix = cstr(u32_at(li, 24)).unwrap_or_default();
                    m.insert("network_share".into(), user_path(cx, &s).into());
                    if target.is_none() {
                        target = Some(format!("{s}\\{suffix}"));
                    }
                }
            }
        }
        at += li.len();
    }
    let mut strings = Vec::new();
    for (bit, key) in [
        (0x4, "description"),
        (0x8, "relative_path"),
        (0x10, "working_directory"),
        (0x20, "arguments"),
        (0x40, "icon_location"),
    ] {
        if flags & bit == 0 {
            continue;
        }
        let n = u16_at(b, at);
        let bytes = if unicode { 2 * n } else { n };
        let raw = b.get(at + 2..at + 2 + bytes)?;
        let s = if unicode {
            String::from_utf16_lossy(&raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect::<Vec<_>>())
        } else {
            raw.iter().map(|&c| char::from(c)).collect()
        };
        strings.push((key, s));
        at += 2 + bytes;
    }
    let mut args = None;
    for (key, s) in strings {
        if key == "arguments" {
            args = Some(s.clone());
        }
        let v = if key == "description" { s } else { user_path(cx, &s) };
        m.insert(key.into(), crate::plugin::truncate_chars(&v, 2000).into());
    }
    // Extra data blocks.
    while at + 8 <= b.len() {
        let size = u32_at(b, at);
        if size < 8 {
            break;
        }
        let Some(blk) = b.get(at..at + size) else { break };
        match u32_at(blk, 4) {
            0xa000_0001 => {
                let t = utf16z(blk.get(268..).unwrap_or_default());
                let t = if t.is_empty() { asciiz(blk.get(8..).unwrap_or_default()) } else { t };
                if !t.is_empty() {
                    m.insert("environment_target".into(), user_path(cx, &t).into());
                    target.get_or_insert(t);
                }
            }
            0xa000_0003 if blk.len() >= 96 => {
                let mut tr = Map::new();
                tr.insert("machine_id".into(), asciiz(&blk[16..32]).into());
                if let Some((time, node)) = droid(&blk[48..64]) {
                    if let Some(t) = time {
                        tr.insert("file_droid_created".into(), t.into());
                    }
                    if !cx.privacy_strict() {
                        tr.insert("mac_address".into(), node.into());
                    }
                }
                m.insert("tracker".into(), Value::Object(tr));
            }
            0xa000_000b => {
                if let Some(g) = blk.get(8..24).and_then(|g| guid(g.try_into().ok()?)) {
                    m.insert("known_folder".into(), g.into());
                }
            }
            0xa000_0006 => {
                m.insert("msi_advertised".into(), true.into());
            }
            _ => {}
        }
        at += size;
    }
    if let Some(t) = &target {
        m.insert("target".into(), user_path(cx, t).into());
    }
    Some((m, target, args))
}

/// The time and node (MAC address) of a version-1 UUID (a droid).
fn droid(g: &[u8]) -> Option<(Option<String>, String)> {
    if g.len() < 16 || g[7] >> 4 != 1 {
        return None;
    }
    let low = le(&g[0..4]);
    let mid = le(&g[4..6]);
    let high = le(&g[6..8]) & 0x0fff;
    // 100 ns intervals since 1582-10-15.
    let ticks = (high << 48) | (mid << 32) | low;
    let secs = i64::try_from(ticks / 10_000_000).ok()? - 12_219_292_800;
    let node = g[10..16].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
    Some((super::unix_time(secs), node))
}

/// `script_shortcut` for a shortcut that runs an interpreter with arguments.
fn check_command(target: Option<&str>, args: Option<&str>, cx: &mut Context<'_>) {
    let Some(t) = target else { return };
    let exe = t.rsplit(['\\', '/']).next().unwrap_or(t).to_ascii_lowercase();
    if INTERPRETERS.contains(&exe.as_str()) && args.is_some_and(|a| !a.trim().is_empty()) {
        cx.security().active_content("command_shortcut");
        cx.security().risk("script_shortcut", Some(exe));
    }
}

impl Extractor for Shell {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let name = probe.name.map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n))?;
        // A compound file named as a jump list (the DestList stream decides
        // it when the OLE extractor looks inside).
        if Cfb::is_cfb(h) && name.to_ascii_lowercase().ends_with(".automaticdestinations-ms") {
            return Some(Sniff { format: "jump_list", confidence: 0.97 });
        }
        if name.starts_with("$I") && h.len() >= 28 {
            let version = le(&h[..8]);
            let fits = match version {
                1 => probe.len == 544,
                2 => u32_at(h, 24) as u64 * 2 + 28 == probe.len,
                _ => false,
            };
            return fits.then_some(Sniff { format: "recycle_bin_info", confidence: 0.9 });
        }
        if name.to_ascii_lowercase().ends_with(".customdestinations-ms") && u32_at(h, 0) == 2 {
            return Some(Sniff { format: "custom_jump_list", confidence: 0.9 });
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "jump_list" => return jump_list(src, cx),
            "prefetch" => return prefetch(src, cx),
            _ => {}
        }
        let len = usize::try_from(src.len().min(cx.parse_limit() as u64)).unwrap_or(0);
        let b = src.read_vec(0, len)?;
        match cx.format_id() {
            "recycle_bin_info" => recycle(&b, cx),
            "thumbcache" => thumbcache(&b, cx),
            "custom_jump_list" => {
                custom(&b, cx);
                Ok(())
            }
            _ => {
                let (m, target, args) = shortcut(&b, cx).ok_or_else(|| ExtractError::malformed("shell link header"))?;
                if let Some(t) = m.get("target_modified").and_then(Value::as_str) {
                    let t = t.to_string();
                    cx.temporal().source("forensic.shell").content_date(crate::plugin::DateField::Modified, t, true);
                }
                for (k, v) in m {
                    cx.format_set(&k, v);
                }
                check_command(target.as_deref(), args.as_deref(), cx);
                Ok(())
            }
        }
    }
}

fn recycle(b: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("$I header");
    let version = le(b.get(..8).ok_or_else(bad)?);
    cx.format_set("version", version);
    cx.format_set("original_size", le(b.get(8..16).ok_or_else(bad)?));
    if let Some(t) = filetime_at(b, 16) {
        cx.format_set("deleted", t.clone());
        cx.temporal().source("forensic.shell").content_date(crate::plugin::DateField::Other, t, true);
    }
    let path =
        if version == 1 { utf16z(b.get(24..).unwrap_or_default()) } else { utf16z(b.get(28..).unwrap_or_default()) };
    cx.format_set("original_path", user_path(cx, &path));
    Ok(())
}

/// The shortcuts of a jump list, summarised.
fn targets(links: &[Vec<u8>], cx: &mut Context<'_>) -> Vec<Value> {
    let mut out = Vec::new();
    for l in links.iter().take(MAX_TARGETS) {
        if let Some((m, target, args)) = shortcut(l, cx) {
            check_command(target.as_deref(), args.as_deref(), cx);
            let mut e = Map::new();
            for k in ["target", "arguments", "target_modified"] {
                if let Some(v) = m.get(k) {
                    e.insert(k.into(), v.clone());
                }
            }
            out.push(Value::Object(e));
        }
    }
    out
}

fn jump_list(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let cfb = Cfb::open(src)?;
    let dest = cfb
        .read_path(src, "DestList", 1 << 20)
        .transpose()?
        .ok_or_else(|| ExtractError::malformed("jump list without DestList"))?;
    cx.format_set("destlist_version", u32_at(&dest, 0));
    cx.format_set("entries", u32_at(&dest, 4));
    cx.format_set("pinned", u32_at(&dest, 8));
    let mut links = Vec::new();
    let names: Vec<String> = cfb.entries.iter().map(|e| e.name.clone()).collect();
    for n in &names {
        if n.chars().all(|c| c.is_ascii_hexdigit())
            && !n.is_empty()
            && let Some(Ok(b)) = cfb.read_path(src, n, 1 << 20)
        {
            links.push(b);
        }
    }
    cx.format_set("shortcuts", links.len());
    let t = targets(&links, cx);
    cx.format_set("targets", t);
    Ok(())
}

/// `customDestinations-ms`: categories of shortcuts back to back.
fn custom(b: &[u8], cx: &mut Context<'_>) {
    const HEADER: &[u8] = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46";
    cx.format_set("version", u32_at(b, 0));
    cx.format_set("categories", u32_at(b, 4));
    let starts: Vec<usize> =
        b.windows(HEADER.len()).enumerate().filter(|(_, w)| *w == HEADER).map(|(i, _)| i).collect();
    let mut links = Vec::new();
    for (i, &s) in starts.iter().enumerate() {
        let end = starts.get(i + 1).copied().unwrap_or(b.len());
        links.push(b[s..end].to_vec());
    }
    cx.format_set("shortcuts", links.len());
    let t = targets(&links, cx);
    cx.format_set("targets", t);
}

/// Prefetch: decompress (`MAM`), then the file information by version.
#[allow(clippy::too_many_lines)] // one layout per Windows generation
fn prefetch(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = usize::try_from(src.len().min(cx.parse_limit() as u64)).unwrap_or(0);
    let raw = src.read_vec(0, len)?;
    let b = if raw.starts_with(b"MAM") {
        let size = u32_at(&raw, 4).min(64 << 20);
        let data = if raw[3] & 0x80 != 0 { &raw[12..] } else { &raw[8..] };
        cx.format_set("compressed", true);
        xpress::decompress(data, size).ok_or_else(|| ExtractError::malformed("LZXPRESS Huffman stream"))?
    } else {
        raw
    };
    if b.get(4..8) != Some(b"SCCA") {
        return Err(ExtractError::malformed("prefetch header"));
    }
    let version = u32_at(&b, 0);
    cx.format_set("format_version", version);
    cx.format_set(
        "windows",
        match version {
            17 => "XP / 2003",
            23 => "Vista / 7",
            26 => "8 / 8.1",
            30 => "10",
            31 => "11",
            _ => "unknown",
        },
    );
    let exe = utf16z(b.get(16..76).unwrap_or_default());
    cx.format_set("executable", exe.clone());
    cx.content().source("forensic.shell").title(exe.clone());
    cx.format_set("prefetch_hash", format!("{:08X}", u32_at(&b, 76)));
    let metrics = u32_at(&b, 84);
    let (times, count_at) = match version {
        17 => (vec![120], 144),
        23 => (vec![128], 152),
        26 => ((0..8).map(|i| 128 + 8 * i).collect(), 208),
        // Windows 10's layout has two sizes, told by where the metrics start.
        _ => ((0..8).map(|i| 128 + 8 * i).collect(), if metrics == 0x130 { 208 } else { 200 }),
    };
    cx.format_set("run_count", u32_at(&b, count_at));
    let runs: Vec<String> = times.iter().filter_map(|&at| filetime_at(&b, at)).collect();
    if let Some(last) = runs.first() {
        cx.temporal().source("forensic.shell").content_date(crate::plugin::DateField::Modified, last.clone(), true);
        cx.format_set("last_run", last.clone());
    }
    if runs.len() > 1 {
        cx.format_set("last_run_times", runs);
    }
    let files = u32_at(&b, 88);
    cx.format_set("files_loaded", files);
    // The executable's full path, among the file name strings.
    let (names_at, names_len) = (u32_at(&b, 100), u32_at(&b, 104));
    if let Some(names) = b.get(names_at..names_at + names_len) {
        let all = utf16_list(names);
        if let Some(p) =
            all.iter().find(|p| p.to_ascii_uppercase().ends_with(&format!("\\{}", exe.to_ascii_uppercase())))
        {
            cx.format_set("executable_path", user_path(cx, p));
        }
    }
    let (vol_at, vol_count) = (u32_at(&b, 108), u32_at(&b, 112));
    let entry = match version {
        17 => 40,
        30 | 31 => 96,
        _ => 104,
    };
    let mut vols = Vec::new();
    for i in 0..vol_count.min(16) {
        let Some(v) = b.get(vol_at + i * entry..vol_at + (i + 1) * entry) else { break };
        let (p_off, p_len) = (u32_at(v, 0), u32_at(v, 4));
        let mut vm = Map::new();
        if let Some(p) = b.get(vol_at + p_off..vol_at + p_off + 2 * p_len) {
            vm.insert("device".into(), utf16z(p).into());
        }
        if let Some(t) = filetime(le(&v[8..16])) {
            vm.insert("created".into(), t.into());
        }
        vm.insert("serial".into(), format!("{:08X}", u32_at(v, 16)).into());
        vols.push(Value::Object(vm));
    }
    cx.format_set("volumes", vols);
    Ok(())
}

fn utf16_list(b: &[u8]) -> Vec<String> {
    let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    units.split(|&u| u == 0).filter(|s| !s.is_empty()).take(100_000).map(String::from_utf16_lossy).collect()
}

crate::register_extractor!(Shell);

/// The thumbnail size class of a cache type, per format version.
fn thumbcache_class(version: u32, kind: u32) -> Option<&'static str> {
    let table: &[&str] = match version {
        20 | 21 => &["32", "96", "256", "1024", "sr"],
        30 => &["16", "32", "48", "96", "256", "1024", "sr", "wide", "exif"],
        31 => &["16", "32", "48", "96", "256", "1024", "1600", "sr", "wide", "exif", "wide_alternate"],
        _ => &[
            "16",
            "32",
            "48",
            "96",
            "256",
            "768",
            "1280",
            "1920",
            "2560",
            "sr",
            "wide",
            "exif",
            "wide_alternate",
            "custom_stream",
        ],
    };
    table.get(kind as usize).copied()
}

fn thumbcache(b: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let u = |o: usize| b.get(o..o + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]));
    let version = u(4).ok_or_else(|| ExtractError::malformed("thumbcache header"))?;
    cx.format_set("format_version", version);
    cx.format_set(
        "windows",
        match version {
            20 => "Vista",
            21 => "7",
            30 => "8",
            31 => "8.1",
            32 => "10 / 11",
            _ => "unknown",
        },
    );
    if b.starts_with(b"IMMM") {
        cx.format_set("kind", "index");
        if let Some(n) = u(if version >= 30 { 16 } else { 12 }) {
            cx.format_set("index_entries", n);
        }
        return Ok(());
    }
    cx.format_set("kind", "cache");
    let kind = u(8).unwrap_or(0);
    if let Some(c) = thumbcache_class(version, kind) {
        cx.format_set("size_class", c);
    }
    let first = u(if version >= 30 { 16 } else { 12 }).unwrap_or(0) as usize;
    let (mut at, mut entries, mut empty) = (first, 0u64, 0u64);
    let mut types: std::collections::BTreeMap<&str, u64> = std::collections::BTreeMap::new();
    let mut largest = (0u32, 0u32);
    while at + 48 <= b.len() && &b[at..at + 4] == b"CMMM" {
        let size = u(at + 4).unwrap_or(0) as usize;
        if size < 48 {
            break;
        }
        // Vista keeps a 4-character extension after the hash; 8 and later add width and height.
        let base = at + 16 + if version == 20 { 8 } else { 0 };
        let (id_len, pad, data_len) =
            (u(base).unwrap_or(0) as usize, u(base + 4).unwrap_or(0) as usize, u(base + 8).unwrap_or(0) as usize);
        let (dims, header) = if version >= 30 {
            ((u(base + 12).unwrap_or(0), u(base + 16).unwrap_or(0)), base + 40 - at)
        } else {
            ((0, 0), base + 32 - at)
        };
        entries += 1;
        if data_len == 0 {
            empty += 1;
        } else {
            let data = b.get(at + header + id_len + pad..).unwrap_or_default();
            let t = if data.starts_with(b"\x89PNG") {
                "PNG"
            } else if data.starts_with(b"\xff\xd8") {
                "JPEG"
            } else if data.starts_with(b"BM") {
                "BMP"
            } else {
                "other"
            };
            *types.entry(t).or_default() += 1;
            if u64::from(dims.0) * u64::from(dims.1) > u64::from(largest.0) * u64::from(largest.1) {
                largest = dims;
            }
        }
        at += size;
        if entries >= 1_000_000 {
            break;
        }
    }
    cx.physical().entries(entries);
    cx.format_set("entries", entries);
    cx.format_set("empty_entries", empty);
    cx.format_set("image_types", json!(types));
    if largest.0 > 0 {
        cx.format_set("largest_thumbnail", json!([largest.0, largest.1]));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::testing::report_for;

    fn lnk(target: &str, args: &str) -> Vec<u8> {
        let mut b = vec![0u8; 0x4c];
        b[..4].copy_from_slice(&0x4cu32.to_le_bytes());
        b[4..20].copy_from_slice(b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46");
        b[20..24].copy_from_slice(&(0x02u32 | 0x20 | 0x80).to_le_bytes());
        // Link info with a local base path.
        let mut li = vec![0u8; 0x1c];
        li[4..8].copy_from_slice(&0x1cu32.to_le_bytes());
        li[8..12].copy_from_slice(&1u32.to_le_bytes());
        let vol_at = li.len();
        let mut vol = vec![0u8; 0x10];
        vol[..4].copy_from_slice(&0x11u32.to_le_bytes());
        vol[4..8].copy_from_slice(&3u32.to_le_bytes());
        vol[8..12].copy_from_slice(&0x1234_abcdu32.to_le_bytes());
        vol[12..16].copy_from_slice(&0x10u32.to_le_bytes());
        vol.push(0);
        li.extend(vol);
        let base_at = li.len();
        li.extend(target.as_bytes());
        li.push(0);
        let suffix_at = li.len();
        li.push(0);
        li[12..16].copy_from_slice(&u32::try_from(vol_at).unwrap().to_le_bytes());
        li[16..20].copy_from_slice(&u32::try_from(base_at).unwrap().to_le_bytes());
        li[24..28].copy_from_slice(&u32::try_from(suffix_at).unwrap().to_le_bytes());
        let n = u32::try_from(li.len()).unwrap();
        li[..4].copy_from_slice(&n.to_le_bytes());
        b.extend(li);
        b.extend(u16::try_from(args.encode_utf16().count()).unwrap().to_le_bytes());
        for u in args.encode_utf16() {
            b.extend(u.to_le_bytes());
        }
        b.extend([0; 4]);
        b
    }

    #[test]
    fn shortcut_running_powershell_is_a_risk() {
        let r = report_for(
            "invoice.lnk",
            &lnk("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-w hidden -c iex"),
        );
        let f = &r.format["lnk"];
        assert_eq!(f["volume"]["serial"], "1234ABCD");
        assert_eq!(f["volume"]["drive_type"], "fixed");
        assert!(r.security.risks.iter().any(|x| x.kind == "script_shortcut"));
        let plain = report_for("notes.lnk", &lnk("C:\\Users\\alice\\notes.txt", ""));
        assert_eq!(plain.security.risks, []);
        assert_eq!(plain.format["lnk"]["target"], "C:\\Users\\[user]\\notes.txt");
    }

    #[test]
    fn version_one_droid() {
        // 1d0e0f00-xxxx-11ef-…: version nibble 1, node 00:0c:29:aa:bb:cc.
        let mut g = [0u8; 16];
        g[..4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        g[4..6].copy_from_slice(&0x0abcu16.to_le_bytes());
        g[6..8].copy_from_slice(&0x11efu16.to_le_bytes());
        g[10..16].copy_from_slice(&[0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc]);
        let (t, node) = droid(&g).unwrap();
        assert_eq!(node, "00:0c:29:aa:bb:cc");
        assert!(t.unwrap().starts_with("20"));
    }

    crate::fixture_tests!("lnk", "jump_list", "custom_jump_list", "recycle_bin_info", "prefetch", "thumbcache");
}
