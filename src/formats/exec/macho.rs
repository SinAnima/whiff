//! Mach-O binaries (executables, dylibs, bundles, kernel extensions,
//! object files, dSYM companions, core files) and universal ("fat")
//! binaries. A universal binary lists its architectures and one slice is
//! described (arm64, else `x86_64`, else the first): CPU, file type, flags;
//! segments and sections (with entropy); linked libraries (weak, re-exported,
//! lazy), the install name and versions of a dylib, run-path entries; the
//! UUID, platform and minimum OS / SDK versions, build tools, source
//! version; imported and exported symbols; hardening (PIE, non-executable
//! heap and stack, stack canary, ARC, hardened runtime, library
//! validation); FairPlay encryption; the code signature (identifier, team,
//! hash type, flags, entitlements, the CMS signer and timestamp); DWARF in
//! dSYM files and objects; and the toolchain scan.
//!
//! Specifications: Apple's `<mach-o/loader.h>`, `<mach-o/fat.h>`,
//! `<mach-o/nlist.h>`; the code-signing blob layout of Apple's
//! `cs_blobs.h` (xnu).

use plist::Value as Plist;
use serde_json::{Map, Value, json};

use super::{Endian, Section, addr, dwarf_summary, hex, names, report_sections, scan_toolchain};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, der};

/// Extractor for Mach-O and universal binaries.
pub struct MachO;

static META: ExtractorMeta = ExtractorMeta {
    id: "exec.macho",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "macho",
        name: "Mach-O / universal binary",
        family: "exec",
        mimes: &["application/x-mach-binary"],
        extensions: &["dylib", "bundle", "kext", "o"],
        magic: &[],
        parent: None,
    }],
};

const MAX_COMMANDS: u32 = 4096;
const MAX_SYMBOLS: u32 = 500_000;
/// Entitlements that weaken the hardened runtime.
const WEAKENING: &[&str] = &[
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.disable-executable-page-protection",
];

fn cpu(ty: u32, sub: u32) -> String {
    match (ty, sub & 0xff) {
        (7, _) => "x86",
        (0x0100_0007, 8) => "x86_64h",
        (0x0100_0007, _) => "x86_64",
        (12, 9) => "armv7",
        (12, 11) => "armv7s",
        (12, _) => "arm",
        (0x0100_000c, 2) => "arm64e",
        (0x0100_000c, _) => "arm64",
        (0x0200_000c, _) => "arm64_32",
        (18, _) => "ppc",
        (0x0100_0012, _) => "ppc64",
        _ => return format!("cpu_{ty:#x}"),
    }
    .to_string()
}

fn file_type(t: u32) -> &'static str {
    match t {
        1 => "object",
        2 => "executable",
        4 => "core",
        5 => "preload",
        6 => "shared_library",
        7 => "dynamic_linker",
        8 => "bundle",
        9 => "dylib_stub",
        10 => "debug_symbols",
        11 => "kernel_extension",
        12 => "fileset",
        _ => "unknown",
    }
}

fn platform(p: u32) -> String {
    match p {
        1 => "macos",
        2 => "ios",
        3 => "tvos",
        4 => "watchos",
        5 => "bridgeos",
        6 => "mac_catalyst",
        7 => "ios_simulator",
        8 => "tvos_simulator",
        9 => "watchos_simulator",
        10 => "driverkit",
        11 => "visionos",
        12 => "visionos_simulator",
        _ => return format!("platform_{p}"),
    }
    .to_string()
}

/// `xxxx.yy.zz` nibble-packed versions.
fn version(v: u32) -> String {
    let (a, b, c) = (v >> 16, (v >> 8) & 0xff, v & 0xff);
    if c == 0 { format!("{a}.{b}") } else { format!("{a}.{b}.{c}") }
}

fn is_fat(h: &[u8]) -> bool {
    let e = Endian { le: false };
    matches!(e.u32(h, 0), Some(0xcafe_babe | 0xcafe_babf))
        && e.u32(h, 4).is_some_and(|n| (1..=30).contains(&n))
        && e.u32(h, 8).is_some_and(|t| matches!(t & 0x00ff_ffff, 7 | 12 | 18))
}

fn thin_magic(h: &[u8]) -> Option<(Endian, bool)> {
    Some(match h.get(..4)? {
        [0xfe, 0xed, 0xfa, 0xce] => (Endian { le: false }, false),
        [0xfe, 0xed, 0xfa, 0xcf] => (Endian { le: false }, true),
        [0xce, 0xfa, 0xed, 0xfe] => (Endian { le: true }, false),
        [0xcf, 0xfa, 0xed, 0xfe] => (Endian { le: true }, true),
        _ => return None,
    })
}

impl Extractor for MachO {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        (thin_magic(probe.head).is_some() || is_fat(probe.head)).then_some(Sniff { format: "macho", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let h = src.read_vec(0, usize::try_from(src.len().min(8 + 32 * 30)).unwrap_or(0))?;
        if !is_fat(&h) {
            return thin(src, cx);
        }
        let e = Endian { le: false };
        let wide = e.u32(&h, 0) == Some(0xcafe_babf);
        let n = e.u32(&h, 4).unwrap_or(0) as usize;
        let mut slices = Vec::new();
        for i in 0..n {
            let at = 8 + i * if wide { 32 } else { 20 };
            let (Some(ty), Some(sub)) = (e.u32(&h, at), e.u32(&h, at + 4)) else { break };
            let (off, size) = if wide {
                (e.u64(&h, at + 8), e.u64(&h, at + 16))
            } else {
                (e.u32(&h, at + 8).map(u64::from), e.u32(&h, at + 12).map(u64::from))
            };
            let (Some(off), Some(size)) = (off, size) else { break };
            slices.push((cpu(ty, sub), off, size));
        }
        cx.format_set("universal", true);
        cx.format_set(
            "architectures",
            slices.iter().map(|(a, o, s)| json!({"architecture": a, "offset": o, "size": s})).collect::<Vec<_>>(),
        );
        let pick = ["arm64", "arm64e", "x86_64"]
            .iter()
            .find_map(|want| slices.iter().find(|s| s.0 == *want))
            .or_else(|| slices.first())
            .cloned();
        let Some((arch, off, size)) = pick else {
            return Err(ExtractError::malformed("universal binary without slices"));
        };
        if off.checked_add(size).is_none_or(|end| end > src.len()) {
            cx.warn(format!("{arch} slice runs past the end of the file"));
            return Ok(());
        }
        cx.format_set("described_architecture", arch);
        let mut slice = src.slice(off, size)?;
        thin(&mut slice, cx)
    }
}

crate::register_extractor!(MachO);

/// Facts gathered from the load commands.
#[derive(Default)]
struct Commands {
    sections: Vec<Section>,
    dwarf: Vec<(String, u64, u64)>,
    libraries: Vec<String>,
    weak: Vec<String>,
    rpaths: Vec<String>,
    symtab: Option<(u32, u32, u32, u32)>,
    signature: Option<(u32, u32)>,
    encrypted: Option<bool>,
}

#[allow(clippy::too_many_lines)] // one load command after another
fn thin(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let head = src.read_vec(0, usize::try_from(src.len().min(32)).unwrap_or(0))?;
    let (e, wide) = thin_magic(&head).ok_or_else(|| ExtractError::malformed("Mach-O magic"))?;
    let bad = || ExtractError::malformed("Mach-O header");
    let ty = e.u32(&head, 4).ok_or_else(bad)?;
    let sub = e.u32(&head, 8).ok_or_else(bad)?;
    let ftype = e.u32(&head, 12).ok_or_else(bad)?;
    let ncmds = e.u32(&head, 16).ok_or_else(bad)?.min(MAX_COMMANDS);
    let sizeofcmds = e.u32(&head, 20).ok_or_else(bad)?;
    let flags = e.u32(&head, 24).ok_or_else(bad)?;
    let start = if wide { 32 } else { 28 };
    cx.format_set("architecture", cpu(ty, sub));
    cx.format_set("bits", if wide { 64 } else { 32 });
    cx.format_set("endianness", if e.le { "little" } else { "big" });
    cx.format_set("kind", file_type(ftype));
    let cmds =
        src.read_vec(start, usize::try_from(u64::from(sizeofcmds).min(src.len().saturating_sub(start))).unwrap_or(0))?;

    let mut c = Commands::default();
    let mut at = 0usize;
    let mut tools = Vec::new();
    let mut other_platforms = Vec::new();
    for _ in 0..ncmds {
        let (Some(cmd), Some(size)) = (e.u32(&cmds, at), e.u32(&cmds, at + 4)) else { break };
        let size = size as usize;
        if size < 8 || at + size > cmds.len() {
            cx.warn("load command runs past the commands area");
            break;
        }
        let lc = &cmds[at..at + size];
        let string_at = |field: usize| -> Option<String> {
            let off = e.u32(lc, field)? as usize;
            let b = lc.get(off..)?;
            Some(String::from_utf8_lossy(&b[..b.iter().position(|&x| x == 0).unwrap_or(b.len())]).into_owned())
        };
        match cmd {
            0x1 | 0x19 => segment(lc, e, cmd == 0x19, ftype == 1, &mut c),
            0xc | 0x8000_0018 | 0x8000_001f | 0x20 | 0x8000_0023 => {
                if let Some(n) = string_at(8) {
                    if cmd == 0x8000_0018 {
                        c.weak.push(n.clone());
                    }
                    c.libraries.push(n);
                }
            }
            0xd => {
                if let Some(n) = string_at(8) {
                    cx.format_set("install_name", n);
                }
                if let (Some(cur), Some(compat)) = (e.u32(lc, 16), e.u32(lc, 20)) {
                    cx.format_set("current_version", version(cur));
                    cx.format_set("compatibility_version", version(compat));
                }
            }
            0x8000_001c => c.rpaths.extend(string_at(8)),
            0x1b => {
                if let Some(u) = lc.get(8..24) {
                    let h = hex(u).to_ascii_uppercase();
                    cx.format_set(
                        "uuid",
                        format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]),
                    );
                }
            }
            0x32 => {
                // Zippered binaries carry one per platform: the first is the main one.
                if let (Some(p), Some(min), Some(sdk)) = (e.u32(lc, 8), e.u32(lc, 12), e.u32(lc, 16)) {
                    if cx.format().contains_key("platform") {
                        other_platforms
                            .push(json!({"platform": platform(p), "minimum_os": version(min), "sdk": version(sdk)}));
                    } else {
                        cx.format_set("platform", platform(p));
                        cx.format_set("minimum_os", version(min));
                        cx.format_set("sdk", version(sdk));
                    }
                }
                let n = e.u32(lc, 20).unwrap_or(0).min(16) as usize;
                for i in 0..n {
                    if let (Some(t), Some(v)) = (e.u32(lc, 24 + i * 8), e.u32(lc, 28 + i * 8)) {
                        let tool = match t {
                            1 => "clang",
                            2 => "swift",
                            3 => "ld",
                            4 => "lld",
                            _ => "other",
                        };
                        tools.push(json!({"tool": tool, "version": version(v)}));
                    }
                }
            }
            0x24 | 0x25 | 0x2f | 0x30 => {
                let p = match cmd {
                    0x24 => "macos",
                    0x25 => "ios",
                    0x2f => "tvos",
                    _ => "watchos",
                };
                cx.format_set("platform", p);
                if let (Some(min), Some(sdk)) = (e.u32(lc, 8), e.u32(lc, 12)) {
                    cx.format_set("minimum_os", version(min));
                    cx.format_set("sdk", version(sdk));
                }
            }
            0x8000_0028 => {
                if let Some(off) = e.u64(lc, 8) {
                    cx.format_set("entry_point", addr(off));
                }
            }
            0x2a => {
                if let Some(v) = e.u64(lc, 8).filter(|&v| v != 0) {
                    let parts = [v >> 40, (v >> 30) & 0x3ff, (v >> 20) & 0x3ff, (v >> 10) & 0x3ff, v & 0x3ff];
                    let s = parts.iter().map(u64::to_string).collect::<Vec<_>>().join(".");
                    cx.format_set("source_version", s);
                }
            }
            0x2 => {
                if let (Some(a), Some(b), Some(cc), Some(d)) =
                    (e.u32(lc, 8), e.u32(lc, 12), e.u32(lc, 16), e.u32(lc, 20))
                {
                    c.symtab = Some((a, b, cc, d));
                }
            }
            0x1d => {
                if let (Some(off), Some(size)) = (e.u32(lc, 8), e.u32(lc, 12)) {
                    c.signature = Some((off, size));
                }
            }
            0x21 | 0x2c => {
                if let Some(id) = e.u32(lc, 16) {
                    c.encrypted = Some(id != 0);
                }
            }
            _ => {}
        }
        at += size;
    }
    if !tools.is_empty() {
        cx.format_set("build_tools", tools);
    }
    if !other_platforms.is_empty() {
        cx.format_set("other_platforms", other_platforms);
    }
    report_sections(src, cx, &c.sections)?;
    if !c.libraries.is_empty() {
        cx.format_set("library_count", c.libraries.len());
        cx.format_set("libraries", names(&c.libraries));
    }
    if !c.weak.is_empty() {
        cx.format_set("weak_libraries", names(&c.weak));
    }
    if !c.rpaths.is_empty() {
        cx.format_set("rpaths", names(&c.rpaths));
    }
    if let Some(enc) = c.encrypted {
        cx.format_set("encrypted", enc);
        if enc {
            cx.security().encrypted(true);
        }
    }

    let mut hard = Map::new();
    if ftype == 2 {
        hard.insert("pie".into(), (flags & 0x0020_0000 != 0).into());
    }
    if flags & 0x0002_0000 != 0 {
        hard.insert("executable_stack".into(), true.into());
        cx.security().risk("writable_executable_memory", Some("MH_ALLOW_STACK_EXECUTION".into()));
    }
    if flags & 0x0100_0000 != 0 {
        hard.insert("nx_heap".into(), true.into());
    }
    if c.sections.iter().any(|s| s.name == "__RESTRICT,__restrict") {
        hard.insert("restrict_segment".into(), true.into());
    }
    let symbols = symbols(src, e, wide, c.symtab)?;
    if let Some((imports, exports)) = symbols {
        let canary = imports.iter().any(|n| n == "___stack_chk_fail" || n == "___stack_chk_guard");
        hard.insert("stack_canary".into(), canary.into());
        hard.insert("arc".into(), imports.iter().any(|n| n == "_objc_release").into());
        if !imports.is_empty() {
            cx.format_set("imported_symbol_count", imports.len());
            cx.format_set("imports", names(&imports));
        }
        if !exports.is_empty() {
            cx.format_set("exported_symbol_count", exports.len());
            cx.format_set("exports", names(&exports));
        }
    }
    if let Some((off, size)) = c.signature {
        code_signature(src, cx, u64::from(off), size, &mut hard)?;
    } else if ftype != 1 && ftype != 10 {
        hard.insert("code_signature".into(), false.into());
    }
    cx.format_set("hardening", Value::Object(hard));
    if !c.dwarf.is_empty() {
        let find = |n: &str| {
            // Section names are cut at 16 bytes (`__debug_str_offs`).
            let mut want = format!("__{}", n.trim_start_matches('.'));
            want.truncate(16);
            c.dwarf.iter().find(|(s, _, _)| *s == want).map(|&(_, o, sz)| (o, sz))
        };
        let mut d = Map::new();
        d.insert("dwarf".into(), true.into());
        if let Some(unit) = dwarf_summary(src, e, &find, cx.redactor()) {
            d.extend(unit);
        }
        cx.format_set("debug", Value::Object(d));
    }
    scan_toolchain(src, cx)?.write(cx);
    Ok(())
}

fn fixed_name(b: &[u8]) -> String {
    String::from_utf8_lossy(&b[..b.iter().position(|&x| x == 0).unwrap_or(b.len())]).into_owned()
}

fn segment(lc: &[u8], e: Endian, wide: bool, object: bool, c: &mut Commands) {
    let Some(seg) = lc.get(8..24).map(fixed_name) else { return };
    let (prot, nsects, sect_at, sect_len) =
        if wide { (e.u32(lc, 60), e.u32(lc, 64), 72, 80) } else { (e.u32(lc, 44), e.u32(lc, 48), 56, 68) };
    let prot = prot.unwrap_or(0);
    let nsects = nsects.unwrap_or(0).min(256) as usize;
    let (read, write, execute) = (prot & 1 != 0, prot & 2 != 0, prot & 4 != 0);
    if nsects == 0 {
        let (vmaddr, vmsize, fileoff, filesize) = if wide {
            (e.u64(lc, 24), e.u64(lc, 32), e.u64(lc, 40), e.u64(lc, 48))
        } else {
            (
                e.u32(lc, 24).map(u64::from),
                e.u32(lc, 28).map(u64::from),
                e.u32(lc, 32).map(u64::from),
                e.u32(lc, 36).map(u64::from),
            )
        };
        // __PAGEZERO and __LINKEDIT carry no sections; list the segment itself.
        if seg != "__PAGEZERO" {
            c.sections.push(Section {
                name: seg,
                offset: fileoff.unwrap_or(0),
                size: filesize.unwrap_or(0),
                address: vmaddr.unwrap_or(0),
                memory_size: vmsize.unwrap_or(0),
                read,
                write,
                execute,
            });
        }
        return;
    }
    for i in 0..nsects {
        let Some(s) = lc.get(sect_at + i * sect_len..sect_at + (i + 1) * sect_len) else { break };
        let name = fixed_name(&s[..16]);
        // Object files put every section in one unnamed segment.
        let seg = fixed_name(&s[16..32]);
        let (address, size, offset, flags) = if wide {
            (e.u64(s, 32), e.u64(s, 40), e.u32(s, 48), e.u32(s, 64))
        } else {
            (e.u32(s, 32).map(u64::from), e.u32(s, 36).map(u64::from), e.u32(s, 40), e.u32(s, 56))
        };
        let (address, size, offset, flags) =
            (address.unwrap_or(0), size.unwrap_or(0), offset.unwrap_or(0), flags.unwrap_or(0));
        let zerofill = matches!(flags & 0xff, 0x1 | 0xc | 0x12) || offset == 0;
        let code = flags & 0x8000_0400 != 0;
        // An object's segment is rwx; its sections say what they hold.
        let (read, write, execute) = if object {
            (true, !code && seg != "__TEXT", code)
        } else {
            (read, write, execute && (code || seg == "__TEXT" && name == "__text"))
        };
        if seg == "__DWARF" {
            c.dwarf.push((name.clone(), u64::from(offset), size));
        }
        c.sections.push(Section {
            name: format!("{seg},{name}"),
            offset: u64::from(offset),
            size: if zerofill { 0 } else { size },
            address,
            memory_size: size,
            read,
            write,
            execute,
        });
    }
}

type Symbols = Option<(Vec<String>, Vec<String>)>;

/// Undefined external symbols (imports) and defined external ones (exports).
fn symbols(
    src: &mut dyn Source,
    e: Endian,
    wide: bool,
    symtab: Option<(u32, u32, u32, u32)>,
) -> Result<Symbols, ExtractError> {
    let Some((symoff, nsyms, stroff, strsize)) = symtab else { return Ok(None) };
    let ent = if wide { 16 } else { 12 };
    let n = u64::from(nsyms.min(MAX_SYMBOLS));
    let end = u64::from(symoff) + n * ent;
    if end > src.len() || u64::from(stroff) + u64::from(strsize) > src.len() {
        return Ok(None);
    }
    let table = src.read_vec(u64::from(symoff), usize::try_from(n * ent).unwrap_or(0))?;
    let strings = src.read_vec(u64::from(stroff), usize::try_from(u64::from(strsize).min(16 << 20)).unwrap_or(0))?;
    let (mut imports, mut exports) = (Vec::new(), Vec::new());
    for s in table.chunks_exact(usize::try_from(ent).unwrap_or(16)) {
        let (Some(strx), Some(&ty)) = (e.u32(s, 0), s.get(4)) else { continue };
        if ty & 0xe0 != 0 {
            continue; // debugging (stab) entries
        }
        let Some(rest) = strings.get(strx as usize..) else { continue };
        let name = String::from_utf8_lossy(&rest[..rest.iter().position(|&x| x == 0).unwrap_or(rest.len()).min(1024)])
            .into_owned();
        if name.is_empty() || ty & 1 == 0 {
            continue;
        }
        match ty & 0x0e {
            0x0 => imports.push(name),
            0xe => exports.push(name),
            _ => {}
        }
    }
    imports.sort();
    imports.dedup();
    exports.sort();
    exports.dedup();
    Ok(Some((imports, exports)))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Endian { le: false }.u32(b, at)
}

fn code_signature(
    src: &mut dyn Source,
    cx: &mut Context<'_>,
    off: u64,
    size: u32,
    hard: &mut Map<String, Value>,
) -> Result<(), ExtractError> {
    if off + u64::from(size) > src.len() {
        cx.warn("code signature past the end of the file");
        return Ok(());
    }
    let blob = src.read_vec(off, usize::try_from(size.min(4 << 20)).unwrap_or(0))?;
    if be32(&blob, 0) != Some(0xfade_0cc0) {
        cx.warn("code signature is not a SuperBlob");
        return Ok(());
    }
    let count = be32(&blob, 8).unwrap_or(0).min(64) as usize;
    let mut sig = Map::new();
    sig.insert("kind".into(), "apple_code_signature".into());
    let mut cms = None;
    for i in 0..count {
        let (Some(ty), Some(o)) = (be32(&blob, 12 + i * 8), be32(&blob, 16 + i * 8)) else { break };
        let o = o as usize;
        let Some(len) = be32(&blob, o + 4).map(|l| l as usize) else { continue };
        let Some(b) = blob.get(o..o.saturating_add(len)) else { continue };
        match (ty, be32(b, 0)) {
            (0, Some(0xfade_0c02)) => code_directory(b, &mut sig, hard),
            (5, Some(0xfade_7171)) => {
                // Some signers end the XML with NULs.
                if let Some(xml) =
                    b.get(8..).map(|x| x.trim_ascii_end().strip_suffix(b"\0").unwrap_or(x.trim_ascii_end()))
                    && let Ok(p) = Plist::from_reader(std::io::Cursor::new(xml))
                {
                    entitlements(cx, &p, &mut sig);
                }
            }
            (0x1_0000, Some(0xfade_0b01)) if len > 8 => cms = der::signed_data(&b[8..]),
            _ => {}
        }
    }
    hard.insert("code_signature".into(), true.into());
    if let Some(s) = cms.filter(|s| s.signer.is_some()) {
        cx.security().signed(true);
        sig.extend(s.facts());
    }
    cx.format_set("signature", Value::Object(sig));
    Ok(())
}

fn code_directory(b: &[u8], sig: &mut Map<String, Value>, hard: &mut Map<String, Value>) {
    let (Some(ver), Some(flags)) = (be32(b, 8), be32(b, 12)) else { return };
    let text_at = |field: usize| -> Option<String> {
        let o = be32(b, field)? as usize;
        if o == 0 {
            return None;
        }
        let s = b.get(o..)?;
        Some(String::from_utf8_lossy(&s[..s.iter().position(|&x| x == 0)?]).into_owned())
    };
    if let Some(id) = text_at(20) {
        sig.insert("identifier".into(), id.into());
    }
    if ver >= 0x2_0200
        && let Some(team) = text_at(48).filter(|t| !t.is_empty())
    {
        sig.insert("team_id".into(), team.into());
    }
    let hash = match b.get(37) {
        Some(1) => "sha1",
        Some(2) => "sha256",
        Some(3) => "sha256_truncated",
        Some(4) => "sha384",
        _ => "unknown",
    };
    sig.insert("hash_type".into(), hash.into());
    let mut f = Vec::new();
    for (bit, name) in [
        (0x2, "adhoc"),
        (0x100, "force_hard"),
        (0x200, "kill"),
        (0x800, "restrict"),
        (0x1000, "enforcement"),
        (0x2000, "library_validation"),
        (0x1_0000, "runtime"),
        (0x2_0000, "linker_signed"),
    ] {
        if flags & bit != 0 {
            f.push(Value::from(name));
        }
    }
    sig.insert("adhoc".into(), (flags & 0x2 != 0).into());
    sig.insert("flags".into(), f.into());
    hard.insert("hardened_runtime".into(), (flags & 0x1_0000 != 0).into());
    if flags & 0x2000 != 0 {
        hard.insert("library_validation".into(), true.into());
    }
}

fn entitlements(cx: &mut Context<'_>, p: &Plist, sig: &mut Map<String, Value>) {
    let Some(d) = p.as_dictionary() else { return };
    let keys: Vec<&str> = d.keys().map(String::as_str).collect();
    sig.insert("entitlements".into(), names(&keys));
    let on = |k: &str| d.get(k).and_then(Plist::as_boolean) == Some(true);
    if on("get-task-allow") || on("com.apple.security.get-task-allow") {
        cx.security().risk("debuggable", Some("get-task-allow entitlement".into()));
    }
    for k in WEAKENING.iter().filter(|k| on(k)) {
        cx.security().risk("weakened_runtime", Some((*k).to_string()));
    }
    if on("com.apple.security.app-sandbox") {
        sig.insert("sandboxed".into(), true.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn universal_or_java() {
        // A universal binary with two slices, and a Java class file (major 52).
        assert!(is_fat(b"\xca\xfe\xba\xbe\x00\x00\x00\x02\x01\x00\x00\x07"));
        assert!(!is_fat(b"\xca\xfe\xba\xbe\x00\x00\x00\x34\x0a\x00\x1d\x0a"));
    }

    #[test]
    fn versions_and_cpus() {
        assert_eq!(version(0x000e_0500), "14.5");
        assert_eq!(version(0x000a_0f01), "10.15.1");
        assert_eq!(cpu(0x0100_000c, 0x8000_0002), "arm64e");
        assert_eq!(cpu(0x0100_0007, 3), "x86_64");
    }

    crate::fixture_tests!("macho");
}
