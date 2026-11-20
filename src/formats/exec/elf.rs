//! ELF executables, shared objects, relocatable objects (`.o`, `.ko`), core
//! dumps and eBPF objects: class, byte order, machine, OS ABI, type, entry
//! point, interpreter; segments and sections (with entropy); the dynamic
//! section (needed libraries, `SONAME`, `RPATH` / `RUNPATH`, binding);
//! imported and exported symbols; notes (GNU build id, ABI tag, GNU
//! properties: IBT / SHSTK / BTI / PAC, Go build id, FDO package metadata,
//! Android API level); hardening (PIE, NX stack, RELRO, stack protector,
//! FORTIFY, stripped); DWARF producer and language; the toolchain scan.
//! Core dumps report the signal, process name, arguments and thread count.
//!
//! Specifications: System V gABI (ELF), the Linux Standard Base and
//! `elf(5)`; GNU property and package-metadata notes; DWARF 2–5.

use serde_json::{Map, Value, json};

use super::{Endian, Section, addr, c_string, dwarf_summary, hex, names, report_sections, scan_toolchain};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source};

/// Extractor for ELF files.
pub struct Elf;

/// Only `elf` carries the magic; the sniffer picks cores and eBPF objects.
const fn spec(
    id: &'static str,
    name: &'static str,
    extensions: &'static [&'static str],
    magic: &'static [Magic],
) -> FormatSpec {
    FormatSpec {
        id,
        name,
        family: "exec",
        mimes: &["application/x-executable", "application/x-sharedlib", "application/x-elf"],
        extensions,
        magic,
        parent: None,
    }
}

const ELF_MAGIC: &[Magic] = &[Magic::prefix(b"\x7fELF")];

static META: ExtractorMeta = ExtractorMeta {
    id: "exec.elf",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        spec("elf", "ELF executable / shared object", &["elf", "so", "o", "ko", "axf", "prx", "mod"], ELF_MAGIC),
        spec("elf_core", "ELF core dump", &["core"], &[]),
        spec("ebpf", "eBPF object", &[], &[]),
    ],
};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const SHT_SYMTAB: u32 = 2;
const SHT_NOTE: u32 = 7;
const SHT_NOBITS: u32 = 8;
const SHT_DYNSYM: u32 = 11;
const MAX_HEADERS: usize = 8192;
const MAX_SYMBOLS: usize = 200_000;

fn machine(m: u16) -> String {
    match m {
        2 => "sparc",
        3 => "x86",
        8 => "mips",
        20 => "ppc",
        21 => "ppc64",
        22 => "s390",
        40 => "arm",
        42 => "superh",
        43 => "sparc64",
        50 => "ia64",
        62 => "x86_64",
        83 => "avr",
        94 => "xtensa",
        105 => "msp430",
        164 => "hexagon",
        183 => "arm64",
        243 => "riscv",
        247 => "bpf",
        258 => "loongarch",
        _ => return format!("machine_{m}"),
    }
    .to_string()
}

fn os_abi(v: u8) -> Option<&'static str> {
    Some(match v {
        1 => "hp-ux",
        2 => "netbsd",
        3 => "linux",
        6 => "solaris",
        7 => "aix",
        8 => "irix",
        9 => "freebsd",
        12 => "openbsd",
        97 => "arm",
        255 => "standalone",
        _ => return None,
    })
}

fn signal(n: u32) -> Option<&'static str> {
    Some(match n {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        31 => "SIGSYS",
        _ => return None,
    })
}

/// The header fields used throughout.
struct Header {
    e: Endian,
    wide: bool,
    kind: u16,
    machine: u16,
}

struct Shdr {
    name: String,
    kind: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
}

struct Phdr {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

impl Extractor for Elf {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if !h.starts_with(b"\x7fELF") || h.len() < 20 {
            return None;
        }
        let e = Endian { le: h[5] != 2 };
        let format = match (e.u16(h, 16)?, e.u16(h, 18)?) {
            (4, _) => "elf_core",
            (_, 247) => "ebpf",
            _ => "elf",
        };
        Some(Sniff { format, confidence: 0.95 })
    }

    #[allow(clippy::too_many_lines)] // the header, then one table after another
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let h = src.read_vec(0, 64.min(usize::try_from(src.len()).unwrap_or(64)))?;
        if h.len() < 52 || !h.starts_with(b"\x7fELF") {
            return Err(ExtractError::malformed("ELF header"));
        }
        let wide = match h[4] {
            1 => false,
            2 => true,
            _ => return Err(ExtractError::malformed("ELF class")),
        };
        let e = Endian { le: h[5] != 2 };
        let bad = || ExtractError::malformed("ELF header");
        let word = |off32: usize, off64: usize| if wide { e.u64(&h, off64) } else { e.u32(&h, off32).map(u64::from) };
        let hd = Header { e, wide, kind: e.u16(&h, 16).ok_or_else(bad)?, machine: e.u16(&h, 18).ok_or_else(bad)? };
        let entry = word(24, 24).ok_or_else(bad)?;
        let phoff = word(28, 32).ok_or_else(bad)?;
        let shoff = word(32, 40).ok_or_else(bad)?;
        let at = if wide { 48 } else { 36 };
        let flags = e.u32(&h, at).ok_or_else(bad)?;
        let phentsize = usize::from(e.u16(&h, at + 6).ok_or_else(bad)?);
        let mut phnum = usize::from(e.u16(&h, at + 8).ok_or_else(bad)?);
        let shentsize = usize::from(e.u16(&h, at + 10).ok_or_else(bad)?);
        let mut shnum = usize::from(e.u16(&h, at + 12).ok_or_else(bad)?);
        let mut shstrndx = usize::from(e.u16(&h, at + 14).ok_or_else(bad)?);

        cx.format_set("bits", if wide { 64 } else { 32 });
        cx.format_set("endianness", if e.le { "little" } else { "big" });
        cx.format_set("architecture", machine(hd.machine));
        if let Some(os) = os_abi(h[7]) {
            cx.format_set("os_abi", os);
        }
        if hd.machine == 243 {
            let abi = match flags & 0x6 {
                0 => "soft-float",
                2 => "single-float",
                4 => "double-float",
                _ => "quad-float",
            };
            cx.format_set("float_abi", abi);
        }
        if entry != 0 {
            cx.format_set("entry_point", addr(entry));
        }

        // Section headers (count and string table index may be extended in entry 0).
        let mut shdrs = Vec::new();
        if shoff != 0 && shentsize >= if wide { 64 } else { 40 } {
            let first = src.read_vec(shoff, shentsize).ok();
            if let Some(f) = &first {
                if shnum == 0 {
                    shnum = usize::try_from(raw_shdr(&hd, f).map_or(0, |s| s.size)).unwrap_or(0);
                }
                if shstrndx == 0xffff {
                    shstrndx = raw_shdr(&hd, f).map_or(0, |s| s.link as usize);
                }
            }
            let n = shnum.min(MAX_HEADERS);
            if let Ok(table) = src.read_vec(shoff, n * shentsize) {
                shdrs = table.chunks_exact(shentsize).filter_map(|c| raw_shdr(&hd, c)).collect();
            } else {
                cx.warn("section header table past the end of the file");
            }
            let names = shdrs.get(shstrndx).map(|s| (s.offset, s.size.min(1 << 20)));
            if let Some((off, size)) = names
                && let Ok(strtab) = src.read_vec(off, usize::try_from(size).unwrap_or(0))
            {
                for s in &mut shdrs {
                    let n: usize = s.name.parse().unwrap_or(usize::MAX);
                    s.name = strtab.get(n..).map(c_string_raw).unwrap_or_default();
                }
            }
        }
        // Program headers.
        let mut phdrs = Vec::new();
        if phoff != 0 && phentsize >= if wide { 56 } else { 32 } {
            phnum = phnum.min(MAX_HEADERS);
            if let Ok(table) = src.read_vec(phoff, phnum * phentsize) {
                phdrs = table.chunks_exact(phentsize).filter_map(|c| raw_phdr(&hd, c)).collect();
            }
        }

        let kind = match hd.kind {
            1 => "object",
            2 => "executable",
            3 => {
                let interp = phdrs.iter().any(|p| p.kind == PT_INTERP);
                if interp { "executable" } else { "shared_library" }
            }
            4 => "core",
            _ => "unknown",
        };
        cx.format_set("kind", kind);

        if hd.kind == 4 {
            return core(src, cx, &hd, &phdrs);
        }

        let mut hard = Map::new();
        if let Some(p) = phdrs.iter().find(|p| p.kind == PT_INTERP) {
            let b = src.read_vec(p.offset, usize::try_from(p.filesz.min(4096)).unwrap_or(0))?;
            cx.format_set("interpreter", c_string_raw(&b));
        }
        let segments: Vec<Value> = phdrs
            .iter()
            .filter(|p| p.kind == PT_LOAD)
            .map(|p| {
                json!({"address": addr(p.vaddr), "file_size": p.filesz, "memory_size": p.memsz,
                    "flags": format!("{}{}{}", if p.flags & 4 != 0 {'r'} else {'-'}, if p.flags & 2 != 0 {'w'} else {'-'}, if p.flags & 1 != 0 {'x'} else {'-'})})
            })
            .collect();
        if !segments.is_empty() {
            cx.format_set("segments", segments);
        }
        for p in phdrs.iter().filter(|p| p.kind == PT_LOAD && p.flags & 3 == 3) {
            cx.security().risk(
                "writable_executable_memory",
                Some(format!("segment at {} is writable and executable", addr(p.vaddr))),
            );
        }
        if let Some(stack) = phdrs.iter().find(|p| p.kind == PT_GNU_STACK) {
            let exec = stack.flags & 1 != 0;
            hard.insert("nx".into(), (!exec).into());
            if exec {
                cx.security().risk("writable_executable_memory", Some("executable stack".into()));
            }
        }

        // Sections, or the loadable segments when there are none.
        let sections: Vec<Section> = if shdrs.len() > 1 {
            shdrs
                .iter()
                .skip(1)
                .map(|s| Section {
                    name: s.name.clone(),
                    offset: s.offset,
                    size: if s.kind == SHT_NOBITS { 0 } else { s.size },
                    address: s.addr,
                    memory_size: s.size,
                    read: s.flags & 2 != 0,
                    write: s.flags & 1 != 0,
                    execute: s.flags & 4 != 0,
                })
                .collect()
        } else {
            phdrs
                .iter()
                .filter(|p| p.kind == PT_LOAD)
                .enumerate()
                .map(|(i, p)| Section {
                    name: format!("LOAD[{i}]"),
                    offset: p.offset,
                    size: p.filesz,
                    address: p.vaddr,
                    memory_size: p.memsz,
                    read: p.flags & 4 != 0,
                    write: p.flags & 2 != 0,
                    execute: p.flags & 1 != 0,
                })
                .collect()
        };
        report_sections(src, cx, &sections)?;
        if hd.machine == 247 {
            ebpf(src, cx, &shdrs)?;
        }

        // Dynamic section.
        let mut bind_now = false;
        if let Some(d) = phdrs.iter().find(|p| p.kind == PT_DYNAMIC) {
            let data = src.read_vec(d.offset, usize::try_from(d.filesz.min(1 << 20)).unwrap_or(0))?;
            let ent = if wide { 16 } else { 8 };
            let mut entries = Vec::new();
            for c in data.chunks_exact(ent) {
                let (Some(tag), Some(val)) = (e.word(c, 0, wide), e.word(c, ent / 2, wide)) else { break };
                if tag == 0 {
                    break;
                }
                entries.push((tag, val));
            }
            let strtab = entries.iter().find(|(t, _)| *t == 5).map(|&(_, v)| v);
            let strsz = entries.iter().find(|(t, _)| *t == 10).map_or(0, |&(_, v)| v);
            let strings = match strtab.and_then(|a| file_offset(&phdrs, a)) {
                Some(off) => src.read_vec(off, usize::try_from(strsz.min(4 << 20)).unwrap_or(0)).unwrap_or_default(),
                None => Vec::new(),
            };
            let s = |v: u64| strings.get(usize::try_from(v).unwrap_or(usize::MAX)..).map(c_string_raw);
            let needed: Vec<String> = entries.iter().filter(|(t, _)| *t == 1).filter_map(|&(_, v)| s(v)).collect();
            if !needed.is_empty() {
                cx.format_set("library_count", needed.len());
                cx.format_set("libraries", names(&needed));
            }
            for (tag, key) in [(14u64, "soname"), (15, "rpath"), (29, "runpath")] {
                if let Some(v) = entries.iter().find(|(t, _)| *t == tag).and_then(|&(_, v)| s(v)) {
                    cx.format_set(key, v);
                }
            }
            let flags = entries.iter().find(|(t, _)| *t == 30).map_or(0, |&(_, v)| v);
            let flags1 = entries.iter().find(|(t, _)| *t == 0x6fff_fffb).map_or(0, |&(_, v)| v);
            bind_now = entries.iter().any(|(t, _)| *t == 24) || flags & 0x8 != 0 || flags1 & 1 != 0;
            if flags1 & 0x0800_0000 != 0 && kind == "shared_library" {
                cx.format_set("kind", "executable");
            }
            if entries.iter().any(|(t, _)| *t == 22) || flags & 0x4 != 0 {
                hard.insert("text_relocations".into(), true.into());
            }
        }
        if hd.kind == 3 && cx.format().get("kind").is_some_and(|k| k == "executable") {
            hard.insert("pie".into(), true.into());
        } else if hd.kind == 2 {
            hard.insert("pie".into(), false.into());
        }
        if hd.kind != 1 {
            let relro = match (phdrs.iter().any(|p| p.kind == PT_GNU_RELRO), bind_now) {
                (true, true) => "full",
                (true, false) => "partial",
                _ => "none",
            };
            hard.insert("relro".into(), relro.into());
        }

        // Symbols.
        let has_symtab = shdrs.iter().any(|s| s.kind == SHT_SYMTAB);
        let mut imports = Vec::new();
        let mut exports = Vec::new();
        let mut all_names: Vec<String> = Vec::new();
        for table in shdrs.iter().filter(|s| s.kind == SHT_DYNSYM || (s.kind == SHT_SYMTAB && hd.kind == 1)) {
            let Some(strs) = shdrs.get(table.link as usize) else { continue };
            let strings = src.read_vec(strs.offset, usize::try_from(strs.size.min(8 << 20)).unwrap_or(0))?;
            let ent = if wide { 24 } else { 16 };
            let n = usize::try_from(table.size / ent as u64).unwrap_or(0).min(MAX_SYMBOLS);
            let data = src.read_vec(table.offset, n * ent)?;
            for c in data.chunks_exact(ent).skip(1) {
                let (name, info, shndx) =
                    if wide { (e.u32(c, 0), c[4], e.u16(c, 6)) } else { (e.u32(c, 0), c[12], e.u16(c, 14)) };
                let (Some(name), Some(shndx)) = (name, shndx) else { continue };
                let n = strings.get(name as usize..).map(c_string_raw).unwrap_or_default();
                if n.is_empty() {
                    continue;
                }
                let bind = info >> 4;
                let ty = info & 0xf;
                if shndx == 0 {
                    imports.push(n.clone());
                } else if (bind == 1 || bind == 2) && (ty == 1 || ty == 2) {
                    exports.push(n.clone());
                }
                all_names.push(n);
            }
        }
        imports.sort();
        imports.dedup();
        exports.sort();
        exports.dedup();
        if !imports.is_empty() {
            cx.format_set("imported_symbol_count", imports.len());
            cx.format_set("imports", names(&imports));
        }
        if !exports.is_empty() {
            cx.format_set("exported_symbol_count", exports.len());
            cx.format_set("exports", names(&exports));
        }
        if hd.kind != 1 {
            hard.insert("stripped".into(), (!has_symtab).into());
        }
        let canary = all_names.iter().any(|n| n == "__stack_chk_fail" || n == "__stack_chk_guard");
        let fortify = all_names.iter().any(|n| n.starts_with("__") && n.ends_with("_chk") && n != "__stack_chk_fail");
        hard.insert("stack_canary".into(), canary.into());
        hard.insert("fortify".into(), fortify.into());

        // Notes.
        let mut notes: Vec<(u64, u64)> =
            shdrs.iter().filter(|s| s.kind == SHT_NOTE).map(|s| (s.offset, s.size)).collect();
        if notes.is_empty() {
            notes = phdrs.iter().filter(|p| p.kind == PT_NOTE).map(|p| (p.offset, p.filesz)).collect();
        }
        for (off, size) in notes {
            let data = src.read_vec(off, usize::try_from(size.min(1 << 16)).unwrap_or(0))?;
            for (owner, ty, desc) in parse_notes(e, &data) {
                note(cx, &hd, &owner, ty, desc, &mut hard);
            }
        }
        cx.format_set("hardening", Value::Object(hard));

        // Debug information.
        let debug: Vec<&Shdr> =
            shdrs.iter().filter(|s| s.name.starts_with(".debug_") || s.name.starts_with(".zdebug_")).collect();
        if !debug.is_empty() || shdrs.iter().any(|s| s.name == ".gnu_debuglink") {
            let mut d = Map::new();
            d.insert("dwarf".into(), (!debug.is_empty()).into());
            if let Some(link) = shdrs.iter().find(|s| s.name == ".gnu_debuglink") {
                let b = src.read_vec(link.offset, usize::try_from(link.size.min(512)).unwrap_or(0))?;
                d.insert("debuglink".into(), c_string_raw(&b).into());
            }
            // Before relocation an object's string offsets are placeholders.
            let relocatable = hd.kind == 1;
            let find = |n: &str| {
                if relocatable && n != ".debug_info" && n != ".debug_abbrev" {
                    return None;
                }
                shdrs.iter().find(|s| s.name == n).map(|s| (s.offset, s.size))
            };
            if let Some(unit) = dwarf_summary(src, hd.e, &find, cx.redactor()) {
                d.extend(unit);
            }
            cx.format_set("debug", Value::Object(d));
        }

        let mut tc = scan_toolchain(src, cx)?;
        if let Some(c) = shdrs.iter().find(|s| s.name == ".comment") {
            let b = src.read_vec(c.offset, usize::try_from(c.size.min(4096)).unwrap_or(0))?;
            for s in
                b.split(|&x| x == 0).map(|s| String::from_utf8_lossy(s).trim().to_string()).filter(|s| !s.is_empty())
            {
                tc.add_compiler(s);
            }
        }
        tc.write(cx);
        Ok(())
    }
}

crate::register_extractor!(Elf);

fn raw_shdr(h: &Header, c: &[u8]) -> Option<Shdr> {
    let e = h.e;
    Some(if h.wide {
        Shdr {
            name: e.u32(c, 0)?.to_string(),
            kind: e.u32(c, 4)?,
            flags: e.u64(c, 8)?,
            addr: e.u64(c, 16)?,
            offset: e.u64(c, 24)?,
            size: e.u64(c, 32)?,
            link: e.u32(c, 40)?,
        }
    } else {
        Shdr {
            name: e.u32(c, 0)?.to_string(),
            kind: e.u32(c, 4)?,
            flags: u64::from(e.u32(c, 8)?),
            addr: u64::from(e.u32(c, 12)?),
            offset: u64::from(e.u32(c, 16)?),
            size: u64::from(e.u32(c, 20)?),
            link: e.u32(c, 24)?,
        }
    })
}

fn raw_phdr(h: &Header, c: &[u8]) -> Option<Phdr> {
    let e = h.e;
    Some(if h.wide {
        Phdr {
            kind: e.u32(c, 0)?,
            flags: e.u32(c, 4)?,
            offset: e.u64(c, 8)?,
            vaddr: e.u64(c, 16)?,
            filesz: e.u64(c, 32)?,
            memsz: e.u64(c, 40)?,
        }
    } else {
        Phdr {
            kind: e.u32(c, 0)?,
            offset: u64::from(e.u32(c, 4)?),
            vaddr: u64::from(e.u32(c, 8)?),
            filesz: u64::from(e.u32(c, 16)?),
            memsz: u64::from(e.u32(c, 20)?),
            flags: e.u32(c, 24)?,
        }
    })
}

/// The text up to the first NUL.
fn c_string_raw(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len()).min(4096);
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// The file offset of a virtual address, through the loadable segments.
fn file_offset(phdrs: &[Phdr], vaddr: u64) -> Option<u64> {
    phdrs
        .iter()
        .filter(|p| p.kind == PT_LOAD)
        .find(|p| vaddr >= p.vaddr && vaddr - p.vaddr < p.filesz)
        .map(|p| p.offset + (vaddr - p.vaddr))
}

/// `(owner, type, descriptor)` of each note.
fn parse_notes(e: Endian, data: &[u8]) -> Vec<(String, u32, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while out.len() < 256 {
        let (Some(namesz), Some(descsz), Some(ty)) = (e.u32(data, at), e.u32(data, at + 4), e.u32(data, at + 8)) else {
            break;
        };
        let (namesz, descsz) = (namesz as usize, descsz as usize);
        let name_at = at + 12;
        let Some(desc_at) = name_at.checked_add(namesz.div_ceil(4) * 4) else { break };
        let Some(name) = data.get(name_at..name_at + namesz) else { break };
        let Some(desc) = desc_at.checked_add(descsz).and_then(|end| data.get(desc_at..end)) else { break };
        out.push((c_string_raw(name), ty, desc));
        at = desc_at + descsz.div_ceil(4) * 4;
    }
    out
}

fn note(cx: &mut Context<'_>, h: &Header, owner: &str, ty: u32, desc: &[u8], hard: &mut Map<String, Value>) {
    let e = h.e;
    match (owner, ty) {
        ("GNU", 3) => cx.format_set("build_id", hex(desc)),
        ("GNU", 1) => {
            let os = match e.u32(desc, 0) {
                Some(0) => "linux",
                Some(1) => "hurd",
                Some(2) => "solaris",
                Some(3) => "freebsd",
                _ => return,
            };
            cx.format_set("os", os);
            if let (Some(a), Some(b), Some(c)) = (e.u32(desc, 4), e.u32(desc, 8), e.u32(desc, 12)) {
                cx.format_set("minimum_kernel", format!("{a}.{b}.{c}"));
            }
        }
        ("GNU", 5) => {
            // GNU properties: (type, size, data) aligned to 8 (64-bit) or 4.
            let align = if h.wide { 8 } else { 4 };
            let mut at = 0;
            while let (Some(pt), Some(sz)) = (e.u32(desc, at), e.u32(desc, at + 4)) {
                let v = e.u32(desc, at + 8).unwrap_or(0);
                match (h.machine, pt) {
                    (62 | 3, 0xc000_0002) => {
                        hard.insert("ibt".into(), (v & 1 != 0).into());
                        hard.insert("shadow_stack".into(), (v & 2 != 0).into());
                    }
                    (183, 0xc000_0000) => {
                        hard.insert("bti".into(), (v & 1 != 0).into());
                        hard.insert("pac".into(), (v & 2 != 0).into());
                    }
                    _ => {}
                }
                at += 8 + (sz as usize).div_ceil(align) * align;
                if at > desc.len() {
                    break;
                }
            }
        }
        ("Go", 4) => cx.format_set("go_build_id", String::from_utf8_lossy(desc).into_owned()),
        ("Android", 1) => {
            if let Some(api) = e.u32(desc, 0) {
                cx.format_set("os", "android");
                cx.format_set("android_api", api);
            }
        }
        ("FDO", 0xcafe_1a7e) => {
            let text = c_string_raw(desc);
            if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(&text) {
                let keep: Map<String, Value> = m
                    .into_iter()
                    .filter(|(k, v)| {
                        v.is_string()
                            && ["type", "name", "version", "architecture", "os", "osVersion", "debugInfoUrl"]
                                .contains(&k.as_str())
                    })
                    .collect();
                cx.format_set("package", Value::Object(keep));
            }
        }
        _ => {}
    }
}

/// eBPF objects: the licence string and the programs (executable sections,
/// named after their attach point: `xdp`, `kprobe/…`, `tracepoint/…`).
fn ebpf(src: &mut dyn Source, cx: &mut Context<'_>, shdrs: &[Shdr]) -> Result<(), ExtractError> {
    if let Some(l) = shdrs.iter().find(|s| s.name == "license") {
        let b = src.read_vec(l.offset, usize::try_from(l.size.min(128)).unwrap_or(0))?;
        cx.format_set("license", c_string_raw(&b));
    }
    let programs: Vec<&str> =
        shdrs.iter().filter(|s| s.flags & 4 != 0 && s.size > 0 && s.name != ".text").map(|s| s.name.as_str()).collect();
    if !programs.is_empty() {
        cx.format_set("programs", names(&programs));
    }
    let maps = shdrs.iter().any(|s| s.name == ".maps" || s.name == "maps");
    cx.format_set("has_maps", maps);
    Ok(())
}

/// Core dumps: the signal, process, arguments and threads from the notes.
fn core(src: &mut dyn Source, cx: &mut Context<'_>, h: &Header, phdrs: &[Phdr]) -> Result<(), ExtractError> {
    let e = h.e;
    let mut threads = 0usize;
    let mut mapped = 0usize;
    for p in phdrs.iter().filter(|p| p.kind == PT_NOTE) {
        if p.offset.saturating_add(p.filesz) > src.len() {
            cx.warn("note segment past the end of the file");
            continue;
        }
        let data = src.read_vec(p.offset, usize::try_from(p.filesz.min(4 << 20)).unwrap_or(0))?;
        for (owner, ty, desc) in parse_notes(e, &data) {
            if owner != "CORE" {
                continue;
            }
            match ty {
                1 => {
                    threads += 1;
                    if threads == 1
                        && let Some(sig) = e.u16(desc, 12)
                    {
                        cx.format_set("signal_number", sig);
                        if let Some(n) = signal(u32::from(sig)) {
                            cx.format_set("signal", n);
                        }
                    }
                }
                3 => {
                    let (pid_at, fname_at) = if h.wide { (24, 40) } else { (12, 28) };
                    if let Some(pid) = e.u32(desc, pid_at) {
                        cx.format_set("pid", pid);
                    }
                    if let Some(name) = desc.get(fname_at..fname_at + 16) {
                        cx.format_set("process", c_string_raw(name));
                    }
                    if let Some(args) = desc.get(fname_at + 16..fname_at + 96) {
                        let a = c_string(args, 80);
                        if !a.is_empty() {
                            cx.format_set("command_line", cx.redact_secrets(&a).into_owned());
                        }
                    }
                }
                0x4649_4c45 => {
                    mapped = usize::try_from(e.word(desc, 0, h.wide).unwrap_or(0)).unwrap_or(0);
                }
                _ => {}
            }
        }
    }
    cx.format_set("threads", threads);
    if mapped > 0 {
        cx.format_set("mapped_files", mapped);
    }
    let segments = phdrs.iter().filter(|p| p.kind == PT_LOAD).count();
    cx.format_set("memory_segments", segments);
    cx.format_set("memory_bytes", phdrs.iter().filter(|p| p.kind == PT_LOAD).map(|p| p.memsz).sum::<u64>());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notes_are_split() {
        let e = Endian { le: true };
        let mut n = Vec::new();
        n.extend([4u8, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0]);
        n.extend(b"GNU\0");
        n.extend([0xde, 0xad, 0xbe, 0xef]);
        let notes = parse_notes(e, &n);
        assert_eq!(notes.len(), 1);
        assert_eq!((notes[0].0.as_str(), notes[0].1, notes[0].2), ("GNU", 3, &[0xde, 0xad, 0xbe, 0xef][..]));
        // A size past the end stops the walk.
        n[4] = 0xff;
        assert_eq!(parse_notes(e, &n).len(), 0);
    }

    #[test]
    fn addresses_map_to_offsets() {
        let p = Phdr { kind: PT_LOAD, flags: 5, offset: 0x1000, vaddr: 0x40_1000, filesz: 0x100, memsz: 0x100 };
        assert_eq!(file_offset(&[p], 0x40_1010), Some(0x1010));
        assert_eq!(machine(183), "arm64");
    }

    crate::fixture_tests!("elf", "elf_core", "ebpf");
}
