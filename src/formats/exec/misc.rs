//! Executable images and blobs outside the ELF / PE / Mach-O mainstream:
//!
//! * Linux kernel images: the x86 boot header of a `bzImage` (boot
//!   protocol, the version string: release, build number, flags and date,
//!   with the builder's `user@host` kept out under strict privacy, and the
//!   payload's compression) and the ARM64 `Image` header (size, page size,
//!   byte order, EFI stub);
//! * Android runtime files: OAT / ODEX (ELF files whose `oatdata` starts
//!   with `oat\n` and a version; the compiler filter from the key-value
//!   store), VDEX (version, sections, the number of DEX files) and ART
//!   images (version);
//! * AIX XCOFF objects and executables (32 and 64 bit: kind, sections,
//!   symbols, time stamp);
//! * flattened device trees (`.dtb`, `.dtbo`: version, the root `model` and
//!   `compatible`, node and property counts, overlay fragments, memory
//!   reservations) and their source (`.dts`);
//! * Xilinx bitstreams (`.bit`: design, user id, tool version, part, date
//!   and time, bitstream size).
//!
//! Specifications: the Linux x86 boot protocol and arm64 booting
//! documents; AOSP's `oat.h`, `vdex_file.h` and `image.h`; IBM's XCOFF
//! object file format; the Devicetree Specification 0.4 (§5); the Xilinx
//! `.bit` header as documented by its readers (`xc3sprog`, `bitinfo`).

use crate::plugin::{
    ByteReader, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff,
    Source, latin1_or_utf8,
};

/// Extractor for kernel images, Android runtime files, XCOFF, device trees
/// and Xilinx bitstreams.
pub struct Misc;

const BIT_PREFIX: &[u8] = b"\x00\x09\x0f\xf0\x0f\xf0\x0f\xf0\x0f\xf0\x00\x00\x01";

static META: ExtractorMeta = ExtractorMeta {
    id: "exec.misc",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "linux_kernel",
            name: "Linux kernel image",
            family: "exec",
            mimes: &["application/x-linux-kernel"],
            extensions: &["vmlinuz", "bzimage"],
            magic: &[Magic::at(0x202, b"HdrS"), Magic::at(0x38, b"ARM\x64")],
            parent: None,
        },
        FormatSpec {
            id: "android_oat",
            name: "Android OAT / ODEX",
            family: "exec",
            mimes: &["application/x-android-oat"],
            extensions: &["oat", "odex"],
            magic: &[],
            parent: Some("elf"),
        },
        FormatSpec {
            id: "android_vdex",
            name: "Android VDEX",
            family: "exec",
            mimes: &["application/x-android-vdex"],
            extensions: &["vdex"],
            magic: &[Magic::prefix(b"vdex")],
            parent: None,
        },
        FormatSpec {
            id: "android_art",
            name: "Android ART image",
            family: "exec",
            mimes: &["application/x-android-art"],
            extensions: &["art"],
            magic: &[Magic::prefix(b"art\n")],
            parent: None,
        },
        FormatSpec {
            id: "xcoff",
            name: "AIX XCOFF",
            family: "exec",
            mimes: &["application/x-xcoff"],
            extensions: &["xcoff"],
            magic: &[Magic::prefix(b"\x01\xdf"), Magic::prefix(b"\x01\xf7")],
            parent: None,
        },
        FormatSpec {
            id: "fdt",
            name: "Device tree blob",
            family: "exec",
            mimes: &["application/x-dtb"],
            extensions: &["dtb", "dtbo"],
            magic: &[Magic::prefix(b"\xd0\x0d\xfe\xed")],
            parent: None,
        },
        FormatSpec {
            id: "dts",
            name: "Device tree source",
            family: "exec",
            mimes: &["text/x-device-tree-source"],
            extensions: &["dts", "dtsi"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "xilinx_bit",
            name: "Xilinx FPGA bitstream",
            family: "exec",
            mimes: &["application/x-xilinx-bitstream"],
            extensions: &["bit"],
            magic: &[Magic::prefix(BIT_PREFIX)],
            parent: None,
        },
    ],
};

/// Device tree nodes walked.
const MAX_NODES: usize = 100_000;

impl Extractor for Misc {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        // An arm64 kernel with an EFI stub also starts with `MZ`.
        if h.get(0x38..0x3c) == Some(b"ARM\x64") {
            return Some(Sniff { format: "linux_kernel", confidence: 0.95 });
        }
        if h.starts_with(b"\x7fELF") {
            let oat = matches!(probe.extension, Some("oat" | "odex")) || find_oat(h).is_some();
            return oat.then_some(Sniff { format: "android_oat", confidence: 0.9 });
        }
        let text = &h[..h.len().min(4096)];
        let dts = text.windows(9).any(|w| w == b"/dts-v1/;")
            || (matches!(probe.extension, Some("dts" | "dtsi")) && text.windows(11).any(|w| w == b"compatible "));
        dts.then_some(Sniff { format: "dts", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "linux_kernel" => kernel(src, cx),
            "android_oat" => oat(src, cx),
            "android_vdex" => vdex(src, cx),
            "android_art" => art(src, cx),
            "xcoff" => xcoff(src, cx),
            "fdt" => fdt(src, cx),
            "dts" => dts(src, cx),
            _ => bit(src, cx),
        }
    }
}

crate::register_extractor!(Misc);

fn cstr(b: &[u8]) -> String {
    latin1_or_utf8(b.split(|&c| c == 0).next().unwrap_or(&[]))
}

// --- Linux kernel ------------------------------------------------------------------

fn compression(b: &[u8]) -> Option<&'static str> {
    Some(match b {
        [0x1f, 0x8b, ..] => "gzip",
        [0xfd, b'7', b'z', b'X', b'Z', 0, ..] => "xz",
        [0x28, 0xb5, 0x2f, 0xfd, ..] => "zstd",
        [0x02, 0x21, 0x4c, 0x18, ..] => "lz4",
        [b'B', b'Z', b'h', ..] => "bzip2",
        [0x89, b'L', b'Z', b'O', ..] => "lzo",
        [0x5d, 0, 0, ..] => "lzma",
        _ => return None,
    })
}

/// `6.12.0-1 (user@host) (gcc …) #1 SMP PREEMPT_DYNAMIC Mon Sep 1 12:00:00 UTC 2025`.
fn version_string(cx: &mut Context<'_>, v: &str) {
    cx.format_set("version_string_present", true);
    let release = v.split_whitespace().next().unwrap_or("");
    cx.format_set("release", release);
    cx.content().title(format!("Linux {release}"));
    if let (Some(a), Some(b)) = (v.find('('), v.find(')'))
        && a < b
        && !cx.privacy_strict()
    {
        cx.format_set("built_by", &v[a + 1..b]);
    }
    if let Some(hash) = v.find(" #") {
        let rest = &v[hash + 2..];
        let mut words = rest.split_whitespace();
        if let Some(n) = words.next() {
            cx.format_set("build", n);
        }
        let flags: Vec<&str> = rest
            .split_whitespace()
            .filter(|w| matches!(*w, "SMP" | "PREEMPT" | "PREEMPT_DYNAMIC" | "PREEMPT_RT"))
            .collect();
        if !flags.is_empty() {
            cx.format_set("flags", flags);
        }
        // The date: the words after the flags (`Mon Sep 1 12:00:00 UTC 2025`).
        let date: Vec<&str> = rest
            .split_whitespace()
            .skip(1)
            .skip_while(|w| w.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
            .collect();
        if date.len() >= 4 {
            cx.format_set("build_date", date.join(" "));
        }
    }
}

/// The `Linux version …` banner in the first 8 MiB, without its prefix.
fn banner(src: &mut dyn Source) -> Result<Option<String>, ExtractError> {
    const NEEDLE: &[u8] = b"Linux version ";
    const WINDOW: u64 = 1 << 20;
    let end = src.len().min(8 << 20);
    let mut at = 0u64;
    while at < end {
        let n = (end - at).min(WINDOW + 512);
        let buf = src.read_vec(at, usize::try_from(n).unwrap_or(0))?;
        if let Some(p) = buf.windows(NEEDLE.len()).position(|w| w == NEEDLE) {
            let v: Vec<u8> =
                buf[p + NEEDLE.len()..].iter().take(400).take_while(|b| (0x20..0x7f).contains(*b)).copied().collect();
            return Ok(Some(latin1_or_utf8(&v)).filter(|v| !v.is_empty()));
        }
        at += WINDOW;
    }
    Ok(None)
}

fn kernel(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    let h = src.read_vec(0, usize::try_from(len.min(64 * 1024)).unwrap_or(0))?;
    if h.get(0x38..0x3c) == Some(b"ARM\x64") {
        cx.format_set("architecture", "arm64");
        let mut r = ByteReader::new(&h).skip(8)?;
        cx.format_set("text_offset", r.le_u64()?);
        cx.format_set("image_bytes", r.le_u64()?);
        let flags = r.le_u64()?;
        cx.format_set("byte_order", if flags & 1 == 0 { "little-endian" } else { "big-endian" });
        if let Some(p) = match (flags >> 1) & 3 {
            1 => Some("4K"),
            2 => Some("16K"),
            3 => Some("64K"),
            _ => None,
        } {
            cx.format_set("page_size", p);
        }
        if h.starts_with(b"MZ") {
            cx.format_set("efi_stub", true);
        }
        // No version pointer: the `Linux version …` banner in the image.
        if let Some(v) = banner(src)? {
            version_string(cx, &v);
        }
        return Ok(());
    }
    cx.format_set("architecture", "x86");
    let mut r = ByteReader::new(&h).skip(0x1f1)?;
    let setup_sects = u64::from(r.u8()?.max(4));
    let mut r = ByteReader::new(&h).skip(0x206)?;
    let protocol = r.le_u16()?;
    cx.format_set("boot_protocol", format!("{}.{:02}", protocol >> 8, protocol & 0xff));
    let mut r = ByteReader::new(&h).skip(0x20e)?;
    let vptr = usize::from(r.le_u16()?);
    if vptr > 0
        && let Some(v) = h.get(0x200 + vptr..)
    {
        let v = cstr(&v[..v.len().min(512)]);
        if !v.is_empty() {
            version_string(cx, &v);
        }
    }
    let flags = h.get(0x211).copied().unwrap_or(0);
    cx.format_set("loads_high", flags & 1 != 0);
    // The compressed kernel: `payload_offset` (protocol 2.08+) from the
    // start of the protected-mode code.
    if protocol >= 0x208 && h.len() >= 0x250 {
        let mut r = ByteReader::new(&h).skip(0x248)?;
        let at = (setup_sects + 1) * 512 + u64::from(r.le_u32()?);
        if at + 8 <= len {
            let p = src.read_vec(at, 8)?;
            if let Some(c) = compression(&p) {
                cx.format_set("compression", c);
            }
        }
    }
    Ok(())
}

// --- Android runtime -------------------------------------------------------------------

/// `oat\n` + three digits + NUL: its offset.
fn find_oat(b: &[u8]) -> Option<usize> {
    b.windows(8).position(|w| &w[..4] == b"oat\n" && w[4..7].iter().all(u8::is_ascii_digit) && w[7] == 0)
}

fn version3(b: &[u8]) -> Option<String> {
    let v = b.get(..4)?;
    (v[..3].iter().all(u8::is_ascii_digit) && v[3] == 0).then(|| latin1_or_utf8(&v[..3]))
}

fn oat(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, usize::try_from(src.len().min(1 << 20)).unwrap_or(0))?;
    let Some(at) = find_oat(&h) else {
        cx.warn("no OAT header in the first MiB");
        return Ok(());
    };
    if let Some(v) = version3(&h[at + 4..]) {
        cx.format_set("oat_version", v);
    }
    // The key-value store holds NUL-terminated pairs.
    let store = &h[at..h.len().min(at + 64 * 1024)];
    for key in ["compiler-filter", "debuggable", "native-debuggable", "concurrent-copying"] {
        let needle = [key.as_bytes(), b"\0"].concat();
        if let Some(p) = store.windows(needle.len()).position(|w| w == needle) {
            let value = cstr(&store[p + needle.len()..store.len().min(p + needle.len() + 64)]);
            if !value.is_empty() {
                cx.format_set(&key.replace('-', "_"), value);
            }
        }
    }
    Ok(())
}

fn vdex(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, usize::try_from(src.len().min(4096)).unwrap_or(0))?;
    let version = version3(h.get(4..).unwrap_or(&[])).ok_or_else(|| ExtractError::malformed("VDEX version"))?;
    cx.format_set("vdex_version", version.clone());
    // Version 027 on (Android 12): a section table of (kind, offset, size).
    if version.as_str() >= "027" {
        let mut r = ByteReader::new(&h).skip(8)?;
        let n = r.le_u32()?.min(16);
        let mut names = Vec::new();
        for _ in 0..n {
            let (kind, _, size) = (r.le_u32()?, r.le_u32()?, r.le_u32()?);
            let name = match kind {
                0 => "checksums",
                1 => "dex_files",
                2 => "verifier_deps",
                3 => "type_lookup_table",
                _ => "other",
            };
            if kind == 0 {
                cx.format_set("dex_files", size / 4);
            }
            if size > 0 {
                names.push(name);
            }
        }
        cx.format_set("sections", names);
    }
    Ok(())
}

fn art(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, usize::try_from(src.len().min(8)).unwrap_or(0))?;
    if let Some(v) = version3(h.get(4..).unwrap_or(&[])) {
        cx.format_set("art_version", v);
    }
    Ok(())
}

// --- XCOFF ---------------------------------------------------------------------------

fn xcoff(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 24)?;
    let wide = h[1] == 0xf7;
    let mut r = ByteReader::new(&h).skip(2)?;
    let sections = r.be_u16()?;
    let time = r.be_u32()?;
    let (symbols, opthdr, flags) = if wide {
        r.advance(8)?;
        let (o, f) = (r.be_u16()?, r.be_u16()?);
        (r.be_u32()?, o, f)
    } else {
        r.advance(4)?;
        let s = r.be_u32()?;
        (s, r.be_u16()?, r.be_u16()?)
    };
    cx.format_set("bits", if wide { 64 } else { 32 });
    cx.format_set("architecture", "PowerPC");
    let kind = if flags & 0x2000 != 0 {
        "shared object"
    } else if flags & 0x0002 != 0 {
        "executable"
    } else {
        "object"
    };
    cx.format_set("kind", kind);
    cx.format_set("symbols", symbols);
    if let Some(t) = super::super::archive::unix_time(i64::from(time)) {
        cx.format_set("time_stamp", t.clone());
        cx.temporal().content_date(DateField::Created, t, true);
    }
    let (start, size) = (if wide { 24 } else { 20 } + u64::from(opthdr), if wide { 72 } else { 40 });
    let table = src.read_vec(start, usize::try_from(u64::from(sections.min(256)) * size).unwrap_or(0))?;
    let list: Vec<serde_json::Value> = table
        .chunks(usize::try_from(size).unwrap_or(40))
        .map(|s| {
            let bytes = if wide {
                u64::from_be_bytes(s[24..32].try_into().unwrap_or([0; 8]))
            } else {
                u64::from(u32::from_be_bytes(s[16..20].try_into().unwrap_or([0; 4])))
            };
            serde_json::json!({ "name": cstr(&s[..8]), "size_bytes": bytes })
        })
        .collect();
    cx.format_set("sections", list);
    Ok(())
}

// --- device trees ------------------------------------------------------------------------

/// A property value as text: NUL-separated strings, joined by `, `.
fn prop_text(v: &[u8]) -> Option<String> {
    let v = v.strip_suffix(b"\0")?;
    (!v.is_empty() && v.iter().all(|&b| b == 0 || (0x20..0x7f).contains(&b)))
        .then(|| v.split(|&b| b == 0).map(latin1_or_utf8).collect::<Vec<_>>().join(", "))
}

fn fdt(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 40)?;
    let mut r = ByteReader::new(&h).skip(4)?;
    let total = u64::from(r.be_u32()?);
    let (off_struct, off_strings, off_rsv) = (r.be_u32()?, r.be_u32()?, r.be_u32()?);
    let (version, last_comp) = (r.be_u32()?, r.be_u32()?);
    r.be_u32()?;
    let strings_size = r.be_u32()?;
    let struct_size = r.be_u32()?;
    cx.format_set("version", version);
    cx.format_set("last_compatible_version", last_comp);
    if total != src.len() {
        cx.format_set("declared_bytes", total);
    }
    let cap = cx.parse_limit() as u64;
    let read = |src: &mut dyn Source, at: u32, n: u32| -> Result<Vec<u8>, ExtractError> {
        let room = src.len().saturating_sub(u64::from(at));
        Ok(src.read_vec(u64::from(at), usize::try_from(u64::from(n).min(cap).min(room)).unwrap_or(0))?)
    };
    let strings = read(src, off_strings, strings_size)?;
    let body = read(
        src,
        off_struct,
        if version >= 17 { struct_size } else { u32::try_from(total).unwrap_or(0).saturating_sub(off_struct) },
    )?;
    // Memory reservations: (address, size) pairs up to a zero pair.
    let rsv = read(src, off_rsv, 16 * 64)?;
    let reservations = rsv.as_chunks::<16>().0.iter().take_while(|c| c.iter().any(|&b| b != 0)).count();
    if reservations > 0 {
        cx.format_set("memory_reservations", reservations);
    }
    let (mut r, mut depth, mut nodes, mut props, mut fragments) =
        (ByteReader::new(&body), 0usize, 0usize, 0usize, 0usize);
    let mut path: Vec<String> = Vec::new();
    while r.remaining() >= 4 && nodes < MAX_NODES {
        match r.be_u32()? {
            1 => {
                let name = cstr(&body[r.position()..]);
                let n = name.len() + 1;
                r.advance(n.next_multiple_of(4))?;
                nodes += 1;
                depth += 1;
                if name.starts_with("fragment@") {
                    fragments += 1;
                }
                path.push(name);
            }
            2 => {
                depth = depth.saturating_sub(1);
                path.pop();
            }
            3 => {
                let (n, name_off) = (usize::try_from(r.be_u32()?).unwrap_or(0), r.be_u32()?);
                let value = r.bytes(n)?.to_vec();
                r.advance(n.next_multiple_of(4) - n)?;
                props += 1;
                if depth == 1 {
                    let name = cstr(strings.get(usize::try_from(name_off).unwrap_or(usize::MAX)..).unwrap_or(&[]));
                    if let ("model" | "compatible", Some(t)) = (name.as_str(), prop_text(&value)) {
                        if name == "model" {
                            cx.content().title(t.clone());
                        }
                        cx.format_set(&name, t);
                    }
                }
            }
            4 => {}
            9 => break,
            _ => return Err(ExtractError::malformed("device tree token")),
        }
    }
    cx.format_set("nodes", nodes);
    cx.format_set("properties", props);
    if fragments > 0 {
        cx.format_set("overlay_fragments", fragments);
    }
    Ok(())
}

fn dts(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let text = src.read_vec(0, usize::try_from(src.len().min(cx.parse_limit() as u64)).unwrap_or(0))?;
    let text = String::from_utf8_lossy(&text);
    let (mut includes, mut nodes, mut depth, mut overlay) = (Vec::new(), 0usize, 0usize, false);
    for line in text.lines() {
        let t = line.trim();
        if let Some(inc) = t.strip_prefix("/include/").or_else(|| t.strip_prefix("#include")) {
            includes.push(inc.trim().trim_matches(['"', '<', '>']).to_string());
        }
        if t == "/plugin/;" {
            overlay = true;
        }
        if t.ends_with('{') {
            nodes += 1;
            depth += 1;
        }
        if depth == 1
            && let Some((k, v)) = t.split_once('=')
            && matches!(k.trim(), "model" | "compatible")
        {
            // The quoted strings: `"a,b", "c,d"`.
            let vals: Vec<&str> = v.split('"').skip(1).step_by(2).collect();
            if !vals.is_empty() {
                cx.format_set(k.trim(), vals.join(", "));
            }
        }
        depth -= t.matches('}').count().min(depth);
    }
    cx.format_set("nodes", nodes);
    if overlay {
        cx.format_set("overlay", true);
    }
    if !includes.is_empty() {
        cx.format_set("includes", includes);
    }
    Ok(())
}

// --- Xilinx bitstreams -------------------------------------------------------------------

fn bit(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, usize::try_from(src.len().min(4096)).unwrap_or(0))?;
    let mut r = ByteReader::new(&h).skip(BIT_PREFIX.len())?;
    while r.remaining() >= 3 {
        let key = r.u8()?;
        if key == b'e' {
            let n = r.be_u32()?;
            cx.format_set("bitstream_bytes", n);
            let rest = r.rest();
            let sync = rest.windows(4).take(256).any(|w| w == [0xaa, 0x99, 0x55, 0x66]);
            cx.format_set("sync_word", sync);
            break;
        }
        let n = usize::from(r.be_u16()?);
        let value = cstr(r.bytes(n)?);
        match key {
            b'a' => {
                // `design;UserID=0X…;Version=2024.2`
                let mut parts = value.split(';');
                if let Some(d) = parts.next() {
                    cx.format_set("design", d);
                    cx.content().title(d.to_string());
                }
                for p in parts {
                    match p.split_once('=') {
                        Some(("UserID", v)) => cx.format_set("user_id", v),
                        Some(("Version", v)) => cx.format_set("tool_version", v),
                        Some(("COMPRESS", v)) => cx.format_set("compressed", v == "TRUE"),
                        _ => {}
                    }
                }
            }
            b'b' => cx.format_set("part", value),
            b'c' => cx.format_set("date", value),
            b'd' => cx.format_set("time", value),
            _ => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!(
        "linux_kernel",
        "android_oat",
        "android_vdex",
        "android_art",
        "xcoff",
        "fdt",
        "dts",
        "xilinx_bit"
    );

    #[test]
    fn helpers() {
        assert_eq!(compression(&[0x1f, 0x8b, 8, 0]), Some("gzip"));
        assert_eq!(find_oat(b"xxoat\n239\0yy"), Some(2));
        assert_eq!(version3(b"027\0"), Some("027".into()));
        assert_eq!(prop_text(b"saltmere,harbour\0saltmere,bell\0").as_deref(), Some("saltmere,harbour, saltmere,bell"));
        assert_eq!(prop_text(b"\x00\x01\x02\x03"), None);
    }
}
