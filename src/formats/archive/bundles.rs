//! ZIP-based bundles named by what they carry:
//!
//! * Python zip applications (`.pyz`, PEP 441): an optional `#!` line, then
//!   a ZIP with `__main__.py` at its root (handed on as a child);
//! * PEX files: a zip application with a `PEX-INFO` manifest (entry point,
//!   requirements, interpreter constraints, the pex version that built it);
//! * Java modules (`.jmod`): `JM` 1.0, then a ZIP whose `classes/`,
//!   `bin/`, `conf/`, `lib/`, `legal/`, `include/` and `man/` folders hold
//!   the module; `classes/module-info.class` is handed on as a child;
//! * Android opaque binary blobs (`.obb`): the package and version from the
//!   `main.<version>.<package>.obb` name and from the `obbtool` footer, and
//!   the content (a ZIP or FAT image) handed on.
//!
//! Specifications: PEP 441; the pex `PEX-INFO` schema; JEP 261 (`jmod`);
//! Android's `ObbFile.cpp` and the expansion-file naming rules.

use std::collections::BTreeMap;

use super::{Inventory, child, zip::entry};
use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, Zip,
    latin1_or_utf8, zip_names,
};

/// Extractor for zip applications, PEX files, Java modules and OBB files.
pub struct Bundles;

static META: ExtractorMeta = ExtractorMeta {
    id: "archive.bundles",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "zipapp",
            name: "Python zip application",
            family: "archive",
            mimes: &["application/x-python-zipapp"],
            extensions: &["pyz", "pyzw"],
            magic: &[],
            parent: Some("zip"),
        },
        FormatSpec {
            id: "pex",
            name: "PEX (Python EXecutable)",
            family: "archive",
            mimes: &["application/x-pex"],
            extensions: &["pex"],
            magic: &[],
            parent: Some("zip"),
        },
        FormatSpec {
            id: "jmod",
            name: "Java module (JMOD)",
            family: "archive",
            mimes: &["application/x-java-jmod"],
            extensions: &["jmod"],
            magic: &[Magic::prefix(b"JM\x01\x00PK\x03\x04")],
            parent: None,
        },
        FormatSpec {
            id: "split_volume",
            name: "Split / multipart archive volume",
            family: "archive",
            mimes: &["application/octet-stream"],
            extensions: &["001", "z01", "r00"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "obb",
            name: "Android opaque binary blob (OBB)",
            family: "archive",
            mimes: &["application/x-android-obb"],
            extensions: &["obb"],
            magic: &[],
            parent: None,
        },
    ],
};

const MAX_ENTRIES: usize = 1 << 16;
/// The `obbtool` footer's signature.
const OBB_SIG: [u8; 4] = 0x0105_9983u32.to_le_bytes();

impl Extractor for Bundles {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // Below any format the content itself names (the first volume of a
        // 7z or RAR set is still a 7z or RAR file).
        if probe.name.and_then(volume).is_some() {
            return Some(Sniff { format: "split_volume", confidence: 0.4 });
        }
        if probe.extension == Some("obb") || probe.tail.ends_with(&OBB_SIG) {
            return Some(Sniff { format: "obb", confidence: 0.95 });
        }
        let names = zip_names(probe, 4000);
        if names.iter().any(|n| n == "PEX-INFO") {
            return Some(Sniff { format: "pex", confidence: 0.95 });
        }
        if names.iter().any(|n| n == "__main__.py") {
            let confidence = if matches!(probe.extension, Some("pyz" | "pyzw")) { 0.9 } else { 0.6 };
            return Some(Sniff { format: "zipapp", confidence });
        }
        // A `#!` line ahead of the ZIP: the names are read from the head.
        let h = probe.head;
        let shebang_zip = h.starts_with(b"#!")
            && h.iter().position(|&b| b == b'\n').is_some_and(|nl| h[nl + 1..].starts_with(b"PK\x03\x04"));
        if shebang_zip {
            let has = |n: &[u8]| h.windows(n.len()).any(|w| w == n);
            if has(b"PEX-INFO") || has(b".bootstrap/") {
                return Some(Sniff { format: "pex", confidence: 0.9 });
            }
            if has(b"__main__.py") || matches!(probe.extension, Some("pyz" | "pyzw")) {
                return Some(Sniff { format: "zipapp", confidence: 0.9 });
            }
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "zipapp" | "pex" => zipapp(src, cx),
            "jmod" => jmod(src, cx),
            "split_volume" => split_volume(src, cx),
            _ => obb(src, cx),
        }
    }
}

crate::register_extractor!(Bundles);

/// The `#!` line, if the file starts with one.
fn shebang(src: &mut dyn Source) -> Result<Option<String>, ExtractError> {
    let h = src.read_vec(0, usize::try_from(src.len().min(512)).unwrap_or(0))?;
    Ok(h.strip_prefix(b"#!").and_then(|r| {
        let end = r.iter().position(|&b| b == b'\n')?;
        Some(latin1_or_utf8(&r[..end]).trim().to_string())
    }))
}

fn zipapp(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    if let Some(s) = shebang(src)? {
        cx.format_set("interpreter", s);
    }
    let zip = Zip::open(src, MAX_ENTRIES)?;
    let mut inv = Inventory::new();
    for e in &zip.entries {
        inv.push(entry(e));
    }
    if cx.format_id() == "pex" {
        if let Some(Ok(text)) = zip.read_text(src, "PEX-INFO", cx, 1 << 20) {
            pex_info(cx, &text);
        }
        // The bootstrap is pex's own code, not the application's.
        let boot = zip.entries.iter().filter(|e| e.name.starts_with(".bootstrap/")).count();
        if boot > 0 {
            cx.format_set("bootstrap_entries", boot);
        }
    }
    let packages: BTreeMap<String, u64> = zip
        .entries
        .iter()
        .filter(|e| {
            std::path::Path::new(&e.name).extension().is_some_and(|x| x.eq_ignore_ascii_case("py"))
                && !e.name.starts_with('.')
        })
        .filter_map(|e| e.name.split_once('/').map(|(top, _)| top.to_string()))
        .fold(BTreeMap::new(), |mut m, p| {
            *m.entry(p).or_default() += 1;
            m
        });
    if !packages.is_empty() {
        cx.format_set("packages", packages.into_keys().collect::<Vec<_>>());
    }
    inv.report(cx, src.len());
    if let Some(main) = zip.entries.iter().find(|e| e.name == "__main__.py").cloned() {
        cx.format_set("main", "__main__.py");
        let data = zip.read(src, &main, cx, cx.parse_limit())?;
        let complete = data.len() as u64 == main.size;
        child(cx, "__main__.py", data, complete)?;
    }
    Ok(())
}

fn pex_info(cx: &mut Context<'_>, text: &str) {
    use serde_json::Value;
    let Ok(Value::Object(m)) = serde_json::from_str::<Value>(text) else {
        cx.warn("PEX-INFO is not a JSON object");
        return;
    };
    let s = |k: &str| m.get(k).and_then(Value::as_str).filter(|v| !v.is_empty()).map(str::to_string);
    let list = |k: &str| -> Vec<Value> {
        m.get(k).and_then(Value::as_array).map(|a| a.iter().take(100).cloned().collect()).unwrap_or_default()
    };
    if let Some(v) = s("entry_point") {
        cx.format_set("entry_point", v);
    }
    if let Some(v) = s("script") {
        cx.format_set("script", v);
    }
    if let Some(v) = m.get("build_properties").and_then(|b| b.get("pex_version")).and_then(Value::as_str) {
        cx.format_set("pex_version", v);
    }
    let reqs = list("requirements");
    cx.format_set("requirements", reqs);
    let ic = list("interpreter_constraints");
    if !ic.is_empty() {
        cx.format_set("interpreter_constraints", ic);
    }
    if let Some(d) = m.get("distributions").and_then(Value::as_object) {
        cx.format_set("distributions", d.len());
    }
    if let Some(v) = m.get("venv").and_then(Value::as_bool) {
        cx.format_set("venv", v);
    }
    if let Some(v) = s("code_hash") {
        cx.format_set("code_hash", v);
    }
}

fn jmod(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    let h = src.read_vec(0, 4)?;
    cx.format_set("jmod_version", format!("{}.{}", h[2], h[3]));
    let mut sub = src.slice(4, len - 4)?;
    let zip = Zip::open(&mut sub, MAX_ENTRIES)?;
    let mut inv = Inventory::new();
    let mut sections: BTreeMap<&str, u64> = BTreeMap::new();
    for e in &zip.entries {
        if let Some((top, _)) = e.name.split_once('/')
            && matches!(top, "classes" | "bin" | "conf" | "lib" | "legal" | "include" | "man")
        {
            *sections.entry(top).or_default() += 1;
        }
        inv.push(entry(e));
    }
    cx.format_set("sections", serde_json::json!(sections));
    inv.report(cx, len);
    if let Some(info) = zip.entries.iter().find(|e| e.name == "classes/module-info.class").cloned() {
        let data = zip.read(&mut sub, &info, cx, cx.parse_limit())?;
        let complete = data.len() as u64 == info.size;
        child(cx, "module-info.class", data, complete)?;
    }
    Ok(())
}

/// A volume's set name, number (1 for the first) and naming scheme, from
/// its file name: `set.7z.002` / `set.002`, `set.z01` (ZIP: the last
/// volume is `set.zip`), `set.r00` (RAR 3: `set.rar` comes first),
/// `set.part2.rar`.
fn volume(name: &str) -> Option<(String, u32, &'static str)> {
    let base = name.rsplit(['/', '\\']).next()?;
    let (stem, ext) = base.rsplit_once('.')?;
    let digits = |s: &str| s.len() >= 2 && s.bytes().all(|b| b.is_ascii_digit());
    // `set.7z.001`; a bare `set.001` only below 100 (`.264` is H.264 video,
    // `.000` an S-57 chart).
    if ext.len() == 3 && digits(ext) {
        let n: u32 = ext.parse().ok()?;
        let inner = stem.rsplit_once('.').map(|(_, x)| x.to_ascii_lowercase());
        let archive = inner.as_deref().is_some_and(|x| {
            matches!(
                x,
                "7z" | "zip"
                    | "rar"
                    | "tar"
                    | "gz"
                    | "tgz"
                    | "bz2"
                    | "xz"
                    | "zst"
                    | "iso"
                    | "img"
                    | "cab"
                    | "arj"
                    | "lzh"
            )
        });
        return (n >= 1 && (archive || n < 100)).then(|| (stem.to_string(), n, "numbered"));
    }
    // `.z64` is a Nintendo 64 ROM, not volume 64 of a ZIP.
    if let Some(n) = ext.strip_prefix(['z', 'Z']).filter(|n| digits(n) && *n != "64") {
        return Some((stem.to_string(), n.parse().ok()?, "zip"));
    }
    if let Some(n) = ext.strip_prefix(['r', 'R']).filter(|n| digits(n)) {
        return Some((stem.to_string(), n.parse::<u32>().ok()? + 2, "rar_old"));
    }
    if ext.eq_ignore_ascii_case("rar") {
        let (set, part) = stem.rsplit_once('.')?;
        let n = part.strip_prefix("part").filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))?;
        return Some((set.to_string(), n.parse().ok()?, "rar_parts"));
    }
    None
}

fn split_volume(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let Some((set, number, scheme)) = src.name_hint().and_then(volume) else { return Ok(()) };
    cx.format_set("set_name", set);
    cx.format_set("volume", number);
    cx.format_set("naming", scheme);
    // A volume after the first starts mid-stream: nothing more to read.
    let h = src.read_vec(0, usize::try_from(src.len().min(8)).unwrap_or(0))?;
    let starts = match h.as_slice() {
        [b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c, ..] => Some("7z"),
        [b'R', b'a', b'r', b'!', 0x1a, 7, ..] => Some("rar"),
        [b'P', b'K', 7, 8, ..] | [b'P', b'K', 3, 4, ..] => Some("zip"),
        _ => None,
    };
    if let Some(kind) = starts {
        cx.format_set("starts_with", kind);
    }
    Ok(())
}

/// `main.<version>.<package>.obb` / `patch.<version>.<package>.obb`.
fn obb_name(name: &str) -> Option<(&str, u64, &str)> {
    let base = name.rsplit(['/', '\\']).next()?.strip_suffix(".obb")?;
    let (kind, rest) = base.split_once('.')?;
    let (version, package) = rest.split_once('.')?;
    (matches!(kind, "main" | "patch") && package.contains('.')).then_some((kind, version.parse().ok()?, package))
}

fn obb(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    if let Some((kind, version, package)) = src.name_hint().and_then(obb_name) {
        cx.format_set("expansion_kind", kind);
        cx.format_set("package_version", version);
        cx.format_set("package", package);
    }
    // obbtool's footer: [version, package version, flags, salt, name
    // length, name] then its size and the signature.
    let mut content = len;
    if len >= 8 {
        let t = src.read_vec(len - 8, 8)?;
        if t[4..] == OBB_SIG {
            let size = u64::from(u32::from_le_bytes([t[0], t[1], t[2], t[3]]));
            if size >= 24 && size + 8 <= len {
                let f = src.read_vec(len - 8 - size, usize::try_from(size.min(4096)).unwrap_or(0))?;
                let mut r = ByteReader::new(&f);
                cx.format_set("footer_version", r.le_u32()?);
                cx.format_set("package_version", r.le_u32()?);
                let flags = r.le_u32()?;
                if flags & 1 != 0 {
                    cx.format_set("overlay", true);
                }
                if flags & 2 != 0 {
                    cx.security().encrypted(true);
                }
                r.advance(8)?;
                let n = usize::try_from(r.le_u32()?).unwrap_or(0);
                cx.format_set("package", latin1_or_utf8(r.bytes(n.min(r.remaining()))?));
                content = len - 8 - size;
            }
        }
    }
    // The blob itself (a ZIP or a FAT image, usually): handed on.
    if content > 0 && cx.child_room() > 0 {
        let n = content.min(cx.parse_limit() as u64);
        let data = src.read_vec(0, usize::try_from(n).unwrap_or(0))?;
        child(cx, "content", data, n == content)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("zipapp", "pex", "jmod", "split_volume", "obb");

    #[test]
    fn volume_names() {
        assert_eq!(volume("tides.7z.002"), Some(("tides.7z".into(), 2, "numbered")));
        assert_eq!(volume("a/b/tides.z01"), Some(("tides".into(), 1, "zip")));
        assert_eq!(volume("tides.r00"), Some(("tides".into(), 2, "rar_old")));
        assert_eq!(volume("tides.part3.rar"), Some(("tides".into(), 3, "rar_parts")));
        assert_eq!(volume("tides.rar"), None);
        assert_eq!(volume("tides.txt"), None);
        assert_eq!(volume("harbour-x264.264"), None);
        assert_eq!(volume("tides.z64"), None);
        assert_eq!(volume("SM5HARB1.000"), None);
        assert_eq!(volume("tides.002"), Some(("tides".into(), 2, "numbered")));
    }

    #[test]
    fn obb_names() {
        assert_eq!(obb_name("main.7.org.saltmere.harbour.obb"), Some(("main", 7, "org.saltmere.harbour")));
        assert_eq!(obb_name("/x/patch.12.com.example.game.obb"), Some(("patch", 12, "com.example.game")));
        assert_eq!(obb_name("data.obb"), None);
        assert_eq!(obb_name("main.x.org.a.obb"), None);
    }
}
