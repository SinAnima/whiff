//! Android apps: APK, App Bundle (AAB), APK sets (`.apks`) and XAPK.
//! The manifest — binary XML in an APK, protocol buffers in an AAB — gives
//! the package name, version code and name, SDK levels, permissions
//! (requested, declared, and which of them Android rates dangerous),
//! features, the application's label (resolved from `resources.arsc`),
//! flags (debuggable, backup, clear-text traffic, test-only) and the
//! components (activities, services, receivers, providers; how many are
//! exported; the launcher activity). The signing schemes come from
//! `META-INF` (v1, JAR signing) and the APK Signing Block (v2, v3, v3.1,
//! source stamp). DEX files, native ABIs and a few framework markers
//! (Flutter, React Native, Xamarin, Unity) are noted. APK sets and XAPKs
//! hand their APKs on.
//!
//! Specifications: AOSP `ResourceTypes.h` (binary XML and resource table),
//! aapt2 `Resources.proto`, "APK Signature Scheme v2 / v3" (source.android.com),
//! the Android manifest reference (permissions' protection levels).

use std::collections::BTreeSet;

use serde_json::Value;

use super::{Package, ext_is, zip_payload};
use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, Zip, zip_names,
};

/// Extractor for Android packages.
pub struct Android;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, $ext:literal) => {
        FormatSpec {
            id: $id,
            name: $name,
            family: "package",
            mimes: &[$mime],
            extensions: &[$ext],
            magic: &[],
            parent: Some("zip"),
        }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "package.android",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!("apk", "Android package", "application/vnd.android.package-archive", "apk"),
        spec!("aab", "Android App Bundle", "application/x-authorware-bin", "aab"),
        spec!("apks", "Android APK set", "application/zip", "apks"),
        spec!("xapk", "XAPK Android package", "application/zip", "xapk"),
    ],
};

const MAX_ENTRIES: usize = 1 << 16;
/// Elements read from a manifest at most.
const MAX_ELEMENTS: usize = 20_000;
/// Largest manifest or resource table read.
const MAX_XML: usize = 16 << 20;

/// Permissions with protection level `dangerous` (runtime permissions).
const DANGEROUS: [&str; 40] = [
    "ACCEPT_HANDOVER",
    "ACCESS_BACKGROUND_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "ACCESS_FINE_LOCATION",
    "ACCESS_MEDIA_LOCATION",
    "ACTIVITY_RECOGNITION",
    "ADD_VOICEMAIL",
    "ANSWER_PHONE_CALLS",
    "BLUETOOTH_ADVERTISE",
    "BLUETOOTH_CONNECT",
    "BLUETOOTH_SCAN",
    "BODY_SENSORS",
    "BODY_SENSORS_BACKGROUND",
    "CALL_PHONE",
    "CAMERA",
    "GET_ACCOUNTS",
    "NEARBY_WIFI_DEVICES",
    "POST_NOTIFICATIONS",
    "PROCESS_OUTGOING_CALLS",
    "READ_CALENDAR",
    "READ_CALL_LOG",
    "READ_CONTACTS",
    "READ_EXTERNAL_STORAGE",
    "READ_MEDIA_AUDIO",
    "READ_MEDIA_IMAGES",
    "READ_MEDIA_VIDEO",
    "READ_MEDIA_VISUAL_USER_SELECTED",
    "READ_PHONE_NUMBERS",
    "READ_PHONE_STATE",
    "READ_SMS",
    "RECEIVE_MMS",
    "RECEIVE_SMS",
    "RECEIVE_WAP_PUSH",
    "RECORD_AUDIO",
    "SEND_SMS",
    "USE_SIP",
    "UWB_RANGING",
    "WRITE_CALENDAR",
    "WRITE_CALL_LOG",
    "WRITE_CONTACTS",
];

/// Framework attribute names by resource id (for manifests whose string
/// pool leaves attribute names empty).
fn attr_name(id: u32) -> Option<&'static str> {
    Some(match id {
        0x0101_0001 => "label",
        0x0101_0002 => "icon",
        0x0101_0003 => "name",
        0x0101_0009 => "protectionLevel",
        0x0101_000b => "sharedUserId",
        0x0101_000f => "debuggable",
        0x0101_0010 => "exported",
        0x0101_020c => "minSdkVersion",
        0x0101_021b => "versionCode",
        0x0101_021c => "versionName",
        0x0101_0270 => "targetSdkVersion",
        0x0101_0271 => "maxSdkVersion",
        0x0101_0272 => "testOnly",
        0x0101_0280 => "allowBackup",
        0x0101_028e => "required",
        0x0101_02b7 => "installLocation",
        0x0101_04ea => "extractNativeLibs",
        0x0101_04ec => "usesCleartextTraffic",
        0x0101_0572 => "compileSdkVersion",
        0x0101_0573 => "compileSdkVersionCodename",
        _ => return None,
    })
}

/// An attribute value.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Attr {
    Str(String),
    Int(i64),
    Bool(bool),
    /// A resource reference (`@0x7f…`).
    Ref(u32),
}

impl Attr {
    pub(crate) fn text(&self) -> String {
        match self {
            Self::Str(s) => s.clone(),
            Self::Int(n) => n.to_string(),
            Self::Bool(b) => b.to_string(),
            Self::Ref(r) => format!("@0x{r:08x}"),
        }
    }

    fn truthy(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::Int(n) => *n != 0,
            Self::Str(s) => s == "true",
            Self::Ref(_) => false,
        }
    }
}

/// One element: depth, local name, attributes by local name.
#[derive(Debug, Default)]
pub(crate) struct Element {
    pub(crate) depth: usize,
    pub(crate) name: String,
    pub(crate) attrs: Vec<(String, Attr)>,
}

impl Element {
    fn get(&self, name: &str) -> Option<&Attr> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    pub(crate) fn str(&self, name: &str) -> Option<String> {
        self.get(name).map(Attr::text)
    }
}

/// A string pool chunk (`ResStringPool_header` at `chunk`).
pub(crate) fn string_pool(chunk: &[u8]) -> Vec<String> {
    let le32 = |at: usize| chunk.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
    let (Some(count), Some(flags), Some(start)) = (le32(8), le32(16), le32(20)) else { return Vec::new() };
    let utf8 = flags & 0x100 != 0;
    let mut out = Vec::with_capacity(count.min(1 << 16));
    for i in 0..count.min(1 << 18) {
        let Some(off) = le32(28 + i * 4) else { break };
        let at = start.saturating_add(off);
        let s = if utf8 { utf8_string(chunk, at) } else { utf16_string(chunk, at) };
        out.push(s.unwrap_or_default());
    }
    out
}

fn utf8_string(b: &[u8], mut at: usize) -> Option<String> {
    // The length in UTF-16 units, then in bytes: one byte each, or two
    // when the high bit is set.
    at += if *b.get(at)? & 0x80 != 0 { 2 } else { 1 };
    let first = *b.get(at)?;
    let len = if first & 0x80 != 0 {
        at += 2;
        usize::from(first & 0x7f) << 8 | usize::from(*b.get(at - 1)?)
    } else {
        at += 1;
        usize::from(first)
    };
    Some(String::from_utf8_lossy(b.get(at..at.checked_add(len)?)?).into_owned())
}

fn utf16_string(b: &[u8], at: usize) -> Option<String> {
    let w = |i: usize| b.get(i..i + 2).map(|x| u16::from_le_bytes([x[0], x[1]]));
    let mut len = usize::from(w(at)?);
    let mut start = at + 2;
    if len & 0x8000 != 0 {
        len = ((len & 0x7fff) << 16) | usize::from(w(at + 2)?);
        start += 2;
    }
    let units: Vec<u16> = (0..len.min(1 << 16)).map_while(|i| w(start + i * 2)).collect();
    Some(String::from_utf16_lossy(&units))
}

/// A typed value (`Res_value`): type and data.
fn typed(ty: u8, data: u32, strings: &[String]) -> Attr {
    match ty {
        0x01 => Attr::Ref(data),
        0x03 => Attr::Str(strings.get(data as usize).cloned().unwrap_or_default()),
        0x10 | 0x11 => Attr::Int(i64::from(data.cast_signed())),
        0x12 => Attr::Bool(data != 0),
        _ => Attr::Int(i64::from(data)),
    }
}

/// Elements of a binary XML (`AXML`) document.
pub(crate) fn binary_xml(data: &[u8]) -> Result<Vec<Element>, ExtractError> {
    let mut doc = ByteReader::new(data);
    if doc.le_u16()? != 0x0003 {
        return Err(ExtractError::malformed("not a binary XML document"));
    }
    let header = usize::from(doc.le_u16()?);
    let mut at = header;
    let mut strings: Vec<String> = Vec::new();
    let mut ids: Vec<u32> = Vec::new();
    let mut out = Vec::new();
    let mut depth = 0usize;
    while at + 8 <= data.len() && out.len() < MAX_ELEMENTS {
        let mut chunk_header = ByteReader::new(&data[at..]);
        let ty = chunk_header.le_u16()?;
        let hsize = usize::from(chunk_header.le_u16()?);
        let size = chunk_header.le_u32()? as usize;
        if size < 8 || at + size > data.len() {
            break;
        }
        let chunk = &data[at..at + size];
        match ty {
            0x0001 => strings = string_pool(chunk),
            0x0180 => {
                ids = chunk[hsize.min(size)..].as_chunks::<4>().0.iter().map(|b| u32::from_le_bytes(*b)).collect();
            }
            0x0102 => {
                let mut ext = ByteReader::new(chunk.get(hsize..).unwrap_or(&[]));
                let _ns = ext.le_u32()?;
                let name = ext.le_u32()? as usize;
                let attr_start = usize::from(ext.le_u16()?);
                let attr_size = usize::from(ext.le_u16()?).max(20);
                let count = usize::from(ext.le_u16()?);
                let mut el = Element { depth, name: strings.get(name).cloned().unwrap_or_default(), attrs: Vec::new() };
                for i in 0..count.min(256) {
                    let base = hsize + attr_start + i * attr_size;
                    let Some(attr) = chunk.get(base..base + 20) else { break };
                    let le = |o: usize| u32::from_le_bytes([attr[o], attr[o + 1], attr[o + 2], attr[o + 3]]);
                    let name_ix = le(4) as usize;
                    let raw = le(8);
                    let mut n = strings.get(name_ix).cloned().unwrap_or_default();
                    if n.is_empty()
                        && let Some(known) = ids.get(name_ix).and_then(|&id| attr_name(id))
                    {
                        n = known.to_string();
                    }
                    let value = if raw == u32::MAX {
                        typed(attr[15], le(16), &strings)
                    } else {
                        Attr::Str(strings.get(raw as usize).cloned().unwrap_or_default())
                    };
                    el.attrs.push((n, value));
                }
                out.push(el);
                depth += 1;
            }
            0x0103 => depth = depth.saturating_sub(1),
            _ => {}
        }
        at += size;
    }
    Ok(out)
}

/// A protocol-buffer field: number, wire type, value (varint or bytes).
fn pb_fields(mut b: &[u8]) -> Vec<(u32, u64, &[u8])> {
    let mut out = Vec::new();
    let varint = |b: &mut &[u8]| -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = b.split_first()?;
            *b = rest;
            v |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    };
    while !b.is_empty() && out.len() < 1 << 16 {
        let Some(key) = varint(&mut b) else { break };
        let (field, wire) = (u32::try_from(key >> 3).unwrap_or(u32::MAX), key & 7);
        match wire {
            0 => {
                let Some(v) = varint(&mut b) else { break };
                out.push((field, v, &[][..]));
            }
            1 | 5 => {
                let n = if wire == 1 { 8 } else { 4 };
                let Some((v, rest)) = b.split_at_checked(n) else { break };
                out.push((field, 0, v));
                b = rest;
            }
            2 => {
                let Some(n) = varint(&mut b).and_then(|n| usize::try_from(n).ok()) else { break };
                let Some((v, rest)) = b.split_at_checked(n) else { break };
                out.push((field, 0, v));
                b = rest;
            }
            _ => break,
        }
    }
    out
}

/// Elements of an aapt2 protocol-buffer `XmlNode` (an AAB's manifest).
fn proto_xml(data: &[u8]) -> Vec<Element> {
    let mut out = Vec::new();
    let mut stack: Vec<(&[u8], usize)> = vec![(data, 0)];
    while let Some((node, depth)) = stack.pop() {
        if out.len() >= MAX_ELEMENTS || depth > 64 {
            break;
        }
        let Some(element) = pb_fields(node).into_iter().find(|f| f.0 == 1).map(|f| f.2) else { continue };
        let mut el = Element { depth, ..Element::default() };
        let mut children = Vec::new();
        for (f, _, v) in pb_fields(element) {
            match f {
                3 => el.name = String::from_utf8_lossy(v).into_owned(),
                4 => {
                    let mut name = String::new();
                    let mut value: Option<Attr> = None;
                    let mut id = 0u32;
                    for (af, av, ab) in pb_fields(v) {
                        match af {
                            2 => name = String::from_utf8_lossy(ab).into_owned(),
                            3 => value = Some(Attr::Str(String::from_utf8_lossy(ab).into_owned())),
                            5 => id = u32::try_from(av).unwrap_or(0),
                            _ => {}
                        }
                    }
                    if name.is_empty()
                        && let Some(n) = attr_name(id)
                    {
                        name = n.to_string();
                    }
                    let value = value.unwrap_or(Attr::Str(String::new()));
                    let value = match &value {
                        Attr::Str(s) if s == "true" || s == "false" => Attr::Bool(s == "true"),
                        _ => value,
                    };
                    el.attrs.push((name, value));
                }
                5 => children.push(v),
                _ => {}
            }
        }
        out.push(el);
        for c in children.into_iter().rev() {
            stack.push((c, depth + 1));
        }
    }
    out
}

/// The string a resource reference resolves to in a resource table
/// (`resources.arsc`), in the first configuration that defines it.
fn resolve_string(arsc: &[u8], id: u32) -> Option<String> {
    let le16 = |b: &[u8], at: usize| b.get(at..at + 2).map(|x| u16::from_le_bytes([x[0], x[1]]));
    let le32 = |b: &[u8], at: usize| b.get(at..at + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]));
    if le16(arsc, 0)? != 0x0002 {
        return None;
    }
    let (want_pkg, want_type, want_entry) = (id >> 24, (id >> 16) & 0xff, id & 0xffff);
    let mut globals: Vec<String> = Vec::new();
    let mut at = usize::from(le16(arsc, 2)?);
    while at + 8 <= arsc.len() {
        let (ty, hsize, size) = (le16(arsc, at)?, usize::from(le16(arsc, at + 2)?), le32(arsc, at + 4)? as usize);
        if size < 8 || at + size > arsc.len() {
            return None;
        }
        let chunk = &arsc[at..at + size];
        match ty {
            0x0001 => globals = string_pool(chunk),
            0x0200 if le32(chunk, 8)? == want_pkg => {
                let mut c = hsize;
                while c + 8 <= chunk.len() {
                    let (cty, chs, cs) =
                        (le16(chunk, c)?, usize::from(le16(chunk, c + 2)?), le32(chunk, c + 4)? as usize);
                    if cs < 8 || c + cs > chunk.len() {
                        break;
                    }
                    let t = &chunk[c..c + cs];
                    if cty == 0x0201 && u32::from(t[8]) == want_type {
                        let flags = t[9];
                        let count = le32(t, 12)? as usize;
                        let entries = le32(t, 16)? as usize;
                        let offset = if flags & 0x01 != 0 {
                            // Sparse: (index, offset / 4) pairs.
                            (0..count).find_map(|i| {
                                (u32::from(le16(t, chs + i * 4)?) == want_entry)
                                    .then(|| le16(t, chs + i * 4 + 2).map(|o| u32::from(o) * 4))
                                    .flatten()
                            })
                        } else if flags & 0x02 != 0 {
                            le16(t, chs + want_entry as usize * 2).filter(|&o| o != 0xffff).map(|o| u32::from(o) * 4)
                        } else if (want_entry as usize) < count {
                            le32(t, chs + want_entry as usize * 4).filter(|&o| o != u32::MAX)
                        } else {
                            None
                        };
                        if let Some(off) = offset {
                            let e = entries + off as usize;
                            let eflags = le16(t, e + 2)?;
                            let (vty, data) = if eflags & 0x08 != 0 {
                                ((eflags >> 8) as u8, le32(t, e + 4)?)
                            } else if eflags & 0x01 == 0 {
                                let vs = e + usize::from(le16(t, e)?);
                                (*t.get(vs + 3)?, le32(t, vs + 4)?)
                            } else {
                                (0, 0)
                            };
                            if vty == 0x03 {
                                return globals.get(data as usize).cloned();
                            }
                        }
                    }
                    c += cs;
                }
            }
            _ => {}
        }
        at += size;
    }
    None
}

/// Signature schemes in the APK Signing Block before the central directory.
fn signing_block(src: &mut dyn Source) -> Result<Vec<&'static str>, ExtractError> {
    let tail = src.tail().to_vec();
    let Some(eocd) = tail.windows(4).rposition(|w| w == b"PK\x05\x06") else { return Ok(Vec::new()) };
    let Some(cd) = tail.get(eocd + 16..eocd + 20).map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    else {
        return Ok(Vec::new());
    };
    if cd < 32 {
        return Ok(Vec::new());
    }
    let footer = src.read_vec(cd - 24, 24)?;
    if footer.len() < 24 || &footer[8..] != b"APK Sig Block 42" {
        return Ok(Vec::new());
    }
    let size = u64::from_le_bytes(footer[..8].try_into().unwrap_or([0; 8]));
    if size < 24 || size > cd || size > 64 << 20 {
        return Ok(Vec::new());
    }
    let block = src.read_vec(cd - size - 8, usize::try_from(size + 8).unwrap_or(0))?;
    let mut out = Vec::new();
    let mut at = 8usize;
    let end = block.len().saturating_sub(24);
    while at + 12 <= end {
        let len = u64::from_le_bytes(block[at..at + 8].try_into().unwrap_or([0; 8]));
        let id = u32::from_le_bytes(block[at + 8..at + 12].try_into().unwrap_or([0; 4]));
        let name = match id {
            0x7109_871a => Some("v2"),
            0xf053_68c0 => Some("v3"),
            0x1b93_ad61 => Some("v3.1"),
            0x6dff_800d => Some("source_stamp"),
            _ => None,
        };
        out.extend(name);
        let Some(next) = usize::try_from(len).ok().and_then(|l| at.checked_add(8)?.checked_add(l)) else { break };
        at = next;
    }
    Ok(out)
}

impl Extractor for Android {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if !probe.head.starts_with(b"PK\x03\x04") {
            return None;
        }
        let names = zip_names(probe, 4000);
        let has = |n: &str| names.iter().any(|x| x == n);
        let format = if has("AndroidManifest.xml") && (names.iter().any(|n| ext_is(n, "dex")) || has("resources.arsc"))
        {
            "apk"
        } else if has("base/manifest/AndroidManifest.xml") {
            "aab"
        } else if has("toc.pb") && names.iter().any(|n| ext_is(n, "apk")) {
            "apks"
        } else if has("manifest.json") && names.iter().any(|n| ext_is(n, "apk")) {
            "xapk"
        } else if probe.extension == Some("apk")
            && (has("classes.dex") || has("AndroidManifest.xml") || names.is_empty())
        {
            // A large APK whose central directory is beyond the tail window.
            return Some(Sniff { format: "apk", confidence: 0.9 });
        } else {
            return None;
        };
        Some(Sniff { format, confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let zip = Zip::open(src, MAX_ENTRIES)?;
        zip.flag_duplicates(cx);
        let mut pkg = Package::new("android");
        let format = cx.format_id().to_string();
        match format.as_str() {
            "apk" | "aab" => {
                let path = if format == "apk" { "AndroidManifest.xml" } else { "base/manifest/AndroidManifest.xml" };
                let raw = zip.find(path).map(|e| zip.read(src, &e.clone(), cx, MAX_XML)).transpose()?;
                let elements = match raw {
                    Some(d) if d.starts_with(&[3, 0]) => binary_xml(&d)?,
                    Some(d) => proto_xml(&d),
                    None => Vec::new(),
                };
                let label_ref = manifest(&elements, &mut pkg);
                if let Some(id) = label_ref
                    && let Some(Ok(arsc)) = zip.find("resources.arsc").map(|e| zip.read(src, &e.clone(), cx, MAX_XML))
                    && let Some(label) = resolve_string(&arsc, id)
                {
                    pkg.set("label", label.clone());
                    pkg.summary = Some(label);
                }
                contents(&zip, &mut pkg, if format == "aab" { "base/" } else { "" });
                let mut schemes: Vec<&str> = Vec::new();
                if zip.entries.iter().any(|e| e.name.starts_with("META-INF/") && ext_is(&e.name, "SF")) {
                    schemes.push("v1");
                }
                if format == "apk" {
                    schemes.extend(signing_block(src)?);
                }
                pkg.signed = Some(!schemes.is_empty());
                pkg.signatures = schemes.into_iter().map(str::to_string).collect();
            }
            "xapk" => {
                if let Some(Ok(t)) = zip.read_text(src, "manifest.json", cx, 4 << 20)
                    && let Ok(v) = serde_json::from_str::<Value>(&t)
                {
                    xapk(&v, &mut pkg);
                }
                apk_list(&zip, &mut pkg);
            }
            _ => apk_list(&zip, &mut pkg),
        }
        if pkg.extra.get("debuggable") == Some(&Value::Bool(true)) {
            cx.security().risk("debuggable", Some(pkg.name.clone().unwrap_or_default()));
        }
        pkg.write(cx);
        zip_payload(src, cx, &zip)
    }
}

crate::register_extractor!(Android);

/// Map manifest elements into the package; returns the label's resource
/// reference when it is not a literal.
#[allow(clippy::too_many_lines)] // one pass over the manifest elements
fn manifest(elements: &[Element], pkg: &mut Package) -> Option<u32> {
    let mut label_ref = None;
    let mut permissions: Vec<String> = Vec::new();
    let mut declared: Vec<String> = Vec::new();
    let mut features: Vec<String> = Vec::new();
    let mut components = [0u64; 4];
    let mut exported = 0u64;
    let mut launcher: Option<String> = None;
    let mut current: Option<String> = None;
    let mut component_depth = usize::MAX;
    let mut is_main = (false, false);
    for e in elements {
        if e.depth <= component_depth {
            if is_main.0 && is_main.1 && launcher.is_none() {
                launcher.clone_from(&current);
            }
            component_depth = usize::MAX;
            is_main = (false, false);
        }
        match e.name.as_str() {
            "manifest" => {
                pkg.name = e.str("package");
                pkg.version = e.str("versionName");
                pkg.release = e.str("versionCode");
                for (a, out) in [
                    ("sharedUserId", "shared_user_id"),
                    ("compileSdkVersion", "compile_sdk"),
                    ("platformBuildVersionName", "platform_build_version"),
                ] {
                    if let Some(v) = e.str(a) {
                        pkg.set(out, v);
                    }
                }
            }
            "uses-sdk" => {
                for (a, out) in
                    [("minSdkVersion", "min_sdk"), ("targetSdkVersion", "target_sdk"), ("maxSdkVersion", "max_sdk")]
                {
                    if let Some(v) = e.str(a) {
                        pkg.set(out, v.parse::<i64>().map_or(Value::String(v), Value::from));
                    }
                }
            }
            "uses-permission" | "uses-permission-sdk-23" | "uses-permission-sdk-m" => {
                if let Some(n) = e.str("name")
                    && !permissions.contains(&n)
                {
                    permissions.push(n);
                }
            }
            "permission" => declared.extend(e.str("name")),
            "uses-feature" => {
                if let Some(n) = e.str("name") {
                    features.push(n);
                }
            }
            "application" => {
                match e.get("label") {
                    Some(Attr::Ref(id)) => label_ref = Some(*id),
                    Some(Attr::Str(s)) if !s.is_empty() && !s.starts_with('@') => {
                        pkg.set("label", s.clone());
                        pkg.summary = Some(s.clone());
                    }
                    _ => {}
                }
                for (a, out) in [
                    ("debuggable", "debuggable"),
                    ("allowBackup", "allow_backup"),
                    ("usesCleartextTraffic", "uses_cleartext_traffic"),
                    ("testOnly", "test_only"),
                ] {
                    if let Some(v) = e.get(a) {
                        pkg.set(out, v.truthy());
                    }
                }
                if let Some(n) = e.str("name") {
                    pkg.set("application_class", n);
                }
            }
            n @ ("activity" | "activity-alias" | "service" | "receiver" | "provider") => {
                let i = match n {
                    "service" => 1,
                    "receiver" => 2,
                    "provider" => 3,
                    _ => 0,
                };
                components[i] += 1;
                if e.get("exported").is_some_and(Attr::truthy) {
                    exported += 1;
                }
                current = e.str("name");
                component_depth = e.depth;
            }
            "action" if e.str("name").as_deref() == Some("android.intent.action.MAIN") => is_main.0 = true,
            "category" if e.str("name").as_deref() == Some("android.intent.category.LAUNCHER") => is_main.1 = true,
            _ => {}
        }
    }
    if is_main.0 && is_main.1 && launcher.is_none() {
        launcher = current;
    }
    if let Some(l) = launcher {
        pkg.set("launcher_activity", l);
    }
    let dangerous: Vec<&String> = permissions
        .iter()
        .filter(|p| p.strip_prefix("android.permission.").is_some_and(|n| DANGEROUS.contains(&n)))
        .collect();
    if !dangerous.is_empty() {
        pkg.set("dangerous_permissions", dangerous.iter().map(|s| s.as_str()).collect::<Vec<_>>());
    }
    if !permissions.is_empty() {
        pkg.set("permissions", permissions);
    }
    if !declared.is_empty() {
        pkg.set("declared_permissions", declared);
    }
    if !features.is_empty() {
        pkg.set("features", features);
    }
    for (i, key) in ["activities", "services", "receivers", "providers"].iter().enumerate() {
        if components[i] > 0 {
            pkg.set(key, components[i]);
        }
    }
    if exported > 0 {
        pkg.set("exported_components", exported);
    }
    label_ref
}

/// DEX files, native ABIs and framework markers.
fn contents(zip: &Zip, pkg: &mut Package, base: &str) {
    let dex_dir = if base.is_empty() { String::new() } else { format!("{base}dex/") };
    let dex = zip
        .entries
        .iter()
        .filter(|e| e.name.strip_prefix(dex_dir.as_str()).is_some_and(|n| !n.contains('/') && ext_is(n, "dex")))
        .count();
    if dex > 0 {
        pkg.set("dex_files", dex);
    }
    let lib = format!("{base}lib/");
    let abis: BTreeSet<&str> =
        zip.entries.iter().filter_map(|e| e.name.strip_prefix(lib.as_str())?.split_once('/').map(|(a, _)| a)).collect();
    if !abis.is_empty() {
        pkg.set("native_abis", abis.into_iter().collect::<Vec<_>>());
    }
    let has = |suffix: &str| zip.entries.iter().any(|e| e.name.ends_with(suffix));
    let frameworks: Vec<&str> = [
        ("libflutter.so", "Flutter"),
        ("index.android.bundle", "React Native"),
        ("libmonodroid.so", "Xamarin"),
        ("libunity.so", "Unity"),
        ("libreactnativejni.so", "React Native"),
    ]
    .into_iter()
    .filter(|(f, _)| has(f))
    .map(|(_, n)| n)
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect();
    if !frameworks.is_empty() {
        pkg.set("frameworks", frameworks);
    }
}

/// The APKs of an APK set or XAPK.
fn apk_list(zip: &Zip, pkg: &mut Package) {
    let apks: Vec<&str> = zip.entries.iter().filter(|e| ext_is(&e.name, "apk")).map(|e| e.name.as_str()).collect();
    pkg.set("apks", apks.len());
    pkg.set("apk_names", apks.into_iter().take(50).collect::<Vec<_>>());
}

/// An XAPK's `manifest.json`.
fn xapk(v: &Value, pkg: &mut Package) {
    let s =
        |k: &str| v.get(k).and_then(|x| x.as_str().map(str::to_string).or_else(|| x.as_u64().map(|n| n.to_string())));
    pkg.name = s("package_name");
    pkg.version = s("version_name");
    pkg.release = s("version_code");
    pkg.summary = s("name");
    if let Some(n) = s("name") {
        pkg.set("label", n);
    }
    for (k, out) in [("min_sdk_version", "min_sdk"), ("target_sdk_version", "target_sdk")] {
        if let Some(x) = v.get(k) {
            pkg.set(out, x.clone());
        }
    }
    if let Some(p) = v.get("permissions").and_then(Value::as_array) {
        pkg.set("permissions", Value::Array(p.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protobuf_fields() {
        // field 3 (bytes) "manifest", field 5 (varint) 7.
        let f = pb_fields(b"\x1a\x08manifest\x28\x07");
        assert_eq!(f[0].0, 3);
        assert_eq!(f[0].2, b"manifest");
        assert_eq!((f[1].0, f[1].1), (5, 7));
        assert_eq!(pb_fields(b"\x1a\xff"), Vec::new());
    }

    #[test]
    fn utf16_strings() {
        assert_eq!(utf16_string(&[2, 0, b'h', 0, b'i', 0, 0, 0], 0).as_deref(), Some("hi"));
        assert_eq!(utf8_string(&[2, 2, b'h', b'i', 0], 0).as_deref(), Some("hi"));
    }

    crate::fixture_tests!("apk", "aab", "apks", "xapk");
}
