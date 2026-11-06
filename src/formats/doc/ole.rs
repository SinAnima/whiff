//! OLE2 compound files: Word, Excel and PowerPoint 97–2003 (and their
//! templates), Visio, Publisher, Project, Hangul HWP, Thumbs.db, encrypted
//! OOXML packages, bare VBA projects, and any other compound file.
//!
//! Every compound file gets its property sets (`SummaryInformation`,
//! `DocumentSummaryInformation`, user-defined properties), its root class,
//! its stream listing, VBA projects (module names, auto-run triggers,
//! suspicious calls) and embedded objects (OLE 1.0 packages and OOXML
//! packages become children). Then, per application:
//! * Word: the FIB (version, template, encryption, quick saves) and the
//!   text through the piece table, with field codes checked for DDE;
//! * Excel: BIFF8 sheets (visibility, Excel 4.0 macro sheets), the shared
//!   strings, cell and formula counts, `Auto_Open` names, encryption;
//! * PowerPoint: slide count, slide titles and text, encryption;
//! * encrypted OOXML: the encryption method (agile / standard).
//!
//! A compound file detected only by its signature is re-identified from its
//! streams; Outlook messages go to the e-mail extractor.
//!
//! Specifications: MS-CFB, MS-OLEPS, MS-DOC, MS-XLS, MS-PPT, MS-OFFCRYPTO, MS-OLEDS.

use serde_json::{Value, json};

use crate::plugin::{
    ByteReader, Cfb, CfbEntry, CfbKind, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec,
    Magic, Map, Probe, Sniff, Source, TextRole, oleps, truncate_chars,
};

/// Extractor for compound-file documents.
pub struct Ole;

macro_rules! spec {
    ($id:literal, $name:literal, [$($mime:literal),*], [$($ext:literal),*]) => {
        FormatSpec {
            id: $id,
            name: $name,
            family: "doc.ole",
            mimes: &[$($mime),*],
            extensions: &[$($ext),*],
            magic: &[],
            parent: Some("cfb"),
        }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "doc.ole",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "cfb",
            name: "OLE2 compound file",
            family: "doc.ole",
            mimes: &["application/x-ole-storage"],
            extensions: &["cfb", "ole"],
            magic: &[Magic::prefix(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")],
            parent: None,
        },
        spec!("doc", "Word 97-2003 document", ["application/msword"], ["doc", "dot", "wiz"]),
        spec!("xls", "Excel 97-2003 workbook", ["application/vnd.ms-excel"], ["xls", "xlt", "xla"]),
        spec!("ppt", "PowerPoint 97-2003 presentation", ["application/vnd.ms-powerpoint"], ["ppt", "pot", "pps"]),
        spec!("vsd", "Visio drawing (legacy)", ["application/vnd.visio"], ["vsd", "vss", "vst"]),
        spec!("pub", "Microsoft Publisher document", ["application/x-mspublisher"], ["pub"]),
        spec!("mpp", "Microsoft Project plan", ["application/vnd.ms-project"], ["mpp"]),
        spec!("hwp", "Hangul HWP document", ["application/x-hwp"], ["hwp"]),
        spec!("thumbs_db", "Windows thumbnail cache", [], ["db"]),
        FormatSpec { family: "image.raster", ..spec!("fpx", "FlashPix image", ["image/vnd.fpx"], ["fpx"]) },
        spec!(
            "office_encrypted",
            "Encrypted Office document",
            ["application/x-ms-office-encrypted"],
            ["docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "xlsb"]
        ),
        // `vbaProject.bin`: found by its streams, not by the generic extension.
        spec!("vba_project", "VBA project", ["application/vnd.ms-office.vbaProject"], []),
    ],
};

/// Bytes of a document stream read at most (Word text, Excel records, PowerPoint records).
const MAX_STREAM: usize = 64 << 20;
const MAX_LISTED: usize = 200;

/// Known root class ids.
fn clsid_name(id: &str) -> Option<&'static str> {
    Some(match id {
        "00020906-0000-0000-C000-000000000046" => "Word.Document.8",
        "00020900-0000-0000-C000-000000000046" => "Word.Document.6",
        "00020820-0000-0000-C000-000000000046" => "Excel.Sheet.8",
        "00020810-0000-0000-C000-000000000046" => "Excel.Sheet.5",
        "64818D10-4F9B-11CF-86EA-00AA00B929E8" => "PowerPoint.Show.8",
        "000C1084-0000-0000-C000-000000000046" => "Windows Installer package",
        "000C1086-0000-0000-C000-000000000046" => "Windows Installer patch",
        "00020D0B-0000-0000-C000-000000000046" | "0006F046-0000-0000-C000-000000000046" => "Outlook message",
        "0003000C-0000-0000-C000-000000000046" => "OLE package",
        "0002CE02-0000-0000-C000-000000000046" => "Equation Editor 3.0",
        "56616700-C154-11CE-8553-00AA00A1F95B" => "FlashPix image",
        _ => return None,
    })
}

/// The format a compound file's stream names point to.
fn kind_of(names: &[String]) -> Option<&'static str> {
    let has = |n: &str| names.iter().any(|x| x.eq_ignore_ascii_case(n));
    Some(if names.iter().any(|n| n.starts_with("__substg1.0_")) || has("__properties_version1.0") {
        "msg"
    } else if has("EncryptedPackage") && has("EncryptionInfo") {
        "office_encrypted"
    } else if has("WordDocument") {
        "doc"
    } else if has("Workbook") || has("Book") {
        "xls"
    } else if has("PowerPoint Document") {
        "ppt"
    } else if has("VisioDocument") {
        "vsd"
    } else if has("Quill") || has("Envelope") && has("Contents") {
        "pub"
    } else if has("FileHeader") && (has("BodyText") || has("DocInfo")) {
        "hwp"
    } else if has("PROJECT") && has("VBA") {
        "vba_project"
    } else if has("DestList") {
        // A Windows jump list (`forensics` feature).
        "jump_list"
    } else if has("Catalog") {
        "thumbs_db"
    } else if has("Data Object Store 000001") && names.iter().any(|n| n.starts_with("Resolution 0")) {
        "fpx"
    } else if names.iter().any(|n| n.trim() == "114" || n.starts_with("   1")) {
        "mpp"
    } else {
        return None;
    })
}

/// Directory names visible in the head window (for the sniffer only: the
/// directory chain is followed while its sectors are in the head).
fn head_names(head: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if head.len() < 512 || !Cfb::is_cfb(head) {
        return out;
    }
    let shift = u16::from_le_bytes([head[30], head[31]]);
    if !(9..=12).contains(&shift) {
        return out;
    }
    let le32 = |b: &[u8], at: usize| b.get(at..at + 4).map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]));
    let size = 1usize << shift;
    let sector = |n: u32| head.get((n as usize + 1) * size..(n as usize + 2) * size);
    // FAT entry `n`, when the header's first FAT sectors are in the head.
    let per = size / 4;
    let fat = |n: u32| {
        let (index, at) = (n as usize / per, n as usize % per);
        let fat_sector = le32(head, 76 + 4 * index).filter(|_| index < 109)?;
        le32(sector(fat_sector)?, 4 * at)
    };
    // Directory sectors: the chain from the header's first one, else the
    // sectors that follow it.
    let first = le32(head, 48).unwrap_or(0);
    let mut dir: Vec<&[u8]> = Vec::new();
    let mut n = first;
    while dir.len() < 16 && n < 0xFFFF_FFFA {
        let Some(s) = sector(n) else { break };
        dir.push(s);
        let Some(next) = fat(n) else {
            dir = vec![head.get((first as usize + 1) * size..).unwrap_or(&[])];
            break;
        };
        n = next;
    }
    for rec in dir.iter().flat_map(|s| s.as_chunks::<128>().0.iter()).take(64) {
        let n = usize::from(u16::from_le_bytes([rec[64], rec[65]])).min(64);
        if n < 2 || rec[66] == 0 {
            continue;
        }
        let units: Vec<u16> = rec[..n - 2].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        out.push(String::from_utf16_lossy(&units));
    }
    out
}

impl Extractor for Ole {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let names = head_names(probe.head);
        let kind = kind_of(&names)?;
        if kind == "msg" {
            return None;
        }
        Some(Sniff { format: kind, confidence: 0.96 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let cfb = Cfb::open(src)?;
        let names: Vec<String> = cfb.entries.iter().map(|e| e.name.clone()).collect();
        let current = cx.format_id().to_string();
        if let Some(kind) = kind_of(&names)
            && kind != current
            && (current == "cfb" || kind == "msg" || kind == "office_encrypted")
        {
            cx.redirect(kind);
            return Ok(());
        }
        common(&cfb, src, cx);
        match current.as_str() {
            "doc" => word(&cfb, src, cx)?,
            "xls" => excel(&cfb, src, cx)?,
            "ppt" => powerpoint(&cfb, src, cx)?,
            "office_encrypted" => encrypted_package(&cfb, src, cx),
            "thumbs_db" => {
                let n = cfb
                    .entries
                    .iter()
                    .filter(|e| e.kind == CfbKind::Stream && e.parent == Some(0) && e.name != "Catalog")
                    .count();
                cx.format_set("thumbnails", n);
            }
            "hwp" => hwp(&cfb, src, cx),
            "fpx" => flashpix(&cfb, src, cx),
            _ => {}
        }
        Ok(())
    }
}

crate::register_extractor!(Ole);

/// FlashPix: the image contents property set gives the resolutions and size.
fn flashpix(cfb: &Cfb, src: &mut dyn Source, cx: &mut Context<'_>) {
    let Some(data) = read(cfb, src, "Data Object Store 000001/\u{5}Image Contents", 1 << 20) else {
        cx.warn("no image contents property set");
        return;
    };
    let Ok(sections) = oleps::parse(&data) else {
        cx.warn("image contents property set is damaged");
        return;
    };
    let get = |id: u32| sections.iter().find_map(|s| s.get(id)).and_then(oleps::PropValue::as_int);
    if let (Some(w), Some(h)) = (get(0x0100_0002), get(0x0100_0003)) {
        cx.physical().image(u32::try_from(w).unwrap_or(0), u32::try_from(h).unwrap_or(0));
    }
    if let Some(n) = get(0x0100_0000) {
        cx.format_set("resolutions", n);
    }
    let subimages =
        cfb.entries.iter().filter(|e| e.name.starts_with("Subimage ") && e.name.ends_with("Header")).count();
    cx.format_set("subimages", subimages);
}

fn read(cfb: &Cfb, src: &mut dyn Source, path: &str, max: usize) -> Option<Vec<u8>> {
    cfb.read_path(src, path, max).and_then(Result::ok)
}

/// Property sets, class id, stream listing, VBA projects, embedded objects.
fn common(cfb: &Cfb, src: &mut dyn Source, cx: &mut Context<'_>) {
    if let Some(id) = cfb.root_clsid() {
        let mut c = json!({ "id": id });
        if let Some(n) = clsid_name(id) {
            c["name"] = json!(n);
        }
        cx.format_set("clsid", c);
    }
    cx.format_set("version", cfb.version);
    let mut props = Map::new();
    for stream in ["\u{5}SummaryInformation", "\u{5}DocumentSummaryInformation", "\u{5}HwpSummaryInformation"] {
        if let Some(data) = read(cfb, src, stream, 4 << 20) {
            match oleps::parse(&data) {
                Ok(sections) => props.extend(oleps::named(&sections)),
                Err(e) => cx.warn(format!("{}: {e}", stream.trim_start_matches('\u{5}'))),
            }
        }
    }
    summary_to_normalised(cx, &props);
    if !props.is_empty() {
        cx.metadata("ole").extend(props);
    }

    // Stream listing: the top two levels.
    let mut listing = Vec::new();
    let (mut streams, mut storages) = (0u64, 0u64);
    for e in cfb.entries.iter().skip(1) {
        match e.kind {
            CfbKind::Stream => streams += 1,
            _ => storages += 1,
        }
        if e.path.matches('/').count() < 2 && listing.len() < MAX_LISTED {
            let name = e.path.replace(|c: char| c.is_control(), "");
            listing.push(if e.kind == CfbKind::Stream {
                json!({ "name": name, "size_bytes": e.size })
            } else {
                json!({ "name": format!("{name}/") })
            });
        }
    }
    cx.format_set("streams", streams);
    cx.format_set("storages", storages);
    cx.format_set("entries", listing);

    let projects = super::vba::projects(cfb);
    let mut analysed = Vec::new();
    for p in &projects {
        match super::vba::analyze(cfb, src, p, cx) {
            Ok(v) => analysed.push(v),
            Err(e) => {
                cx.security()
                    .active_content("macros")
                    .risk("macros", Some(if p.is_empty() { "VBA".into() } else { p.clone() }));
                cx.warn(format!("VBA project {p}: {e}"));
            }
        }
    }
    if !analysed.is_empty() {
        cx.format_set("vba", if analysed.len() == 1 { analysed.remove(0) } else { json!(analysed) });
    }
    embedded(cfb, src, cx);
}

/// `SummaryInformation` / `DocumentSummaryInformation` → normalised sections.
fn summary_to_normalised(cx: &mut Context<'_>, p: &Map) {
    let s = |k: &str| p.get(k).and_then(Value::as_str).map(str::trim).filter(|v| !v.is_empty());
    if let Some(t) = s("Title") {
        cx.content().source("ole.Title").title(t);
        cx.emit_text(TextRole::Title, t);
    }
    if let Some(d) = s("Comments").or_else(|| s("Subject")) {
        cx.content().source("ole.Comments").description(d);
        cx.emit_text(TextRole::Caption, d);
    }
    if let Some(a) = s("Author") {
        for name in a.split(';').map(str::trim).filter(|n| !n.is_empty()) {
            cx.content().source("ole.Author").author(name);
            cx.rights().source("ole.Author").creator(name);
        }
    }
    if let Some(k) = s("Keywords") {
        let sep = if k.contains(';') { ';' } else { ',' };
        for kw in k.split(sep).map(str::trim).filter(|w| !w.is_empty()).take(100) {
            cx.content().source("ole.Keywords").keyword(kw);
        }
    }
    if let Some(c) = s("Company") {
        cx.rights().source("ole.Company").credit(c);
    }
    for (key, field) in
        [("CreateDate", DateField::Created), ("ModifyDate", DateField::Modified), ("LastPrinted", DateField::Printed)]
    {
        if let Some(v) = s(key) {
            cx.temporal().source(format!("ole.{key}")).content_date(field, v, true);
        }
    }
    let n = |k: &str| p.get(k).and_then(Value::as_u64).filter(|v| *v > 0);
    if let Some(v) = n("Pages") {
        cx.physical().pages(v);
    }
    if let Some(v) = n("Words") {
        cx.physical().words(v);
    }
    if let Some(v) = n("Slides") {
        cx.physical().slides(v);
    }
    if p.get("Security").and_then(Value::as_array).is_some_and(|f| f.iter().any(|x| x == "password_protected")) {
        cx.security().encrypted(true);
    }
}

/// OLE 1.0 packages (`\x01Ole10Native`) and OOXML packages (`Package`)
/// inside embedded-object storages become children.
fn embedded(cfb: &Cfb, src: &mut dyn Source, cx: &mut Context<'_>) {
    let objects: Vec<&CfbEntry> = cfb
        .entries
        .iter()
        .filter(|e| e.kind == CfbKind::Storage && cfb.find(&format!("{}/\u{1}CompObj", e.path)).is_some())
        .collect();
    if objects.is_empty() {
        return;
    }
    cx.security().active_content("ole_objects");
    let mut listed = Vec::new();
    let max = cx.parse_limit();
    for o in &objects {
        let class =
            o.clsid.as_deref().and_then(clsid_name).map(str::to_string).or_else(|| comp_obj_name(cfb, src, &o.path));
        if class.as_deref().is_some_and(|c| c.starts_with("Equation")) {
            cx.security().risk("equation_editor_object", Some(o.path.clone()));
        }
        if listed.len() < MAX_LISTED {
            listed.push(json!({ "storage": o.path, "class": class }));
        }
        if cx.options().limits.max_depth == 0 {
            continue;
        }
        let child = if let Some(native) = read(cfb, src, &format!("{}/\u{1}Ole10Native", o.path), max) {
            ole10_native(&native)
        } else {
            read(cfb, src, &format!("{}/Package", o.path), max).map(|d| (format!("{}.package", o.name), d))
        };
        if let Some((name, data)) = child
            && cx.emit_child(&name, data).is_err()
        {
            break;
        }
    }
    cx.format_set("embedded_objects", listed);
}

/// The user type in `\x01CompObj` (e.g. `Microsoft Equation 3.0`).
fn comp_obj_name(cfb: &Cfb, src: &mut dyn Source, storage: &str) -> Option<String> {
    let data = read(cfb, src, &format!("{storage}/\u{1}CompObj"), 4096)?;
    let mut r = ByteReader::new(&data).skip(28).ok()?;
    let n = r.le_u32().ok()? as usize;
    let name = r.bytes(n.min(r.remaining())).ok()?;
    let s = crate::plugin::latin1_or_utf8(name).trim_end_matches('\0').trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// The payload of an OLE 1.0 `Ole10Native` package: (file name, data).
fn ole10_native(data: &[u8]) -> Option<(String, Vec<u8>)> {
    let mut r = ByteReader::new(data);
    let _total = r.le_u32().ok()?;
    let _flags = r.le_u16().ok()?;
    let label = crate::plugin::latin1_or_utf8(r.cstr().ok()?);
    let _path = r.cstr().ok()?;
    let _ = r.le_u16().ok()?;
    let _ = r.le_u16().ok()?;
    let n = r.le_u32().ok()? as usize;
    r.advance(n).ok()?;
    let size = r.le_u32().ok()? as usize;
    let payload = r.bytes(size.min(r.remaining())).ok()?;
    let name = if label.trim().is_empty() { "Ole10Native".to_string() } else { label };
    Some((name, payload.to_vec()))
}

// ---------------------------------------------------------------- Word

#[allow(clippy::similar_names)] // FIB field names (csw, cslw)
fn word(cfb: &Cfb, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let doc =
        read(cfb, src, "WordDocument", MAX_STREAM).ok_or_else(|| ExtractError::malformed("no WordDocument stream"))?;
    let mut r = ByteReader::new(&doc);
    let ident = r.le_u16()?;
    if ident != 0xA5EC {
        return Err(ExtractError::malformed(format!("Word FIB ident {ident:#06x}")));
    }
    let nfib = r.le_u16()?;
    r.advance(2)?;
    let lid = r.le_u16()?;
    r.advance(2)?;
    let flags = r.le_u16()?;
    let version = match nfib {
        0x00C1 => "Word 97",
        0x00D9 => "Word 2000",
        0x0101 => "Word 2002",
        0x010C => "Word 2003",
        0x0112 => "Word 2007",
        _ => "Word",
    };
    let mut f = json!({ "nfib": nfib, "application": version, "lid": lid });
    let template = flags & 1 != 0;
    let encrypted = flags & 0x0100 != 0;
    let obfuscated = flags & 0x8000 != 0;
    if template {
        f["template"] = json!(true);
    }
    let quick_saves = (flags >> 4) & 0xF;
    if quick_saves > 0 {
        f["quick_saves"] = json!(quick_saves);
    }
    if flags & 0x0400 != 0 {
        f["read_only_recommended"] = json!(true);
    }
    for (k, v) in f.as_object().cloned().unwrap_or_default() {
        cx.format().insert(k, v);
    }
    if encrypted {
        cx.security().encrypted(true);
        cx.format_set("encryption", if obfuscated { "xor_obfuscation" } else { "rc4" });
        return Ok(());
    }
    let table = if flags & 0x0200 != 0 { "1Table" } else { "0Table" };
    // FibRgW97 (csw words), FibRgLw97 (cslw longs), then the fc/lcb pairs.
    let csw = usize::from(u16::from_le_bytes([*doc.get(32).unwrap_or(&0), *doc.get(33).unwrap_or(&0)]));
    let lw = 34 + csw * 2;
    let cslw = usize::from(u16::from_le_bytes([*doc.get(lw).unwrap_or(&0), *doc.get(lw + 1).unwrap_or(&0)]));
    let rglw = lw + 2;
    let ccp_text = ByteReader::new(doc.get(rglw + 12..).unwrap_or(&[])).le_u32().unwrap_or(0) as usize;
    let fclcb = rglw + cslw * 4 + 2;
    let pair = |i: usize| -> Option<(u32, u32)> {
        let mut r = ByteReader::new(doc.get(fclcb + i * 8..)?);
        Some((r.le_u32().ok()?, r.le_u32().ok()?))
    };
    let Some((fc_clx, lcb_clx)) = pair(33).filter(|(_, l)| *l > 0) else { return Ok(()) };
    let Some(tbl) = read(cfb, src, table, MAX_STREAM) else {
        cx.warn(format!("no {table} stream"));
        return Ok(());
    };
    let clx = tbl
        .get(fc_clx as usize..fc_clx as usize + lcb_clx as usize)
        .ok_or_else(|| ExtractError::malformed("Clx out of range"))?;
    let text = piece_text(&doc, clx, ccp_text.clamp(1, MAX_STREAM))?;
    let (body, fields) = split_fields(&text);
    if !body.trim().is_empty() {
        cx.emit_text(TextRole::Body, &body);
    }
    let mut counts = std::collections::BTreeMap::<String, u64>::new();
    for code in &fields {
        let Some(word) = super::field::code(code) else { continue };
        match super::field::risk(code) {
            Some("dde") => {
                cx.security().active_content("dde").risk("dde", Some(truncate_chars(code.trim(), 200)));
            }
            Some(risk) => {
                cx.security().risk(risk, Some(truncate_chars(code.trim(), 200)));
            }
            None => {}
        }
        if counts.len() < 50 || counts.contains_key(&word) {
            *counts.entry(word).or_default() += 1;
        }
    }
    if !counts.is_empty() {
        cx.format_set("fields", json!(counts));
    }
    cx.format_set("characters", text.chars().count());
    Ok(())
}

/// The first `max` characters of a Word document through its piece table.
fn piece_text(doc: &[u8], clx: &[u8], max: usize) -> Result<String, ExtractError> {
    let mut r = ByteReader::new(clx);
    // Skip Prc entries (property modifiers) before the piece table.
    while r.peek(1) == Some(&[1]) {
        r.advance(1)?;
        let n = usize::from(r.le_u16()?);
        r.advance(n)?;
    }
    if r.u8()? != 2 {
        return Err(ExtractError::malformed("piece table"));
    }
    let lcb = r.le_u32()? as usize;
    let plc = r.bytes(lcb.min(r.remaining()))?;
    let n = plc.len().saturating_sub(4) / 12;
    let mut cps = ByteReader::new(plc);
    let cp: Vec<u32> = (0..=n).filter_map(|_| cps.le_u32().ok()).collect();
    let mut out = String::new();
    let mut count = 0usize;
    for i in 0..n {
        let pcd =
            plc.get((n + 1) * 4 + i * 8..(n + 1) * 4 + i * 8 + 8).ok_or_else(|| ExtractError::malformed("piece"))?;
        let fc = u32::from_le_bytes([pcd[2], pcd[3], pcd[4], pcd[5]]);
        let chars = cp.get(i + 1).zip(cp.get(i)).map_or(0, |(b, a)| b.saturating_sub(*a)) as usize;
        let chars = chars.min(max.saturating_sub(count));
        if chars == 0 {
            break;
        }
        if fc & 0x4000_0000 != 0 {
            let at = ((fc & 0x3FFF_FFFF) / 2) as usize;
            let bytes = doc.get(at..at + chars).unwrap_or(&[]);
            out.push_str(&encoding_rs::WINDOWS_1252.decode_without_bom_handling(bytes).0);
        } else {
            let at = fc as usize;
            let bytes = doc.get(at..at + chars * 2).unwrap_or(&[]);
            let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
            out.push_str(&String::from_utf16_lossy(&units));
        }
        count += chars;
    }
    Ok(out)
}

/// Word's special characters → text, with field codes (between 0x13 and
/// 0x14) taken out and returned separately.
fn split_fields(text: &str) -> (String, Vec<String>) {
    let mut body = String::with_capacity(text.len());
    let mut fields = Vec::new();
    let mut code: Vec<String> = Vec::new();
    let mut in_code: Vec<bool> = Vec::new();
    for c in text.chars() {
        match c {
            '\u{13}' => {
                in_code.push(true);
                code.push(String::new());
            }
            '\u{14}' => {
                if let Some(last) = in_code.last_mut() {
                    *last = false;
                }
            }
            '\u{15}' => {
                in_code.pop();
                if let Some(c) = code.pop()
                    && fields.len() < 1000
                {
                    fields.push(c);
                }
            }
            _ if in_code.last() == Some(&true) => {
                if let Some(c0) = code.last_mut()
                    && c0.len() < 1024
                {
                    c0.push(c);
                }
            }
            '\r' | '\u{b}' | '\u{c}' => body.push('\n'),
            '\u{7}' => body.push('\t'),
            '\u{1}' | '\u{2}' | '\u{3}' | '\u{4}' | '\u{5}' | '\u{8}' => {}
            _ => body.push(c),
        }
    }
    (body, fields)
}

// ---------------------------------------------------------------- Excel

struct Records<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for Records<'a> {
    type Item = (u16, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        let h = self.data.get(self.pos..self.pos + 4)?;
        let kind = u16::from_le_bytes([h[0], h[1]]);
        let len = usize::from(u16::from_le_bytes([h[2], h[3]]));
        let body = self.data.get(self.pos + 4..self.pos + 4 + len)?;
        self.pos += 4 + len;
        Some((kind, body))
    }
}

/// Reads BIFF8 unicode strings across `CONTINUE` record boundaries.
struct Sst<'a> {
    parts: Vec<&'a [u8]>,
    part: usize,
    pos: usize,
}

impl Sst<'_> {
    fn byte(&mut self) -> Option<u8> {
        while self.parts.get(self.part)?.len() <= self.pos {
            self.part += 1;
            self.pos = 0;
        }
        let b = self.parts[self.part][self.pos];
        self.pos += 1;
        Some(b)
    }

    fn skip(&mut self, mut n: usize) -> Option<()> {
        while n > 0 {
            let left = self.parts.get(self.part)?.len().saturating_sub(self.pos);
            if left == 0 {
                self.part += 1;
                self.pos = 0;
                continue;
            }
            let step = left.min(n);
            self.pos += step;
            n -= step;
        }
        Some(())
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes([self.byte()?, self.byte()?]))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes([self.byte()?, self.byte()?, self.byte()?, self.byte()?]))
    }

    fn string(&mut self) -> Option<String> {
        let mut chars = usize::from(self.u16()?);
        let mut flags = self.byte()?;
        let runs = if flags & 8 != 0 { usize::from(self.u16()?) } else { 0 };
        let ext = if flags & 4 != 0 { self.u32()? as usize } else { 0 };
        let mut out = String::new();
        while chars > 0 {
            let part = self.part;
            let wide = flags & 1 != 0;
            let left = self.parts.get(self.part)?.len().saturating_sub(self.pos);
            if left == 0 {
                // A string continued in the next record restarts with a flags byte.
                self.part += 1;
                self.pos = 0;
                flags = self.byte()?;
                continue;
            }
            let take = if wide { (left / 2).min(chars) } else { left.min(chars) };
            if take == 0 {
                return None;
            }
            let bytes = &self.parts[part][self.pos..self.pos + if wide { take * 2 } else { take }];
            if wide {
                let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                out.push_str(&String::from_utf16_lossy(&units));
            } else {
                out.extend(bytes.iter().map(|&b| char::from(b)));
            }
            self.pos += bytes.len();
            chars -= take;
        }
        self.skip(runs * 4 + ext)?;
        Some(out)
    }
}

#[allow(clippy::too_many_lines)] // one pass over the BIFF records
fn excel(cfb: &Cfb, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let book = read(cfb, src, "Workbook", MAX_STREAM)
        .or_else(|| read(cfb, src, "Book", MAX_STREAM))
        .ok_or_else(|| ExtractError::malformed("no Workbook stream"))?;
    let mut sheets = Vec::new();
    let mut encrypted = None;
    let (mut formulas, mut cells, mut names, mut macro_sheets) = (0u64, 0u64, 0u64, 0u64);
    let mut auto_open = false;
    let mut sst_parts: Vec<&[u8]> = Vec::new();
    let mut in_sst = false;
    let mut biff = None;
    let mut locked_sheets = 0u64;
    for (n, (kind, body)) in (Records { data: &book, pos: 0 }).enumerate() {
        if n.is_multiple_of(65_536) {
            cx.checkpoint()?;
        }
        if kind != 0x003C {
            in_sst = false;
        }
        // After FILEPASS every record body is encrypted (BoundSheet8 keeps
        // only its stream offset in clear): count records, read nothing.
        if encrypted.is_some() {
            match kind {
                0x0085 => locked_sheets += 1,
                0x0018 => names += 1,
                _ => {}
            }
            continue;
        }
        match kind {
            0x0809 if biff.is_none() => biff = body.get(..2).map(|v| u16::from_le_bytes([v[0], v[1]])),
            0x002F => {
                encrypted = Some(match body.first().copied().zip(body.get(1).copied()) {
                    Some((0, 0)) => "xor_obfuscation",
                    _ => match body.get(2..4) {
                        Some([2..=4, 0]) => "cryptoapi",
                        _ => "rc4",
                    },
                });
            }
            0x0085 => {
                let mut r = ByteReader::new(body).skip(4)?;
                let state = r.u8()?;
                let dt = r.u8()?;
                let cch = usize::from(r.u8()?);
                let high = r.u8()? & 1 != 0;
                let name = if high {
                    let b = r.bytes((cch * 2).min(r.remaining()))?;
                    String::from_utf16_lossy(
                        &b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect::<Vec<_>>(),
                    )
                } else {
                    encoding_rs::WINDOWS_1252
                        .decode_without_bom_handling(r.bytes(cch.min(r.remaining()))?)
                        .0
                        .into_owned()
                };
                let kind = match dt {
                    0 => "worksheet",
                    1 => "macro_sheet",
                    2 => "chart",
                    6 => "vb_module",
                    _ => "other",
                };
                if dt == 1 {
                    macro_sheets += 1;
                }
                if sheets.len() < MAX_LISTED {
                    let mut s = json!({ "name": name, "kind": kind });
                    match state & 3 {
                        1 => s["state"] = json!("hidden"),
                        2 => s["state"] = json!("veryHidden"),
                        _ => {}
                    }
                    sheets.push(s);
                }
            }
            0x0018 => {
                names += 1;
                // Built-in name 0x01 = Auto_Open.
                // Lbl: grbit (fBuiltin = 0x20), …, then the name at offset 15
                // (one character for built-in names: 0x01 = Auto_Open).
                let builtin = body.first().is_some_and(|f| f & 0x20 != 0);
                let name = body.get(15..).unwrap_or(&[]);
                if (builtin && name.first() == Some(&1))
                    || name.get(..9).is_some_and(|n| n.eq_ignore_ascii_case(b"auto_open"))
                {
                    auto_open = true;
                }
            }
            0x00FC => {
                sst_parts.clear();
                sst_parts.push(body);
                in_sst = true;
            }
            0x003C if in_sst => sst_parts.push(body),
            0x0006 => formulas += 1,
            0x00FD | 0x0203 | 0x027E | 0x0204 | 0x0205 => cells += 1,
            0x00BD => cells += u64::try_from(body.len().saturating_sub(6) / 6).unwrap_or(0),
            _ => {}
        }
    }
    if let Some(e) = encrypted {
        cx.security().encrypted(true);
        cx.format_set("encryption", e);
    }
    if let Some(v) = biff {
        cx.format_set("biff_version", format!("{v:#06x}"));
    }
    let hidden = sheets.iter().filter(|s| s.get("state").is_some()).count();
    cx.physical().sheets(sheets.iter().filter(|s| s["kind"] != "vb_module").count() as u64 + locked_sheets);
    if macro_sheets > 0 {
        cx.security()
            .active_content("excel4_macros")
            .risk("xlm_macros", Some(format!("{macro_sheets} Excel 4.0 macro sheet(s)")));
        if sheets.iter().any(|s| s["kind"] == "macro_sheet" && s.get("state").is_some()) {
            cx.security().risk("hidden_macro_sheet", None);
        }
    }
    if auto_open {
        cx.security().risk("auto_exec_macro", Some("Auto_Open".into()));
    }
    if encrypted.is_none() {
        cx.format_set("sheets", sheets);
    }
    if hidden > 0 {
        cx.format_set("hidden_sheets", hidden);
    }
    if names > 0 {
        cx.format_set("defined_names", names);
    }
    if encrypted.is_none() {
        cx.format_set("cells", cells);
        cx.format_set("formulas", formulas);
    }
    if !sst_parts.is_empty() && encrypted.is_none() {
        let mut sst = Sst { parts: sst_parts, part: 0, pos: 8 };
        let total = u32::from_le_bytes(sst.parts[0].get(4..8).and_then(|b| b.try_into().ok()).unwrap_or([0; 4]));
        let mut text = String::new();
        let mut n = 0u32;
        while n < total.min(1_000_000) {
            let Some(s) = sst.string() else { break };
            n += 1;
            if text.len() < (1 << 20) {
                text.push_str(&s);
                text.push('\n');
            }
        }
        cx.format_set("shared_strings", n);
        cx.emit_text(TextRole::Data, &text);
    }
    Ok(())
}

// ---------------------------------------------------------------- PowerPoint

#[allow(clippy::too_many_lines)] // one walk over the record tree
fn powerpoint(cfb: &Cfb, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let data = read(cfb, src, "PowerPoint Document", MAX_STREAM)
        .ok_or_else(|| ExtractError::malformed("no PowerPoint Document stream"))?;
    let (mut slides, mut notes, mut objects) = (0u64, 0u64, 0u64);
    let (mut encrypted, mut vba) = (false, false);
    let mut titles: Vec<String> = Vec::new();
    let mut body = String::new();
    let mut text_type: Option<u32> = None;
    // A bounded walk: each container's children stop at its end, so a
    // child whose length overruns its parent cannot shift the records
    // after it. `open` holds (record type, end) of the enclosing containers.
    let mut open: Vec<(u16, usize)> = Vec::new();
    let mut pos = 0usize;
    let mut steps = 0usize;
    loop {
        while open.last().is_some_and(|&(_, end)| pos + 8 > end) {
            if let Some((_, end)) = open.pop() {
                pos = pos.max(end);
            }
        }
        let limit = open.last().map_or(data.len(), |&(_, end)| end);
        if pos + 8 > limit {
            break;
        }
        steps += 1;
        if steps.is_multiple_of(65_536) {
            cx.checkpoint()?;
        }
        let ver_inst = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let kind = u16::from_le_bytes([data[pos + 2], data[pos + 3]]);
        let len = u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]) as usize;
        let start = pos + 8;
        let end = start.saturating_add(len).min(limit);
        if ver_inst & 0xF == 0xF {
            match kind {
                0x03EE => slides += 1,
                0x03F0 => notes += 1,
                _ => {}
            }
            if open.len() < 64 {
                open.push((kind, end));
                pos = start;
            } else {
                pos = end;
            }
            continue;
        }
        let atom = &data[start..end];
        // Master and handout placeholders ("Click to edit Master title
        // style") are not the document's text.
        let in_master = open.iter().any(|&(k, _)| matches!(k, 0x03F8 | 0x0FC9));
        match kind {
            0x0F9F => text_type = atom.get(..4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            0x0FA0 | 0x0FA8 if !in_master => {
                let text = if kind == 0x0FA0 {
                    String::from_utf16_lossy(
                        &atom.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect::<Vec<_>>(),
                    )
                } else {
                    encoding_rs::WINDOWS_1252.decode_without_bom_handling(atom).0.into_owned()
                };
                let text = text.replace('\r', "\n");
                if matches!(text_type, Some(0 | 6)) && titles.len() < MAX_LISTED {
                    titles.push(crate::plugin::squash_whitespace(&text));
                } else if body.len() < (1 << 20) {
                    body.push_str(&text);
                    body.push('\n');
                }
                text_type = None;
            }
            0x2F14 => encrypted = true,
            0x1011 => objects += 1,
            // VbaInfoAtom: persistIdRef, fHasMacros, version. PowerPoint
            // writes one with fHasMacros = 0 in files without a project.
            0x0400 => vba |= atom.get(4..8).is_some_and(|b| b != [0, 0, 0, 0]),
            _ => {}
        }
        pos = end;
    }
    let locked = encrypted || cfb.find("EncryptedSummary").is_some();
    if locked {
        cx.security().encrypted(true);
        cx.format_set("encryption", "cryptoapi");
    } else {
        cx.physical().slides(slides);
    }
    for t in titles.iter().filter(|t| !t.is_empty()) {
        cx.emit_heading(1, t);
    }
    if let Some(t) = titles.first().filter(|t| !t.is_empty()) {
        cx.content().source("ppt.slide1.title").title(t.clone());
    }
    if !body.trim().is_empty() {
        cx.emit_text(TextRole::Body, &body);
    }
    if objects > 0 {
        cx.security().active_content("ole_objects");
        cx.format_set("embedded_objects", objects);
    }
    if vba {
        cx.security().active_content("macros").risk("macros", Some("VBA project in the presentation".into()));
    }
    // An encrypted document stream hides its slides.
    if !locked {
        cx.format_set("slides", slides);
        cx.format_set("slide_titles", titles);
    }
    if notes > 0 {
        cx.format_set("notes_pages", notes);
    }
    Ok(())
}

// ---------------------------------------------------------------- encrypted OOXML, HWP

fn encrypted_package(cfb: &Cfb, src: &mut dyn Source, cx: &mut Context<'_>) {
    cx.security().encrypted(true);
    let info = read(cfb, src, "EncryptionInfo", 1 << 20).unwrap_or_default();
    let mut r = ByteReader::new(&info);
    let (major, minor) = (r.le_u16().unwrap_or(0), r.le_u16().unwrap_or(0));
    let mut e = json!({ "version": format!("{major}.{minor}") });
    match (major, minor) {
        (4, 4) => {
            e["method"] = json!("agile");
            let xml = String::from_utf8_lossy(info.get(8..).unwrap_or(&[]));
            if let Some(key_data) = xml.find("<keyData").map(|i| &xml[i..]) {
                for (attr, key) in [("cipherAlgorithm", "cipher"), ("keyBits", "key_bits"), ("hashAlgorithm", "hash")] {
                    if let Some(v) = key_data.split(&format!("{attr}=\"")).nth(1).and_then(|v| v.split('"').next()) {
                        e[key] = v.parse::<u64>().map_or_else(|_| json!(v), |n| json!(n));
                    }
                }
            }
            if let Some(v) =
                xml.split("spinCount=\"").nth(1).and_then(|v| v.split('"').next()).and_then(|v| v.parse::<u64>().ok())
            {
                e["spin_count"] = json!(v);
            }
        }
        (2..=4, 2) => {
            e["method"] = json!("standard");
            // EncryptionHeader after flags (4) and header size (4): flags, sizeExtra, algId, algIdHash, keySize.
            let mut h = ByteReader::new(info.get(12..).unwrap_or(&[])).skip(8).unwrap_or_else(|_| ByteReader::new(&[]));
            if let (Ok(alg), Ok(_hash), Ok(bits)) = (h.le_u32(), h.le_u32(), h.le_u32()) {
                e["cipher"] = json!(match alg {
                    0x660E => "AES-128",
                    0x660F => "AES-192",
                    0x6610 => "AES-256",
                    0x6801 => "RC4",
                    _ => "unknown",
                });
                e["key_bits"] = json!(bits);
            }
        }
        (3 | 4, 3) => e["method"] = json!("extensible"),
        _ => {}
    }
    if let Some(p) = cfb.find("EncryptedPackage") {
        let size = read(cfb, src, "EncryptedPackage", 8).and_then(|b| b.try_into().ok()).map(u64::from_le_bytes);
        e["package_bytes"] = json!(size.unwrap_or(p.size));
    }
    cx.format_set("encryption", e);
}

fn hwp(cfb: &Cfb, src: &mut dyn Source, cx: &mut Context<'_>) {
    let Some(h) = read(cfb, src, "FileHeader", 256) else { return };
    let mut r = ByteReader::new(h.get(32..).unwrap_or(&[]));
    if let (Ok(v), Ok(flags)) = (r.le_u32(), r.le_u32()) {
        cx.format_set("hwp_version", format!("{}.{}.{}.{}", v >> 24, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF));
        cx.format_set("compressed", flags & 1 != 0);
        if flags & 2 != 0 {
            cx.security().encrypted(true);
        }
        if flags & 0x10 != 0 {
            cx.security().signed(true);
        }
    }
    if cfb.entries.iter().any(|e| e.path.starts_with("Scripts")) {
        cx.security().active_content("scripts");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_split_out() {
        let (body, fields) =
            split_fields("Hello \u{13} HYPERLINK \"x\" \u{14}link\u{15} world\r\u{13}DDEAUTO cmd\u{15}");
        assert_eq!(body, "Hello link world\n");
        assert_eq!(fields, [" HYPERLINK \"x\" ", "DDEAUTO cmd"]);
    }

    #[test]
    fn kinds_from_names() {
        let n = |v: &[&str]| kind_of(&v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        assert_eq!(n(&["WordDocument", "1Table"]), Some("doc"));
        assert_eq!(n(&["__substg1.0_0037001F"]), Some("msg"));
        assert_eq!(n(&["EncryptionInfo", "EncryptedPackage"]), Some("office_encrypted"));
        assert_eq!(n(&["Other"]), None);
    }

    /// A PowerPoint record: header, then `body` (an atom) or children.
    #[allow(clippy::cast_possible_truncation)] // test records are small
    fn rec(kind: u16, container: bool, body: &[u8]) -> Vec<u8> {
        let mut v = (if container { 0x000Fu16 } else { 0 }).to_le_bytes().to_vec();
        v.extend_from_slice(&kind.to_le_bytes());
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    fn slide(title: &str) -> Vec<u8> {
        let text = [rec(0x0F9F, false, &0u32.to_le_bytes()), rec(0x0FA8, false, title.as_bytes())].concat();
        rec(0x03EE, true, &rec(0x040C, true, &rec(0xF00D, true, &text)))
    }

    fn ppt_report(stream: &[u8]) -> crate::plugin::Report {
        let file = crate::plugin::testing::cfb(&[("PowerPoint Document", stream)]);
        crate::plugin::testing::report_for("deck.ppt", &file)
    }

    #[test]
    fn powerpoint_vba_info_needs_macros_flag() {
        let vba = |has: u8| rec(0x03FF, true, &rec(0x0400, false, &[0, 0, 0, 0, has, 0, 0, 0, 2, 0, 0, 0]));
        let document = |has| rec(0x03E8, true, &vba(has));
        let plain = ppt_report(&[document(0), slide("Harbour")].concat());
        assert!(plain.security.risks.is_empty(), "{:?}", plain.security.risks);
        let with = ppt_report(&[document(1), slide("Harbour")].concat());
        assert_eq!(with.security.risks[0].kind, "macros");
    }

    #[test]
    fn powerpoint_overrunning_child_and_master_text() {
        // A container whose last child claims more than the container holds
        // must not shift the next slide; master placeholders are not text.
        let mut broken = rec(0x0BC3, false, &[0; 8]);
        broken.extend_from_slice(&rec(0x0420, false, &[0; 8])[..9]);
        let master_text = [rec(0x0F9F, false, &0u32.to_le_bytes()), rec(0x0FA8, false, b"Click to edit")].concat();
        let stream = [
            rec(0x03F8, true, &rec(0xF00D, true, &master_text)),
            rec(0x03EE, true, &rec(0xF011, true, &broken)),
            slide("Tides"),
            slide("Berths"),
        ]
        .concat();
        let r = ppt_report(&stream);
        let f = &r.format["ppt"];
        assert_eq!(f["slides"], 3);
        assert_eq!(f["slide_titles"], serde_json::json!(["Tides", "Berths"]));
    }

    crate::fixture_tests!(
        "cfb",
        "doc",
        "xls",
        "ppt",
        "vsd",
        "pub",
        "mpp",
        "hwp",
        "thumbs_db",
        "fpx",
        "office_encrypted",
        "vba_project"
    );
}
