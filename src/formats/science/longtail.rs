//! More scientific and medical files:
//!
//! * HDF4 (and HDF-EOS 2): library version, data descriptors by tag,
//!   scientific data sets, vgroups, global attributes (names, and short
//!   text values), and the HDF-EOS swaths, grids and points named in
//!   `StructMetadata`;
//! * Maple worksheets (`.mw`): Maple version, groups, inputs, outputs,
//!   text and math fields, plots;
//! * Mathcad worksheets (`.xmcd`): the release that wrote them, title,
//!   regions by kind, math and text regions;
//! * SCP-ECG (EN 1064 / ISO 11073-91064): sections, acquisition date and
//!   time, device and its maker, leads, sampling rate, duration; patient
//!   details only with `--privacy off`;
//! * HL7 annotated ECG (aECG XML): time range, series, leads, sampling
//!   rate, samples, annotations, device; the subject only with
//!   `--privacy off`.
//!
//! Specifications: the HDF4 file format (The HDF Group); HDF-EOS 2
//! `StructMetadata`; Maplesoft's worksheet XML and Mathcad's
//! `worksheet30` schema as their applications write them; EN 1064:2005
//! (SCP-ECG); HL7 v3 Annotated ECG (FDA aECG).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, xmlwalk,
};

/// Extractor for the formats above.
pub struct LongTail;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, [$($ext:literal),*], [$($magic:expr),*]) => {
        FormatSpec { id: $id, name: $name, family: "sci", mimes: &[$mime], extensions: &[$($ext),*], magic: &[$($magic),*], parent: None }
    };
}

const HDF4: &[u8] = b"\x0e\x03\x13\x01";

static META: ExtractorMeta = ExtractorMeta {
    id: "science.longtail",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!("hdf4", "HDF4 / HDF-EOS", "application/x-hdf", ["hdf", "hdf4", "he4", "h4"], [Magic::prefix(HDF4)]),
        spec!("maple_mw", "Maple worksheet", "application/x-maple-worksheet", ["mw"], []),
        spec!("mathcad", "Mathcad worksheet", "application/x-mathcad", ["xmcd"], []),
        spec!("scp_ecg", "SCP-ECG", "application/x-scp-ecg", ["scp"], []),
        spec!("aecg", "HL7 annotated ECG", "application/hl7-aecg+xml", [], []),
    ],
};

/// Names listed.
const MAX_LISTED: usize = 100;

impl Extractor for LongTail {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let pick = |format: &'static str| Some(Sniff { format, confidence: 0.95 });
        // SCP-ECG: section 0 starts at byte 6 with "SCPECG" in its reserved field.
        if h.get(16..22) == Some(b"SCPECG") && h.get(8..10) == Some(&[0, 0]) {
            return pick("scp_ecg");
        }
        let text = String::from_utf8_lossy(&h[..h.len().min(8192)]);
        if text.contains("<Worksheet") && (text.contains("<Version") || text.contains("maplesoft")) {
            return pick("maple_mw");
        }
        if text.contains("schemas.mathsoft.com/worksheet") {
            return pick("mathcad");
        }
        if text.contains("<AnnotatedECG") {
            return pick("aecg");
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, cut) = cx.read_bytes(src)?;
        if cut {
            cx.format_set("truncated", true);
        }
        match cx.format_id() {
            "hdf4" => hdf4(cx, &b),
            "maple_mw" => maple(cx, &String::from_utf8_lossy(&b))?,
            "mathcad" => mathcad(cx, &String::from_utf8_lossy(&b))?,
            "scp_ecg" => scp(cx, &b),
            _ => aecg(cx, &String::from_utf8_lossy(&b))?,
        }
        Ok(())
    }
}

crate::register_extractor!(LongTail);

fn be16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2).map_or(0, |s| u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn text_of(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    crate::plugin::latin1_or_utf8(&b[..end]).trim().to_string()
}

// --- HDF4 ------------------------------------------------------------------------------------

/// The name of an HDF4 tag.
fn tag_name(tag: u16) -> String {
    match tag & 0x3fff {
        1 => "null".into(),
        30 => "version".into(),
        100 => "file identifier".into(),
        101 => "file description".into(),
        102 => "tag identifier".into(),
        104 => "data identifier".into(),
        105 => "data annotation".into(),
        106 => "number type".into(),
        107 => "machine type".into(),
        200..=202 => "raster image (8-bit)".into(),
        300..=311 => "raster image".into(),
        700 => "scientific data group".into(),
        701 => "SD dimensions".into(),
        702 => "scientific data".into(),
        703..=713 => "SD attribute".into(),
        720 => "numeric data group".into(),
        731 => "calibration".into(),
        732 => "fill value".into(),
        1962 => "vdata header".into(),
        1963 => "vdata".into(),
        1965 => "vgroup".into(),
        t => format!("tag {t}"),
    }
}

/// An HDF4 string field: a big-endian u16 length, then the bytes.
fn hstr(b: &[u8], at: usize) -> Option<(String, usize)> {
    let n = usize::from(be16(b, at));
    let s = b.get(at + 2..at + 2 + n)?;
    Some((crate::plugin::latin1_or_utf8(s), at + 2 + n))
}

#[allow(clippy::too_many_lines)] // one tag after another
fn hdf4(cx: &mut Context<'_>, b: &[u8]) {
    // Data descriptor blocks: count, next block, then (tag, ref, offset, length).
    let mut dds: Vec<(u16, u16, usize, usize)> = Vec::new();
    let mut block = 4usize;
    let mut seen = BTreeSet::new();
    while block != 0 && block + 6 <= b.len() && seen.insert(block) && dds.len() < 1_000_000 {
        let n = usize::from(be16(b, block));
        let next = be32(b, block + 2) as usize;
        for i in 0..n {
            let at = block + 6 + i * 12;
            if at + 12 > b.len() {
                break;
            }
            let tag = be16(b, at);
            if tag == 1 {
                continue;
            }
            dds.push((tag, be16(b, at + 2), be32(b, at + 4) as usize, be32(b, at + 8) as usize));
        }
        block = next;
    }
    let data = |off: usize, len: usize| b.get(off..off.saturating_add(len)).unwrap_or_default();
    let mut tags: BTreeMap<String, u64> = BTreeMap::new();
    for (tag, ..) in &dds {
        let n = tags.entry(tag_name(*tag)).or_default();
        *n += 1;
    }
    cx.format_set("descriptors", dds.len());
    cx.format_set("tags", json!(tags));
    if let Some((_, _, off, len)) = dds.iter().find(|d| d.0 == 30) {
        let v = data(*off, *len);
        let version = format!("{}.{}.{}", be32(v, 0), be32(v, 4), be32(v, 8));
        cx.format_set("library_version", version);
        let s = text_of(v.get(12..).unwrap_or_default());
        if !s.is_empty() {
            cx.format_set("library_string", s);
        }
    }
    // Vgroups: name and class (`Var0.0` marks an SD data set, `Dim0.0` a dimension).
    let (mut datasets, mut groups, mut dims) = (Vec::new(), Vec::new(), 0u64);
    for (_, _, off, len) in dds.iter().filter(|d| d.0 == 1965) {
        let v = data(*off, *len);
        let n = usize::from(be16(v, 0));
        let at = 2 + n * 4;
        let Some((name, at)) = hstr(v, at) else { continue };
        let class = hstr(v, at).map(|c| c.0).unwrap_or_default();
        match class.as_str() {
            "Var0.0" => datasets.push(name),
            "Dim0.0" | "UDim0.0" => dims += 1,
            "CDF0.0" | "RIG0.0" => {}
            _ => groups.push(if class.is_empty() { name } else { format!("{name} ({class})") }),
        }
    }
    // Vdatas: field layout, then the name and class; `Attr0.0` holds an attribute.
    let mut attrs = Map::new();
    let mut eos = String::new();
    for (_, r, off, len) in dds.iter().filter(|d| d.0 == 1962) {
        let v = data(*off, *len);
        let nfields = usize::from(be16(v, 8));
        let types: Vec<u16> = (0..nfields).map(|i| be16(v, 10 + i * 2)).collect();
        let mut at = 10 + nfields * 2 * 4;
        for _ in 0..nfields {
            let Some((_, a)) = hstr(v, at) else { break };
            at = a;
        }
        let Some((name, at)) = hstr(v, at) else { continue };
        let class = hstr(v, at).map(|c| c.0).unwrap_or_default();
        if class != "Attr0.0" {
            continue;
        }
        // Character attributes (DFNT_CHAR8 = 4, UCHAR8 = 3): the text.
        let value = dds
            .iter()
            .find(|d| d.0 == 1963 && d.1 == *r)
            .filter(|_| matches!(types.first(), Some(3 | 4)))
            .map(|d| text_of(data(d.2, d.3)));
        if name.starts_with("StructMetadata") || name.starts_with("CoreMetadata") {
            if let Some(t) = &value {
                eos.push_str(t);
            }
            continue;
        }
        if attrs.len() < MAX_LISTED {
            let shown = value.map_or(Value::Null, |t| json!(crate::plugin::truncate_chars(&t, 200)));
            attrs.insert(name, shown);
        }
    }
    cx.format_set("datasets", datasets.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("dimensions", dims);
    if !groups.is_empty() {
        cx.format_set("vgroups", groups.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    }
    cx.format_set("attributes", Value::Object(attrs));
    if !eos.is_empty() {
        // `GROUP=SwathStructure … SwathName="…"`.
        let names = |key: &str| -> Vec<String> {
            eos.match_indices(key)
                .filter_map(|(p, _)| eos[p + key.len()..].split('"').nth(1).map(str::to_string))
                .take(MAX_LISTED)
                .collect()
        };
        cx.format_set(
            "hdf_eos",
            json!({ "swaths": names("SwathName="), "grids": names("GridName="), "points": names("PointName=") }),
        );
    }
}

// --- Maple / Mathcad --------------------------------------------------------------------------------

fn maple(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    xmlwalk::walk(text, cx, 10_000_000, |cx, ev| {
        let xmlwalk::Ev::Start(name, a) = ev else { return };
        match name {
            "Version" => {
                if let (Some(m), Some(n)) = (xmlwalk::attr(a, "major"), xmlwalk::attr(a, "minor")) {
                    cx.format_set("maple_version", format!("{m}.{n}"));
                }
            }
            "Group" | "Input" | "Output" | "Text-field" | "Equation" | "Plot" | "Image" | "Section" | "Title"
            | "Table" | "Spreadsheet" => {
                *counts.entry(name.to_lowercase().replace("text-field", "text_field")).or_default() += 1;
            }
            _ => {}
        }
    })?;
    cx.format_set("elements", json!(counts));
    Ok(())
}

fn mathcad(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut regions, mut kinds, mut path) = (0u64, BTreeMap::<String, u64>::new(), Vec::<String>::new());
    let mut meta = Map::new();
    xmlwalk::walk(text, cx, 10_000_000, |cx, ev| match ev {
        xmlwalk::Ev::Start(name, a) => {
            let parent = path.last().cloned().unwrap_or_default();
            path.push(name.to_string());
            match name {
                "pointReleaseData" | "version" if parent == "settings" || parent == "worksheet" => {}
                "region" => regions += 1,
                "math" | "text" | "picture" | "plot" | "chartComponent" | "solveblock" | "area" | "pageBreak"
                    if parent == "region" =>
                {
                    *kinds.entry(name.to_string()).or_default() += 1;
                }
                "worksheet" => {
                    if let Some(v) = xmlwalk::attr(a, "version") {
                        cx.format_set("schema_version", v);
                    }
                }
                _ => {}
            }
        }
        xmlwalk::Ev::Text(t) => {
            // `metadata/generator`, `metadata/userData/title` …
            let last = path.last().map_or("", String::as_str);
            let in_meta = path.iter().any(|p| p == "metadata");
            // The author and last editor only with `--privacy off`.
            let public = matches!(last, "title" | "description" | "company" | "generator");
            let personal = matches!(last, "author" | "lastSavedBy") && !cx.privacy_strict();
            if in_meta && (public || personal) {
                meta.entry(last.to_string()).or_insert(json!(t));
            }
        }
        xmlwalk::Ev::End(_) => {
            path.pop();
        }
    })?;
    if let Some(t) = meta.get("title").and_then(Value::as_str) {
        cx.content().title(t.to_string());
    }
    cx.format_set("metadata", Value::Object(meta));
    cx.format_set("regions", regions);
    cx.format_set("region_kinds", json!(kinds));
    Ok(())
}

// --- SCP-ECG ----------------------------------------------------------------------------------------------

/// Lead names by SCP lead identifier.
fn lead_name(id: u8) -> String {
    match id {
        1 => "I".into(),
        2 => "II".into(),
        3..=8 => format!("V{}", id - 2),
        61 => "III".into(),
        62 => "aVR".into(),
        63 => "aVL".into(),
        64 => "aVF".into(),
        86..=88 => ["X", "Y", "Z"][usize::from(id - 86)].into(),
        0 => "unspecified".into(),
        n => format!("lead {n}"),
    }
}

#[allow(clippy::too_many_lines)] // one section after another
fn scp(cx: &mut Context<'_>, b: &[u8]) {
    let strict = cx.privacy_strict();
    cx.format_set("declared_size_bytes", le32(b, 2));
    // Section 0: pointers to the other sections (id, length, 1-based index).
    let s0_len = le32(b, 6 + 4) as usize;
    let mut sections: BTreeMap<u16, (usize, usize)> = BTreeMap::new();
    let mut at = 6 + 16;
    while at + 10 <= (6 + s0_len).min(b.len()) {
        let (id, len, index) = (le16(b, at), le32(b, at + 2) as usize, le32(b, at + 6) as usize);
        if len > 0 && index > 0 {
            sections.insert(id, (index - 1, len));
        }
        at += 10;
    }
    cx.format_set("protocol_version", b.get(6 + 9).copied().unwrap_or(0));
    cx.format_set("sections", sections.keys().copied().collect::<Vec<_>>());
    let body = |id: u16| sections.get(&id).and_then(|&(start, len)| b.get(start + 16..(start + len).min(b.len())));
    // Section 1: tagged header fields (tag, length, value).
    if let Some(s1) = body(1) {
        let (mut device, mut patient, mut people) = (Map::new(), Map::new(), Vec::new());
        let mut p = 0;
        while p + 3 <= s1.len() {
            let (tag, len) = (s1[p], usize::from(le16(s1, p + 1)));
            let Some(v) = s1.get(p + 3..p + 3 + len) else { break };
            match tag {
                255 => break,
                0 | 1 | 3 if !strict => {
                    let key = ["last_name", "first_name", "", "second_last_name"][usize::from(tag)];
                    patient.insert(key.into(), json!(text_of(v)));
                }
                2 if !strict => _ = patient.insert("id".into(), json!(text_of(v))),
                4 if !strict && len >= 3 => _ = patient.insert("age".into(), json!(le16(v, 0))),
                5 if !strict && len >= 4 => {
                    patient.insert("birth_date".into(), json!(format!("{:04}-{:02}-{:02}", le16(v, 0), v[2], v[3])));
                }
                8 if !strict && len >= 1 => {
                    let sex = match v[0] {
                        1 => "male",
                        2 => "female",
                        9 => "unspecified",
                        _ => "unknown",
                    };
                    patient.insert("sex".into(), json!(sex));
                }
                14 if len >= 36 => {
                    device.insert("institution".into(), json!(le16(v, 0)));
                    device.insert("department".into(), json!(le16(v, 2)));
                    device.insert("device_id".into(), json!(le16(v, 4)));
                    device.insert("manufacturer_code".into(), json!(v[7]));
                    device.insert("model".into(), json!(text_of(&v[8..14])));
                    // Byte 35: the analysing program's length and text; then
                    // null-terminated: serial number, system software, SCP
                    // software, manufacturer.
                    let n = usize::from(v[35]);
                    let program = text_of(v.get(36..36 + n).unwrap_or_default());
                    let rest = v.get(36 + n..).unwrap_or_default();
                    let strings = std::iter::once(program).chain(rest.split(|&c| c == 0).map(text_of));
                    for (key, s) in
                        ["analysing_program", "serial_number", "system_software", "scp_software", "manufacturer"]
                            .iter()
                            .zip(strings)
                    {
                        if !s.is_empty() {
                            device.insert((*key).into(), json!(s));
                        }
                    }
                }
                16 | 17 => {
                    let key = if tag == 16 { "acquiring_institution" } else { "analysing_institution" };
                    cx.format_set(key, text_of(v));
                }
                20..=22 if !strict => people.push(text_of(v)),
                25 if len >= 4 => {
                    cx.format_set("acquisition_date", format!("{:04}-{:02}-{:02}", le16(v, 0), v[2], v[3]));
                }
                26 if len >= 3 => cx.format_set("acquisition_time", format!("{:02}:{:02}:{:02}", v[0], v[1], v[2])),
                27 if len >= 2 => cx.format_set("baseline_filter_hz", f64::from(le16(v, 0)) / 100.0),
                28 if len >= 2 => cx.format_set("low_pass_filter_hz", le16(v, 0)),
                _ => {}
            }
            p += 3 + len;
        }
        if !device.is_empty() {
            cx.format_set("device", Value::Object(device));
        }
        if !strict {
            if !patient.is_empty() {
                cx.format_set("patient", Value::Object(patient));
            }
            if !people.is_empty() {
                cx.format_set("staff", people);
            }
        }
    }
    // Section 3: leads (start and end sample, id).
    let mut samples = 0u64;
    if let Some(s3) = body(3) {
        let n = usize::from(s3.first().copied().unwrap_or(0));
        let leads: Vec<String> = (0..n)
            .filter_map(|i| s3.get(2 + i * 9..2 + i * 9 + 9))
            .map(|l| {
                samples = samples.max(u64::from(le32(l, 4).saturating_sub(le32(l, 0)) + 1));
                lead_name(l[8])
            })
            .collect();
        cx.format_set("leads", leads);
        cx.format_set("simultaneous", s3.get(1).is_some_and(|f| f & 4 != 0));
    }
    // Section 6: rhythm data (amplitude multiplier, sample interval in µs, encoding).
    if let Some(s6) = body(6) {
        let (avm, interval) = (le16(s6, 0), le16(s6, 2));
        cx.format_set("amplitude_nv", avm);
        if interval > 0 {
            let rate = 1_000_000.0 / f64::from(interval);
            cx.format_set("sampling_rate_hz", (rate * 1000.0).round() / 1000.0);
            if samples > 0 {
                #[allow(clippy::cast_precision_loss)]
                let d = samples as f64 * f64::from(interval) / 1e6;
                cx.physical().duration_s((d * 1000.0).round() / 1000.0);
            }
        }
        cx.format_set(
            "encoding",
            ["real", "first difference", "second difference"]
                .get(usize::from(s6.get(4).copied().unwrap_or(9)))
                .copied()
                .unwrap_or("unknown"),
        );
        cx.format_set("bimodal_compression", s6.get(5) == Some(&1));
    }
}

// --- aECG ----------------------------------------------------------------------------------------------------

#[allow(clippy::too_many_lines)] // one element after another
fn aecg(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let strict = cx.privacy_strict();
    let (mut path, mut leads, mut series, mut annotations) = (Vec::<String>::new(), Vec::new(), 0u64, 0u64);
    let (mut times, mut increment, mut samples, mut subject) =
        (Vec::new(), None::<(String, String)>, None::<usize>, Map::new());
    let (mut device, mut pending_code) = (Map::new(), None::<String>);
    xmlwalk::walk(text, cx, 20_000_000, |_, ev| match ev {
        xmlwalk::Ev::Start(name, a) => {
            let parent = path.last().cloned().unwrap_or_default();
            path.push(name.to_string());
            let in_ = |n: &str| path.iter().any(|p| p == n);
            match name {
                "series" => series += 1,
                "annotation" => annotations += 1,
                "low" | "high" if parent == "effectiveTime" && path.len() <= 4 => {
                    times.extend(xmlwalk::attr(a, "value").map(str::to_string));
                }
                "code" if parent == "sequence" => pending_code = xmlwalk::attr(a, "code").map(str::to_string),
                "increment" if in_("sequence") && increment.is_none() => {
                    increment = xmlwalk::attr(a, "value")
                        .map(|v| (v.to_string(), xmlwalk::attr(a, "unit").unwrap_or("s").to_string()));
                }
                "administrativeGenderCode" if !strict => {
                    _ = subject.insert("sex".into(), json!(xmlwalk::attr(a, "code")));
                }
                "birthTime" if !strict => _ = subject.insert("birth_time".into(), json!(xmlwalk::attr(a, "value"))),
                _ => {}
            }
        }
        xmlwalk::Ev::Text(t) => {
            let last = path.last().map_or("", String::as_str);
            let in_ = |n: &str| path.iter().any(|p| p == n);
            match last {
                "digits" => {
                    if let Some(code) = pending_code.take().filter(|c| c.starts_with("MDC_ECG_LEAD_")) {
                        leads.push(code.trim_start_matches("MDC_ECG_LEAD_").to_string());
                        samples = samples.or(Some(t.split_whitespace().count()));
                    }
                }
                "manufacturerModelName" | "softwareName" | "name"
                    if in_("manufacturedSeriesDevice") || in_("manufacturerOrganization") =>
                {
                    let key = if in_("manufacturerOrganization") { "manufacturer" } else { last };
                    device.entry(key.to_string()).or_insert(json!(t));
                }
                "given" | "family" if in_("subjectDemographicPerson") && !strict => {
                    subject.entry(last.to_string()).or_insert(json!(t));
                }
                _ => {}
            }
        }
        xmlwalk::Ev::End(_) => {
            path.pop();
        }
    })?;
    times.sort();
    if let (Some(a), Some(b)) = (times.first(), times.last()) {
        cx.format_set("time_range", json!([a, b]));
    }
    cx.format_set("series", series);
    cx.format_set("leads", leads.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    if let Some((v, unit)) = increment {
        let secs = v.parse::<f64>().ok().map(|x| match unit.as_str() {
            "ms" => x / 1000.0,
            "us" => x / 1e6,
            _ => x,
        });
        if let Some(s) = secs.filter(|s| *s > 0.0) {
            cx.format_set("sampling_rate_hz", (1.0 / s * 1000.0).round() / 1000.0);
            if let Some(n) = samples {
                #[allow(clippy::cast_precision_loss)]
                let d = n as f64 * s;
                cx.physical().duration_s((d * 1000.0).round() / 1000.0);
            }
        }
    }
    if let Some(n) = samples {
        cx.format_set("samples_per_lead", n);
    }
    cx.format_set("annotations", annotations);
    if !device.is_empty() {
        cx.format_set("device", Value::Object(device));
    }
    if !strict && !subject.is_empty() {
        cx.format_set("subject", Value::Object(subject));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("hdf4", "maple_mw", "mathcad", "scp_ecg", "aecg");

    /// Patient, subject and author details appear only with
    /// `--privacy off` (the fixtures' people are fictitious).
    #[test]
    fn people_follow_privacy() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        for (file, needles) in [
            ("scp_ecg/harbour-clinic.scp", &["Gull", "SALT-0001", "1960-03-12", "Lighthouse"][..]),
            ("aecg/harbour-clinic.aecg.xml", &["Gull", "19600312"][..]),
            ("mathcad/mooring-loads.xmcd", &["Ana Lighthouse"][..]),
        ] {
            let bytes = std::fs::read(dir.join(file)).unwrap();
            let name = file.rsplit('/').next().unwrap();
            let strict = serde_json::to_string(&crate::plugin::testing::report_for(name, &bytes).format).unwrap();
            let off =
                serde_json::to_string(&crate::plugin::testing::report_without_privacy(name, &bytes).format).unwrap();
            for n in needles {
                assert!(!strict.contains(n), "{file}: {n} in a strict report");
                assert!(off.contains(n), "{file}: {n} missing with privacy off");
            }
        }
    }

    #[test]
    fn names() {
        assert_eq!(lead_name(3), "V1");
        assert_eq!(lead_name(64), "aVF");
        assert_eq!(tag_name(1965), "vgroup");
    }
}
