//! Vector drawings and diagrams:
//! * CGM (binary and clear-text encodings): version, description, fonts,
//!   pictures, VDC extent, element counts by class, text strings;
//! * `CorelDRAW` (`.cdr`, `.cdt`; RIFF up to X3, zip from X4): version,
//!   pages, thumbnail, the RIFF chunks or package parts;
//! * draw.io / diagrams.net (`.drawio`): pages, vertices, edges, labels,
//!   the editor that saved it (compressed pages are inflated);
//! * Macromedia `FreeHand` (`.fh*`): version from the `AGD` signature;
//! * Mermaid and `PlantUML` text diagrams: diagram type, title, direction,
//!   nodes / participants, edges, labels;
//! * Visio 2003 XML drawings, stencils and templates (`.vdx`, `.vsx`,
//!   `.vtx`): document properties, pages, masters, shapes, connections,
//!   shape text;
//! * Xfig (`.fig`) and Graphviz DOT (`.dot`, `.gv`): header settings,
//!   object counts and text; graph kind, name, nodes, edges, subgraphs and
//!   labels.
//!
//! References: ISO/IEC 8632-1/3/4 (CGM); `libcdr` and the `CorelDRAW` RIFF
//! notes; draw.io "mxfile" format (`jgraph/drawio`); Mermaid and `PlantUML`
//! language references; Microsoft "Visio XML Schema Reference" 2003; Xfig
//! "FORMAT3.2"; Graphviz "The DOT Language".

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::plugin::xmlwalk::{Ev, attr, walk, xml_root};
use crate::plugin::{
    ByteReader, Compression, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff,
    Source, TextRole, Zip, html_text, latin1_or_utf8, squash_whitespace, truncate_chars, zip_first_stored,
};

/// Extractor for vector drawings and text diagrams.
pub struct Diagram;

const fn vector(
    id: &'static str,
    name: &'static str,
    mimes: &'static [&'static str],
    ext: &'static [&'static str],
    magic: &'static [Magic],
    parent: Option<&'static str>,
) -> FormatSpec {
    FormatSpec { id, name, family: "image.vector", mimes, extensions: ext, magic, parent }
}

static META: ExtractorMeta = ExtractorMeta {
    id: "image.diagram",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        vector("cgm", "Computer Graphics Metafile", &["image/cgm"], &["cgm"], &[], None),
        vector(
            "cdr",
            "CorelDRAW drawing",
            &["application/vnd.corel-draw", "image/x-coreldraw"],
            &["cdr", "cdt", "cdx"],
            &[],
            None,
        ),
        vector("drawio", "draw.io diagram", &["application/vnd.jgraph.mxfile"], &["drawio", "dio"], &[], Some("xml")),
        vector(
            "freehand",
            "Macromedia FreeHand drawing",
            &["image/x-freehand"],
            &["fh", "fh3", "fh4", "fh5", "fh7", "fh8", "fh9", "fh10", "fh11", "fhd"],
            &[Magic::prefix(b"AGD")],
            None,
        ),
        vector("mermaid", "Mermaid diagram", &["text/vnd.mermaid"], &["mmd", "mermaid"], &[], Some("text")),
        vector(
            "plantuml",
            "PlantUML diagram",
            &["text/x-plantuml"],
            &["puml", "plantuml", "pu", "iuml", "wsd"],
            &[],
            Some("text"),
        ),
        vector("vdx", "Visio XML drawing", &["application/vnd.visio.xml"], &["vdx", "vsx", "vtx"], &[], Some("xml")),
        vector("xfig", "Xfig drawing", &["image/x-xfig"], &["fig"], &[Magic::prefix(b"#FIG ")], Some("text")),
        vector("graphviz", "Graphviz DOT graph", &["text/vnd.graphviz"], &["gv", "dot"], &[], Some("text")),
    ],
};

const MAX_LISTED: usize = 200;
/// Text read at most for text formats and XML.
const MAX_TEXT: usize = 32 << 20;
/// Inflated draw.io page size at most.
const MAX_PAGE: usize = 64 << 20;
const MAX_DEPTH: usize = 64;

impl Extractor for Diagram {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let hit = |format| Some(Sniff { format, confidence: 0.95 });
        if cgm_binary_start(h) {
            return hit("cgm");
        }
        if h.starts_with(b"RIFF") && h.get(8..11).is_some_and(|f| f == b"CDR" || f == b"cdr" || f == b"CDT") {
            return hit("cdr");
        }
        if let Some(m) = zip_first_stored(h, "mimetype")
            && m.windows(11).any(|w| w == b"vnd.corel.")
        {
            return Some(Sniff { format: "cdr", confidence: 0.97 });
        }
        let text = String::from_utf8_lossy(&h[..h.len().min(4096)]);
        let first = first_line(&text);
        if first.to_ascii_uppercase().starts_with("BEGMF") {
            return hit("cgm");
        }
        if first.starts_with("@start") {
            return hit("plantuml");
        }
        if dot_header(&text).is_some() {
            return Some(Sniff { format: "graphviz", confidence: 0.9 });
        }
        if let Some((kind, _)) = mermaid_type(&text) {
            if matches!(probe.extension, Some("mmd" | "mermaid")) {
                return hit("mermaid");
            }
            // Without the extension, only keywords prose does not start with.
            let strong = kind.contains(|c: char| c.is_ascii_uppercase() || c == '-')
                || matches!(kind, "flowchart" | "gitGraph")
                || kind == "graph"
                    && first.split_whitespace().nth(1).is_some_and(|d| matches!(d, "TD" | "TB" | "BT" | "RL" | "LR"));
            if strong {
                return Some(Sniff { format: "mermaid", confidence: 0.7 });
            }
        }
        if let Some((root, _)) = xml_root(h) {
            match root.as_str() {
                "mxfile" | "mxGraphModel" => return hit("drawio"),
                "VisioDocument" => return hit("vdx"),
                _ => {}
            }
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "cdr" => return cdr(src, cx),
            "freehand" => return freehand(src.head(), cx),
            _ => {}
        }
        let n = usize::try_from(src.len()).unwrap_or(usize::MAX).min(MAX_TEXT);
        if (n as u64) < src.len() {
            cx.warn("file cut at 32 MiB");
        }
        let data = src.read_vec(0, n)?;
        match cx.format_id() {
            "cgm" if cgm_binary_start(&data) => cgm_binary(&data, cx),
            "cgm" => cgm_text(&latin1_or_utf8(&data), cx),
            "drawio" => drawio(&String::from_utf8_lossy(&data), cx),
            "mermaid" => mermaid(&String::from_utf8_lossy(&data), cx),
            "plantuml" => plantuml(&String::from_utf8_lossy(&data), cx),
            "vdx" => vdx(&String::from_utf8_lossy(&data), cx),
            "xfig" => xfig(&latin1_or_utf8(&data), cx),
            "graphviz" => graphviz(&String::from_utf8_lossy(&data), cx),
            other => Err(ExtractError::Unsupported(format!("format {other}"))),
        }
    }
}

crate::register_extractor!(Diagram);

fn first_line(text: &str) -> &str {
    text.trim_start_matches('\u{feff}').lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("")
}

fn push(list: &mut Vec<String>, s: &str) {
    let s = squash_whitespace(s);
    if list.len() < MAX_LISTED && !s.is_empty() {
        list.push(truncate_chars(&s, 300));
    }
}

fn emit_labels(labels: &[String], cx: &mut Context<'_>) {
    if !labels.is_empty() {
        cx.emit_text(TextRole::Body, &labels.join("\n"));
    }
}

// ---- CGM ---------------------------------------------------------------------------

/// A binary CGM starts with BEGIN METAFILE (class 0, element 1).
fn cgm_binary_start(h: &[u8]) -> bool {
    let Some(w) = h.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]])) else { return false };
    if w >> 5 != 1 {
        return false;
    }
    let len = usize::from(w & 31);
    let (len, at) = if len == 31 {
        (h.get(2..4).map_or(0, |b| usize::from(u16::from_be_bytes([b[0], b[1]]) & 0x7fff)), 4)
    } else {
        (len, 2)
    };
    // The parameter is a string: its length byte must fit the element.
    h.get(at).is_some_and(|&n| n == 255 || usize::from(n) < len.max(1))
        && h.get(at + 1..at + len).is_some_and(|s| s.iter().all(|&c| c >= 0x20 && c != 0x7f))
}

/// A CGM binary string parameter: a length byte (255 = long form), then bytes.
fn cgm_string(p: &[u8]) -> (String, usize) {
    let Some(&n) = p.first() else { return (String::new(), 0) };
    let (n, at) = if n == 255 && p.len() >= 3 {
        (usize::from(u16::from_be_bytes([p[1], p[2]]) & 0x7fff), 3)
    } else {
        (usize::from(n), 1)
    };
    let s = p.get(at..at + n).unwrap_or(&p[at.min(p.len())..]);
    (latin1_or_utf8(s), at + n)
}

#[allow(clippy::too_many_lines)] // one walk over the element stream
fn cgm_binary(d: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(d);
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    let (mut pictures, mut fonts, mut texts) = (Vec::new(), Vec::new(), Vec::new());
    let mut elements = 0u64;
    let mut ended = false;
    while r.remaining() >= 2 {
        let w = r.be_u16()?;
        let (class, id) = (w >> 12, (w >> 5) & 0x7f);
        let len = usize::from(w & 31);
        let mut params = Vec::new();
        if len == 31 {
            // Long form, possibly partitioned (bit 15 = more partitions follow).
            loop {
                let l = r.be_u16()?;
                let part = usize::from(l & 0x7fff);
                params.extend_from_slice(r.bytes(part.min(r.remaining()))?);
                if part % 2 == 1 && r.remaining() > 0 {
                    r.advance(1)?;
                }
                if l & 0x8000 == 0 {
                    break;
                }
            }
        } else {
            params.extend_from_slice(r.bytes(len.min(r.remaining()))?);
            if len % 2 == 1 && r.remaining() > 0 {
                r.advance(1)?;
            }
        }
        elements += 1;
        if elements.is_multiple_of(65_536) {
            cx.checkpoint()?;
        }
        *counts
            .entry(match class {
                0 => "delimiter",
                1 => "metafile descriptor",
                2 => "picture descriptor",
                3 => "control",
                4 => "graphical primitive",
                5 => "attribute",
                6 => "escape",
                7 => "external",
                8 => "segment",
                9 => "application structure",
                _ => "other",
            })
            .or_default() += 1;
        match (class, id) {
            (0, 1) => cx.format_set("name", cgm_string(&params).0),
            (0, 2) => {
                ended = true;
                break;
            }
            (0, 3) => push(&mut pictures, &cgm_string(&params).0),
            (1, 1) if params.len() >= 2 => cx.format_set("version", i16::from_be_bytes([params[0], params[1]])),
            (1, 2) => cx.format_set("description", truncate_chars(&cgm_string(&params).0, 1000)),
            (1, 13) => {
                let mut at = 0;
                while at < params.len() {
                    let (s, n) = cgm_string(&params[at..]);
                    if n == 0 {
                        break;
                    }
                    push(&mut fonts, &s);
                    at += n;
                }
            }
            (2, 6) if params.len() >= 8 && pictures.len() <= 1 => {
                let v: Vec<i16> = params[..8].as_chunks::<2>().0.iter().map(|c| i16::from_be_bytes(*c)).collect();
                cx.format_set("vdc_extent", json!(v));
            }
            // TEXT: point (2 × VDC), final flag (enum, 2 bytes), string.
            (4, 4) if params.len() > 6 => push(&mut texts, &cgm_string(&params[6..]).0),
            // RESTRICTED TEXT: delta width / height, point, flag, string.
            (4, 5) if params.len() > 10 => push(&mut texts, &cgm_string(&params[10..]).0),
            (4, 6) if params.len() > 2 => push(&mut texts, &cgm_string(&params[2..]).0),
            _ => {}
        }
    }
    if !ended {
        cx.warn("no END METAFILE");
    }
    cx.format_set("encoding", "binary");
    cgm_report(elements, &counts, &pictures, &fonts, &texts, cx);
    Ok(())
}

fn cgm_report(
    elements: u64,
    counts: &BTreeMap<&str, u64>,
    pictures: &[String],
    fonts: &[String],
    texts: &[String],
    cx: &mut Context<'_>,
) {
    cx.format_set("elements", elements);
    cx.format_set("element_classes", json!(counts));
    cx.format_set("pictures", json!(pictures));
    cx.physical().pages(pictures.len() as u64);
    if !fonts.is_empty() {
        cx.format_set("fonts", json!(fonts));
    }
    if !texts.is_empty() {
        cx.format_set("texts", texts.len());
        emit_labels(texts, cx);
    }
}

/// Clear-text CGM: statements ending in `;` or `/`, quoted strings in `'` or `"`.
fn cgm_statements(text: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let (mut words, mut cur, mut quote) = (Vec::new(), String::new(), None);
    let mut strings = Vec::new();
    for c in text.chars() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
                strings.push(std::mem::take(&mut cur));
            } else {
                cur.push(c);
            }
            continue;
        }
        match c {
            '\'' | '"' => quote = Some(c),
            ';' | '/' => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
                if let Some(first) = words.first() {
                    out.push((first.to_ascii_uppercase().replace('_', ""), std::mem::take(&mut strings)));
                }
                words.clear();
                strings.clear();
                if out.len() >= 1_000_000 {
                    break;
                }
            }
            c if c.is_whitespace() || c == ',' => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    out
}

fn cgm_text(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let statements = cgm_statements(text);
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    let (mut pictures, mut fonts, mut texts) = (Vec::new(), Vec::new(), Vec::new());
    for (kw, strings) in &statements {
        let first = strings.first().map_or("", String::as_str);
        match kw.as_str() {
            "BEGMF" => cx.format_set("name", first),
            "MFDESC" => cx.format_set("description", truncate_chars(first, 1000)),
            "BEGPIC" => push(&mut pictures, first),
            "FONTLIST" => strings.iter().for_each(|s| push(&mut fonts, s)),
            "TEXT" | "RESTRTEXT" | "APNDTEXT" => push(&mut texts, first),
            _ => {}
        }
        let class = match kw.as_str() {
            "BEGMF" | "ENDMF" | "BEGPIC" | "BEGPICBODY" | "ENDPIC" | "BEGSEG" | "ENDSEG" | "BEGFIG" | "ENDFIG" => {
                "delimiter"
            }
            k if k.starts_with("MF")
                || matches!(
                    k,
                    "VDCTYPE"
                        | "INTEGERPREC"
                        | "REALPREC"
                        | "INDEXPREC"
                        | "COLRPREC"
                        | "FONTLIST"
                        | "CHARSETLIST"
                        | "MAXCOLRINDEX"
                ) =>
            {
                "metafile descriptor"
            }
            "SCALEMODE" | "COLRMODE" | "LINEWIDTHMODE" | "MARKERSIZEMODE" | "EDGEWIDTHMODE" | "VDCEXT" | "BACKCOLR" => {
                "picture descriptor"
            }
            "LINE" | "DISJTLINE" | "MARKER" | "TEXT" | "RESTRTEXT" | "APNDTEXT" | "POLYGON" | "POLYGONSET"
            | "CELLARRAY" | "RECT" | "CIRCLE" | "ARC3PT" | "ARCCTR" | "ELLIPSE" | "ELLIPARC" => "graphical primitive",
            _ => "other",
        };
        *counts.entry(class).or_default() += 1;
    }
    if let Some((_, _)) = statements.iter().find(|(k, _)| k == "MFVERSION") {
        let v = text
            .to_ascii_uppercase()
            .split("MFVERSION")
            .nth(1)
            .and_then(|r| r.split([';', '/']).next().map(|v| v.trim().to_string()));
        if let Some(v) = v.and_then(|v| v.parse::<i64>().ok()) {
            cx.format_set("version", v);
        }
    }
    if statements.first().map(|(k, _)| k.as_str()) != Some("BEGMF") {
        return Err(ExtractError::malformed("no BEGMF"));
    }
    cx.format_set("encoding", "clear text");
    cgm_report(statements.len() as u64, &counts, &pictures, &fonts, &texts, cx);
    Ok(())
}

// ---- CorelDRAW ------------------------------------------------------------------------

fn cdr_version(form: u8) -> Option<u32> {
    match form {
        b'1'..=b'9' => Some(u32::from(form - b'0')),
        b'A'..=b'Z' => Some(u32::from(form - b'A') + 10),
        b'a'..=b'z' => Some(u32::from(form - b'a') + 10),
        _ => None,
    }
}

fn cdr(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.head();
    if h.starts_with(b"PK") {
        return cdr_zip(src, cx);
    }
    if !h.starts_with(b"RIFF") || h.len() < 12 {
        return Err(ExtractError::malformed("no RIFF header"));
    }
    let template = &h[8..11] == b"CDT";
    let mut version = cdr_version(h[11]);
    let n = usize::try_from(src.len().min(64 << 20)).unwrap_or(0);
    let d = src.read_vec(0, n)?;
    let mut chunks: BTreeMap<String, u64> = BTreeMap::new();
    let mut pages = 0u64;
    let mut thumbnail = None;
    let mut at = 12usize;
    let mut stack: Vec<usize> = vec![d.len()];
    let mut walked = 0;
    while at + 8 <= d.len() && walked < 200_000 {
        walked += 1;
        while stack.last().is_some_and(|&end| at >= end) && stack.len() > 1 {
            stack.pop();
        }
        let id = String::from_utf8_lossy(&d[at..at + 4]).into_owned();
        let len = u32::from_le_bytes([d[at + 4], d[at + 5], d[at + 6], d[at + 7]]) as usize;
        if id == "LIST" && at + 12 <= d.len() {
            let kind = String::from_utf8_lossy(&d[at + 8..at + 12]).trim().to_string();
            if kind == "page" {
                pages += 1;
            }
            *chunks.entry(format!("LIST:{kind}")).or_default() += 1;
            if stack.len() < MAX_DEPTH {
                stack.push(at + 8 + len);
            }
            at += 12;
            continue;
        }
        match id.as_str() {
            "vrsn" if len >= 2 => version = Some(u32::from(u16::from_le_bytes([d[at + 8], d[at + 9]])) / 100),
            "DISP" => thumbnail = Some(len),
            _ => {}
        }
        *chunks.entry(id).or_default() += 1;
        at += 8 + len + (len & 1);
    }
    if let Some(v) = version {
        cx.format_set("version", v);
    }
    cx.format_set("template", template);
    cx.format_set("container", "RIFF");
    if pages > 0 {
        cx.physical().pages(pages);
    }
    if let Some(t) = thumbnail {
        cx.format_set("thumbnail_bytes", t);
    }
    cx.format_set("chunks", json!(chunks));
    Ok(())
}

fn cdr_zip(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let zip = Zip::open(src, 10_000)?;
    let mime = zip.read_text(src, "mimetype", cx, 256).and_then(Result::ok).unwrap_or_default();
    cx.format_set("container", "zip");
    if !mime.is_empty() {
        cx.format_set("mimetype", mime.trim());
        cx.format_set("template", mime.contains("template"));
    }
    if let Some(Ok(riff)) = ["content/riffData.cdr", "content/root.dat"]
        .iter()
        .find_map(|n| zip.find(n))
        .map(|e| zip.read_prefix(src, e, cx, 4096))
    {
        let d = riff.0;
        if d.starts_with(b"RIFF") && d.len() >= 12 {
            if let Some(v) = cdr_version(d[11]) {
                cx.format_set("version", v);
            }
            if let Some(i) = d.windows(4).position(|w| w == b"vrsn")
                && let Some(b) = d.get(i + 8..i + 10)
            {
                cx.format_set("version", u16::from_le_bytes([b[0], b[1]]) / 100);
            }
        }
    }
    let pages = zip
        .entries
        .iter()
        .filter(|e| e.name.starts_with("content/data/") || e.name.starts_with("content/pages/"))
        .count();
    if pages > 0 {
        cx.format_set("data_parts", pages);
    }
    if let Some(t) =
        zip.entries.iter().find(|e| e.name.starts_with("previews/") || e.name.starts_with("metadata/thumbnails/"))
    {
        cx.format_set("thumbnail", t.name.clone());
    }
    if let Some(Ok(x)) = zip
        .entries
        .iter()
        .find(|e| e.name.to_ascii_lowercase().ends_with("metadata.xml"))
        .map(|e| zip.read_prefix(src, e, cx, 4 << 20))
        && x.0.windows(9).any(|w| w == b"x:xmpmeta")
    {
        cx.emit_block(crate::plugin::BlockKind::XMP, x.0);
    }
    cx.physical().entries(zip.entries.len() as u64);
    Ok(())
}

fn freehand(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let digit =
        h.get(3).copied().filter(u8::is_ascii_digit).ok_or_else(|| ExtractError::malformed("no AGD version digit"))?;
    // AGD3 = FreeHand 8 and AGD4 = FreeHand 9 (libmagic); the rest follow in order.
    let n = u32::from(digit - b'0');
    cx.format_set("signature", String::from_utf8_lossy(&h[..4]).into_owned());
    cx.format_set(
        "version",
        match n {
            1 => "7".to_string(),
            2 => "7 or 8".to_string(),
            3 => "8".to_string(),
            4 => "9".to_string(),
            5 => "10".to_string(),
            6 => "MX (11)".to_string(),
            _ => format!("AGD{n}"),
        },
    );
    Ok(())
}

// ---- draw.io ---------------------------------------------------------------------------

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(v) = b
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Default)]
struct Cells {
    vertices: u64,
    edges: u64,
    labels: Vec<String>,
}

impl Cells {
    fn scan(&mut self, xml: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        walk(xml, cx, 2_000_000, |_, ev| {
            if let Ev::Start("mxCell" | "UserObject" | "object", a) = ev {
                if attr(a, "vertex") == Some("1") {
                    self.vertices += 1;
                }
                if attr(a, "edge") == Some("1") {
                    self.edges += 1;
                }
                if let Some(v) = attr(a, "value").or_else(|| attr(a, "label")).filter(|v| !v.is_empty()) {
                    push(&mut self.labels, &html_text(v, 2000).0);
                }
            }
        })
    }
}

fn drawio(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut pages = Vec::new();
    let mut compressed = Vec::new();
    let mut in_diagram = false;
    let mut file = Map::new();
    walk(text, cx, 2_000_000, |_, ev| match ev {
        Ev::Start("mxfile", a) => {
            for k in ["host", "agent", "version", "modified", "type"] {
                if let Some(v) = attr(a, k) {
                    file.insert(k.into(), json!(truncate_chars(v, 300)));
                }
            }
        }
        Ev::Start("diagram", a) => {
            in_diagram = true;
            push(&mut pages, attr(a, "name").unwrap_or(""));
        }
        Ev::End("diagram") => in_diagram = false,
        Ev::Text(t) if in_diagram && !t.is_empty() && compressed.len() < MAX_LISTED => compressed.push(t.to_string()),
        _ => {}
    })?;
    let mut cells = Cells::default();
    cells.scan(text, cx)?;
    for c in compressed {
        let Some(raw) = super::super::audio::vorbis::base64(c.trim()) else {
            cx.warn("a page is neither XML nor base64");
            continue;
        };
        match cx.inflate(&raw, Compression::Deflate, MAX_PAGE) {
            Ok(xml) => cells.scan(&percent_decode(&String::from_utf8_lossy(&xml)), cx)?,
            Err(e) => cx.warn(format!("compressed page: {e}")),
        }
    }
    if let Some(m) = file.remove("modified").and_then(|v| v.as_str().map(str::to_string)) {
        cx.temporal().source("drawio.modified").content_date(crate::plugin::DateField::Modified, &m, m.ends_with('Z'));
    }
    if !file.is_empty() {
        cx.format_set("editor", Value::Object(file));
    }
    cx.physical().pages(pages.len().max(1) as u64);
    cx.format_set("pages", json!(pages));
    cx.format_set("vertices", cells.vertices);
    cx.format_set("edges", cells.edges);
    if !cells.labels.is_empty() {
        cx.format_set("labels", json!(cells.labels));
        emit_labels(&cells.labels, cx);
    }
    Ok(())
}

// ---- Mermaid -----------------------------------------------------------------------------

const MERMAID_TYPES: &[&str] = &[
    "flowchart",
    "graph",
    "sequenceDiagram",
    "classDiagram",
    "stateDiagram-v2",
    "stateDiagram",
    "erDiagram",
    "journey",
    "gantt",
    "pie",
    "quadrantChart",
    "requirementDiagram",
    "gitGraph",
    "C4Context",
    "C4Container",
    "C4Component",
    "C4Dynamic",
    "C4Deployment",
    "mindmap",
    "timeline",
    "zenuml",
    "sankey-beta",
    "xychart-beta",
    "block-beta",
    "packet-beta",
    "architecture-beta",
    "kanban",
    "radar-beta",
];

/// The diagram type and the front-matter title.
fn mermaid_type(text: &str) -> Option<(&'static str, Option<String>)> {
    let mut lines = text.trim_start_matches('\u{feff}').lines().map(str::trim).peekable();
    let mut title = None;
    if lines.peek() == Some(&"---") {
        lines.next();
        for l in lines.by_ref() {
            if l == "---" {
                break;
            }
            if let Some(t) = l.strip_prefix("title:") {
                title = Some(t.trim().trim_matches('"').to_string());
            }
        }
    }
    let first = lines.find(|l| !l.is_empty() && !l.starts_with("%%"))?;
    let word = first.split_whitespace().next()?;
    MERMAID_TYPES.iter().find(|t| **t == word).map(|t| (*t, title))
}

const MERMAID_ARROWS: &[&str] = &[
    "-->", "---", "-.->", "-.-", "==>", "===", "->>", "-->>", "-)", "--)", "-x", "--x", "--o", "<-->", "<|--", "*--",
    "o--", "..>", "..|>", "||--", "}|--", "|o--", "}o--",
];

fn mermaid(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let (kind, title) = mermaid_type(text).ok_or_else(|| ExtractError::malformed("no diagram type"))?;
    cx.format_set("diagram_type", kind);
    let mut title = title;
    let mut edges = 0u64;
    let mut nodes = BTreeSet::new();
    let mut labels = Vec::new();
    let mut seen_type = false;
    for l in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with("%%")) {
        if !seen_type {
            if l.split_whitespace().next() == Some(kind) {
                seen_type = true;
                if let Some(d) = l.split_whitespace().nth(1)
                    && matches!(kind, "flowchart" | "graph")
                {
                    cx.format_set("direction", d);
                }
                if kind == "pie" && l.contains(" title ") {
                    title = l.split_once(" title ").map(|(_, t)| t.trim().to_string());
                }
            }
            continue;
        }
        if let Some(t) = l.strip_prefix("title ").or_else(|| l.strip_prefix("title:")) {
            title.get_or_insert_with(|| t.trim().to_string());
            continue;
        }
        if let Some(rest) = l.strip_prefix("participant ").or_else(|| l.strip_prefix("actor ")) {
            nodes.insert(rest.split(" as ").next().unwrap_or(rest).trim().to_string());
            continue;
        }
        let arrows = MERMAID_ARROWS.iter().filter(|a| l.contains(**a)).map(|a| a.len()).max();
        if arrows.is_some() {
            // Each arrow joins two endpoints: count arrow tokens in the line.
            let mut n = 0;
            let mut rest = l;
            while let Some((i, a)) = MERMAID_ARROWS
                .iter()
                .filter_map(|a| rest.find(a).map(|i| (i, a.len())))
                .min_by_key(|(i, len)| (*i, usize::MAX - len))
            {
                n += 1;
                rest = &rest[i + a..];
                rest = rest.trim_start_matches(['-', '.', '=', '>', 'x', 'o', '|']);
            }
            edges += n;
            // Edge labels (`-->|yes|`) are not nodes.
            let mut plain = String::new();
            let mut in_label = false;
            for c in l.chars() {
                if c == '|' {
                    in_label = !in_label;
                } else if !in_label {
                    plain.push(c);
                }
            }
            for part in plain.split(|c: char| "-.=<>|".contains(c)).map(str::trim).filter(|p| !p.is_empty()) {
                let id: String = part.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                if !id.is_empty() && nodes.len() < 100_000 && !part.starts_with(':') {
                    nodes.insert(id);
                }
            }
        }
        for (open, close) in [('[', ']'), ('(', ')'), ('{', '}'), ('"', '"')] {
            let mut rest = l;
            while let Some(i) = rest.find(open) {
                let after = &rest[i + 1..];
                let Some(j) = after.find(close) else { break };
                let lab = after[..j].trim_matches(|c| "[](){}\"/\\".contains(c));
                if !lab.is_empty() {
                    push(&mut labels, lab);
                }
                rest = &after[j + 1..];
            }
        }
        if let Some((_, msg)) = l.split_once(": ") {
            push(&mut labels, msg);
        }
    }
    if let Some(t) = title.filter(|t| !t.is_empty()) {
        cx.content().source("mermaid.title").title(truncate_chars(&t, 300));
    }
    cx.format_set("nodes", nodes.len());
    cx.format_set("edges", edges);
    if !labels.is_empty() {
        cx.format_set("labels", json!(labels));
        emit_labels(&labels, cx);
    }
    Ok(())
}

// ---- PlantUML ----------------------------------------------------------------------------

fn plantuml(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut diagrams = Vec::new();
    let mut title = None;
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    let mut arrows = 0u64;
    let mut labels = Vec::new();
    let mut kind = "uml";
    for l in text.lines().map(str::trim) {
        if let Some(rest) = l.strip_prefix("@start") {
            let (k, name) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            diagrams.push(json!({ "kind": k, "name": name.trim() }));
            kind = match k {
                "uml" => "uml",
                "mindmap" => "mindmap",
                "gantt" => "gantt",
                "wbs" => "wbs",
                "salt" => "salt",
                "json" => "json",
                "yaml" => "yaml",
                _ => "other",
            };
            continue;
        }
        if l.starts_with('\'') || l.starts_with("@end") || l.is_empty() {
            continue;
        }
        if let Some(t) = l.strip_prefix("title ") {
            title.get_or_insert_with(|| t.trim().to_string());
            continue;
        }
        let word = l.split_whitespace().next().unwrap_or("");
        let element = match word {
            "participant" | "actor" | "boundary" | "control" | "entity" | "database" | "collections" | "queue" => {
                Some("participant")
            }
            "class" | "interface" | "abstract" | "enum" | "annotation" => Some("class"),
            "usecase" => Some("use case"),
            "state" => Some("state"),
            "component" | "[" => Some("component"),
            "node" | "cloud" | "frame" | "folder" | "rectangle" | "package" => Some("container"),
            "object" => Some("object"),
            _ if l.starts_with(':') && l.ends_with(';') => Some("activity"),
            _ => None,
        };
        if let Some(e) = element {
            *counts.entry(e).or_default() += 1;
            if let Some(q) = l.split('"').nth(1) {
                push(&mut labels, q);
            } else if e == "activity" {
                push(&mut labels, l.trim_start_matches(':').trim_end_matches(';'));
            }
        }
        if ["->", "-->", "<-", "<--", "..>", "--|>", "<|--", "*--", "o--", "-[", "->>"].iter().any(|a| l.contains(a))
            && !l.starts_with(':')
        {
            arrows += 1;
            if let Some((_, msg)) = l.split_once(" : ") {
                push(&mut labels, msg);
            }
        }
    }
    if diagrams.is_empty() {
        return Err(ExtractError::malformed("no @start line"));
    }
    let detected = if kind != "uml" {
        kind
    } else if counts.contains_key("participant") && !counts.contains_key("class") {
        "sequence"
    } else if counts.contains_key("class") {
        "class"
    } else if counts.contains_key("activity") {
        "activity"
    } else if counts.contains_key("use case") {
        "use case"
    } else if counts.contains_key("state") {
        "state"
    } else if counts.contains_key("component") || counts.contains_key("container") {
        "component / deployment"
    } else {
        "uml"
    };
    cx.format_set("diagram_type", detected);
    cx.format_set("diagrams", Value::Array(diagrams));
    if let Some(t) = title.filter(|t| !t.is_empty()) {
        cx.content().source("plantuml.title").title(truncate_chars(&t, 300));
    }
    cx.format_set("elements", json!(counts));
    cx.format_set("arrows", arrows);
    if !labels.is_empty() {
        cx.format_set("labels", json!(labels));
        emit_labels(&labels, cx);
    }
    Ok(())
}

// ---- Visio XML ------------------------------------------------------------------------------

fn vdx(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut path: Vec<String> = Vec::new();
    let mut props = Map::new();
    let (mut pages, mut masters, mut texts) = (Vec::new(), Vec::new(), Vec::new());
    let (mut shapes, mut connects) = (0u64, 0u64);
    walk(text, cx, 4_000_000, |_, ev| match ev {
        Ev::Start(name, a) => {
            match name {
                "Page" => push(&mut pages, attr(a, "NameU").or_else(|| attr(a, "Name")).unwrap_or("")),
                "Master" if path.last().map(String::as_str) == Some("Masters") => {
                    push(&mut masters, attr(a, "NameU").or_else(|| attr(a, "Name")).unwrap_or(""));
                }
                "Shape" if path.iter().any(|p| p == "Page") => shapes += 1,
                "Connect" => connects += 1,
                _ => {}
            }
            path.push(name.to_string());
        }
        Ev::End(_) => {
            path.pop();
        }
        Ev::Text(t) => {
            let in_props = path.len() >= 2 && path[path.len() - 2] == "DocumentProperties";
            if in_props && props.len() < 64 {
                props.insert(path[path.len() - 1].clone(), json!(truncate_chars(t, 1000)));
            } else if path.last().map(String::as_str) == Some("Text") && path.iter().any(|p| p == "Page") {
                push(&mut texts, t);
            }
        }
    })?;
    let get = |k: &str| props.get(k).and_then(Value::as_str).map(str::to_string);
    if let Some(t) = get("Title") {
        cx.content().source("vdx.Title").title(t);
    }
    if let Some(t) = get("Subject") {
        cx.content().source("vdx.Subject").description(t);
    }
    if let Some(t) = get("Creator") {
        cx.content().source("vdx.Creator").author(t);
    }
    if let Some(k) = get("Keywords") {
        for w in k.split([',', ';']).map(str::trim).filter(|w| !w.is_empty()) {
            cx.content().source("vdx.Keywords").keyword(w);
        }
    }
    if let Some(t) = get("TimeCreated") {
        cx.temporal().source("vdx.TimeCreated").content_date(crate::plugin::DateField::Created, &t, false);
    }
    if let Some(t) = get("TimeSaved") {
        cx.temporal().source("vdx.TimeSaved").content_date(crate::plugin::DateField::Modified, &t, false);
    }
    if !props.is_empty() {
        cx.format_set("document_properties", Value::Object(props));
    }
    cx.physical().pages(pages.len() as u64);
    cx.format_set("pages", json!(pages));
    cx.format_set("masters", json!(masters));
    cx.format_set("shapes", shapes);
    cx.format_set("connections", connects);
    if !texts.is_empty() {
        emit_labels(&texts, cx);
        cx.format_set("shape_texts", texts.len());
    }
    Ok(())
}

// ---- Xfig -------------------------------------------------------------------------------------

/// Xfig text: `\ooo` octal escapes and `\\`; the string ends at `\001`.
fn fig_string(s: &str) -> String {
    let s = s.split("\\001").next().unwrap_or(s);
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let oct: String = std::iter::from_fn(|| chars.next_if(|d| ('0'..='7').contains(d))).take(3).collect();
        if oct.is_empty() {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else if let Some(ch) = u32::from_str_radix(&oct, 8).ok().and_then(char::from_u32) {
            out.push(ch);
        }
    }
    out
}

fn xfig(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut lines = text.lines();
    let header = lines.next().unwrap_or("");
    let version = header.strip_prefix("#FIG ").ok_or_else(|| ExtractError::malformed("no #FIG header"))?;
    cx.format_set("version", version.split_whitespace().next().unwrap_or(""));
    let mut settings = Vec::new();
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    let mut texts = Vec::new();
    let mut comments = Vec::new();
    let wanted = if version.starts_with("3.2") {
        8
    } else if version.starts_with("3.1") {
        4
    } else {
        1
    };
    for l in lines.by_ref() {
        if let Some(c) = l.strip_prefix('#') {
            push(&mut comments, c.trim());
            continue;
        }
        settings.push(l.trim().to_string());
        if settings.len() >= wanted {
            break;
        }
    }
    if wanted == 8 {
        for (i, k) in [
            "orientation",
            "justification",
            "units",
            "paper_size",
            "magnification",
            "multiple_page",
            "transparent_color",
        ]
        .iter()
        .enumerate()
        {
            if let Some(v) = settings.get(i) {
                cx.format_set(k, v.as_str());
            }
        }
    } else if wanted == 4 {
        for (i, k) in ["orientation", "justification", "units"].iter().enumerate() {
            if let Some(v) = settings.get(i) {
                cx.format_set(k, v.as_str());
            }
        }
    }
    if let Some(res) = settings.last().and_then(|r| r.split_whitespace().next()).and_then(|r| r.parse::<u64>().ok()) {
        cx.format_set("resolution", res);
    }
    for l in lines {
        if l.starts_with(['\t', ' ']) || l.is_empty() {
            continue;
        }
        if let Some(c) = l.strip_prefix('#') {
            push(&mut comments, c.trim());
            continue;
        }
        let code = l.split_whitespace().next().unwrap_or("");
        let kind = match code {
            "0" => "colour",
            "1" => "ellipse",
            "2" => "polyline",
            "3" => "spline",
            "4" => "text",
            "5" => "arc",
            "6" => "compound",
            _ => continue,
        };
        *counts.entry(kind).or_default() += 1;
        if kind == "text" {
            // 13 numeric fields, then the string.
            let mut rest = l;
            for _ in 0..13 {
                rest = rest.trim_start();
                rest = rest.find(char::is_whitespace).map_or("", |i| &rest[i..]);
            }
            push(&mut texts, &fig_string(rest.strip_prefix(' ').unwrap_or(rest)));
        }
    }
    cx.format_set("objects", json!(counts));
    if !comments.is_empty() {
        cx.format_set("comments", json!(comments));
    }
    if !texts.is_empty() {
        cx.format_set("texts", json!(texts));
        emit_labels(&texts, cx);
    }
    Ok(())
}

// ---- Graphviz DOT -------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Id(String),
    Quoted(String),
    Sym(char),
    EdgeOp,
}

fn dot_tokens(text: &str) -> Vec<Tok> {
    let b: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line_start = true;
    let mut plus = false;
    while i < b.len() && out.len() < 4_000_000 {
        let c = b[i];
        if c == '\n' {
            line_start = true;
            i += 1;
            continue;
        }
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '#' && line_start {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
            continue;
        }
        line_start = false;
        if c == '/' && b.get(i + 1) == Some(&'/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && b.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == '*' && b[i + 1] == '/') {
                i += 1;
            }
            i += 2;
        } else if c == '"' {
            let mut s = String::new();
            i += 1;
            while i < b.len() && b[i] != '"' {
                if b[i] == '\\' && b.get(i + 1) == Some(&'"') {
                    s.push('"');
                    i += 2;
                    continue;
                }
                if b[i] == '\\' && b.get(i + 1) == Some(&'\n') {
                    i += 2;
                    continue;
                }
                s.push(b[i]);
                i += 1;
            }
            i += 1;
            // `"a" + "b"` concatenation.
            match (plus, out.last_mut()) {
                (true, Some(Tok::Quoted(prev))) => prev.push_str(&s),
                _ => out.push(Tok::Quoted(s)),
            }
            plus = false;
        } else if c == '<' {
            let mut depth = 0;
            let mut s = String::new();
            while i < b.len() {
                if b[i] == '<' {
                    depth += 1;
                } else if b[i] == '>' {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                s.push(b[i]);
                i += 1;
            }
            out.push(Tok::Quoted(html_text(s.trim_start_matches('<'), 2000).0));
        } else if c == '-' && matches!(b.get(i + 1), Some('-' | '>')) {
            out.push(Tok::EdgeOp);
            i += 2;
        } else if "{}[];=,:".contains(c) {
            out.push(Tok::Sym(c));
            i += 1;
        } else if c == '+' {
            plus = true;
            i += 1;
        } else {
            let mut s = String::new();
            while i < b.len()
                && (b[i].is_alphanumeric()
                    || b[i] == '_'
                    || b[i] == '.'
                    || (b[i] == '-' && !matches!(b.get(i + 1), Some('-' | '>'))))
            {
                s.push(b[i]);
                i += 1;
            }
            if s.is_empty() {
                i += 1;
            } else {
                out.push(Tok::Id(s));
            }
        }
    }
    out
}

/// `[strict] graph|digraph [name] {` at the start of a DOT file.
fn dot_header(text: &str) -> Option<(bool, bool, Option<String>)> {
    let head: String = text.chars().take(4096).collect();
    let toks = dot_tokens(&head);
    let mut it = toks.iter();
    let mut t = it.next()?;
    let strict = matches!(t, Tok::Id(s) if s.eq_ignore_ascii_case("strict"));
    if strict {
        t = it.next()?;
    }
    let directed = match t {
        Tok::Id(s) if s.eq_ignore_ascii_case("digraph") => true,
        Tok::Id(s) if s.eq_ignore_ascii_case("graph") => false,
        _ => return None,
    };
    match it.next()? {
        Tok::Sym('{') => Some((strict, directed, None)),
        Tok::Id(n) | Tok::Quoted(n) => matches!(it.next()?, Tok::Sym('{')).then(|| (strict, directed, Some(n.clone()))),
        _ => None,
    }
}

struct DotParser<'t> {
    t: &'t [Tok],
    at: usize,
    nodes: BTreeSet<String>,
    edges: u64,
    /// For `strict` graphs: the distinct edges (endpoints sorted unless directed).
    strict: Option<(bool, BTreeSet<(String, String)>)>,
    subgraphs: Vec<String>,
    labels: Vec<String>,
    graph_label: Option<String>,
}

impl DotParser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.at)
    }
    fn next(&mut self) -> Option<&Tok> {
        self.at += 1;
        self.t.get(self.at - 1)
    }
    fn id(&mut self) -> Option<String> {
        match self.peek()? {
            Tok::Id(s) | Tok::Quoted(s) => {
                let s = s.clone();
                self.at += 1;
                Some(s)
            }
            _ => None,
        }
    }
    fn is_kw(&self, kw: &str) -> bool {
        matches!(self.peek(), Some(Tok::Id(s)) if s.eq_ignore_ascii_case(kw))
    }

    /// `[a=b, c=d][…]`; returns the `label`.
    fn attrs(&mut self) -> Option<String> {
        let mut label = None;
        while self.peek() == Some(&Tok::Sym('[')) {
            self.at += 1;
            while let Some(t) = self.peek() {
                if *t == Tok::Sym(']') {
                    self.at += 1;
                    break;
                }
                if matches!(t, Tok::Sym(',' | ';')) {
                    self.at += 1;
                    continue;
                }
                let Some(k) = self.id() else {
                    self.at += 1;
                    continue;
                };
                if self.peek() == Some(&Tok::Sym('=')) {
                    self.at += 1;
                    let v = self.id();
                    if k == "label" {
                        label = v;
                    }
                }
            }
        }
        label
    }

    /// A statement list up to `}`; returns the nodes it mentions.
    fn stmts(&mut self, depth: usize) -> BTreeSet<String> {
        let mut here = BTreeSet::new();
        while let Some(t) = self.peek() {
            match t {
                Tok::Sym('}') => {
                    self.at += 1;
                    break;
                }
                Tok::Sym(';' | ',') => self.at += 1,
                _ => {
                    let before = self.at;
                    let s = self.stmt(depth);
                    here.extend(s);
                    if self.at == before {
                        self.at += 1;
                    }
                }
            }
        }
        here
    }

    /// A node id or a subgraph (edge operand); returns its nodes.
    fn operand(&mut self, depth: usize) -> Option<BTreeSet<String>> {
        if self.is_kw("subgraph") || self.peek() == Some(&Tok::Sym('{')) {
            let mut name = None;
            if self.is_kw("subgraph") {
                self.at += 1;
                if self.peek() != Some(&Tok::Sym('{')) {
                    name = self.id();
                }
            }
            if self.next() != Some(&Tok::Sym('{')) || depth > MAX_DEPTH {
                return Some(BTreeSet::new());
            }
            if let Some(n) = name.filter(|_| self.subgraphs.len() < MAX_LISTED) {
                self.subgraphs.push(n);
            }
            return Some(self.stmts(depth + 1));
        }
        let id = self.id()?;
        // Port: `:port[:compass]`.
        while self.peek() == Some(&Tok::Sym(':')) {
            self.at += 1;
            self.id();
        }
        if self.nodes.len() < 1_000_000 {
            self.nodes.insert(id.clone());
        }
        Some(BTreeSet::from([id]))
    }

    fn stmt(&mut self, depth: usize) -> BTreeSet<String> {
        if self.is_kw("graph") || self.is_kw("node") || self.is_kw("edge") {
            let graph = self.is_kw("graph");
            self.at += 1;
            if let Some(l) = self.attrs()
                && graph
                && depth == 0
            {
                self.graph_label.get_or_insert(l);
            }
            return BTreeSet::new();
        }
        // `ID = ID` graph attribute.
        if matches!(self.peek(), Some(Tok::Id(_) | Tok::Quoted(_))) && self.t.get(self.at + 1) == Some(&Tok::Sym('=')) {
            let k = self.id().unwrap_or_default();
            self.at += 1;
            let v = self.id();
            if k == "label"
                && depth == 0
                && let Some(v) = v
            {
                self.graph_label.get_or_insert(v);
            }
            return BTreeSet::new();
        }
        let Some(mut left) = self.operand(depth) else { return BTreeSet::new() };
        let mut all = left.clone();
        let mut was_edge = false;
        while self.peek() == Some(&Tok::EdgeOp) {
            self.at += 1;
            let Some(right) = self.operand(depth) else { break };
            if let Some((directed, set)) = self.strict.as_mut() {
                for a in &left {
                    for b in &right {
                        let pair = if *directed || a <= b { (a.clone(), b.clone()) } else { (b.clone(), a.clone()) };
                        if set.len() < 1_000_000 {
                            set.insert(pair);
                        }
                    }
                }
            } else {
                self.edges += (left.len() as u64).saturating_mul(right.len() as u64);
            }
            all.extend(right.iter().cloned());
            left = right;
            was_edge = true;
        }
        if let Some(l) = self.attrs()
            && !was_edge
        {
            push(&mut self.labels, &l.replace("\\n", " ").replace("\\l", " ").replace("\\r", " "));
        }
        all
    }
}

fn graphviz(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let (strict, directed, name) =
        dot_header(text).ok_or_else(|| ExtractError::malformed("no graph / digraph header"))?;
    let toks = dot_tokens(text);
    let start = toks.iter().position(|t| *t == Tok::Sym('{')).unwrap_or(0) + 1;
    let mut p = DotParser {
        t: &toks,
        at: start,
        nodes: BTreeSet::new(),
        edges: 0,
        strict: strict.then(|| (directed, BTreeSet::new())),
        subgraphs: Vec::new(),
        labels: Vec::new(),
        graph_label: None,
    };
    p.stmts(0);
    if let Some((_, set)) = &p.strict {
        p.edges = set.len() as u64;
    }
    cx.format_set("kind", if directed { "digraph" } else { "graph" });
    cx.format_set("strict", strict);
    if let Some(n) = name {
        cx.format_set("name", n);
    }
    if let Some(l) = p.graph_label.take() {
        cx.content().source("dot.label").title(truncate_chars(&l.replace("\\n", " "), 300));
    }
    cx.format_set("nodes", p.nodes.len());
    cx.format_set("edges", p.edges);
    if !p.subgraphs.is_empty() {
        cx.format_set("subgraphs", json!(p.subgraphs));
    }
    if !p.labels.is_empty() {
        cx.format_set("labels", json!(p.labels));
        emit_labels(&p.labels, cx);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_counts() {
        let toks = dot_tokens("digraph G { a -> {b c}; c -> d -> e [label=x]; f; subgraph cluster_0 { g -- h } }");
        let start = toks.iter().position(|t| *t == Tok::Sym('{')).unwrap() + 1;
        let mut p = DotParser {
            t: &toks,
            at: start,
            nodes: BTreeSet::new(),
            edges: 0,
            strict: None,
            subgraphs: Vec::new(),
            labels: Vec::new(),
            graph_label: None,
        };
        p.stmts(0);
        assert_eq!(p.nodes.len(), 8);
        assert_eq!(p.edges, 5);
        assert_eq!(p.subgraphs, ["cluster_0"]);
        assert_eq!(dot_header("strict digraph \"x y\" {"), Some((true, true, Some("x y".into()))));
        assert_eq!(dot_header("graph {"), Some((false, false, None)));
        assert_eq!(dot_header("hello"), None);
    }

    #[test]
    fn fig_text() {
        assert_eq!(fig_string("Harbour\\001"), "Harbour");
        assert_eq!(fig_string("caf\\351 \\\\ x\\001"), "café \\ x");
    }

    #[test]
    fn mermaid_detects() {
        assert_eq!(mermaid_type("---\ntitle: Tides\n---\nflowchart LR\n").map(|t| t.0), Some("flowchart"));
        assert_eq!(mermaid_type("%% c\nsequenceDiagram\n").map(|t| t.0), Some("sequenceDiagram"));
        assert!(mermaid_type("hello\n").is_none());
        assert_eq!(percent_decode("a%20b%3C"), "a b<");
    }

    crate::fixture_tests!("cgm", "cdr", "drawio", "freehand", "mermaid", "plantuml", "vdx", "xfig", "graphviz");
}
