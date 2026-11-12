//! Long-tail document formats: PostScript and EPS (DSC comments, previews,
//! XMP) and BibTeX / BibLaTeX (entries, types, years, identifiers). LaTeX
//! sources are read by `code.source`.
//!
//! References: Adobe DSC 3.0 (TN 5001), EPSF 3.0 (TN 5002), the BibTeX
//! format as read by `biber`.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::plugin::{
    BlockKind, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Map, Probe, Sniff,
    Source, TextRole, parse_date, truncate_chars,
};

/// Extractor for PostScript, EPS and BibTeX.
pub struct Other;

static META: ExtractorMeta = ExtractorMeta {
    id: "doc.other",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "ps",
            name: "PostScript",
            family: "doc.other",
            mimes: &["application/postscript"],
            extensions: &["ps"],
            magic: &[Magic::prefix(b"%!PS"), Magic::prefix(b"\x04%!PS")],
            parent: None,
        },
        FormatSpec {
            id: "eps",
            name: "Encapsulated PostScript",
            family: "doc.other",
            mimes: &["application/postscript", "image/x-eps"],
            extensions: &["eps", "epsf", "epsi"],
            // Text EPS starts like PostScript and is told apart by `sniff`, which
            // also recognises the binary DOS EPS header (C5 D0 D3 C6).
            magic: &[],
            parent: Some("ps"),
        },
        FormatSpec {
            id: "ai",
            name: "Adobe Illustrator drawing (PostScript)",
            family: "image.vector",
            mimes: &["application/illustrator"],
            extensions: &["ai"],
            // PostScript with Illustrator's DSC comments, told apart by `sniff`;
            // PDF-based files (Illustrator 9 and later) are read as PDF.
            magic: &[],
            parent: Some("ps"),
        },
        FormatSpec {
            id: "bib",
            name: "BibTeX bibliography",
            family: "doc.other",
            mimes: &["application/x-bibtex", "text/x-bibtex"],
            extensions: &["bib"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

const MAX_LISTED: usize = 200;

impl Extractor for Other {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let head = &probe.head[..probe.head.len().min(4096)];
        if head.starts_with(b"\xC5\xD0\xD3\xC6") {
            return Some(Sniff { format: "eps", confidence: 0.97 });
        }
        if head.starts_with(b"%!PS") {
            if probe.extension == Some("ai")
                || head.windows(18).any(|w| w == b"Adobe Illustrator(")
                || head.windows(4).any(|w| w == b"%AI5" || w == b"%AI3")
            {
                return Some(Sniff { format: "ai", confidence: 0.96 });
            }
            let first = head.split(|&b| b == b'\n' || b == b'\r').next().unwrap_or_default();
            let eps =
                first.windows(4).any(|w| w == b"EPSF") || matches!(probe.extension, Some("eps" | "epsf" | "epsi"));
            return eps.then_some(Sniff { format: "eps", confidence: 0.95 });
        }
        let text = String::from_utf8_lossy(head);
        if probe.extension == Some("bib") || bib_like(&text) {
            return Some(Sniff { format: "bib", confidence: if probe.extension == Some("bib") { 0.9 } else { 0.6 } });
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "ps" | "eps" => postscript(src, cx),
            "ai" => {
                let head = String::from_utf8_lossy(&src.head()[..src.head().len().min(16_384)]).into_owned();
                postscript(src, cx)?;
                illustrator(&head, cx);
                Ok(())
            }
            "bib" => {
                let text = cx.read_text(src)?.text;
                bibtex(&text, cx)
            }
            other => Err(ExtractError::Unsupported(format!("format {other}"))),
        }
    }
}

crate::register_extractor!(Other);

/// Illustrator's own header comments: the creator version and file format.
fn illustrator(head: &str, cx: &mut Context<'_>) {
    for line in head.lines().take(400) {
        let line = line.trim_end();
        let Some(rest) = line.strip_prefix("%%AI").or_else(|| line.strip_prefix("%AI")) else { continue };
        let Some((key, value)) = rest.split_once(':').or_else(|| rest.split_once(' ')) else { continue };
        let key = key.trim_start_matches(|c: char| c.is_ascii_digit()).trim_start_matches('_');
        let value = value.trim();
        match key {
            "CreatorVersion" => cx.format_set("illustrator_version", value),
            "FileFormat" => cx.format_set("illustrator_file_format", value),
            "ColorUsage" => cx.format_set("color_usage", value),
            "ArtSize" => cx.format_set("art_size", value),
            _ => {}
        }
    }
}

fn bib_like(text: &str) -> bool {
    let entries = ["@article{", "@book{", "@inproceedings{", "@misc{", "@incollection{", "@phdthesis{", "@techreport{"];
    let lower = text.to_ascii_lowercase();
    entries.iter().filter(|e| lower.contains(*e)).count() >= 1 && lower.matches('@').count() >= 2
}

// ---- PostScript / EPS -------------------------------------------------------

#[allow(clippy::too_many_lines)] // one pass over the DSC comments, then the fields
fn postscript(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let (bytes, _) = cx.read_bytes(src)?;
    let mut ps: &[u8] = &bytes;
    let mut format = Map::new();
    // DOS EPS binary header: PostScript section plus a WMF or TIFF preview.
    if bytes.starts_with(b"\xC5\xD0\xD3\xC6") && bytes.len() >= 30 {
        let u = |i: usize| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
        let (ps_off, ps_len, wmf_len, tiff_len) = (u(4), u(8), u(16), u(24));
        ps = bytes.get(ps_off..ps_off.saturating_add(ps_len).min(bytes.len())).unwrap_or_default();
        let preview = if tiff_len > 0 {
            Some(("tiff", tiff_len))
        } else if wmf_len > 0 {
            Some(("wmf", wmf_len))
        } else {
            None
        };
        if let Some((kind, size)) = preview {
            format.insert("preview".into(), json!({ "type": kind, "size_bytes": size }));
        }
        format.insert("dos_eps_header".into(), json!(true));
    }
    let text = String::from_utf8_lossy(ps);
    let mut dsc: BTreeMap<String, String> = BTreeMap::new();
    let mut pages = 0u64;
    let mut in_header = true;
    let mut in_trailer = false;
    let mut fonts: Vec<String> = Vec::new();
    let mut first = true;
    for line in text.lines() {
        if first {
            first = false;
            let l = line.trim_start_matches('\u{4}');
            if let Some(v) = l.strip_prefix("%!PS-Adobe-") {
                let mut parts = v.split_whitespace();
                if let Some(ver) = parts.next() {
                    format.insert("dsc_version".into(), json!(ver));
                }
                if let Some(eps) = parts.find(|p| p.starts_with("EPSF-")) {
                    format.insert("epsf_version".into(), json!(eps.trim_start_matches("EPSF-")));
                }
            }
            continue;
        }
        let Some(rest) = line.strip_prefix("%%") else {
            if in_header && !line.starts_with('%') && !line.trim().is_empty() {
                in_header = false;
            }
            continue;
        };
        if rest.starts_with("Page:") {
            pages += 1;
            in_header = false;
            continue;
        }
        if rest.starts_with("EndComments") {
            in_header = false;
            continue;
        }
        if rest.starts_with("Trailer") {
            in_trailer = true;
            continue;
        }
        if rest.starts_with("BeginPreview") {
            format.entry("preview").or_insert_with(|| json!({ "type": "epsi" }));
            continue;
        }
        let Some((key, value)) = rest.split_once(':') else { continue };
        let value = value.trim();
        if key == "DocumentFonts"
            || key == "DocumentNeededFonts"
            || (key == "+" && fonts.len() < MAX_LISTED && !fonts.is_empty())
        {
            fonts.extend(value.split_whitespace().filter(|f| *f != "(atend)").map(str::to_string).take(MAX_LISTED));
        } else if key == "DocumentNeededResources" || key == "DocumentSuppliedResources" {
            let mut parts = value.split_whitespace();
            if parts.next() == Some("font") {
                fonts.extend(parts.map(str::to_string).take(MAX_LISTED));
            }
        }
        if !(in_header || in_trailer) {
            continue;
        }
        if value == "(atend)" {
            // The value follows in the trailer.
            continue;
        }
        if (in_trailer || !dsc.contains_key(key)) && dsc.len() < 100 {
            dsc.insert(key.to_string(), truncate_chars(value, 500));
        }
    }
    let clean = |v: &str| -> String {
        let v = v.trim();
        let v = v.strip_prefix('(').and_then(|x| x.strip_suffix(')')).unwrap_or(v);
        // Several text values, `(5/1/24) (7:42 PM)`, are joined with a space.
        v.replace(") (", " ").replace("\\(", "(").replace("\\)", ")").trim().to_string()
    };
    if let Some(t) = dsc.get("Title").map(|v| clean(v)).filter(|t| !t.is_empty()) {
        cx.content().source("ps.dsc.Title").title(&t);
        cx.emit_text(TextRole::Title, &t);
    }
    if let Some(c) = dsc.get("Creator").map(|v| clean(v)) {
        format.insert("creator".into(), json!(c));
    }
    if let Some(f) = dsc.get("For").map(|v| clean(v))
        && !cx.privacy_strict()
    {
        format.insert("for".into(), json!(f));
    }
    if let Some(c) = dsc.get("Copyright").map(|v| clean(v)) {
        cx.rights().source("ps.dsc.Copyright").copyright(&c);
    }
    if let Some(d) = dsc.get("CreationDate").map(|v| clean(v)) {
        if let Some((v, tz)) = parse_date(&d).or_else(|| super::pdf::pdf_date(&d)) {
            cx.temporal().source("ps.dsc.CreationDate").content_date(DateField::Created, v, tz);
        } else {
            format.insert("creation_date".into(), json!(d));
        }
    }
    let declared = dsc.get("Pages").and_then(|p| p.split_whitespace().next()).and_then(|p| p.parse::<u64>().ok());
    if let Some(n) = declared.or((pages > 0).then_some(pages)) {
        cx.physical().pages(n);
    }
    for (key, out) in [("BoundingBox", "bounding_box"), ("HiResBoundingBox", "hires_bounding_box")] {
        if let Some(b) = dsc.get(key) {
            let nums: Vec<f64> = b.split_whitespace().filter_map(|n| n.parse().ok()).collect();
            if nums.len() == 4 {
                format.insert(out.into(), json!(nums));
            }
        }
    }
    for (key, out) in [
        ("LanguageLevel", "language_level"),
        ("Orientation", "orientation"),
        ("DocumentData", "document_data"),
        ("PageOrder", "page_order"),
        ("DocumentMedia", "media"),
    ] {
        if let Some(v) = dsc.get(key) {
            format.insert(out.into(), json!(v));
        }
    }
    fonts.sort();
    fonts.dedup();
    if !fonts.is_empty() {
        format.insert("fonts".into(), json!(fonts));
    }
    // XMP packet (Adobe applications embed one in EPS).
    if let Some(start) = find(ps, b"<?xpacket begin")
        && let Some(end) = find(&ps[start..], b"<?xpacket end").map(|e| start + e)
    {
        let close = ps[end..].iter().position(|&b| b == b'>').map_or(end, |p| end + p + 1);
        cx.emit_block(BlockKind::XMP, ps[start..close].to_vec());
    }
    let shown = shown_text(&text);
    if !shown.trim().is_empty() {
        cx.emit_text(TextRole::Body, &shown);
    }
    cx.format().extend(format);
    Ok(())
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Strings drawn with `show` and friends: a heuristic for generated
/// PostScript, where text appears as `(Some words) show`.
fn shown_text(ps: &str) -> String {
    let mut out = String::new();
    let b = ps.as_bytes();
    let mut i = 0;
    while i < b.len() && out.len() < 1 << 20 {
        match b[i] {
            b'%' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'(' => {
                let (s, end) = ps_string(b, i);
                i = end;
                // The operator after the string.
                let rest = &b[i.min(b.len())..];
                let start = rest.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(rest.len());
                let op: String =
                    rest[start..].iter().take_while(|c| c.is_ascii_alphanumeric()).map(|&c| char::from(c)).collect();
                let letters = s.chars().filter(|c| c.is_alphabetic()).count();
                let shown = matches!(
                    op.as_str(),
                    "show" | "ashow" | "widthshow" | "awidthshow" | "kshow" | "xshow" | "yshow" | "xyshow"
                );
                // Re-encoded fonts draw glyph codes, not text: keep strings that read as words.
                if shown && letters >= 2 && letters * 2 >= s.chars().filter(|c| !c.is_whitespace()).count() {
                    out.push_str(&s);
                    out.push('\n');
                }
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

fn ps_string(b: &[u8], start: usize) -> (String, usize) {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut i = start;
    while i < b.len() {
        let c = b[i];
        i += 1;
        match c {
            b'(' => {
                depth += 1;
                if depth > 1 {
                    out.push(c);
                }
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
                out.push(c);
            }
            b'\\' => {
                if let Some(&e) = b.get(i) {
                    i += 1;
                    match e {
                        b'n' | b'r' => out.push(b' '),
                        b'0'..=b'7' => {
                            let mut v = u32::from(e - b'0');
                            for _ in 0..2 {
                                if let Some(&d @ b'0'..=b'7') = b.get(i) {
                                    v = v * 8 + u32::from(d - b'0');
                                    i += 1;
                                }
                            }
                            out.push(u8::try_from(v & 0xFF).unwrap_or(b'?'));
                        }
                        b'\n' => {}
                        other => out.push(other),
                    }
                }
            }
            _ => out.push(c),
        }
        if out.len() > 4096 {
            break;
        }
    }
    (encoding_rs::WINDOWS_1252.decode_without_bom_handling(&out).0.into_owned(), i)
}

// ---- BibTeX ------------------------------------------------------------------

struct Entry {
    kind: String,
    key: String,
    fields: Vec<(String, String)>,
}

/// Entries of a BibTeX file (`@string`, `@preamble` and `@comment` skipped).
fn bib_entries(s: &str, max: usize) -> Vec<Entry> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() && out.len() < max {
        let Some(at) = s[i..].find('@') else { break };
        i += at + 1;
        let kind: String = s[i..].chars().take_while(char::is_ascii_alphanumeric).collect();
        i += kind.len();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let open = match b.get(i) {
            Some(b'{') => b'}',
            Some(b'(') => b')',
            _ => continue,
        };
        let kind = kind.to_ascii_lowercase();
        // The entry body, balanced.
        let start = i + 1;
        let mut depth = 0i32;
        let mut j = i;
        while j < b.len() {
            match b[j] {
                b'{' | b'(' if b[j] == b'{' || open == b')' => depth += 1,
                b'}' | b')' if b[j] == b'}' || open == b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        let body = &s[start..j.min(s.len())];
        i = j + 1;
        if matches!(kind.as_str(), "string" | "preamble" | "comment") || kind.is_empty() {
            continue;
        }
        let (key, rest) = body.split_once(',').unwrap_or((body, ""));
        out.push(Entry { kind, key: key.trim().to_string(), fields: bib_fields(rest) });
    }
    out
}

fn bib_fields(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && out.len() < 100 {
        let Some(eq) = s[i..].find('=') else { break };
        let name = s[i..i + eq].trim().trim_start_matches(',').trim().to_ascii_lowercase();
        i += eq + 1;
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        // Values are `{…}`, `"…"`, numbers or macros, joined by `#`.
        loop {
            match b.get(i) {
                Some(b'{') => {
                    let mut depth = 0;
                    let start = i + 1;
                    while i < b.len() {
                        match b[i] {
                            b'{' => depth += 1,
                            b'}' => {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                            _ => {}
                        }
                        i += 1;
                    }
                    value.push_str(&s[start..i.min(s.len())]);
                    i += 1;
                }
                Some(b'"') => {
                    let start = i + 1;
                    i += 1;
                    let mut depth = 0;
                    while i < b.len() && !(b[i] == b'"' && depth == 0) {
                        match b[i] {
                            b'{' => depth += 1,
                            b'}' => depth -= 1,
                            _ => {}
                        }
                        i += 1;
                    }
                    value.push_str(&s[start..i.min(s.len())]);
                    i += 1;
                }
                Some(_) => {
                    let start = i;
                    while i < b.len() && !matches!(b[i], b',' | b'#' | b'}') {
                        i += 1;
                    }
                    value.push_str(s[start..i].trim());
                }
                None => break,
            }
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if b.get(i) == Some(&b'#') {
                i += 1;
                while i < b.len() && b[i].is_ascii_whitespace() {
                    i += 1;
                }
                continue;
            }
            break;
        }
        if !name.is_empty() && !name.contains(char::is_whitespace) {
            out.push((name, crate::plugin::latex_text(&value)));
        }
        while i < b.len() && b[i] != b',' {
            i += 1;
        }
        i += 1;
    }
    out
}

fn bibtex(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let entries = bib_entries(text, 200_000);
    cx.checkpoint()?;
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut years: Vec<u16> = Vec::new();
    let mut dois = 0u64;
    let mut authors = std::collections::HashSet::new();
    let mut keys = Vec::new();
    let mut titles = String::new();
    for e in &entries {
        *types.entry(e.kind.clone()).or_default() += 1;
        if keys.len() < MAX_LISTED {
            keys.push(e.key.clone());
        }
        for (k, v) in &e.fields {
            match k.as_str() {
                "year" | "date" => {
                    if let Ok(y) = v.trim().get(..4).unwrap_or_default().parse::<u16>() {
                        years.push(y);
                    }
                }
                "doi" => dois += 1,
                "author" | "editor" => {
                    for a in v.split(" and ").map(str::trim).filter(|a| !a.is_empty()) {
                        if authors.len() < 100_000 {
                            authors.insert(a.to_ascii_lowercase());
                        }
                    }
                }
                "title" if titles.len() < 1 << 20 => {
                    titles.push_str(v);
                    titles.push('\n');
                }
                _ => {}
            }
        }
    }
    let mut format = Map::new();
    format.insert("entries".into(), json!(entries.len()));
    if !types.is_empty() {
        format.insert("entry_types".into(), json!(types));
    }
    if let (Some(lo), Some(hi)) = (years.iter().min(), years.iter().max()) {
        format.insert("year_range".into(), json!([lo, hi]));
    }
    if dois > 0 {
        format.insert("dois".into(), json!(dois));
    }
    if !authors.is_empty() {
        format.insert("distinct_authors".into(), json!(authors.len()));
    }
    if !keys.is_empty() {
        format.insert("keys".into(), Value::Array(keys.into_iter().map(Value::String).collect()));
    }
    let macros = text.to_ascii_lowercase().matches("@string").count();
    if macros > 0 {
        format.insert("string_macros".into(), json!(macros));
    }
    if !titles.is_empty() {
        cx.emit_text(TextRole::Body, &titles);
    }
    cx.physical().entries(entries.len() as u64);
    cx.format().extend(format);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bibtex_entries() {
        let e = bib_entries(
            r#"@string{jnl = "Journal of Tides"}
@Article{lighthouse2024,
  author = {Ana Lighthouse and Gull, Ben},
  title = {On {S}pring Tides at Saltmere},
  journal = jnl,
  year = 2024,
  doi = {10.1234/tides.2024.1},
}
@book(castell2023, title = "Harbour" # " Guide", year = "2023")
@comment{ignored}"#,
            100,
        );
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].kind, "article");
        assert_eq!(e[0].key, "lighthouse2024");
        let f = |i: usize, k: &str| e[i].fields.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(f(0, "title").as_deref(), Some("On Spring Tides at Saltmere"));
        assert_eq!(f(0, "year").as_deref(), Some("2024"));
        assert_eq!(f(1, "title").as_deref(), Some("Harbour Guide"));
    }

    #[test]
    fn reads_postscript_dsc() {
        let ps = b"%!PS-Adobe-3.0 EPSF-3.0\n%%Title: (Tide chart)\n%%Creator: whiff\n%%BoundingBox: 0 0 200 100\n%%Pages: 1\n%%EndComments\n/Helvetica findfont 12 scalefont setfont\n10 10 moveto (High water) show\n%%EOF\n";
        let r = crate::plugin::testing::report_for("chart.eps", ps);
        assert_eq!(r.identification.format, "eps");
        assert_eq!(r.content.title.as_deref(), Some("Tide chart"));
        let f = &r.format["eps"];
        assert_eq!(f["epsf_version"], "3.0");
        assert_eq!(f["bounding_box"], json!([0.0, 0.0, 200.0, 100.0]));
        assert!(r.content.excerpt.as_deref().unwrap_or_default().contains("High water"));
    }

    crate::fixture_tests!("ps", "eps", "ai", "bib");
}
