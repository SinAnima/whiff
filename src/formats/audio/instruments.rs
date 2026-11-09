//! Sample-based instruments:
//!
//! * SoundFont 2 / 3 (`sfbk`): version, sound engine, bank name, ROM,
//!   author, product, copyright, the program that wrote it, presets (with
//!   their bank and program numbers), instruments and samples (with their
//!   rates), sample data size and 24-bit extension;
//! * DLS level 1 / 2 (`DLS `): instruments, regions, waves, the INFO text;
//! * SFZ text instruments: headers, regions, distinct samples, key range;
//! * Logic EXS24 instruments: zones, groups, samples and their names.
//!
//! Specifications: the SoundFont 2.04 technical specification (and
//! MuseScore's SF3 variant); the MMA DLS level 1 / 2 specifications; the
//! SFZ format (sfzformat.com); EXS24 as read by open-source converters.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::Tags;
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source};

/// Extractor for sample-based instruments.
pub struct Instruments;

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.instrument",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "soundfont",
            name: "SoundFont",
            family: "audio",
            mimes: &["audio/x-soundfont"],
            extensions: &["sf2", "sf3", "sbk"],
            magic: &[Magic::masked(0, b"RIFF\0\0\0\0sfbk", b"\xff\xff\xff\xff\0\0\0\0\xff\xff\xff\xff")],
            parent: None,
        },
        FormatSpec {
            id: "dls",
            name: "Downloadable Sounds (DLS)",
            family: "audio",
            mimes: &["audio/dls"],
            extensions: &["dls"],
            magic: &[Magic::masked(0, b"RIFF\0\0\0\0DLS ", b"\xff\xff\xff\xff\0\0\0\0\xff\xff\xff\xff")],
            parent: None,
        },
        FormatSpec {
            id: "sfz",
            name: "SFZ instrument",
            family: "audio",
            mimes: &["text/x-sfz"],
            extensions: &["sfz"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "exs",
            name: "Logic EXS24 instrument",
            family: "audio",
            mimes: &["application/x-exs24"],
            // `.exs` is also an Elixir script: recognised by its chunk magic.
            extensions: &[],
            magic: &[],
            parent: None,
        },
    ],
};

/// Names listed.
const MAX_LISTED: usize = 100;

impl Extractor for Instruments {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.len() > 84 && matches!(h.get(16..20), Some(b"TBOS" | b"SOBT" | b"JBOS" | b"SOBJ")) {
            return Some(Sniff { format: "exs", confidence: 0.9 });
        }
        let ext = probe.extension.unwrap_or("");
        let text = String::from_utf8_lossy(&h[..h.len().min(4096)]);
        (ext.eq_ignore_ascii_case("sfz") || (text.contains("<region>") && text.contains("sample=")))
            .then_some(Sniff { format: "sfz", confidence: 0.85 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, cut) = cx.read_bytes(src)?;
        if cut {
            cx.format_set("truncated", true);
        }
        match cx.format_id() {
            "soundfont" => soundfont(cx, &b),
            "dls" => dls(cx, &b),
            "sfz" => sfz(cx, &String::from_utf8_lossy(&b)),
            _ => exs(cx, &b),
        }
        Ok(())
    }
}

crate::register_extractor!(Instruments);

fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    crate::plugin::latin1_or_utf8(&b[..end]).trim().to_string()
}

/// RIFF chunks in `b` (after a list type): (id, body).
fn chunks(b: &[u8]) -> Vec<([u8; 4], &[u8])> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 8 <= b.len() && out.len() < 100_000 {
        let id = [b[at], b[at + 1], b[at + 2], b[at + 3]];
        let n = le32(b, at + 4) as usize;
        let end = (at + 8).saturating_add(n).min(b.len());
        out.push((id, &b[at + 8..end]));
        at = end + (n & 1);
    }
    out
}

/// The INFO list's text fields.
fn info(cx: &mut Context<'_>, body: &[u8], tags: &mut Tags) {
    for (id, v) in chunks(body) {
        let text = cstr(v);
        let key = match &id {
            b"INAM" => "bank_name",
            b"isng" => "sound_engine",
            b"irom" => "rom",
            b"ICRD" => "created",
            b"IENG" => "engineers",
            b"IPRD" => "product",
            b"ICOP" => "copyright",
            b"ICMT" => "comment",
            b"ISFT" => "software",
            b"ISBJ" => "subject",
            b"IART" => "artist",
            b"ifil" | b"iver" => {
                if v.len() >= 4 {
                    let key = if &id == b"ifil" { "version" } else { "rom_version" };
                    cx.format_set(key, format!("{}.{:02}", le16(v, 0), le16(v, 2)));
                }
                continue;
            }
            _ => continue,
        };
        if text.is_empty() {
            continue;
        }
        match key {
            "bank_name" => {
                cx.content().title(text.clone());
                tags.set("title", &text, "riff_info");
            }
            "copyright" | "comment" | "artist" => tags.set(key, &text, "riff_info"),
            "software" => tags.set("encoder", &text, "riff_info"),
            _ => {}
        }
        cx.format_set(key, text);
    }
}

fn soundfont(cx: &mut Context<'_>, b: &[u8]) {
    let mut tags = Tags::default();
    tags.system("riff_info");
    for (id, body) in chunks(b.get(12..).unwrap_or_default()) {
        if &id != b"LIST" || body.len() < 4 {
            continue;
        }
        let (kind, rest) = body.split_at(4);
        match kind {
            b"INFO" => info(cx, rest, &mut tags),
            b"sdta" => {
                for (cid, data) in chunks(rest) {
                    match &cid {
                        b"smpl" => cx.format_set("sample_data_bytes", data.len()),
                        b"sm24" => cx.format_set("sample_data_24bit", true),
                        _ => {}
                    }
                }
            }
            b"pdta" => {
                for (cid, data) in chunks(rest) {
                    match &cid {
                        b"phdr" => {
                            // 38-byte records; the last is the terminal "EOP".
                            let recs: Vec<&[u8]> = data.as_chunks::<38>().0.iter().map(|r| &r[..]).collect();
                            let real = recs.len().saturating_sub(1);
                            cx.format_set("presets", real);
                            let list: Vec<Value> = recs[..real]
                                .iter()
                                .take(MAX_LISTED)
                                .map(|r| json!({ "name": cstr(&r[..20]), "program": le16(r, 20), "bank": le16(r, 22) }))
                                .collect();
                            cx.format_set("preset_list", list);
                        }
                        b"inst" => cx.format_set("instruments", (data.len() / 22).saturating_sub(1)),
                        b"shdr" => {
                            let recs: Vec<&[u8]> = data.as_chunks::<46>().0.iter().map(|r| &r[..]).collect();
                            let real = recs.len().saturating_sub(1);
                            cx.format_set("samples", real);
                            let rates: BTreeSet<u32> =
                                recs[..real].iter().map(|r| le32(r, 36)).filter(|r| *r > 0).collect();
                            cx.format_set("sample_rates", rates.into_iter().collect::<Vec<_>>());
                            // SF3: sample type bit 0x10 marks Ogg Vorbis data.
                            if recs[..real].iter().any(|r| le16(r, 44) & 0x10 != 0) {
                                cx.format_set("compressed_samples", "Ogg Vorbis (SF3)");
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    tags.report(cx);
}

fn dls(cx: &mut Context<'_>, b: &[u8]) {
    let mut tags = Tags::default();
    tags.system("riff_info");
    let (mut names, mut regions, mut waves) = (Vec::new(), 0u64, 0u64);
    for (id, body) in chunks(b.get(12..).unwrap_or_default()) {
        match &id {
            b"colh" => cx.format_set("declared_instruments", le32(body, 0)),
            b"vers" => cx.format_set(
                "version",
                format!("{}.{}.{}.{}", le16(body, 2), le16(body, 0), le16(body, 6), le16(body, 4)),
            ),
            b"ptbl" => cx.format_set("pool_cues", le32(body, 4)),
            b"LIST" if body.len() >= 4 => {
                let (kind, rest) = body.split_at(4);
                match kind {
                    b"INFO" => info(cx, rest, &mut tags),
                    b"lins" => {
                        for (_, ins) in chunks(rest).into_iter().filter(|(i, c)| i == b"LIST" && c.starts_with(b"ins "))
                        {
                            let mut name = String::new();
                            for (cid, c) in chunks(&ins[4..]) {
                                if &cid == b"insh" {
                                    regions += u64::from(le32(c, 0));
                                } else if &cid == b"LIST" && c.starts_with(b"INFO") {
                                    name = chunks(&c[4..])
                                        .into_iter()
                                        .find(|(i, _)| i == b"INAM")
                                        .map(|(_, v)| cstr(v))
                                        .unwrap_or_default();
                                }
                            }
                            names.push(name);
                        }
                    }
                    b"wvpl" => {
                        waves +=
                            chunks(rest).iter().filter(|(i, c)| i == b"LIST" && c.starts_with(b"wave")).count() as u64;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    cx.format_set("instruments", names.len());
    cx.format_set("instrument_names", names.into_iter().filter(|n| !n.is_empty()).take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("regions", regions);
    cx.format_set("waves", waves);
    tags.report(cx);
}

fn sfz(cx: &mut Context<'_>, text: &str) {
    let mut headers: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let (mut samples, mut includes, mut defines) = (BTreeSet::new(), Vec::new(), 0u64);
    let (mut lo, mut hi) = (None::<u32>, None::<u32>);
    let note = |v: &str| -> Option<u32> {
        if let Ok(n) = v.parse::<u32>() {
            return Some(n);
        }
        // c4 = 60, c#4 = 61 …
        let b = v.to_ascii_lowercase();
        let base = match b.chars().next()? {
            'c' => 0,
            'd' => 2,
            'e' => 4,
            'f' => 5,
            'g' => 7,
            'a' => 9,
            'b' => 11,
            _ => return None,
        };
        let (acc, rest) = if b[1..].starts_with('#') {
            (1, &b[2..])
        } else if b[1..].starts_with('b') {
            (-1, &b[2..])
        } else {
            (0, &b[1..])
        };
        let octave: i32 = rest.parse().ok()?;
        u32::try_from((octave + 1) * 12 + base + acc).ok()
    };
    for raw in text.lines() {
        let line = raw.split("//").next().unwrap_or("");
        let t = line.trim();
        if let Some(r) = t.strip_prefix("#include") {
            includes.push(r.trim().trim_matches('"').to_string());
            continue;
        }
        if t.starts_with("#define") {
            defines += 1;
            continue;
        }
        let mut rest = line;
        while let Some(p) = rest.find('<') {
            let Some(e) = rest[p..].find('>') else { break };
            *headers.entry(rest[p + 1..p + e].to_string()).or_default() += 1;
            rest = &rest[p + e + 1..];
        }
        for (key, value) in opcodes(line) {
            match key {
                "sample" => {
                    if samples.len() < 10_000 {
                        samples.insert(value.replace('\\', "/"));
                    }
                }
                "lokey" | "key" | "hikey" => {
                    if let Some(n) = note(value) {
                        if key != "hikey" {
                            lo = Some(lo.map_or(n, |l| l.min(n)));
                        }
                        if key != "lokey" {
                            hi = Some(hi.map_or(n, |h| h.max(n)));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    cx.format_set("headers", json!(headers));
    cx.format_set("regions", headers.get("region").copied().unwrap_or(0));
    cx.format_set("groups", headers.get("group").copied().unwrap_or(0));
    cx.format_set("samples", samples.len());
    let names: Vec<String> =
        samples.iter().take(MAX_LISTED).map(|s| s.rsplit('/').next().unwrap_or(s).to_string()).collect();
    cx.format_set("sample_files", names);
    if let (Some(l), Some(h)) = (lo, hi) {
        cx.format_set("key_range", json!([l, h]));
    }
    if !includes.is_empty() {
        cx.format_set("includes", includes);
    }
    if defines > 0 {
        cx.format_set("defines", defines);
    }
}

/// The `key=value` opcodes of an SFZ line. A value runs to the next
/// opcode, so sample paths may hold spaces.
fn opcodes(line: &str) -> Vec<(&str, &str)> {
    // Start of each key: the word before every `=`.
    let starts: Vec<(usize, usize)> = line
        .match_indices('=')
        .map(|(eq, _)| {
            let key_start = line[..eq]
                .char_indices()
                .rev()
                .find(|(_, c)| c.is_whitespace() || *c == '>')
                .map_or(0, |(p, c)| p + c.len_utf8());
            (key_start, eq)
        })
        .collect();
    starts
        .iter()
        .enumerate()
        .map(|(i, &(k, eq))| {
            // A value holding `=` makes the next "key" start inside it.
            let end = starts.get(i + 1).map_or(line.len(), |n| n.0).max(eq + 1);
            let value = line[eq + 1..end].split('<').next().unwrap_or("").trim();
            (&line[k..eq], value)
        })
        .collect()
}

fn exs(cx: &mut Context<'_>, b: &[u8]) {
    // Chunks: a 4-byte signature (type in its high byte), the body size,
    // then a 64-byte name at 20; each chunk is its size plus 84 bytes.
    let big = matches!(b.get(16..20), Some(b"SOBT" | b"SOBJ"));
    let rd = |at: usize| -> u32 {
        b.get(at..at + 4).map_or(0, |s| {
            let a = [s[0], s[1], s[2], s[3]];
            if big { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
        })
    };
    let (mut at, mut zones, mut groups, mut samples, mut params) = (0usize, 0u64, 0u64, Vec::new(), 0u64);
    let mut name = None;
    for _ in 0..100_000 {
        if at + 84 > b.len() {
            break;
        }
        let sig = rd(at);
        let size = rd(at + 4) as usize;
        let chunk_name = cstr(&b[at + 20..at + 84]);
        match (sig & 0x0f00_0000) >> 24 {
            0 if name.is_none() => name = Some(chunk_name),
            1 => zones += 1,
            2 => groups += 1,
            3 => samples.push(chunk_name),
            4 => params += 1,
            _ => {}
        }
        let Some(next) = at.checked_add(size + 84) else { break };
        at = next;
    }
    cx.format_set("byte_order", if big { "big-endian" } else { "little-endian" });
    if let Some(n) = name.filter(|n| !n.is_empty()) {
        cx.content().title(n.clone());
        cx.format_set("name", n);
    }
    cx.format_set("zones", zones);
    cx.format_set("groups", groups);
    cx.format_set("samples", samples.len());
    cx.format_set("sample_names", samples.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("parameter_chunks", params);
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("soundfont", "dls", "sfz", "exs");
}
