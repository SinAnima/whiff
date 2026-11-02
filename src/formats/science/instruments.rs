//! Instrument and signal recordings:
//! * mzML and mzXML (mass spectrometry): version, run, instrument,
//!   software, file content, spectra and chromatograms, MS levels;
//! * EDF / EDF+ and BioSemi BDF / BDF+: the recording field, start time,
//!   duration, records, the signals with their units and sampling rates
//!   (the patient field only with privacy off);
//! * BrainVision headers (`.vhdr`): data and marker files, format,
//!   channels with their units, sampling rate;
//! * NI TDMS: segments, groups and channels, file properties;
//! * VCD value change dumps: date, version, timescale, scopes and
//!   variables, the last time stamp;
//! * sigrok sessions (`.sr`): the capture's driver, sample rate, channels.
//!
//! Specifications: HUPO-PSI mzML 1.1, mzXML 3.2; EDF (Kemp 1992) and EDF+
//! (2003), BioSemi BDF; Brain Products "BrainVision Core Data Format" 1.0;
//! NI "TDMS File Format Internal Structure"; IEEE 1364 §18 (VCD); sigrok
//! session file format v2.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, Zip,
    redact_sensitive, truncate_chars, zip_names,
};

/// Extractor for instrument and signal recordings.
pub struct Instruments;

static META: ExtractorMeta = ExtractorMeta {
    id: "science.instruments",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "mzml",
            name: "mzML mass spectrometry",
            family: "sci",
            mimes: &[],
            extensions: &["mzml"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "mzxml",
            name: "mzXML mass spectrometry",
            family: "sci",
            mimes: &[],
            extensions: &["mzxml"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "edf",
            name: "EDF / EDF+ recording",
            family: "sci",
            mimes: &[],
            extensions: &["edf"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "bdf_eeg",
            name: "BioSemi BDF",
            family: "sci",
            mimes: &[],
            extensions: &[],
            magic: &[Magic::at(0, b"\xffBIOSEMI")],
            parent: None,
        },
        FormatSpec {
            id: "vhdr",
            name: "BrainVision header",
            family: "sci",
            mimes: &[],
            extensions: &["vhdr"],
            magic: &[Magic::at(0, b"Brain Vision Data Exchange Header File")],
            parent: Some("text"),
        },
        FormatSpec {
            id: "tdms",
            name: "NI TDMS",
            family: "sci",
            mimes: &[],
            extensions: &["tdms"],
            magic: &[Magic::at(0, b"TDSm")],
            parent: None,
        },
        FormatSpec {
            id: "vcd",
            name: "VCD waveform",
            family: "sci",
            mimes: &[],
            extensions: &["vcd"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "sigrok",
            name: "Sigrok session",
            family: "sci",
            mimes: &[],
            extensions: &["sr"],
            magic: &[],
            parent: Some("zip"),
        },
    ],
};

fn has(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

/// An XML attribute of the first `<el ...>` in `text`.
fn attr(text: &str, el: &str, name: &str) -> Option<String> {
    let i = text.find(&format!("<{el} ")).or_else(|| text.find(&format!("<{el}>")))?;
    let tag = &text[i..i + text[i..].find('>')?];
    let k = tag.find(&format!(" {name}=\""))? + name.len() + 3;
    Some(tag[k..].split('"').next()?.to_string())
}

fn mzml(cx: &mut Context<'_>, text: &str) {
    for (el, a, out) in [
        ("mzML", "version", "mzml_version"),
        ("run", "id", "run"),
        ("run", "startTimeStamp", "start_time"),
        ("spectrumList", "count", "spectra"),
        ("chromatogramList", "count", "chromatograms"),
    ] {
        if let Some(v) = attr(text, el, a) {
            match v.parse::<u64>() {
                Ok(n) if out == "spectra" || out == "chromatograms" => cx.format_set(out, n),
                _ => cx.format_set(out, truncate_chars(&v, 200)),
            }
        }
    }
    if let Some(t) = attr(text, "run", "startTimeStamp")
        && let Some((d, tz)) = crate::plugin::parse_date(&t)
    {
        cx.temporal().source("mzml.run.startTimeStamp").content_date(DateField::Captured, d, tz);
    }
    // cvParam names under the instrument configuration, file content, software.
    let section = |open: &str, close: &str| -> Vec<String> {
        let Some(i) = text.find(open) else { return Vec::new() };
        let end = text[i..].find(close).map_or(text.len(), |e| i + e);
        text[i..end]
            .split("<cvParam")
            .skip(1)
            .filter_map(|p| p.split("name=\"").nth(1)?.split('"').next().map(str::to_string))
            .take(20)
            .collect()
    };
    let instrument = section("<instrumentConfiguration ", "</instrumentConfiguration>");
    if !instrument.is_empty() {
        cx.format_set("instrument", instrument);
    }
    let content = section("<fileContent", "</fileContent>");
    if !content.is_empty() {
        cx.format_set("file_content", content);
    }
    let sw: Vec<String> = text
        .split("<software ")
        .skip(1)
        .filter_map(|s| {
            let id = s.split("id=\"").nth(1)?.split('"').next()?;
            let v = s.split("version=\"").nth(1).and_then(|v| v.split('"').next()).unwrap_or("");
            Some(truncate_chars(&format!("{id} {v}"), 100))
        })
        .take(20)
        .collect();
    if !sw.is_empty() {
        cx.format_set("software", sw);
    }
    let mut levels: BTreeMap<String, u64> = BTreeMap::new();
    for p in text.split("name=\"ms level\"").skip(1).take(10_000_000) {
        if let Some(v) = p.split("value=\"").nth(1).and_then(|v| v.split('"').next()) {
            *levels.entry(format!("MS{v}")).or_default() += 1;
        }
    }
    if !levels.is_empty() {
        cx.format_set(
            "ms_levels",
            Value::Object(levels.into_iter().map(|(k, v)| (k, v.into())).collect::<Map<_, _>>()),
        );
    }
}

fn mzxml(cx: &mut Context<'_>, text: &str) {
    for (el, a, out) in [
        ("msRun", "scanCount", "scans"),
        ("msRun", "startTime", "start_time"),
        ("msRun", "endTime", "end_time"),
        ("msManufacturer", "value", "manufacturer"),
        ("msModel", "value", "model"),
    ] {
        if let Some(v) = attr(text, el, a) {
            match v.parse::<u64>() {
                Ok(n) => cx.format_set(out, n),
                Err(_) => cx.format_set(out, truncate_chars(&v, 200)),
            }
        }
    }
    let mut levels: BTreeMap<String, u64> = BTreeMap::new();
    for p in text.split("<scan ").skip(1).take(10_000_000) {
        if let Some(v) = p.split("msLevel=\"").nth(1).and_then(|v| v.split('"').next()) {
            *levels.entry(format!("MS{v}")).or_default() += 1;
        }
    }
    cx.format_set("ms_levels", Value::Object(levels.into_iter().map(|(k, v)| (k, v.into())).collect::<Map<_, _>>()));
}

fn ascii(b: &[u8], at: usize, n: usize) -> String {
    String::from_utf8_lossy(b.get(at..at + n).unwrap_or_default()).trim().to_string()
}

fn edf(cx: &mut Context<'_>, b: &[u8]) -> Option<()> {
    let bdf = b.first() == Some(&0xff);
    let reserved = ascii(b, 192, 44);
    let kind = match (bdf, reserved.as_str()) {
        (true, r) if r.starts_with("BDF+") => format!("BDF+ ({})", &r[4..5.min(r.len())]),
        (true, _) => "BDF".into(),
        (false, r) if r.starts_with("EDF+") => {
            format!("EDF+ ({})", if r.starts_with("EDF+D") { "discontinuous" } else { "continuous" })
        }
        _ => "EDF".into(),
    };
    cx.format_set("type", kind);
    let patient = ascii(b, 8, 80);
    if !patient.is_empty() && !cx.privacy_strict() {
        cx.format_set("patient", truncate_chars(&patient, 80));
    } else if !patient.is_empty() {
        cx.format_set("patient_field_present", true);
    }
    let recording = ascii(b, 88, 80);
    if !recording.is_empty() {
        cx.format_set("recording", truncate_chars(&redact_sensitive(&recording), 80));
    }
    let (date, time) = (ascii(b, 168, 8), ascii(b, 176, 8));
    // dd.mm.yy hh.mm.ss; EDF uses 1985–2084 for yy.
    let d: Vec<u32> = date.split('.').filter_map(|x| x.parse().ok()).collect();
    let t: Vec<u32> = time.split('.').filter_map(|x| x.parse().ok()).collect();
    if d.len() == 3 && t.len() == 3 {
        let year = if d[2] >= 85 { 1900 + d[2] } else { 2000 + d[2] };
        let stamp = format!("{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}", d[1], d[0], t[0], t[1], t[2]);
        cx.format_set("start", stamp.clone());
        cx.temporal().source("edf.startdate").content_date(DateField::Captured, stamp, false);
    }
    let records: i64 = ascii(b, 236, 8).parse().ok()?;
    let duration: f64 = ascii(b, 244, 8).parse().ok()?;
    let ns: usize = ascii(b, 252, 4).parse().ok()?;
    cx.format_set("records", records);
    cx.format_set("record_duration_s", duration);
    #[allow(clippy::cast_precision_loss)] // a duration in seconds
    let total = records.max(0) as f64 * duration;
    cx.format_set("duration_s", total);
    cx.physical().duration_s(total);
    let ns = ns.min(1024);
    let field = |i: usize, off: usize, w: usize| ascii(b, 256 + off * ns + i * w, w);
    let mut signals = Map::new();
    // Offsets (in units of ns) of label 16, transducer 80, dimension 8, ..., samples 8.
    for i in 0..ns {
        let label = field(i, 0, 16);
        let unit = ascii(b, 256 + ns * 96 + i * 8, 8);
        let samples: f64 = ascii(b, 256 + ns * 216 + i * 8, 8).parse().unwrap_or(0.0);
        let rate = if duration > 0.0 { samples / duration } else { 0.0 };
        signals.insert(
            truncate_chars(&label, 50),
            Value::String(format!("{rate} Hz{}", if unit.is_empty() { String::new() } else { format!(" [{unit}]") })),
        );
    }
    cx.format_set("signal_count", ns);
    cx.format_set("signals", Value::Object(signals));
    Some(())
}

/// INI sections of a BrainVision header.
fn vhdr(cx: &mut Context<'_>, text: &str) {
    let mut section = String::new();
    let mut channels = Map::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with(';') || t.is_empty() {
            continue;
        }
        if let Some(s) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = s.to_string();
            continue;
        }
        let Some((k, v)) = t.split_once('=') else { continue };
        match (section.as_str(), k) {
            ("Common Infos", "DataFile") => cx.format_set("data_file", truncate_chars(v, 200)),
            ("Common Infos", "MarkerFile") => cx.format_set("marker_file", truncate_chars(v, 200)),
            ("Common Infos", "DataFormat") => cx.format_set("data_format", truncate_chars(v, 30)),
            ("Common Infos", "DataOrientation") => cx.format_set("orientation", truncate_chars(v, 30)),
            ("Common Infos", "NumberOfChannels") => cx.format_set("channel_count", v.parse::<u64>().unwrap_or(0)),
            ("Common Infos", "SamplingInterval") => {
                if let Ok(us) = v.parse::<f64>()
                    && us > 0.0
                {
                    cx.format_set("sampling_rate_hz", 1e6 / us);
                }
            }
            ("Binary Infos", "BinaryFormat") => cx.format_set("binary_format", truncate_chars(v, 30)),
            ("Channel Infos", ch) if channels.len() < 1024 => {
                let parts: Vec<&str> = v.split(',').collect();
                let unit = parts.get(3).map_or("µV", |u| if u.is_empty() { "µV" } else { u });
                channels.insert(
                    format!("{ch}: {}", truncate_chars(parts.first().unwrap_or(&""), 50)),
                    Value::String(unit.to_string()),
                );
            }
            _ => {}
        }
    }
    if !channels.is_empty() {
        cx.format_set("channels", Value::Object(channels));
    }
}

#[allow(clippy::too_many_lines)] // lead-in, metadata, objects and properties
fn tdms(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let len = src.len();
    let mut at = 0u64;
    let (mut segments, mut groups, mut channels) =
        (0u64, std::collections::BTreeSet::new(), std::collections::BTreeSet::new());
    let mut props = Map::new();
    let mut version = 0u32;
    while at.checked_add(28).is_some_and(|e| e <= len) && segments < 1_000_000 {
        if segments % 1024 == 0 {
            cx.checkpoint()?;
        }
        let lead = src.read_vec(at, 28).map_err(|_| ExtractError::malformed("lead-in"))?;
        if &lead[..4] != b"TDSm" {
            break;
        }
        let toc = u32::from_le_bytes([lead[4], lead[5], lead[6], lead[7]]);
        // kTocBigEndian: the rest of the segment, lead-in included, is big-endian.
        let big = toc & 0x40 != 0;
        let int = |s: &[u8]| -> u64 { s.iter().rev().fold(0, |a, &x| a << 8 | u64::from(x)) };
        let num = |s: &[u8]| -> u64 { if big { s.iter().fold(0, |a, &x| a << 8 | u64::from(x)) } else { int(s) } };
        version = u32::try_from(num(&lead[8..12])).unwrap_or(0);
        let next = num(&lead[12..20]);
        let raw = num(&lead[20..28]);
        segments += 1;
        if toc & 0x2 != 0 && raw > 0 && raw <= 16 << 20 {
            // Metadata: objects with their paths and properties.
            let m = src
                .read_vec(at + 28, usize::try_from(raw).unwrap_or(0))
                .map_err(|_| ExtractError::malformed("metadata"))?;
            let mut i = 0usize;
            let u32_at = |i: usize| m.get(i..i + 4).map(|s| u32::try_from(num(s)).unwrap_or(0));
            let string = |i: &mut usize| -> Option<String> {
                let n = usize::try_from(u32_at(*i)?).ok()?;
                let s = String::from_utf8_lossy(m.get(*i + 4..*i + 4 + n)?).into_owned();
                *i += 4 + n;
                Some(s)
            };
            let Some(count) = u32_at(i) else { break };
            i += 4;
            for _ in 0..count.min(100_000) {
                let Some(path) = string(&mut i) else { break };
                let Some(index) = u32_at(i) else { break };
                i += 4;
                if index != 0xffff_ffff && index != 0 {
                    // The index length counts its own four bytes.
                    i += usize::try_from(index).unwrap_or(0).saturating_sub(4);
                }
                let depth = path.matches("'/'").count();
                if path != "/" {
                    if depth == 0 {
                        groups.insert(path.trim_matches(['/', '\'']).to_string());
                    } else {
                        channels.insert(path.replace("'/'", "/").trim_matches(['/', '\'']).to_string());
                    }
                }
                let Some(np) = u32_at(i) else { break };
                i += 4;
                for _ in 0..np.min(10_000) {
                    let Some(name) = string(&mut i) else { break };
                    let Some(t) = u32_at(i) else { break };
                    i += 4;
                    let v = match t {
                        0x20 => string(&mut i).map(|s| Value::String(truncate_chars(&redact_sensitive(&s), 200))),
                        1 | 5 | 0x21 => {
                            i += 1;
                            m.get(i - 1).map(|&x| Value::from(x))
                        }
                        2 | 6 => {
                            i += 2;
                            m.get(i - 2..i).map(|s| Value::from(num(s)))
                        }
                        3 | 7 => {
                            i += 4;
                            u32_at(i - 4).map(Value::from)
                        }
                        4 | 8 => {
                            i += 8;
                            m.get(i - 8..i).map(|s| Value::from(num(s)))
                        }
                        9 => {
                            i += 4;
                            m.get(i - 4..i)
                                .map(|s| super::number(f64::from(f32::from_bits(u32::try_from(num(s)).unwrap_or(0)))))
                        }
                        10 => {
                            i += 8;
                            m.get(i - 8..i).map(|s| super::number(f64::from_bits(num(s))))
                        }
                        0x44 => {
                            i += 16;
                            None
                        }
                        _ => break,
                    };
                    if path == "/"
                        && let Some(v) = v
                        && props.len() < 100
                    {
                        props.insert(truncate_chars(&name, 100), v);
                    }
                }
            }
        }
        let Some(n) = at.checked_add(28).and_then(|a| a.checked_add(next)).filter(|&n| n > at && next != u64::MAX)
        else {
            break;
        };
        at = n;
    }
    cx.format_set("tdms_version", version);
    cx.format_set("segments", segments);
    cx.format_set("groups", groups.into_iter().take(500).collect::<Vec<_>>());
    cx.format_set("channel_count", channels.len());
    cx.format_set("channels", channels.into_iter().take(500).collect::<Vec<_>>());
    if !props.is_empty() {
        if let Some(n) = props.get("name").and_then(Value::as_str) {
            cx.content().source("tdms.name").title(n.to_string());
        }
        cx.format_set("properties", Value::Object(props));
    }
    Ok(())
}

fn vcd(cx: &mut Context<'_>, text: &str) {
    let mut vars = Vec::new();
    let mut scopes = Vec::new();
    let mut last = 0u64;
    let mut it = text.split_whitespace().peekable();
    while let Some(tok) = it.next() {
        match tok {
            "$date" | "$version" | "$timescale" | "$comment" => {
                let mut v = Vec::new();
                for t in it.by_ref() {
                    if t == "$end" {
                        break;
                    }
                    v.push(t);
                }
                let key = &tok[1..];
                if key != "comment" {
                    cx.format_set(key, truncate_chars(&v.join(" "), 200));
                }
            }
            "$scope" => {
                let kind = it.next().unwrap_or("");
                let name = it.next().unwrap_or("");
                if scopes.len() < 500 {
                    scopes.push(format!("{kind} {name}"));
                }
            }
            "$var" => {
                let kind = it.next().unwrap_or("");
                let size = it.next().unwrap_or("");
                let _id = it.next();
                let name = it.next().unwrap_or("");
                if vars.len() < 500 {
                    vars.push(format!("{name} ({kind} {size})"));
                }
            }
            t if t.starts_with('#') => {
                if let Ok(n) = t[1..].parse::<u64>() {
                    last = last.max(n);
                }
            }
            _ => {}
        }
    }
    cx.format_set("scopes", scopes);
    cx.format_set("variable_count", vars.len());
    cx.format_set("variables", vars);
    cx.format_set("last_time", last);
}

fn sigrok(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let zip = Zip::open(src, 100_000)?;
    if let Some(Ok(v)) = zip.read_text(src, "version", cx, 64) {
        cx.format_set("session_version", truncate_chars(v.trim(), 10));
    }
    let meta = zip.read_text(src, "metadata", cx, 1 << 20).and_then(Result::ok).unwrap_or_default();
    let mut channels = Vec::new();
    for line in meta.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        match k.trim() {
            "sigrok version" => cx.format_set("sigrok_version", truncate_chars(v.trim(), 30)),
            "driver" => cx.format_set("driver", truncate_chars(v.trim(), 50)),
            "samplerate" => cx.format_set("sample_rate", truncate_chars(v.trim(), 30)),
            "total probes" | "total analog" => {
                cx.format_set(k.trim().replace(' ', "_").as_str(), v.trim().parse::<u64>().unwrap_or(0));
            }
            "unitsize" => cx.format_set("unit_size", v.trim().parse::<u64>().unwrap_or(0)),
            k if (k.starts_with("probe") || k.starts_with("analog")) && channels.len() < 256 => {
                channels.push(truncate_chars(v.trim(), 50));
            }
            _ => {}
        }
    }
    cx.format_set("channels", channels);
    let data: u64 = zip
        .entries
        .iter()
        .filter(|e| e.name.starts_with("logic-") || e.name.starts_with("analog-"))
        .map(|e| e.size)
        .sum();
    cx.format_set("capture_bytes", data);
    Ok(())
}

impl Extractor for Instruments {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if has(h, b"<mzML") || has(h, b"<indexedmzML") {
            return Some(Sniff { format: "mzml", confidence: 0.98 });
        }
        if has(h, b"<mzXML") {
            return Some(Sniff { format: "mzxml", confidence: 0.98 });
        }
        // EDF: version "0" padded, numeric header size and record fields.
        if h.starts_with(b"0       ")
            && h.len() >= 256
            && std::str::from_utf8(&h[184..192]).is_ok_and(|s| s.trim().parse::<u32>().is_ok())
        {
            return Some(Sniff { format: "edf", confidence: 0.95 });
        }
        if h.starts_with(b"$date")
            || h.starts_with(b"$version")
            || h.starts_with(b"$timescale")
            || (probe.extension == Some("vcd") && has(h, b"$var"))
        {
            return Some(Sniff { format: "vcd", confidence: 0.95 });
        }
        let names = zip_names(probe, 50);
        let sr = names.iter().any(|n| n == "metadata") && names.iter().any(|n| n == "version");
        sr.then_some(Sniff { format: "sigrok", confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id().to_string().as_str() {
            "tdms" => tdms(cx, src),
            "sigrok" => sigrok(cx, src),
            "edf" | "bdf_eeg" => {
                let b = src
                    .read_vec(0, usize::try_from(src.len()).unwrap_or(0).min(1 << 20))
                    .map_err(|_| ExtractError::malformed("header"))?;
                edf(cx, &b).ok_or_else(|| ExtractError::malformed("EDF header"))
            }
            id => {
                let text = cx.read_text(src)?.text;
                match id {
                    "mzml" => mzml(cx, &text),
                    "mzxml" => mzxml(cx, &text),
                    "vhdr" => vhdr(cx, &text),
                    _ => vcd(cx, &text),
                }
                Ok(())
            }
        }
    }
}

crate::register_extractor!(Instruments);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_attributes() {
        assert_eq!(attr("<run id=\"r1\" startTimeStamp=\"x\">", "run", "id").as_deref(), Some("r1"));
        assert_eq!(attr("<run>", "run", "id"), None);
    }

    crate::fixture_tests!("mzml", "mzxml", "edf", "bdf_eeg", "vhdr", "tdms", "vcd", "sigrok");
}
