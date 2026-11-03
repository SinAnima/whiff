//! GPS tracks and logs:
//! * Garmin FIT: protocol and profile versions, file type, manufacturer and
//!   product, creation time, sessions (sport, start, duration, distance),
//!   records with positions (bounds, distance, elevation, time span),
//!   message counts; the device serial number only with privacy off;
//! * IGC flight logs: logger, date, glider type and ID, datum, fixes with
//!   pressure and GNSS altitude, time span, the security record; the
//!   pilot's name only with privacy off;
//! * NMEA 0183 logs: sentence types, talkers, checksum failures, fixes
//!   from GGA / RMC / GLL with their time span.
//!
//! Specifications: Garmin FIT SDK protocol and profile (21.x); FAI "IGC
//! flight recorder specification" (Technical Specification for GNSS
//! flight recorders, appendix A); NMEA 0183 v4.11 sentence layouts.

use std::collections::BTreeMap;

use super::{Track, hist, num};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    parse_date, truncate_chars,
};

/// Extractor for GPS tracks and logs.
pub struct Tracks;

static META: ExtractorMeta = ExtractorMeta {
    id: "geo.tracks",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "garmin_fit",
            name: "Garmin FIT",
            family: "geo",
            mimes: &["application/vnd.ant.fit"],
            extensions: &["fit"],
            magic: &[Magic::at(8, b".FIT")],
            parent: None,
        },
        FormatSpec {
            id: "igc",
            name: "TCX / IGC / NMEA logs",
            family: "geo",
            mimes: &[],
            extensions: &["igc"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "nmea",
            name: "NMEA 0183 log",
            family: "geo",
            mimes: &[],
            extensions: &["nmea"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

/// Seconds between 1970-01-01 and the FIT epoch (1989-12-31T00:00:00Z).
const FIT_EPOCH: i64 = 631_065_600;

fn fit_time(v: u64) -> Option<String> {
    (v != 0xffff_ffff && v >= 0x1000_0000).then(|| super::unix_time(i64::try_from(v).ok()? + FIT_EPOCH)).flatten()
}

fn sport(v: u64) -> String {
    const NAMES: [&str; 54] = [
        "generic",
        "running",
        "cycling",
        "transition",
        "fitness_equipment",
        "swimming",
        "basketball",
        "soccer",
        "tennis",
        "american_football",
        "training",
        "walking",
        "cross_country_skiing",
        "alpine_skiing",
        "snowboarding",
        "rowing",
        "mountaineering",
        "hiking",
        "multisport",
        "paddling",
        "flying",
        "e_biking",
        "motorcycling",
        "boating",
        "driving",
        "golf",
        "hang_gliding",
        "horseback_riding",
        "hunting",
        "fishing",
        "inline_skating",
        "rock_climbing",
        "sailing",
        "ice_skating",
        "sky_diving",
        "snowshoeing",
        "snowmobiling",
        "stand_up_paddleboarding",
        "surfing",
        "wakeboarding",
        "water_skiing",
        "kayaking",
        "rafting",
        "windsurfing",
        "kitesurfing",
        "tactical",
        "jumpmaster",
        "boxing",
        "floor_climbing",
        "baseball",
        "softball_fast_pitch",
        "softball_slow_pitch",
        "shooting",
        "diving",
    ];
    usize::try_from(v).ok().and_then(|i| NAMES.get(i)).map_or_else(|| format!("sport {v}"), |s| (*s).to_string())
}

fn file_type(v: u64) -> String {
    match v {
        1 => "device",
        2 => "settings",
        3 => "sport",
        4 => "activity",
        5 => "workout",
        6 => "course",
        7 => "schedules",
        9 => "weight",
        10 => "totals",
        11 => "goals",
        14 => "blood_pressure",
        15 => "monitoring_a",
        20 => "activity_summary",
        28 => "monitoring_daily",
        32 => "monitoring_b",
        34 => "segment",
        35 => "segment_list",
        40 => "exd_configuration",
        _ => return format!("type {v}"),
    }
    .into()
}

fn manufacturer(v: u64) -> String {
    match v {
        1 => "garmin",
        13 => "dynastream_oem",
        15 => "dynastream",
        23 => "suunto",
        32 => "wahoo_fitness",
        69 => "stages_cycling",
        70 => "sigmasport",
        89 => "tacx",
        123 => "polar",
        255 => "development",
        260 => "zwift",
        265 => "strava",
        289 => "hammerhead",
        294 => "coros",
        _ => return format!("manufacturer {v}"),
    }
    .into()
}

/// A FIT definition: (global message number, big-endian, fields (number,
/// size, base type), developer bytes).
struct Def {
    global: u16,
    big: bool,
    fields: Vec<(u8, u8, u8)>,
    dev: usize,
}

/// A field value as an unsigned integer, `None` when it holds the base
/// type's invalid value.
fn field_value(raw: &[u8], big: bool, base: u8) -> Option<u64> {
    let v = match raw.len() {
        1 => u64::from(raw[0]),
        2 => u64::from(if big { u16::from_be_bytes([raw[0], raw[1]]) } else { u16::from_le_bytes([raw[0], raw[1]]) }),
        4 => {
            let r = [raw[0], raw[1], raw[2], raw[3]];
            u64::from(if big { u32::from_be_bytes(r) } else { u32::from_le_bytes(r) })
        }
        _ => return None,
    };
    let invalid = match (base & 0x1f, raw.len()) {
        (0x00 | 0x02 | 0x0d, 1) => 0xff,
        (0x01, 1) => 0x7f,

        (0x03, 2) => 0x7fff,
        (0x04, 2) => 0xffff,

        (0x05, 4) => 0x7fff_ffff,
        (0x06 | 0x08, 4) => 0xffff_ffff,
        (0x0a, 1) | (0x0b, 2) | (0x0c, 4) => 0,
        _ => u64::MAX,
    };
    (v != invalid).then_some(v)
}

/// Semicircles (signed 32-bit) to degrees.
fn semicircles(v: u64) -> f64 {
    let s = i32::from_ne_bytes(u32::try_from(v).unwrap_or(0).to_ne_bytes());
    f64::from(s) * (180.0 / 2_147_483_648.0)
}

#[allow(clippy::too_many_lines)] // header, then one arm per message of interest
fn fit(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("FIT header");
    let hsize = usize::from(*b.first().ok_or_else(bad)?);
    if hsize < 12 || b.get(8..12) != Some(b".FIT") {
        return Err(bad());
    }
    cx.format_set("protocol_version", format!("{}.{}", b[1] >> 4, b[1] & 0x0f));
    let profile = u16::from_le_bytes([b[2], b[3]]);
    cx.format_set("profile_version", format!("{}.{:02}", profile / 100, profile % 100));
    let size = usize::try_from(u32::from_le_bytes([b[4], b[5], b[6], b[7]])).map_err(|_| bad())?;
    let end = hsize.saturating_add(size).min(b.len());
    if hsize + size > b.len() {
        cx.warn("the data size runs past the end of the file");
    }
    let mut defs: BTreeMap<u8, Def> = BTreeMap::new();
    let mut counts: BTreeMap<u16, u64> = BTreeMap::new();
    let mut track = Track::default();
    let mut sessions = Vec::new();
    let mut at = hsize;
    let mut steps = 0u64;
    while at < end {
        steps += 1;
        if steps.is_multiple_of(65_536) {
            cx.checkpoint()?;
        }
        let rh = b[at];
        at += 1;
        if rh & 0x80 == 0 && rh & 0x40 != 0 {
            // Definition message.
            let dev = rh & 0x20 != 0;
            let Some(h) = b.get(at..at + 5) else { break };
            let big = h[1] == 1;
            let global = if big { u16::from_be_bytes([h[2], h[3]]) } else { u16::from_le_bytes([h[2], h[3]]) };
            let n = usize::from(h[4]);
            at += 5;
            let Some(f) = b.get(at..at + 3 * n) else { break };
            let fields = f.as_chunks::<3>().0.iter().map(|c| (c[0], c[1], c[2])).collect();
            at += 3 * n;
            let mut dev_bytes = 0;
            if dev {
                let Some(&nd) = b.get(at) else { break };
                at += 1;
                let Some(d) = b.get(at..at + 3 * usize::from(nd)) else { break };
                dev_bytes = d.as_chunks::<3>().0.iter().map(|c| usize::from(c[1])).sum();
                at += 3 * usize::from(nd);
            }
            defs.insert(rh & 0x0f, Def { global, big, fields, dev: dev_bytes });
            continue;
        }
        // Data message (normal or compressed-timestamp header).
        let local = if rh & 0x80 != 0 { (rh >> 5) & 0x03 } else { rh & 0x0f };
        let Some(def) = defs.get(&local) else {
            cx.warn("a data message without its definition");
            break;
        };
        let mut values: BTreeMap<u8, u64> = BTreeMap::new();
        for &(num_, size, base) in &def.fields {
            let Some(raw) = b.get(at..at + usize::from(size)) else { break };
            if let Some(v) = field_value(raw, def.big, base) {
                values.insert(num_, v);
            }
            at += usize::from(size);
        }
        at += def.dev;
        *counts.entry(def.global).or_default() += 1;
        match def.global {
            0 if counts[&0] == 1 => {
                if let Some(&t) = values.get(&0) {
                    cx.format_set("file_type", file_type(t));
                }
                if let Some(&m) = values.get(&1) {
                    cx.format_set("manufacturer", manufacturer(m));
                }
                if let Some(&p) = values.get(&2) {
                    cx.format_set("product", p);
                }
                if let Some(&s) = values.get(&3).filter(|_| !cx.privacy_strict()) {
                    cx.format_set("serial_number", s);
                }
                if let Some(t) = values.get(&4).and_then(|&t| fit_time(t)) {
                    cx.format_set("time_created", t.clone());
                    cx.temporal().source("fit.file_id.time_created").content_date(DateField::Created, t, true);
                }
            }
            18 if sessions.len() < 100 => {
                let mut s = serde_json::Map::new();
                if let Some(&v) = values.get(&5) {
                    s.insert("sport".into(), sport(v).into());
                }
                if let Some(t) = values.get(&2).and_then(|&t| fit_time(t)) {
                    s.insert("start".into(), t.into());
                }
                if let Some(&v) = values.get(&7) {
                    s.insert("elapsed_s".into(), num(v as f64 / 1000.0, 1));
                }
                if let Some(&v) = values.get(&9) {
                    s.insert("distance_km".into(), num(v as f64 / 100_000.0, 3));
                }
                sessions.push(serde_json::Value::Object(s));
            }
            20 => {
                if let (Some(&la), Some(&lo)) = (values.get(&0), values.get(&1)) {
                    // Altitude: field 2 (scale 5, offset 500) or enhanced 78.
                    let alt = values
                        .get(&78)
                        .map(|&a| a as f64 / 5.0 - 500.0)
                        .or_else(|| values.get(&2).map(|&a| a as f64 / 5.0 - 500.0));
                    let time = values.get(&253).and_then(|&t| fit_time(t));
                    track.fix(semicircles(la), semicircles(lo), alt, time.as_deref());
                }
            }
            _ => {}
        }
    }
    cx.format_set("sessions", sessions);
    let names: BTreeMap<String, u64> = counts
        .into_iter()
        .map(|(g, n)| {
            let name = match g {
                0 => "file_id".to_string(),
                18 => "session".into(),
                19 => "lap".into(),
                20 => "record".into(),
                21 => "event".into(),
                23 => "device_info".into(),
                34 => "activity".into(),
                49 => "file_creator".into(),
                _ => format!("message {g}"),
            };
            (name, n)
        })
        .collect();
    cx.format_set("messages", hist(names));
    if let Some(s) = &track.first_time
        && let Some((d, tz)) = parse_date(s)
    {
        cx.temporal().source("fit.record.timestamp").content_date(DateField::Captured, d, tz);
    }
    track.report(cx, "fit.record");
    Ok(())
}

/// `DDMMmmm` + hemisphere to degrees (IGC; NMEA uses `DDMM.mmmm`).
fn igc_angle(digits: &str, deg_len: usize, hemi: u8) -> Option<f64> {
    let d: f64 = digits.get(..deg_len)?.parse().ok()?;
    let m: f64 = digits.get(deg_len..)?.parse::<f64>().ok()? / 1000.0;
    let v = d + m / 60.0;
    Some(if matches!(hemi, b'S' | b'W') { -v } else { v })
}

fn igc(cx: &mut Context<'_>, text: &str) {
    let mut track = Track::default();
    let mut date: Option<String> = None;
    let (mut pressure, mut gnss) = (super::Bounds::default(), super::Bounds::default());
    let mut signed = false;
    for line in text.lines().take(10_000_000) {
        let l = line.trim_end();
        match l.as_bytes().first() {
            Some(b'A') => cx.format_set("logger", truncate_chars(&l[1..], 40)),
            Some(b'H') => {
                let (key, value) = l
                    .get(2..5)
                    .zip(l.split_once(':').map(|(_, v)| v.trim()).or_else(|| l.get(5..)))
                    .unwrap_or(("", ""));
                match key {
                    "DTE" => {
                        let d: String = value.chars().filter(char::is_ascii_digit).take(6).collect();
                        if d.len() == 6 {
                            date = Some(format!("20{}-{}-{}", &d[4..6], &d[2..4], &d[0..2]));
                        }
                    }
                    "PLT" if !cx.privacy_strict() => cx.format_set("pilot", truncate_chars(value, 60)),
                    "GTY" => cx.format_set("glider_type", truncate_chars(value, 60)),
                    "GID" => cx.format_set("glider_id", truncate_chars(value, 30)),
                    "DTM" => cx.format_set("datum", truncate_chars(value, 30)),
                    "FTY" => cx.format_set("recorder", truncate_chars(value, 80)),
                    "RFW" => cx.format_set("firmware", truncate_chars(value, 30)),
                    "CID" => cx.format_set("competition_id", truncate_chars(value, 20)),
                    "SIT" => cx.format_set("site", truncate_chars(value, 60)),
                    _ => {}
                }
            }
            // B HHMMSS DDMMmmmN DDDMMmmmE V PPPPP GGGGG
            Some(b'B') if l.len() >= 35 && l.is_ascii() => {
                let lb = l.as_bytes();
                let lat = igc_angle(&l[7..14], 2, lb[14]);
                let lon = igc_angle(&l[15..23], 3, lb[23]);
                let time = date.as_ref().map(|d| format!("{d}T{}:{}:{}Z", &l[1..3], &l[3..5], &l[5..7]));
                let (p, g) = (l[25..30].parse::<f64>().ok(), l[30..35].parse::<f64>().ok());
                if let (Some(la), Some(lo)) = (lat, lon) {
                    track.fix(la, lo, g, time.as_deref());
                    if let Some(p) = p {
                        pressure.add_z(p);
                    }
                    if let Some(g) = g {
                        gnss.add_z(g);
                    }
                }
            }
            Some(b'G') => signed = true,
            _ => {}
        }
    }
    if let Some(d) = &date {
        cx.format_set("date", d.clone());
    }
    for (key, b) in [("pressure_altitude_range", pressure), ("gnss_altitude_range", gnss)] {
        if b.has_z {
            cx.format_set(key, serde_json::Value::Array(vec![num(b.min[2], 0), num(b.max[2], 0)]));
        }
    }
    cx.format_set("security_record", signed);
    if let Some(s) = &track.first_time
        && let Some((d, tz)) = parse_date(s)
    {
        cx.temporal().source("igc.B").content_date(DateField::Captured, d, tz);
    }
    track.report(cx, "igc.B");
}

/// `DDMM.mmmm` or `DDDMM.mmmm` + hemisphere to degrees.
fn nmea_angle(v: &str, hemi: &str) -> Option<f64> {
    let dot = v.find('.').unwrap_or(v.len());
    let deg_len = dot.checked_sub(2)?;
    let d: f64 = v.get(..deg_len)?.parse().ok()?;
    let m: f64 = v.get(deg_len..)?.parse().ok()?;
    let x = d + m / 60.0;
    Some(if matches!(hemi, "S" | "W") { -x } else { x })
}

fn nmea(cx: &mut Context<'_>, text: &str) {
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut talkers: BTreeMap<String, u64> = BTreeMap::new();
    let (mut bad, mut sentences) = (0u64, 0u64);
    let mut track = Track::default();
    let mut date: Option<String> = None;
    for line in text.lines().take(50_000_000) {
        let l = line.trim();
        let Some(body) = l.strip_prefix('$').or_else(|| l.strip_prefix('!')) else { continue };
        sentences += 1;
        let (data, sum) = body.split_once('*').unwrap_or((body, ""));
        if !sum.is_empty() {
            let x = data.bytes().fold(0u8, |a, c| a ^ c);
            if u8::from_str_radix(sum.get(..2).unwrap_or(""), 16).ok() != Some(x) {
                bad += 1;
                continue;
            }
        }
        let f: Vec<&str> = data.split(',').collect();
        let head = f[0];
        if head.len() < 5 || !head.is_ascii() {
            continue;
        }
        let (talker, kind) = head.strip_prefix('P').map_or_else(|| head.split_at(2), |k| ("P", k));
        *talkers.entry(talker.into()).or_default() += 1;
        if types.len() < 100 || types.contains_key(kind) {
            *types.entry(kind.into()).or_default() += 1;
        }
        let g = |i: usize| f.get(i).copied().unwrap_or("");
        let hms = |t: &str| (t.len() >= 6 && t.is_ascii()).then(|| format!("{}:{}:{}", &t[..2], &t[2..4], &t[4..6]));
        match kind {
            "RMC" if g(2) == "A" => {
                let d = g(9);
                if d.len() == 6 && d.is_ascii() {
                    date = Some(format!("20{}-{}-{}", &d[4..6], &d[2..4], &d[..2]));
                }
                if let (Some(la), Some(lo)) = (nmea_angle(g(3), g(4)), nmea_angle(g(5), g(6))) {
                    let t = date.as_ref().zip(hms(g(1))).map(|(d, t)| format!("{d}T{t}Z"));
                    track.fix(la, lo, None, t.as_deref());
                }
            }
            "GGA" if g(6) != "0" && !g(6).is_empty() => {
                if let (Some(la), Some(lo)) = (nmea_angle(g(2), g(3)), nmea_angle(g(4), g(5))) {
                    let t = date.as_ref().zip(hms(g(1))).map(|(d, t)| format!("{d}T{t}Z"));
                    track.fix(la, lo, g(9).parse().ok(), t.as_deref());
                }
            }
            _ => {}
        }
    }
    cx.format_set("sentences", sentences);
    cx.format_set("sentence_types", hist(types));
    cx.format_set("talkers", hist(talkers));
    if bad > 0 {
        cx.format_set("checksum_failures", bad);
    }
    if let Some(s) = &track.first_time
        && let Some((d, tz)) = parse_date(s)
    {
        cx.temporal().source("nmea.RMC").content_date(DateField::Captured, d, tz);
    }
    track.report(cx, "nmea");
}

impl Extractor for Tracks {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let lines: Vec<&[u8]> = h.split(|&c| c == b'\n').take(20).collect();
        let first = lines.first().copied().unwrap_or_default();
        if first.first() == Some(&b'A')
            && first.len() >= 4
            && first[1..4].iter().all(u8::is_ascii_alphanumeric)
            && lines.iter().any(|l| l.starts_with(b"HFDTE"))
        {
            return Some(Sniff { format: "igc", confidence: 0.97 });
        }
        let nmea = lines
            .iter()
            .filter(|l| {
                l.len() > 7
                    && matches!(l[0], b'$' | b'!')
                    && l[1..6].iter().all(u8::is_ascii_alphanumeric)
                    && l[6] == b','
            })
            .count();
        (nmea >= 3 || nmea >= 1 && probe.extension == Some("nmea"))
            .then_some(Sniff { format: "nmea", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "garmin_fit" => {
                let (b, _) = cx.read_bytes(src)?;
                fit(cx, &b)
            }
            "igc" => {
                let text = cx.read_text(src)?.text;
                igc(cx, &text);
                Ok(())
            }
            _ => {
                let text = cx.read_text(src)?.text;
                nmea(cx, &text);
                Ok(())
            }
        }
    }
}

crate::register_extractor!(Tracks);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn angles() {
        assert!((igc_angle("5110179", 2, b'N').unwrap() - 51.169_65).abs() < 1e-5);
        assert!((igc_angle("00006136", 3, b'W').unwrap() + 0.102_266).abs() < 1e-5);
        assert!((nmea_angle("4807.038", "N").unwrap() - 48.1173).abs() < 1e-4);
        assert!((nmea_angle("01131.000", "E").unwrap() - 11.516_667).abs() < 1e-5);
        assert!((semicircles(0x4000_0000) - 90.0).abs() < 1e-9);
        assert_eq!(field_value(&[0xff, 0xff, 0xff, 0x7f], false, 0x85), None);
    }

    crate::fixture_tests!("garmin_fit", "igc", "nmea");
}
