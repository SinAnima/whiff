//! More forensic artefacts:
//!
//! * macOS unified log files (`.tracev3`): mach timebase, start time,
//!   time-zone bias, the build and hardware model, boot UUID, time-zone
//!   path, chunks by kind;
//! * Apple System Log databases (`.asl`): version, creation time, records,
//!   levels, time range (messages are not copied);
//! * nfdump captures (`nfcapd.*`, layouts 1 and 2): version, creation
//!   time, compression, blocks, the identifier;
//! * IPFIX files (RFC 5655): messages, observation domains, export time
//!   range, template, options-template and data sets, templates defined;
//! * browser caches: Firefox `cache2` entries (URL, response status and
//!   content type, fetch count, times, size) and Chrome block files, index
//!   and simple-cache entries; URLs as their host only, unless
//!   `--privacy off`.
//!
//! Specifications: the tracev3 layout documented by Mandiant's
//! macos-UnifiedLogs; Apple's `asl_file.h`; nfdump `nffileV2.h`; RFC 7011 /
//! RFC 5655 (IPFIX); Firefox `CacheFileMetadata.h`; Chromium
//! `disk_cache/blockfile/disk_format.h` and `simple/simple_entry_format.h`.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source};

/// Extractor for the artefacts above.
pub struct LongTail;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, [$($ext:literal),*], [$($magic:expr),*]) => {
        FormatSpec { id: $id, name: $name, family: "forensic", mimes: &[$mime], extensions: &[$($ext),*], magic: &[$($magic),*], parent: None }
    };
}

const SIMPLE_CACHE: &[u8] = b"\x30\x5c\x72\xa7\x1b\x6d\xfb\xfc";

static META: ExtractorMeta = ExtractorMeta {
    id: "forensic.longtail",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!(
            "unified_log",
            "macOS unified log (tracev3)",
            "application/x-apple-tracev3",
            ["tracev3"],
            [Magic::prefix(b"\x00\x10\x00\x00\x11\x00\x00\x00")]
        ),
        spec!(
            "asl",
            "Apple System Log database",
            "application/x-apple-asl",
            ["asl"],
            [Magic::prefix(b"ASL DB\0\0\0\0\0\0")]
        ),
        spec!(
            "nfcapd",
            "nfdump capture",
            "application/x-nfdump",
            [],
            [Magic::prefix(b"\x0c\xa5\x01\x00"), Magic::prefix(b"\x0c\xa5\x02\x00")]
        ),
        spec!("ipfix", "IPFIX file", "application/ipfix", ["ipfix"], []),
        spec!("firefox_cache", "Firefox cache2 entry", "application/x-firefox-cache", [], []),
        spec!(
            "chrome_cache",
            "Chrome cache file",
            "application/x-chrome-cache",
            [],
            [Magic::prefix(b"\xc3\xca\x04\xc1"), Magic::prefix(b"\xc3\xca\x03\xc1"), Magic::prefix(SIMPLE_CACHE)]
        ),
    ],
};

/// Records walked at most.
const MAX_RECORDS: u64 = 1_000_000;

impl Extractor for LongTail {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let (h, t) = (probe.head, probe.tail);
        // IPFIX: version 10, a message length within the file, then sets.
        if h.len() >= 20 && h[..2] == [0, 10] {
            let len = usize::from(u16::from_be_bytes([h[2], h[3]]));
            let set = u16::from_be_bytes([h[16], h[17]]);
            if len >= 20 && (set == 2 || set == 3 || set >= 256) {
                return Some(Sniff { format: "ipfix", confidence: 0.85 });
            }
        }
        // Firefox cache2: the last 4 bytes point at the metadata, whose header
        // (after the hashes) has version 1 – 3 and a key starting `:` / `a,` / `O^`.
        if t.len() >= 4 && probe.len > 40 && u32::try_from(probe.len).is_ok() {
            let meta = u64::from(u32::from_be_bytes([t[t.len() - 4], t[t.len() - 3], t[t.len() - 2], t[t.len() - 1]]));
            let tail_start = probe.len - t.len() as u64;
            if meta >= tail_start && meta < probe.len {
                let chunks = usize::try_from(meta.div_ceil(262_144)).ok()?;
                let at = usize::try_from(meta - tail_start).ok()? + 4 + chunks * 2;
                let version = t.get(at..at + 4).map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
                let key = t.get(at + 32..at + 35);
                if matches!(version, Some(1..=3))
                    && key.is_some_and(|k| k[0] == b':' || k.starts_with(b"a,") || k.starts_with(b"O^"))
                {
                    return Some(Sniff { format: "firefox_cache", confidence: 0.9 });
                }
            }
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, cut) = cx.read_bytes(src)?;
        if cut {
            cx.format_set("truncated", true);
        }
        match cx.format_id() {
            "unified_log" => tracev3(cx, &b),
            "asl" => asl(cx, &b),
            "nfcapd" => nfcapd(cx, &b),
            "ipfix" => ipfix(cx, &b),
            "firefox_cache" => firefox(cx, &b),
            _ => chrome(cx, &b),
        }
        Ok(())
    }
}

crate::register_extractor!(LongTail);

fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn le64(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8).map_or(0, |s| u64::from_le_bytes(s.try_into().unwrap_or([0; 8])))
}

fn be16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2).map_or(0, |s| u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be64(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8).map_or(0, |s| u64::from_be_bytes(s.try_into().unwrap_or([0; 8])))
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    crate::plugin::latin1_or_utf8(&b[..end]).trim().to_string()
}

fn unix(secs: u64) -> Option<String> {
    let ticks = secs.checked_mul(10_000_000)?.checked_add(116_444_736_000_000_000)?;
    crate::plugin::filetime(ticks)
}

fn uuid(b: &[u8]) -> String {
    let h = b.iter().fold(String::new(), |mut s, x| {
        use std::fmt::Write as _;
        let _ = write!(s, "{x:02X}");
        s
    });
    if h.len() == 32 { format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]) } else { h }
}

// --- unified log ----------------------------------------------------------------------------------

fn tracev3(cx: &mut Context<'_>, b: &[u8]) {
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let mut at = 0usize;
    while at + 16 <= b.len() && kinds.values().sum::<u64>() < MAX_RECORDS {
        let (tag, size) = (le32(b, at), usize::try_from(le64(b, at + 8)).unwrap_or(usize::MAX));
        let data = b.get(at + 16..(at + 16).saturating_add(size).min(b.len())).unwrap_or_default();
        let name = match tag {
            0x1000 => "header",
            0x600b => "catalog",
            0x600d => "chunkset",
            0x6001 => "firehose",
            0x6002 => "oversize",
            0x6003 => "statedump",
            0x6004 => "simpledump",
            _ => "other",
        };
        *kinds.entry(name.to_string()).or_default() += 1;
        if tag == 0x1000 && data.len() >= 48 {
            cx.format_set("mach_timebase", format!("{}/{}", le32(data, 0), le32(data, 4)));
            if let Some(t) = unix(le64(data, 16)) {
                cx.format_set("start_time", t);
            }
            cx.format_set("timezone_bias_minutes", le32(data, 28).cast_signed());
            cx.format_set("daylight_saving", le32(data, 32) != 0);
            // Sub-chunks: 0x6100 continuous time, 0x6101 system info, 0x6102 generation, 0x6103 time zone.
            let mut p = 40;
            while p + 8 <= data.len() {
                let (sub, n) = (le32(data, p), le32(data, p + 4) as usize);
                let d = data.get(p + 8..(p + 8 + n).min(data.len())).unwrap_or_default();
                match sub {
                    0x6101 if d.len() >= 56 => {
                        cx.format_set("build_version", cstr(&d[8..24]));
                        cx.format_set("hardware_model", cstr(&d[24..56]));
                    }
                    0x6102 if d.len() >= 16 => cx.format_set("boot_uuid", uuid(&d[..16])),
                    0x6103 => cx.format_set("timezone", cstr(d)),
                    _ => {}
                }
                p += 8 + n;
            }
        }
        let Some(next) = (at + 16).checked_add(size).map(|n| n.next_multiple_of(8)) else { break };
        at = next;
    }
    cx.format_set("chunks", json!(kinds));
}

// --- ASL -------------------------------------------------------------------------------------------

fn asl(cx: &mut Context<'_>, b: &[u8]) {
    cx.format_set("version", be32(b, 12));
    if let Some(t) = unix(be64(b, 24)) {
        cx.format_set("created", t);
    }
    // Records: u16 0, u32 length, u64 next, u64 id, u64 time, u32 ns, u16 level …
    let (mut at, mut records, mut levels, mut times) =
        (usize::try_from(be64(b, 16)).unwrap_or(0), 0u64, BTreeMap::<String, u64>::new(), Vec::new());
    let mut seen = std::collections::BTreeSet::new();
    while at != 0 && at + 40 <= b.len() && seen.insert(at) && records < MAX_RECORDS {
        records += 1;
        let next = usize::try_from(be64(b, at + 6)).unwrap_or(0);
        times.push(be64(b, at + 22));
        let level = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]
            .get(usize::from(be16(b, at + 34)))
            .copied()
            .unwrap_or("other");
        *levels.entry(level.to_string()).or_default() += 1;
        at = next;
    }
    times.sort_unstable();
    cx.format_set("records", records);
    cx.format_set("levels", json!(levels));
    if let (Some(a), Some(z)) = (times.first().and_then(|t| unix(*t)), times.last().and_then(|t| unix(*t))) {
        cx.format_set("time_range", json!([a, z]));
    }
}

// --- nfdump / IPFIX ---------------------------------------------------------------------------------------

fn nfcapd(cx: &mut Context<'_>, b: &[u8]) {
    let version = le16(b, 2);
    cx.format_set("layout_version", version);
    let codec = |c: u32| ["none", "LZO", "bzip2", "LZ4", "zstd"].get(c as usize).copied().unwrap_or("unknown");
    if version == 1 {
        let flags = le32(b, 4);
        let c = if flags & 1 != 0 {
            1
        } else if flags & 8 != 0 {
            2
        } else if flags & 16 != 0 {
            3
        } else {
            0
        };
        cx.format_set("compression", codec(c));
        cx.format_set("blocks", le32(b, 8));
        cx.format_set("ident", cstr(b.get(12..140).unwrap_or_default()));
    } else {
        cx.format_set("nfdump_version", format!("{:x}", le32(b, 4)));
        if let Some(t) = unix(le64(b, 8)) {
            cx.format_set("created", t);
        }
        cx.format_set("compression", codec(u32::from(b.get(16).copied().unwrap_or(0))));
        cx.format_set("encrypted", b.get(17).is_some_and(|e| *e != 0));
        cx.format_set("appendix_blocks", le16(b, 18));
        cx.format_set("block_size", le32(b, 32));
        cx.format_set("blocks", le32(b, 36));
    }
}

fn ipfix(cx: &mut Context<'_>, b: &[u8]) {
    let (mut at, mut messages, mut domains, mut times) = (0usize, 0u64, std::collections::BTreeSet::new(), Vec::new());
    let (mut sets, mut templates) = (BTreeMap::<String, u64>::new(), 0u64);
    while at + 16 <= b.len() && messages < MAX_RECORDS {
        if be16(b, at) != 10 {
            break;
        }
        let len = usize::from(be16(b, at + 2));
        if len < 16 {
            break;
        }
        messages += 1;
        times.push(u64::from(be32(b, at + 4)));
        domains.insert(be32(b, at + 12));
        let end = (at + len).min(b.len());
        let mut p = at + 16;
        while p + 4 <= end {
            let (id, slen) = (be16(b, p), usize::from(be16(b, p + 2)));
            if slen < 4 {
                break;
            }
            let kind = match id {
                2 => {
                    // Template records: id, field count, then fields (enterprise bit adds 4 bytes).
                    let mut q = p + 4;
                    while q + 4 <= p + slen {
                        let n = usize::from(be16(b, q + 2));
                        templates += 1;
                        q += 4;
                        for _ in 0..n {
                            let enterprise = be16(b, q) & 0x8000 != 0;
                            q += if enterprise { 8 } else { 4 };
                        }
                    }
                    "template"
                }
                3 => "options template",
                id if id >= 256 => "data",
                _ => "reserved",
            };
            *sets.entry(kind.to_string()).or_default() += 1;
            p += slen;
        }
        at += len;
    }
    times.sort_unstable();
    cx.format_set("messages", messages);
    cx.format_set("observation_domains", domains.into_iter().collect::<Vec<_>>());
    cx.format_set("sets", json!(sets));
    cx.format_set("templates", templates);
    if let (Some(a), Some(z)) = (times.first().and_then(|t| unix(*t)), times.last().and_then(|t| unix(*t))) {
        cx.format_set("export_time_range", json!([a, z]));
    }
}

// --- browser caches ----------------------------------------------------------------------------------------

/// A cached URL as the privacy mode allows: the host, or the whole URL.
fn url_ref(strict: bool, url: &str) -> Value {
    if !strict {
        return json!(url);
    }
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    json!({ "host": rest.split(['/', '?', '#']).next().unwrap_or(rest) })
}

fn firefox(cx: &mut Context<'_>, b: &[u8]) {
    let strict = cx.privacy_strict();
    let meta = be32(b, b.len().saturating_sub(4)) as usize;
    cx.format_set("data_bytes", meta);
    let chunks = meta.div_ceil(262_144);
    let h = meta + 4 + chunks * 2;
    cx.format_set("version", be32(b, h));
    cx.format_set("fetch_count", be32(b, h + 4));
    for (off, key) in [(8, "last_fetched"), (12, "last_modified"), (20, "expires")] {
        let v = be32(b, h + off);
        if v != 0
            && v != u32::MAX
            && let Some(t) = unix(u64::from(v))
        {
            cx.format_set(key, t);
        }
    }
    let key_len = be32(b, h + 24) as usize;
    let key_at = h + if be32(b, h) >= 2 { 32 } else { 28 };
    let key = String::from_utf8_lossy(b.get(key_at..key_at + key_len).unwrap_or_default()).into_owned();
    // `a,:https://…`, `:https://…`, `O^partitionKey=…,:https://…`: the URL follows the last `:` before the scheme.
    let url = key.find("://").and_then(|p| key[..p].rfind(':').map(|c| &key[c + 1..])).unwrap_or(&key);
    cx.format_set("url", url_ref(strict, url));
    // Elements: null-terminated key / value pairs up to the final offset.
    let elements = b.get(key_at + key_len + 1..b.len().saturating_sub(4)).unwrap_or_default();
    let parts: Vec<String> = elements.split(|&c| c == 0).map(|s| String::from_utf8_lossy(s).into_owned()).collect();
    for pair in parts.chunks(2) {
        let [k, v] = pair else { continue };
        match k.as_str() {
            "request-method" => cx.format_set("method", v.as_str()),
            "response-head" => {
                if let Some(status) = v.lines().next() {
                    cx.format_set("status", status.trim());
                }
                for line in v.lines() {
                    if let Some((name, value)) = line.split_once(':') {
                        match name.trim().to_ascii_lowercase().as_str() {
                            "content-type" => cx.format_set("content_type", value.trim()),
                            "content-length" => cx.format_set("content_length", value.trim()),
                            "server" => cx.format_set("server", value.trim()),
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn chrome(cx: &mut Context<'_>, b: &[u8]) {
    let strict = cx.privacy_strict();
    match b.get(..4) {
        Some(b"\xc3\xca\x04\xc1") => {
            cx.format_set("kind", "block file");
            cx.format_set("version", format!("{}.{}", le32(b, 4) >> 16, le32(b, 4) & 0xffff));
            cx.format_set("file_number", le16(b, 8));
            cx.format_set("entry_size", le32(b, 12));
            cx.format_set("entries", le32(b, 16));
            cx.format_set("max_entries", le32(b, 20));
        }
        Some(b"\xc3\xca\x03\xc1") => {
            cx.format_set("kind", "index");
            cx.format_set("version", format!("{}.{}", le32(b, 4) >> 16, le32(b, 4) & 0xffff));
            cx.format_set("entries", le32(b, 8));
            cx.format_set("bytes", le32(b, 12));
            cx.format_set("table_length", le32(b, 28));
            // Creation time: microseconds since 1601 (Windows epoch).
            if let Some(t) = le64(b, 40).checked_mul(10).and_then(crate::plugin::filetime) {
                cx.format_set("created", t);
            }
        }
        _ => {
            cx.format_set("kind", "simple cache entry");
            cx.format_set("version", le32(b, 8));
            let n = le32(b, 12) as usize;
            let key = String::from_utf8_lossy(b.get(20..20 + n).unwrap_or_default()).into_owned();
            // Keys may carry a `1/0/_dk_<site> <frame>` partition prefix: the
            // URL is the last space-separated part.
            let url = key.rsplit(' ').next().unwrap_or(&key);
            cx.format_set("url", url_ref(strict, url));
            cx.format_set("data_bytes", b.len().saturating_sub(20 + n));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("unified_log", "asl", "nfcapd", "ipfix", "firefox_cache", "chrome_cache");

    /// Cached URLs give only their host under strict privacy (neutral sample).
    #[test]
    fn urls_follow_privacy() {
        assert_eq!(url_ref(true, "https://a.example/p?q=1"), json!({ "host": "a.example" }));
        assert_eq!(url_ref(false, "https://a.example/p?q=1"), json!("https://a.example/p?q=1"));
        assert_eq!(uuid(&[0; 16]), "00000000-0000-0000-0000-000000000000");
    }
}
