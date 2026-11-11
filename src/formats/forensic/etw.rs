//! Windows Event Tracing (ETW) log files (`.etl`): the trace header (the
//! session and log file names, Windows version, processors, CPU speed,
//! pointer size, clock, time zone, boot, start and end times, buffers
//! written and lost, events lost, the logging mode), then every buffer's
//! records counted by header kind, with the providers that wrote them
//! (GUID, the name a `TraceLogging` provider carries or a well-known one,
//! events and event IDs), kernel event groups and the number of
//! processes. Event data is not decoded. The log file path has the user
//! name hidden when privacy is strict.
//!
//! Specifications: `TRACE_LOGFILE_HEADER`, `EVENT_HEADER` and
//! `EVENT_HEADER_EXTENDED_DATA_ITEM` (Microsoft's `evntrace.h` /
//! `evntcons.h`); the buffer and trace headers as documented by Geoff
//! Chappell (`WMI_BUFFER_HEADER`, `SYSTEM_TRACE_HEADER`,
//! `PERFINFO_TRACE_HEADER`), as read by Airbus CERT's etl-parser.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::{Map, Value, json};

use super::{filetime, user_path};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, guid};

/// Extractor for ETW trace logs.
pub struct Etw;

static META: ExtractorMeta = ExtractorMeta {
    id: "forensic.etw",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "etw_trace",
        name: "Windows event trace log (ETL)",
        family: "forensic",
        mimes: &["application/x-ms-etl"],
        extensions: &["etl"],
        // The first bytes are a buffer size: the sniff checks the header.
        magic: &[],
        parent: None,
    }],
};

/// `WMI_BUFFER_HEADER` size.
const BUFFER_HEADER: usize = 0x48;
/// Records walked at most.
const MAX_RECORDS: u64 = 2_000_000;
/// Providers listed.
const MAX_PROVIDERS: usize = 100;
/// Event IDs listed per provider.
const MAX_IDS: usize = 20;
/// `ETW_BUFFER_FLAG_COMPRESSED`.
const COMPRESSED: u16 = 0x40;

impl Extractor for Etw {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let (size, saved) = (le32(h, 0) as usize, le32(h, 4) as usize);
        // A buffer, then the log-file header event: a system trace header
        // (32- or 64-bit, flags 0xC0) of group 0 (header), type 0.
        (h.len() >= BUFFER_HEADER + 8
            && size >= 0x200
            && size.is_multiple_of(8)
            && (BUFFER_HEADER + 0x20..=size).contains(&saved)
            && matches!(h[0x4a], 1 | 2)
            && h[0x4b] == 0xC0
            && h[0x4e] == 0
            && h[0x4f] == 0)
            .then_some(Sniff { format: "etw_trace", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, cut) = cx.read_bytes(src)?;
        if cut {
            cx.format_set("truncated", true);
        }
        header(cx, &b).ok_or_else(|| ExtractError::malformed("no trace log-file header"))?;
        events(cx, &b)?;
        Ok(())
    }
}

crate::register_extractor!(Etw);

fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn le64(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8).map_or(0, |s| u64::from_le_bytes(s.try_into().unwrap_or([0; 8])))
}

fn guid_at(b: &[u8], at: usize) -> Option<String> {
    guid(b.get(at..at + 16)?.try_into().ok()?)
}

/// A NUL-terminated UTF-16LE string at `at` (at most `max` code units),
/// and the offset after its terminator.
fn wstr(b: &[u8], at: usize, max: usize) -> (String, usize) {
    let mut units = Vec::new();
    let mut i = at;
    while units.len() < max {
        let Some(s) = b.get(i..i + 2) else { break };
        i += 2;
        let u = u16::from_le_bytes([s[0], s[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    (String::from_utf16_lossy(&units), i)
}

/// `LogFileMode` flags (`EVENT_TRACE_*_MODE`).
const MODES: [(u32, &str); 14] = [
    (0x1, "file_sequential"),
    (0x2, "file_circular"),
    (0x4, "file_append"),
    (0x8, "file_new"),
    (0x20, "file_preallocate"),
    (0x40, "nonstoppable"),
    (0x80, "secure"),
    (0x100, "real_time"),
    (0x400, "buffering"),
    (0x800, "private_logger"),
    (0x1000, "add_header"),
    (0x0200_0000, "system_logger"),
    (0x0400_0000, "compressed"),
    (0x0800_0000, "independent_session"),
];

/// The `TRACE_LOGFILE_HEADER` event at the start of the first buffer.
fn header(cx: &mut Context<'_>, b: &[u8]) -> Option<()> {
    let first = BUFFER_HEADER;
    let kind = *b.get(first + 2)?;
    // System trace header: 0x20 bytes (with kernel / user times).
    let m = first + 0x20;
    let size = usize::from(le16(b, first + 4));
    let end = (first + size).min(b.len());
    if !matches!(kind, 1 | 2) || size < 0x20 + 0x110 || m + 0x110 > end {
        return None;
    }
    cx.format_set("buffer_size", le32(b, m));
    let v = b.get(m + 4..m + 8)?;
    let build = le32(b, m + 8);
    if v[0] > 0 {
        cx.format_set("os_version", format!("{}.{}.{build}", v[0], v[1]));
    }
    cx.format_set("processors", le32(b, m + 0x0C));
    if let Some(t) = filetime(le64(b, m + 0x10)) {
        cx.format_set("end_time", t);
    }
    cx.format_set("timer_resolution_100ns", le32(b, m + 0x18));
    let max_mb = le32(b, m + 0x1C);
    if max_mb > 0 {
        cx.format_set("maximum_file_size_mb", max_mb);
    }
    let mode = le32(b, m + 0x20);
    let modes: Vec<&str> = MODES.iter().filter(|(bit, _)| mode & bit != 0).map(|(_, n)| *n).collect();
    cx.format_set("log_file_mode", json!({ "value": format!("0x{mode:08X}"), "flags": modes }));
    cx.format_set("buffers_written", le32(b, m + 0x24));
    let pointer = le32(b, m + 0x2C) as usize;
    cx.format_set("pointer_size", pointer);
    cx.format_set("events_lost", le32(b, m + 0x30));
    let mhz = le32(b, m + 0x34);
    if mhz > 0 {
        cx.format_set("cpu_mhz", mhz);
    }
    let p = if pointer == 4 { 4 } else { 8 };
    // TIME_ZONE_INFORMATION: bias, then the standard name (32 units).
    let tz = m + 0x38 + 2 * p;
    let bias = le32(b, tz).cast_signed();
    let (zone, _) = wstr(b, tz + 4, 32);
    let mut zone_info = Map::new();
    zone_info.insert("bias_minutes".into(), json!(bias));
    if !zone.is_empty() {
        zone_info.insert("standard_name".into(), json!(zone));
    }
    cx.format_set("time_zone", Value::Object(zone_info));
    let after = tz + 0xB0;
    if let Some(t) = filetime(le64(b, after)) {
        cx.format_set("boot_time", t);
    }
    let freq = le64(b, after + 8);
    if freq > 0 {
        cx.format_set("performance_frequency", freq);
    }
    if let Some(t) = filetime(le64(b, after + 16)) {
        cx.format_set("start_time", t);
    }
    let clock = match le32(b, after + 24) {
        1 => "query_performance_counter",
        2 => "system_time",
        3 => "cpu_cycle_counter",
        _ => "",
    };
    if !clock.is_empty() {
        cx.format_set("clock", clock);
    }
    cx.format_set("buffers_lost", le32(b, after + 28));
    let (session, next) = wstr(b, after + 32, 1024);
    if !session.is_empty() {
        cx.format_set("session", session);
    }
    let (file, _) = wstr(b, next.min(end), 1024);
    if !file.is_empty() {
        let shown = user_path(cx, &file);
        cx.format_set("log_file_name", shown);
    }
    Some(())
}

/// Well-known provider GUIDs.
fn provider_name(g: &str) -> Option<&'static str> {
    Some(match g {
        "68FDD900-4A3E-11D1-84F4-0000F80464E3" => "EventTraceEvent (log-file header)",
        "9E814AAD-3204-11D2-9A82-006008A86939" => "MSNT_SystemTrace (kernel logger)",
        "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716" => "Microsoft-Windows-Kernel-Process",
        "EDD08927-9CC4-4E65-B970-C2560FB5C289" => "Microsoft-Windows-Kernel-File",
        "7DD42A49-5329-4832-8DFD-43D979153A88" => "Microsoft-Windows-Kernel-Network",
        "70EB4F03-C1DE-4F73-A051-33D13D5413BD" => "Microsoft-Windows-Kernel-Registry",
        "2A576B87-09A7-520E-C21A-4942F0271D67" => "Microsoft-Antimalware-Scan-Interface",
        "E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4" => "Microsoft-Windows-DotNETRuntime",
        "A0C1853B-5C40-4B15-8766-3CF1C58F985A" => "Microsoft-Windows-PowerShell",
        "5770385F-C22A-43E0-BF4C-06F5698FFBD9" => "Microsoft-Windows-Sysmon",
        "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D" => "Microsoft-Windows-DNS-Client",
        "2F07E2EE-15DB-40F1-90EF-9D7BA282188A" => "Microsoft-Windows-TCPIP",
        "F4E1897C-BB5D-5668-F1D8-040F4D8DD344" => "Microsoft-Windows-Threat-Intelligence",
        _ => return None,
    })
}

/// Kernel event groups (the high byte of a system / perfinfo hook ID).
const GROUPS: [&str; 31] = [
    "header",
    "io",
    "memory",
    "process",
    "file",
    "thread",
    "tcpip",
    "job",
    "udpip",
    "registry",
    "dbgprint",
    "config",
    "spare1",
    "wnf",
    "pool",
    "perfinfo",
    "heap",
    "object",
    "power",
    "modbound",
    "image",
    "dpc",
    "gdi",
    "critsec",
    "stackwalk",
    "ums",
    "alpc",
    "splitio",
    "thread_pool",
    "hypervisor",
    "hypervisorx",
];

#[derive(Default)]
struct Provider {
    events: u64,
    ids: BTreeSet<u16>,
}

#[derive(Default)]
struct Walk {
    kinds: BTreeMap<&'static str, u64>,
    groups: BTreeMap<&'static str, u64>,
    providers: HashMap<String, Provider>,
    names: HashMap<String, String>,
    processes: BTreeSet<u32>,
    records: u64,
}

impl Walk {
    fn provider(&mut self, g: Option<String>, id: u16) {
        let Some(g) = g else { return };
        let p = self.providers.entry(g).or_default();
        p.events += 1;
        if p.ids.len() < MAX_IDS {
            p.ids.insert(id);
        }
    }

    /// One record at `p` (within `end`); its size, or `None` to stop the buffer.
    fn record(&mut self, b: &[u8], p: usize, end: usize) -> Option<usize> {
        let kind = *b.get(p + 2)?;
        let flags = *b.get(p + 3)?;
        if le16(b, p + 2) == 0x9000 {
            // A trace with no documented header: size, marker, event ID, flags, provider.
            let size = usize::from(le16(b, p));
            *self.kinds.entry("windows_trace").or_insert(0) += 1;
            self.provider(guid_at(b, p + 8), le16(b, p + 4));
            self.processes.insert(le32(b, p + 0x1C));
            return Some(size);
        }
        if flags & 0xC0 != 0xC0 {
            return None;
        }
        let size = match kind {
            // System (with times), compact system, perfinfo: packet size at 4.
            1..=4 | 0x10 | 0x11 => {
                let label = if kind >= 0x10 { "perfinfo" } else { "system" };
                *self.kinds.entry(label).or_insert(0) += 1;
                let group = usize::from(*b.get(p + 7)?);
                *self.groups.entry(GROUPS.get(group).copied().unwrap_or("other")).or_insert(0) += 1;
                if kind <= 4 {
                    self.processes.insert(le32(b, p + 0x0C));
                }
                usize::from(le16(b, p + 4))
            }
            // EVENT_HEADER (manifest and TraceLogging events).
            0x12 | 0x13 => {
                *self.kinds.entry("event").or_insert(0) += 1;
                let g = guid_at(b, p + 0x18);
                self.provider(g.clone(), le16(b, p + 0x28));
                self.processes.insert(le32(b, p + 0x0C));
                let size = usize::from(le16(b, p));
                if le16(b, p + 4) & 1 != 0
                    && let Some(g) = g
                {
                    self.extended(b, p + 0x50, (p + size).min(end), &g);
                }
                size
            }
            // EVENT_TRACE_HEADER (classic providers).
            0x0A | 0x14 => {
                *self.kinds.entry("classic").or_insert(0) += 1;
                self.provider(guid_at(b, p + 0x18), u16::from(*b.get(p + 4)?));
                self.processes.insert(le32(b, p + 0x0C));
                usize::from(le16(b, p))
            }
            _ => {
                *self.kinds.entry("other").or_insert(0) += 1;
                usize::from(le16(b, p))
            }
        };
        Some(size)
    }

    /// Extended data items; a provider-traits item names a `TraceLogging` provider.
    fn extended(&mut self, b: &[u8], mut at: usize, end: usize, g: &str) {
        for _ in 0..16 {
            if at + 8 > end {
                return;
            }
            let (kind, linkage, size) = (le16(b, at + 2), le16(b, at + 4), usize::from(le16(b, at + 6)));
            let data = at + 8;
            // EVENT_HEADER_EXT_TYPE_PROV_TRAITS: total size, then the name.
            if kind == 0x000C && !self.names.contains_key(g) {
                let name = b.get(data + 2..(data + size).min(end)).unwrap_or_default();
                let name = name.split(|&c| c == 0).next().unwrap_or_default();
                if let Ok(n) = std::str::from_utf8(name)
                    && !n.is_empty()
                {
                    self.names.insert(g.to_string(), n.to_string());
                }
            }
            if linkage & 1 == 0 {
                return;
            }
            at = (data + size).next_multiple_of(8);
        }
    }
}

/// Every buffer's records.
fn events(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    let mut w = Walk::default();
    let (mut buffers, mut compressed, mut at) = (0u64, 0u64, 0usize);
    while at + BUFFER_HEADER <= b.len() && w.records < MAX_RECORDS {
        let size = le32(b, at) as usize;
        let saved = le32(b, at + 4) as usize;
        if size < BUFFER_HEADER || !size.is_multiple_of(8) {
            break;
        }
        buffers += 1;
        if buffers % 64 == 0 {
            cx.checkpoint()?;
        }
        if le16(b, at + 0x34) & COMPRESSED != 0 {
            compressed += 1;
        } else {
            let end = (at + saved.min(size)).min(b.len());
            let mut p = at + BUFFER_HEADER;
            while p + 8 <= end && w.records < MAX_RECORDS {
                let Some(n) = w.record(b, p, end) else { break };
                if n < 8 {
                    break;
                }
                w.records += 1;
                p += n.next_multiple_of(8);
            }
        }
        at += size;
    }
    cx.format_set("buffers", buffers);
    if compressed > 0 {
        cx.format_set("compressed_buffers", compressed);
    }
    cx.format_set("records", w.records);
    cx.format_set("records_by_kind", json!(w.kinds));
    if !w.groups.is_empty() {
        cx.format_set("kernel_groups", json!(w.groups));
    }
    w.processes.remove(&0);
    w.processes.remove(&u32::MAX);
    cx.format_set("processes", w.processes.len());
    let mut providers: Vec<(String, Provider)> = w.providers.into_iter().collect();
    providers.sort_by(|a, b| b.1.events.cmp(&a.1.events).then_with(|| a.0.cmp(&b.0)));
    cx.format_set("provider_count", providers.len());
    let listed: Vec<Value> = providers
        .iter()
        .take(MAX_PROVIDERS)
        .map(|(g, p)| {
            let mut m = Map::new();
            m.insert("guid".into(), json!(g));
            if let Some(n) = w.names.get(g).map(String::as_str).or_else(|| provider_name(g)) {
                m.insert("name".into(), json!(n));
            }
            m.insert("events".into(), json!(p.events));
            m.insert("event_ids".into(), json!(p.ids));
            Value::Object(m)
        })
        .collect();
    cx.format_set("providers", listed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("etw_trace");

    #[test]
    fn traits_name_a_provider() {
        // One extended item of type PROV_TRAITS: size 0x0E, "Tide.Gauge".
        let mut b = vec![0u8; 8];
        b[2] = 0x0C;
        b[6] = 0x0E;
        b.extend_from_slice(&[0x0E, 0x00]);
        b.extend_from_slice(b"Tide.Gauge\0\0");
        let mut w = Walk::default();
        w.extended(&b, 0, b.len(), "G");
        assert_eq!(w.names.get("G").map(String::as_str), Some("Tide.Gauge"));
    }
}
