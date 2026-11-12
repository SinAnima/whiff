//! `archive` extractors (feature `common`): files that hold other files.
//! Every format reads its directory into [`Entry`]s and reports them the
//! same way through [`Inventory`]: entry, file, folder and link counts,
//! total and compressed sizes (and the ratio), compression methods,
//! encrypted entries, a file-type histogram, the range of modification
//! times, the top-level folders, the first entries, and the risk signals
//! (paths that climb out of the target folder, absolute paths, links that
//! point outside the archive, double extensions, decompression bombs).
//!
//! Entries are handed on as children (within the child, depth and
//! decompression limits) where the format stores or compresses them in a
//! way whiff reads; only listings are produced otherwise.

pub(crate) mod alzip;
pub(crate) mod ar;
pub(crate) mod backups;
pub(crate) mod bundles;
pub(crate) mod cab;
pub(crate) mod cpio;
pub(crate) mod dos;
pub(crate) mod encoded;
pub(crate) mod legacy;
pub(crate) mod mac;
pub(crate) mod rar;
pub(crate) mod sevenz;
pub(crate) mod squashfs;
pub(crate) mod tar;
pub(crate) mod wim;
pub(crate) mod zip;

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::plugin::{Context, DateField, ExtractError, Source, risky_file_name};

/// Entries kept in memory per archive (counts go on past it).
pub(crate) const MAX_ENTRIES: usize = 1 << 16;
/// Entries listed in the report.
const MAX_LISTED: usize = 50;
/// File types and top-level folders listed.
const MAX_KEYS: usize = 20;
/// Uncompressed total from which a high ratio is a decompression bomb.
const BOMB_BYTES: u64 = 1 << 30;
/// Ratio (uncompressed / archive size) above which a large total is a bomb.
const BOMB_RATIO: u64 = 100;

/// What an entry is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Kind {
    #[default]
    File,
    Dir,
    Symlink,
    Hardlink,
    /// Device, FIFO, socket.
    Special,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Dir => "directory",
            Self::Symlink => "symlink",
            Self::Hardlink => "hardlink",
            Self::Special => "special",
        }
    }

    /// From the file-type bits of a Unix mode.
    pub fn from_mode(mode: u32) -> Self {
        match mode & 0o170_000 {
            0o040_000 => Self::Dir,
            0o120_000 => Self::Symlink,
            0o100_000 | 0 => Self::File,
            _ => Self::Special,
        }
    }
}

/// One archive entry, as every format reads it.
#[derive(Debug, Clone, Default)]
pub(crate) struct Entry {
    /// Path as stored (`/` or `\` separated).
    pub path: String,
    pub kind: Kind,
    /// Uncompressed size.
    pub size: Option<u64>,
    /// Stored (compressed) size.
    pub compressed: Option<u64>,
    /// RFC 3339 (UTC) or civil `YYYY-MM-DDTHH:MM:SS` modification time.
    pub modified: Option<String>,
    /// Unix permission bits.
    pub mode: Option<u32>,
    /// Link target.
    pub link: Option<String>,
    pub encrypted: bool,
    /// Compression method name.
    pub method: Option<String>,
}

/// Path components, `\` treated as `/`.
fn components(path: &str) -> impl Iterator<Item = &str> {
    path.split(['/', '\\']).filter(|c| !c.is_empty() && *c != ".")
}

/// Whether `path` is absolute (Unix root, drive letter, UNC).
fn is_absolute(path: &str) -> bool {
    let b = path.as_bytes();
    path.starts_with(['/', '\\']) || (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
}

/// Whether following `path` (relative to `base` components already deep)
/// climbs above the starting folder.
fn climbs(path: &str, mut depth: usize) -> bool {
    for c in components(path) {
        if c == ".." {
            if depth == 0 {
                return true;
            }
            depth -= 1;
        } else {
            depth += 1;
        }
    }
    false
}

/// The archive's inventory, built entry by entry.
#[derive(Debug, Default)]
pub(crate) struct Inventory {
    listed: Vec<Entry>,
    pub entries: u64,
    files: u64,
    dirs: u64,
    links: u64,
    size: u64,
    size_known: bool,
    compressed: u64,
    compressed_known: bool,
    encrypted: u64,
    methods: BTreeMap<String, u64>,
    types: BTreeMap<String, u64>,
    roots: BTreeMap<String, u64>,
    oldest: Option<String>,
    newest: Option<String>,
    traversal: Option<String>,
    absolute: Option<String>,
    link_escape: Option<String>,
    double_extension: Option<String>,
    /// More entries than were read (a listing limit, or the end of the
    /// readable part).
    pub truncated: bool,
}

impl Inventory {
    pub fn new() -> Self {
        Self { size_known: true, compressed_known: true, ..Self::default() }
    }

    /// Add an entry.
    pub fn push(&mut self, e: Entry) {
        self.entries += 1;
        match e.kind {
            Kind::Dir => self.dirs += 1,
            Kind::Symlink | Kind::Hardlink => self.links += 1,
            Kind::File => self.files += 1,
            Kind::Special => {}
        }
        if e.kind == Kind::File {
            match e.size {
                Some(n) => self.size = self.size.saturating_add(n),
                None => self.size_known = false,
            }
            match e.compressed {
                Some(n) => self.compressed = self.compressed.saturating_add(n),
                None => self.compressed_known = false,
            }
            if let Some(m) = &e.method {
                *self.methods.entry(m.clone()).or_default() += 1;
            }
            let name = e.path.rsplit(['/', '\\']).next().unwrap_or(&e.path);
            let ext = name.rsplit_once('.').map_or("(none)".to_string(), |(_, x)| x.to_ascii_lowercase());
            if ext.len() <= 12 {
                *self.types.entry(ext).or_default() += 1;
            }
            if self.double_extension.is_none() && risky_file_name(name) == Some("double_extension") {
                self.double_extension = Some(e.path.clone());
            }
        }
        if e.encrypted {
            self.encrypted += 1;
        }
        if let Some(root) = components(&e.path).next() {
            let has_more = components(&e.path).nth(1).is_some() || e.kind == Kind::Dir;
            let key = if has_more { format!("{root}/") } else { root.to_string() };
            *self.roots.entry(key).or_default() += 1;
        }
        if let Some(t) = e.modified.as_deref().filter(|t| t.len() >= 19) {
            // RFC 3339 and civil times sort alike on their first 19 characters.
            let t = t.to_string();
            if self.oldest.as_ref().is_none_or(|o| t[..19] < o[..19]) {
                self.oldest = Some(t.clone());
            }
            if self.newest.as_ref().is_none_or(|n| t[..19] > n[..19]) {
                self.newest = Some(t);
            }
        }
        if self.absolute.is_none() && is_absolute(&e.path) {
            self.absolute = Some(e.path.clone());
        } else if self.traversal.is_none() && climbs(&e.path, 0) {
            self.traversal = Some(e.path.clone());
        }
        if matches!(e.kind, Kind::Symlink | Kind::Hardlink)
            && self.link_escape.is_none()
            && let Some(target) = &e.link
        {
            // A symlink resolves from its own folder; a hard link from the root.
            let base = if e.kind == Kind::Symlink { components(&e.path).count().saturating_sub(1) } else { 0 };
            if is_absolute(target) || climbs(target, base) {
                self.link_escape = Some(format!("{} -> {target}", e.path));
            }
        }
        if self.listed.len() < MAX_LISTED {
            self.listed.push(e);
        }
    }

    /// Treat absolute entry paths as expected (packages whose payload names
    /// the installed paths, `/usr/local/bin/…`), not as a risk.
    pub fn allow_absolute(&mut self) {
        self.absolute = None;
    }

    /// Write the inventory into the report. `archive_bytes` is the
    /// archive's size, for the ratio.
    pub fn report(self, cx: &mut Context<'_>, archive_bytes: u64) {
        cx.physical().entries(self.entries);
        cx.format_set("files", self.files);
        if self.dirs > 0 {
            cx.format_set("directories", self.dirs);
        }
        if self.links > 0 {
            cx.format_set("links", self.links);
        }
        if self.size_known && self.entries > 0 {
            cx.physical().uncompressed_bytes(self.size);
        }
        if self.compressed_known && self.files > 0 {
            cx.format_set("compressed_bytes", self.compressed);
        }
        if self.encrypted > 0 {
            cx.physical().encrypted_entries(self.encrypted);
            cx.security().encrypted(true);
        }
        if !self.methods.is_empty() {
            cx.format_set("methods", counts(&self.methods, MAX_KEYS));
        }
        if !self.types.is_empty() {
            cx.format_set("file_types", counts(&self.types, MAX_KEYS));
        }
        if !self.roots.is_empty() {
            let mut roots: Vec<(&String, &u64)> = self.roots.iter().collect();
            roots.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
            let names: Vec<&String> = roots.iter().take(MAX_KEYS).map(|(k, _)| *k).collect();
            cx.format_set("top_level", json!(names));
        }
        if let (Some(old), Some(new)) = (self.oldest, self.newest) {
            cx.format_set("modified_range", json!([old, new]));
            let tz = new.ends_with('Z');
            cx.temporal().content_date(DateField::Modified, new, tz);
        }
        if self.truncated {
            cx.format_set("listing_truncated", true);
        }
        let listed: Vec<Value> = self.listed.iter().map(entry_json).collect();
        if !listed.is_empty() {
            cx.format_set("entries", Value::Array(listed));
        }
        if let Some(p) = self.traversal {
            cx.security().risk("path_traversal", Some(p));
        }
        if let Some(p) = self.absolute {
            cx.security().risk("absolute_path", Some(p));
        }
        if let Some(p) = self.link_escape {
            cx.security().risk("symlink_escape", Some(p));
        }
        if let Some(p) = self.double_extension {
            cx.security().risk("double_extension", Some(p));
        }
        if self.size_known && self.size >= BOMB_BYTES && self.size / archive_bytes.max(1) > BOMB_RATIO {
            cx.security().risk("decompression_bomb", Some(format!("{} bytes from {archive_bytes}", self.size)));
        }
    }
}

fn counts(map: &BTreeMap<String, u64>, max: usize) -> Value {
    let mut v: Vec<(&String, &u64)> = map.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    Value::Object(v.into_iter().take(max).map(|(k, n)| (k.clone(), json!(n))).collect())
}

fn entry_json(e: &Entry) -> Value {
    let mut m = Map::new();
    m.insert("path".into(), json!(e.path));
    if e.kind != Kind::File {
        m.insert("type".into(), json!(e.kind.as_str()));
    }
    if let Some(n) = e.size.filter(|_| e.kind == Kind::File) {
        m.insert("size_bytes".into(), json!(n));
    }
    if let Some(t) = &e.modified {
        m.insert("modified".into(), json!(t));
    }
    if let Some(mode) = e.mode {
        m.insert("mode".into(), json!(format!("{:o}", mode & 0o7777)));
    }
    if let Some(l) = &e.link {
        m.insert("link".into(), json!(l));
    }
    if e.encrypted {
        m.insert("encrypted".into(), json!(true));
    }
    Value::Object(m)
}

/// Hand an entry's data on as a child when the limits allow; `complete`
/// false means `data` is only its start. Returns `false` once no more
/// children fit.
pub(crate) fn child(cx: &mut Context<'_>, name: &str, data: Vec<u8>, complete: bool) -> Result<bool, ExtractError> {
    if cx.child_room() == 0 {
        return Ok(false);
    }
    // Windows writers separate folders with `\`.
    let name = name.replace('\\', "/");
    if complete {
        cx.emit_child(&name, data)?;
    } else {
        cx.emit_child_prefix(&name, data)?;
    }
    Ok(cx.child_room() > 0)
}

/// An entry stored without compression: (name, data offset, size).
pub(crate) type Stored = (String, u64, u64);

/// Hand stored entries on as children, in order, as far as the limits allow.
pub(crate) fn stored_children(
    src: &mut dyn Source,
    cx: &mut Context<'_>,
    stored: Vec<Stored>,
) -> Result<(), ExtractError> {
    let limit = cx.parse_limit() as u64;
    let len = src.len();
    for (name, offset, size) in stored {
        if cx.child_room() == 0 || offset >= len {
            break;
        }
        let n = size.min(limit).min(len - offset);
        let data = src.read_vec(offset, usize::try_from(n).unwrap_or(0))?;
        if !child(cx, &name, data, n == size)? {
            break;
        }
    }
    Ok(())
}

/// Whether an entry is worth handing on: a non-empty, unencrypted file.
pub(crate) fn wanted(e: &Entry) -> bool {
    e.kind == Kind::File && !e.encrypted && e.size != Some(0)
}

/// A DOS date and time as a civil `YYYY-MM-DDTHH:MM:SS`.
pub(crate) fn dos_time(date: u16, time: u16) -> Option<String> {
    let (y, mo, d) = (1980 + (date >> 9), (date >> 5) & 15, date & 31);
    let (h, mi, s) = (time >> 11, (time >> 5) & 63, (time & 31) * 2);
    ((1..=12).contains(&mo) && (1..=31).contains(&d) && h < 24 && mi < 60 && s < 60)
        .then(|| format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}"))
}

/// A 32-bit DOS stamp (date in the high half, time in the low half).
pub(crate) fn dos_stamp(stamp: u32) -> Option<String> {
    let [t0, t1, d0, d1] = stamp.to_le_bytes();
    dos_time(u16::from_le_bytes([d0, d1]), u16::from_le_bytes([t0, t1]))
}

/// Unix seconds as RFC 3339 UTC (`None` for 0 and out-of-range values).
pub(crate) fn unix_time(secs: i64) -> Option<String> {
    if secs <= 0 {
        return None;
    }
    let ts = jiff::Timestamp::from_second(secs).ok()?;
    Some(ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Windows FILETIME (100 ns since 1601) as RFC 3339 UTC.
pub(crate) fn filetime(ticks: u64) -> Option<String> {
    unix_time(i64::try_from(ticks / 10_000_000).ok()? - 11_644_473_600)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, kind: Kind, link: Option<&str>) -> Entry {
        Entry { path: path.into(), kind, link: link.map(str::to_string), size: Some(10), ..Entry::default() }
    }

    #[test]
    fn path_checks() {
        assert!(climbs("../x", 0));
        assert!(climbs("a/../../x", 0));
        assert!(!climbs("a/../b", 0));
        assert!(!climbs("a/./b/..", 0));
        assert!(climbs("..\\x", 0));
        assert!(climbs("../../etc", 1));
        assert!(!climbs("../sibling", 1));
        assert!(is_absolute("/etc/x") && is_absolute("C:\\x") && is_absolute("\\\\server\\x"));
        assert!(!is_absolute("etc/x"));
    }

    #[test]
    fn risks_and_counts() {
        let mut inv = Inventory::new();
        inv.push(entry("docs/", Kind::Dir, None));
        inv.push(entry("docs/a.txt", Kind::File, None));
        inv.push(entry("docs/up", Kind::Symlink, Some("../root.txt")));
        inv.push(entry("docs/link", Kind::Symlink, Some("../../outside")));
        inv.push(entry("docs/ok", Kind::Symlink, Some("a.txt")));
        inv.push(entry("../escape.txt", Kind::File, None));
        inv.push(entry("/abs.txt", Kind::File, None));
        inv.push(entry("invoice.pdf.exe", Kind::File, None));
        assert_eq!((inv.entries, inv.files, inv.dirs, inv.links), (8, 4, 1, 3));
        assert_eq!(inv.traversal.as_deref(), Some("../escape.txt"));
        assert_eq!(inv.absolute.as_deref(), Some("/abs.txt"));
        assert_eq!(inv.link_escape.as_deref(), Some("docs/link -> ../../outside"));
        assert_eq!(inv.double_extension.as_deref(), Some("invoice.pdf.exe"));
        assert_eq!(inv.roots.get("docs/"), Some(&5));
        assert_eq!(inv.types.get("txt"), Some(&3));
    }

    #[test]
    fn times() {
        assert_eq!(dos_time(0x5921, 0x6000).as_deref(), Some("2024-09-01T12:00:00"));
        assert_eq!(filetime(133_000_000_000_000_000).as_deref(), Some("2022-06-18T04:26:40Z"));
        assert_eq!(unix_time(0), None);
    }
}
