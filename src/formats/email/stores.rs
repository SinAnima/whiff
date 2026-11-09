//! Mail stores:
//!
//! * Outlook data files (PST / OST / PAB): content type, ANSI / Unicode /
//!   4K-page layout, data version, encryption, declared file size (the
//!   header only; the node and block trees are not walked);
//! * Lotus Notes databases (NSF / NTF): on-disk structure version and the
//!   Notes release it belongs to, declared size (the header only);
//! * Outlook Express folders (DBX): messages or folder index, item count;
//! * Outlook for Mac archives (OLM): accounts, folders, messages, contacts,
//!   calendar items and the range of message dates;
//! * Mork databases (Thunderbird / Mozilla address books and mail
//!   summaries): tables, rows and column names; the rows' values only with
//!   `--privacy off`.
//!
//! Specifications: [MS-PST] and libpff's PFF notes; libnsfdb's NSF notes;
//! the Outlook Express DBX notes; Mozilla's Mork notes (`mork.txt`).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, Zip, zip_names,
};

/// Extractor for mail stores.
pub struct Stores;

const PST: &[u8] = b"!BDN";
const DBX: &[u8] = b"\xcf\xad\x12\xfe";
const MORK: &[u8] = b"// <!-- <mdb:mork:z";

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, [$($ext:literal),*], [$($magic:expr),*]) => {
        FormatSpec { id: $id, name: $name, family: "email", mimes: &[$mime], extensions: &[$($ext),*], magic: &[$($magic),*], parent: None }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "email.stores",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!(
            "pst",
            "Outlook data file (PST / OST)",
            "application/vnd.ms-outlook-pst",
            ["pst", "ost", "pab"],
            [Magic::prefix(PST)]
        ),
        spec!("lotus_notes", "Lotus Notes database", "application/vnd.lotus-notes", ["ntf"], []),
        spec!("dbx", "Outlook Express folder (DBX)", "application/octet-stream", ["dbx"], [Magic::prefix(DBX)]),
        spec!("olm", "Outlook for Mac archive (OLM)", "application/zip", ["olm"], []),
        spec!("mork", "Mork database", "text/x-mork", ["mab", "msf"], [Magic::prefix(MORK)]),
    ],
};

/// Names listed.
const MAX_LISTED: usize = 50;

impl Extractor for Stores {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let pick = |format: &'static str| Some(Sniff { format, confidence: 0.97 });
        if h.starts_with(PST) && h.len() > 10 && matches!(&h[8..10], b"SM" | b"SO" | b"AB") {
            return pick("pst");
        }
        if h.starts_with(DBX) {
            return pick("dbx");
        }
        if h.starts_with(MORK) {
            return pick("mork");
        }
        // NSF: 0x1A 0x00, the header size, then an ODS version Notes knows.
        let ext = probe.extension.unwrap_or("");
        if h.len() >= 10
            && h.starts_with(b"\x1a\x00")
            && (ext.eq_ignore_ascii_case("nsf") || ext.eq_ignore_ascii_case("ntf"))
            && notes_release(u32::from_le_bytes([h[6], h[7], h[8], h[9]])).is_some()
        {
            return pick("lotus_notes");
        }
        if h.starts_with(b"PK\x03\x04") {
            let names = zip_names(probe, 2000);
            if names.iter().any(|n| n.contains("com.microsoft.__Messages") || n.contains("com.microsoft.__Contacts")) {
                return pick("olm");
            }
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "olm" => olm(src, cx),
            "mork" => {
                let (b, cut) = cx.read_bytes(src)?;
                if cut {
                    cx.format_set("truncated", true);
                }
                mork(cx, &String::from_utf8_lossy(&b));
                Ok(())
            }
            id => {
                let size = src.len();
                let head = src.read_vec(0, usize::try_from(size.min(4096)).unwrap_or(0))?;
                match id {
                    "pst" => pst(cx, &head, size),
                    "dbx" => dbx(cx, &head),
                    _ => nsf(cx, &head, size),
                }
                Ok(())
            }
        }
    }
}

crate::register_extractor!(Stores);

fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn le64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

// --- PST / OST ----------------------------------------------------------------------------------

fn pst(cx: &mut Context<'_>, h: &[u8], size: u64) {
    let kind = match h.get(8..10) {
        Some(b"SM") => "PST (personal folders)",
        Some(b"SO") => "OST (offline folders)",
        Some(b"AB") => "PAB (personal address book)",
        _ => "unknown",
    };
    cx.format_set("content_type", kind);
    let Some(version) = le16(h, 10) else { return };
    cx.format_set("data_version", version);
    let (layout, unicode) = match version {
        14 | 15 => ("ANSI (32-bit)", false),
        21 | 23 => ("Unicode (64-bit)", true),
        36 => ("Unicode with 4 KiB pages", true),
        _ => ("unknown", version > 15),
    };
    cx.format_set("layout", layout);
    if let Some(c) = le16(h, 12) {
        cx.format_set("content_version", c);
    }
    let (size_at, crypt_at) = if unicode { (184, 513) } else { (168, 461) };
    let declared = if unicode { le64(h, size_at) } else { le32(h, size_at).map(u64::from) };
    if let Some(d) = declared {
        cx.format_set("declared_size_bytes", d);
        if d > size {
            cx.warn(format!("the header declares {d} bytes, the file has {size}"));
        }
    }
    if let Some(&e) = h.get(crypt_at) {
        let name = match e {
            0 => "none",
            1 => "compressible (permutation)",
            2 => "high (cyclic)",
            0x10 => "Windows Information Protection",
            _ => "unknown",
        };
        cx.format_set("encryption", name);
    }
    let sentinel = if unicode { 512 } else { 460 };
    cx.format_set("header_valid", h.get(sentinel) == Some(&0x80));
}

// --- Lotus Notes ------------------------------------------------------------------------------------

/// The Notes release an on-disk structure (ODS) version belongs to.
fn notes_release(ods: u32) -> Option<&'static str> {
    Some(match ods {
        16 => "Notes 1.x / 2.x",
        17 => "Notes 3.x",
        20 => "Notes 4.x",
        41 => "Notes 5.x",
        43 => "Notes 6 – 8",
        48 => "Notes 8",
        51 => "Notes 8.5",
        52 => "Notes 9",
        53..=55 => "Domino 10 – 12",
        _ => return None,
    })
}

fn nsf(cx: &mut Context<'_>, h: &[u8], size: u64) {
    // A 6-byte file header (signature, database header size), then DBINFO.
    if let Some(n) = le32(h, 2) {
        cx.format_set("header_size_bytes", n);
    }
    if let Some(ods) = le32(h, 6) {
        cx.format_set("ods_version", ods);
        if let Some(r) = notes_release(ods) {
            cx.format_set("release", r);
        }
    }
    if let Some(n) = le32(h, 6 + 82) {
        let declared = u64::from(n) * 256;
        cx.format_set("declared_size_bytes", declared);
        if declared > size.saturating_add(256) {
            cx.warn(format!("the header declares {declared} bytes, the file has {size}"));
        }
    }
}

// --- Outlook Express ---------------------------------------------------------------------------------

fn dbx(cx: &mut Context<'_>, h: &[u8]) {
    let kind = match h.get(4..8) {
        Some(b"\xc5\xfd\x74\x6f") => "messages",
        Some(b"\xc6\xfd\x74\x6f") => "folder list",
        Some(b"\xc7\xfd\x74\x6f") => "pop3uidl",
        Some(b"\x30\x9d\xfe\x26") => "offline",
        _ => "unknown",
    };
    cx.format_set("kind", kind);
    if let Some(n) = le32(h, 0xC4) {
        cx.format_set("items", n);
    }
}

fn is_xml(name: &str) -> bool {
    std::path::Path::new(name).extension().is_some_and(|x| x.eq_ignore_ascii_case("xml"))
}

// --- Outlook for Mac -------------------------------------------------------------------------------

fn olm(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let zip = Zip::open(src, 1 << 20)?;
    let (mut accounts, mut folders, mut messages) = (BTreeSet::new(), BTreeSet::new(), Vec::new());
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    for e in &zip.entries {
        let n = e.name.as_str();
        if let Some(rest) = n.strip_prefix("Accounts/")
            && let Some(acct) = rest.split('/').next()
        {
            accounts.insert(acct.to_string());
        }
        if let Some(p) = n.find("com.microsoft.__Messages/") {
            let after = &n[p + 25..];
            if let Some((folder, file)) = after.rsplit_once('/') {
                folders.insert(folder.to_string());
                if file.starts_with("message_") && is_xml(file) {
                    messages.push(e.clone());
                }
            }
        } else if n.contains("com.microsoft.__Contacts") && is_xml(n) {
            *counts.entry("contact_files").or_default() += 1;
        } else if n.contains("com.microsoft.__Calendar") && is_xml(n) {
            *counts.entry("calendar_files").or_default() += 1;
        } else if n.contains("com.microsoft.__Tasks") && is_xml(n) {
            *counts.entry("task_files").or_default() += 1;
        } else if n.contains("com.microsoft.__Notes") && is_xml(n) {
            *counts.entry("note_files").or_default() += 1;
        }
    }
    let mut dates = Vec::new();
    for e in messages.iter().take(500) {
        cx.checkpoint()?;
        let Ok(b) = zip.read(src, e, cx, 1 << 20) else { continue };
        let t = String::from_utf8_lossy(&b);
        for tag in ["<OPFMessageCopySentTime>", "<OPFMessageCopyReceivedTime>"] {
            if let Some(p) = t.find(tag) {
                dates.extend(t[p + tag.len()..].get(..10).map(str::to_string));
                break;
            }
        }
    }
    dates.sort();
    let shown: Vec<Value> = accounts.iter().take(MAX_LISTED).map(|a| cx.mailbox(None, Some(a))).collect();
    cx.format_set("accounts", shown);
    cx.format_set("folders", folders.len());
    cx.format_set("folder_names", folders.into_iter().take(MAX_LISTED).collect::<Vec<_>>());
    cx.format_set("messages", messages.len());
    cx.format_set("other", json!(counts));
    if let (Some(a), Some(b)) = (dates.first(), dates.last()) {
        cx.format_set("date_range", json!([a, b]));
    }
    Ok(())
}

// --- Mork ----------------------------------------------------------------------------------------------

/// A Mork value: `\)` and `\\` escapes, `$XX` hex bytes, `\` line joins.
fn unescape(v: &str) -> String {
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if i + 1 < b.len() => {
                if b[i + 1] == b'\n' || b[i + 1] == b'\r' {
                    i += 2;
                    while i < b.len() && matches!(b[i], b'\n' | b'\r' | b' ') {
                        i += 1;
                    }
                    continue;
                }
                out.push(b[i + 1]);
                i += 2;
            }
            b'$' if i + 2 < b.len() => {
                if let Ok(x) = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                    out.push(x);
                    i += 3;
                } else {
                    out.push(b'$');
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The `( … )` cell starting at `b[i]`; returns its content and the index after it.
fn cell(b: &[u8], i: usize) -> (String, usize) {
    let mut j = i + 1;
    while j < b.len() && b[j] != b')' {
        if b[j] == b'\\' {
            j += 1;
        }
        j += 1;
    }
    (String::from_utf8_lossy(&b[i + 1..j.min(b.len())]).into_owned(), (j + 1).min(b.len()))
}

/// A Mork row being read: its id and cells.
type Row = (String, Map<String, Value>);

#[allow(clippy::too_many_lines)] // a small tokenizer
fn mork(cx: &mut Context<'_>, text: &str) {
    if let Some(v) = text.find("v=\"").map(|p| &text[p + 3..]).and_then(|r| r.split('"').next()) {
        cx.format_set("mork_version", v);
    }
    let b = text.as_bytes();
    let (mut columns, mut atoms) = (BTreeMap::<String, String>::new(), BTreeMap::<String, String>::new());
    let mut rows: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let (mut tables, mut groups) = (0u64, 0u64);
    // Context: inside a dict (`<`, columns or atoms) or a row (`[`).
    let (mut dict_depth, mut column_dict, mut row): (u32, bool, Option<Row>) = (0, false, None);
    let mut i = 0;
    let mut steps = 0usize;
    while i < b.len() && steps < 5_000_000 {
        steps += 1;
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                i = b[i..].iter().position(|&c| c == b'\n').map_or(b.len(), |p| i + p + 1);
            }
            b'<' => {
                dict_depth += 1;
                // `<(a=c)>` marks the dict that follows as the column dict.
                if b[i + 1..].starts_with(b"(a=c)>") {
                    column_dict = true;
                    dict_depth -= 1;
                    i += 7;
                    continue;
                }
                i += 1;
            }
            b'>' => {
                dict_depth = dict_depth.saturating_sub(1);
                if dict_depth == 0 {
                    column_dict = false;
                }
                i += 1;
            }
            b'{' => {
                // `{(k^81:c)(s=9)}` inside a table header is its meta-table.
                if b[i + 1..].iter().find(|c| !c.is_ascii_whitespace()) != Some(&b'(') {
                    tables += 1;
                }
                i += 1;
            }
            b'@' if b[i..].starts_with(b"@$${") => {
                groups += 1;
                i += 4;
            }
            b'[' => {
                let end = b[i + 1..]
                    .iter()
                    .position(|&c| matches!(c, b'(' | b']' | b' ' | b'\n'))
                    .map_or(b.len(), |p| i + 1 + p);
                let id = String::from_utf8_lossy(&b[i + 1..end])
                    .trim_start_matches('-')
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .to_string();
                row = Some((id, Map::new()));
                i = end;
            }
            b']' => {
                if let Some((id, cells)) = row.take()
                    && rows.len() < 100_000
                {
                    rows.entry(id).or_default().extend(cells);
                }
                i += 1;
            }
            b'(' => {
                let (c, next) = cell(b, i);
                i = next;
                if let Some((_, cells)) = row.as_mut() {
                    // `(^col^atom)`, `(^col=value)`, `(col=value)`.
                    let c = c.trim_start_matches('^');
                    let (col, value) = if let Some((col, atom)) = c.split_once('^') {
                        (col, atoms.get(atom).cloned().unwrap_or_default())
                    } else if let Some((col, v)) = c.split_once('=') {
                        (col, unescape(v))
                    } else {
                        continue;
                    };
                    let name = columns.get(col).cloned().unwrap_or_else(|| col.to_string());
                    if cells.len() < 200 {
                        cells.insert(name, json!(value));
                    }
                } else if dict_depth > 0
                    && let Some((k, v)) = c.split_once('=')
                {
                    let target = if column_dict { &mut columns } else { &mut atoms };
                    if target.len() < 200_000 {
                        target.insert(k.trim().to_string(), unescape(v));
                    }
                }
            }
            _ => i += 1,
        }
    }
    let mut used: BTreeSet<String> = BTreeSet::new();
    for r in rows.values() {
        used.extend(r.keys().cloned());
    }
    let book = used.iter().any(|c| c == "PrimaryEmail" || c == "DisplayName" || c == "FirstName");
    let summary = used.iter().any(|c| c == "message-id" || c == "subject" || c == "sender");
    cx.format_set(
        "kind",
        if book {
            "address book"
        } else if summary {
            "mail folder summary"
        } else {
            "database"
        },
    );
    cx.format_set("tables", tables);
    cx.format_set("rows", rows.len());
    if groups > 0 {
        cx.format_set("transaction_groups", groups);
    }
    cx.format_set("columns", used.iter().take(200).cloned().collect::<Vec<_>>());
    if book {
        cx.format_set(
            "cards",
            rows.values().filter(|r| r.contains_key("PrimaryEmail") || r.contains_key("DisplayName")).count(),
        );
    }
    if !cx.privacy_strict() {
        let list: Vec<Value> = rows.into_values().filter(|r| !r.is_empty()).take(200).map(Value::Object).collect();
        cx.format_set("row_list", list);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("pst", "lotus_notes", "dbx", "olm", "mork");

    #[test]
    fn mork_values() {
        assert_eq!(unescape(r"a\)b$41"), "a)bA");
        assert_eq!(notes_release(43), Some("Notes 6 – 8"));
    }

    /// Address-book values appear only with `--privacy off` (neutral sample).
    #[test]
    fn mork_follows_privacy() {
        let mab = b"// <!-- <mdb:mork:z v=\"1.4\"/> -->\n< <(a=c)> (80=DisplayName)(81=PrimaryEmail)>\n<(90=Alpha Beta)(91=a@example.org)>\n{1:^80 [1(^80^90)(^81^91)]}\n";
        let strict = serde_json::to_string(&crate::plugin::testing::report_for("abook.mab", mab)).unwrap();
        assert!(!strict.contains("Alpha Beta") && !strict.contains("a@example.org"));
        assert!(strict.contains("PrimaryEmail"));
        let off = serde_json::to_string(&crate::plugin::testing::report_without_privacy("abook.mab", mab)).unwrap();
        assert!(off.contains("Alpha Beta") && off.contains("a@example.org"));
    }
}
