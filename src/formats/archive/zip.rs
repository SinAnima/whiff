//! ZIP archives that are not a more specific ZIP-based format (those —
//! Office, OpenDocument, EPUB, packages — have their own sniffers, which
//! win): the central directory with Zip64, entry times from the extended
//! timestamp and NTFS fields, Unix modes, encryption (ZipCrypto and WinZip
//! AES), the comment, the system that made it, a self-extractor or polyglot
//! prefix, and entries whose data overlaps (an overlapping-entry zip bomb).
//! Stored, deflate, bzip2, LZMA, Zstandard and xz entries are handed on.
//!
//! Specification: PKWARE APPNOTE.TXT 6.3.10; WinZip AE-1 / AE-2.

use std::collections::BTreeMap;

use super::{Entry, Inventory, Kind, MAX_ENTRIES, child, wanted};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, Zip, ZipEntry,
    redact_sensitive, user_path, zip_method_name,
};

/// Extractor for ZIP archives.
pub struct ZipArchive;

static META: ExtractorMeta = ExtractorMeta {
    id: "archive.zip",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "zip",
        name: "ZIP archive",
        family: "archive",
        mimes: &["application/zip"],
        extensions: &["zip", "zipx"],
        magic: &[],
        parent: None,
    }],
};

/// Symbolic-link targets read at most (each is a small entry).
const MAX_LINKS_READ: usize = 1000;

fn host_name(host: u8) -> &'static str {
    match host {
        0 => "MS-DOS",
        1 => "Amiga",
        2 => "OpenVMS",
        3 => "Unix",
        5 => "Atari ST",
        6 => "OS/2",
        7 => "Macintosh",
        10 => "Windows NTFS",
        11 => "MVS",
        13 => "Acorn RISC OS",
        14 => "VFAT",
        16 => "BeOS",
        18 => "OS/400",
        19 => "macOS",
        _ => "other",
    }
}

impl Extractor for ZipArchive {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // Below every ZIP-based format's sniffer: a plain ZIP is what is left.
        [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"]
            .iter()
            .any(|m| probe.head.starts_with(*m))
            .then_some(Sniff { format: "zip", confidence: 0.5 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let zip = Zip::open(src, MAX_ENTRIES)?;
        zip.flag_duplicates(cx);
        if !zip.comment.trim().is_empty() {
            cx.format_set("comment", zip.comment.trim());
            cx.content().description(zip.comment.trim());
        }
        if zip.zip64 {
            cx.format_set("zip64", true);
        }
        if zip.prefix_bytes > 0 {
            // A self-extractor stub, or data put in front of the archive.
            cx.format_set("prefix_bytes", zip.prefix_bytes);
        }
        if zip.declared_entries != zip.entries.len() as u64 && !zip.truncated {
            cx.format_set("declared_entries", zip.declared_entries);
        }
        let mut hosts: BTreeMap<&str, u64> = BTreeMap::new();
        let mut encryption: Vec<String> = Vec::new();
        let mut apple_double = 0u64;
        let mut inv = Inventory::new();
        inv.truncated = zip.truncated;
        let mut links_read = 0;
        for e in &zip.entries {
            *hosts.entry(host_name(e.host)).or_default() += 1;
            if e.is_encrypted() {
                let kind = match e.aes {
                    None => "ZipCrypto".to_string(),
                    Some((0, _)) => "AES (unknown strength)".to_string(),
                    Some((bits, _)) => format!("AES-{bits}"),
                };
                if !encryption.contains(&kind) {
                    encryption.push(kind);
                }
            }
            if e.name.starts_with("__MACOSX/") {
                apple_double += 1;
            }
            let mut entry = entry(e);
            if entry.kind == Kind::Symlink && links_read < MAX_LINKS_READ && e.size <= 4096 {
                links_read += 1;
                if let Ok(target) = zip.read(src, e, cx, 4096) {
                    let target = String::from_utf8_lossy(&target);
                    // A target can name a profile folder or carry a secret.
                    entry.link = Some(if cx.privacy_strict() {
                        redact_sensitive(&user_path(cx, &target)).into_owned()
                    } else {
                        target.into_owned()
                    });
                }
            }
            inv.push(entry);
        }
        if let Some((host, _)) = hosts.iter().max_by_key(|(_, n)| **n) {
            cx.format_set("created_on", *host);
        }
        if !encryption.is_empty() {
            cx.format_set("encryption", encryption);
        }
        if apple_double > 0 {
            cx.format_set("macos_metadata_entries", apple_double);
        }
        let overlaps = overlapping(&zip.entries);
        if overlaps > 0 {
            cx.security().risk("overlapping_entries", Some(format!("{overlaps} entries share data with another")));
        }
        inv.report(cx, src.len());
        if overlaps > 0 {
            // Every entry would decompress the same bytes again.
            return Ok(());
        }
        children(src, cx, &zip)
    }
}

crate::register_extractor!(ZipArchive);

pub(crate) fn entry(e: &ZipEntry) -> Entry {
    let kind = if e.is_dir() {
        Kind::Dir
    } else if e.is_symlink() {
        Kind::Symlink
    } else {
        e.unix_mode.map_or(Kind::File, Kind::from_mode)
    };
    Entry {
        path: e.name.clone(),
        kind,
        size: Some(e.size),
        compressed: Some(e.compressed_size),
        modified: e.modified_utc.clone().or_else(|| e.modified.clone()),
        mode: e.unix_mode.map(|m| m & 0o7777).filter(|_| kind != Kind::Symlink),
        link: None,
        encrypted: e.is_encrypted(),
        method: Some(zip_method_name(e.real_method())),
    }
}

/// Entries whose data starts inside another entry's (the overlapping-file
/// construction of David Fifield's zip bombs). Local extra fields are not
/// read, so the estimate errs towards no overlap.
fn overlapping(entries: &[ZipEntry]) -> usize {
    let mut spans: Vec<(u64, u64)> = entries
        .iter()
        .filter(|e| !e.is_dir() && e.compressed_size > 0)
        .map(|e| (e.local_offset, e.min_data_offset.saturating_add(e.compressed_size)))
        .collect();
    spans.sort_unstable();
    spans.windows(2).filter(|w| w[1].0 < w[0].1).count()
}

/// Hand the readable entries on, in order, as far as the limits allow.
pub(crate) fn children(src: &mut dyn Source, cx: &mut Context<'_>, zip: &Zip) -> Result<(), ExtractError> {
    let limit = cx.parse_limit();
    let mut unreadable = 0u64;
    for e in &zip.entries {
        if cx.child_room() == 0 {
            break;
        }
        if !wanted(&entry(e)) || e.name.starts_with("__MACOSX/") {
            continue;
        }
        cx.checkpoint()?;
        match zip.read_prefix(src, e, cx, limit) {
            Ok((data, complete)) => {
                if !child(cx, &e.name, data, complete)? {
                    break;
                }
            }
            Err(ExtractError::Timeout) => return Err(ExtractError::Timeout),
            Err(_) => unreadable += 1,
        }
    }
    if unreadable > 0 {
        cx.format_set("unreadable_entries", unreadable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(local: u64, data: u64, csize: u64) -> ZipEntry {
        ZipEntry {
            name: "x".into(),
            method: 8,
            flags: 0,
            compressed_size: csize,
            size: csize * 10,
            crc32: 0,
            local_offset: local,
            modified: None,
            unix_mode: None,
            host: 3,
            modified_utc: None,
            aes: None,
            min_data_offset: data,
            dos_attributes: 0,
        }
    }

    #[test]
    fn overlaps() {
        assert_eq!(overlapping(&[at(0, 31, 100), at(131, 162, 5)]), 0);
        // Fifield: every entry's data runs into the next local header.
        assert_eq!(overlapping(&[at(0, 31, 1000), at(40, 71, 960), at(80, 111, 920)]), 2);
        assert_eq!(overlapping(&[at(0, 31, 10), at(0, 31, 10)]), 1);
    }

    /// `zip` with entry `index` made on Unix with mode `mode`.
    fn with_unix_mode(mut zip: Vec<u8>, index: usize, mode: u32) -> Vec<u8> {
        let mut at = 0;
        for _ in 0..=index {
            at += zip[at..].windows(4).position(|w| w == b"PK\x01\x02").unwrap() + 1;
        }
        let at = at - 1;
        zip[at + 5] = 3;
        zip[at + 38..at + 42].copy_from_slice(&(mode << 16).to_le_bytes());
        zip
    }

    #[test]
    fn duplicate_names_are_a_risk() {
        let z = crate::plugin::testing::zip(&[("a.txt", b"one", false), ("a.txt", b"two", false)]);
        let r = crate::plugin::testing::report_for("twice.zip", &z);
        let risk = r.security.risks.iter().find(|x| x.kind == "duplicate_entry_names").expect("risk");
        assert_eq!(risk.detail.as_deref(), Some("1 entry repeats an earlier name; the last is read"));
    }

    #[test]
    fn symlink_targets_hide_the_user_under_strict_privacy() {
        let z = crate::plugin::testing::zip(&[("key", b"/Users/alice/.ssh/id_ed25519", false)]);
        let z = with_unix_mode(z, 0, 0o120_777);
        let strict = crate::plugin::testing::report_for("links.zip", &z);
        let json = serde_json::to_string(&strict).unwrap();
        assert!(json.contains("/Users/[user]/.ssh/id_ed25519"), "{json}");
        assert!(!json.contains("alice"));
        let off = crate::plugin::testing::report_without_privacy("links.zip", &z);
        assert!(serde_json::to_string(&off).unwrap().contains("/Users/alice/.ssh/id_ed25519"));
    }

    crate::fixture_tests!("zip");
}
