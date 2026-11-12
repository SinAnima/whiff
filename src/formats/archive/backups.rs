//! Backup and archive streams from operating systems and backup tools:
//!
//! * Apple Archive (`.aar`, `AA01`): each entry's typed fields (type,
//!   path, mode, owner, times, size) listed; the `pbz*` compressed form
//!   gives its algorithm and sizes (LZFSE is not decompressed);
//! * Android backups (`.ab`, `adb backup`): version, compression and
//!   encryption from the text header; an unencrypted backup's tar is handed
//!   on;
//! * BSD / Linux `dump` tapes: the `TS_TAPE` header (dump and previous dump
//!   dates, level, label, file system, device, host);
//! * Borg Backup repositories: the `config` file (version, segment layout,
//!   append-only, quota, whether a key is stored in it) and the `README`.
//!
//! Specifications: Apple's `AppleArchive.h` (field types) and the `pbzx`
//! chunk layout; Android's `BackupManagerService` header; `dumprestore.h` of
//! dump 0.4; Borg's repository documentation.

use super::{Entry, Inventory, Kind, child, unix_time, wanted};
use crate::plugin::{
    ByteReader, Compression, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic,
    Probe, Sniff, Source, latin1_or_utf8,
};

/// Extractor for Apple Archive, Android backup, dump and Borg files.
pub struct Backups;

static META: ExtractorMeta = ExtractorMeta {
    id: "archive.backups",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "apple_archive",
            name: "Apple Archive",
            family: "archive",
            mimes: &["application/x-apple-archive"],
            extensions: &["aar", "yaa"],
            magic: &[
                Magic::prefix(b"AA01"),
                Magic::prefix(b"YAA1"),
                Magic::prefix(b"pbze"),
                Magic::prefix(b"pbz4"),
                Magic::prefix(b"pbzx"),
                Magic::prefix(b"pbzz"),
            ],
            parent: None,
        },
        FormatSpec {
            id: "android_backup",
            name: "Android backup",
            family: "archive",
            mimes: &["application/x-android-backup"],
            extensions: &["ab"],
            magic: &[Magic::prefix(b"ANDROID BACKUP\n")],
            parent: None,
        },
        FormatSpec {
            id: "unix_dump",
            name: "Unix dump / restore tape",
            family: "archive",
            mimes: &["application/x-dump"],
            extensions: &["dump", "dmp"],
            // NFS_MAGIC (60012) in either byte order, at the TS_TAPE header.
            magic: &[Magic::at(24, b"\x6c\xea\x00\x00"), Magic::at(24, b"\x00\x00\xea\x6c")],
            parent: None,
        },
        FormatSpec {
            id: "borg_repository",
            name: "Borg Backup repository",
            family: "archive",
            mimes: &["text/x-borg-repository"],
            extensions: &[],
            magic: &[Magic::prefix(b"[repository]\n"), Magic::prefix(b"This is a Borg Backup repository.")],
            parent: None,
        },
    ],
};

const MAX_ENTRIES: usize = 1 << 16;

impl Extractor for Backups {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let borg = (h.starts_with(b"[repository]\n") && h.windows(16).any(|w| w == b"segments_per_dir"))
            || h.starts_with(b"This is a Borg Backup repository.");
        borg.then_some(Sniff { format: "borg_repository", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "apple_archive" => apple_archive(src, cx),
            "android_backup" => android_backup(src, cx),
            "unix_dump" => unix_dump(src, cx),
            _ => borg(src, cx),
        }
    }
}

crate::register_extractor!(Backups);

// --- Apple Archive -----------------------------------------------------------------

/// One field's value, by its subtype character.
enum AaValue {
    Uint(u64),
    Text(String),
    /// A blob that follows the header: its size.
    Blob(u64),
    Time(i64),
    Flag,
}

/// The fields of one `AA01` header (after the magic and size).
fn aa_fields(h: &[u8]) -> Result<Vec<([u8; 3], AaValue)>, ExtractError> {
    let mut r = ByteReader::new(h);
    let mut out = Vec::new();
    while r.remaining() >= 4 {
        let k = r.bytes(4)?;
        let key = [k[0], k[1], k[2]];
        let v = match k[3] {
            b'1' => AaValue::Uint(u64::from(r.u8()?)),
            b'2' => AaValue::Uint(u64::from(r.le_u16()?)),
            b'4' => AaValue::Uint(u64::from(r.le_u32()?)),
            b'8' => AaValue::Uint(r.le_u64()?),
            b'A' => AaValue::Blob(u64::from(r.le_u16()?)),
            b'B' => AaValue::Blob(u64::from(r.le_u32()?)),
            b'C' => AaValue::Blob(r.le_u64()?),
            b'P' => {
                let n = usize::from(r.le_u16()?);
                AaValue::Text(latin1_or_utf8(r.bytes(n)?))
            }
            b'S' => AaValue::Time(i64::try_from(r.le_u64()?).unwrap_or(0)),
            b'T' => {
                let t = AaValue::Time(i64::try_from(r.le_u64()?).unwrap_or(0));
                r.le_u32()?;
                t
            }
            b'*' => AaValue::Flag,
            // Hashes and other fixed-size values: their size is not known
            // here, so the rest of the header is not read.
            _ => break,
        };
        out.push((key, v));
    }
    Ok(out)
}

fn apple_archive(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    let h = src.read_vec(0, usize::try_from(len.min(4)).unwrap_or(0))?;
    if let Some(alg) = h.strip_prefix(b"pbz") {
        let algorithm = match alg {
            b"e" => "LZFSE",
            b"4" => "LZ4",
            b"x" => "LZMA",
            b"z" => "zlib",
            _ => "other",
        };
        cx.format_set("compression", algorithm);
        // pbz*: a big-endian chunk size, then per chunk its raw and stored
        // sizes and the data.
        let mut at = 4u64;
        let chunk = ByteReader::new(&src.read_vec(at, 8)?).be_u64()?;
        cx.format_set("chunk_bytes", chunk);
        at += 8;
        let (mut raw, mut chunks) = (0u64, 0u64);
        while at + 16 <= len && chunks < 1 << 20 {
            let b = src.read_vec(at, 16)?;
            let mut r = ByteReader::new(&b);
            let (size, stored) = (r.be_u64()?, r.be_u64()?);
            raw = raw.saturating_add(size);
            chunks += 1;
            at = at.saturating_add(16).saturating_add(stored);
        }
        cx.format_set("chunks", chunks);
        cx.physical().uncompressed_bytes(raw);
        if algorithm == "LZFSE" {
            cx.warn("the LZFSE-compressed entries are not listed");
        }
        return Ok(());
    }
    if h.as_slice() == b"YAA1" {
        cx.format_set("variant", "YAA1");
        return Ok(());
    }
    let mut inv = Inventory::new();
    let mut stored = Vec::new();
    let mut at = 0u64;
    for i in 0..MAX_ENTRIES {
        if i % 1024 == 1023 {
            cx.checkpoint()?;
        }
        if at + 6 > len {
            break;
        }
        let pre = src.read_vec(at, 6)?;
        if &pre[..4] != b"AA01" {
            cx.warn(format!("no Apple Archive header at offset {at}"));
            inv.truncated = true;
            break;
        }
        let size = u64::from(u16::from_le_bytes([pre[4], pre[5]]));
        if size < 6 {
            return Err(ExtractError::malformed("Apple Archive header size"));
        }
        let body = src.read_vec(at + 6, usize::try_from(size - 6).unwrap_or(0))?;
        let fields = aa_fields(&body)?;
        let (mut e, mut blobs, mut data) = (Entry::default(), 0u64, None);
        let mut typ = b'F';
        for (key, v) in &fields {
            match (key, v) {
                (b"TYP", AaValue::Uint(t)) => typ = u8::try_from(*t).unwrap_or(b'?'),
                (b"PAT", AaValue::Text(p)) => e.path.clone_from(p),
                (b"MOD", AaValue::Uint(m)) => e.mode = u32::try_from(*m).ok(),
                (b"MTM", AaValue::Time(t)) => e.modified = unix_time(*t),
                (b"SIZ", AaValue::Uint(n)) => e.size = Some(*n),
                (b"LNK", AaValue::Text(l)) => e.link = Some(l.clone()),
                (b"DAT", AaValue::Blob(n)) => {
                    data = Some((blobs, *n));
                    e.size = Some(*n);
                }
                _ => {}
            }
            if let AaValue::Blob(n) = v {
                blobs = blobs.saturating_add(*n);
            }
        }
        e.kind = match typ {
            b'D' => Kind::Dir,
            b'L' => Kind::Symlink,
            b'H' => Kind::Hardlink,
            b'F' => Kind::File,
            _ => Kind::Special,
        };
        let data_at = at + size;
        if e.path.is_empty() && e.kind == Kind::Dir {
            // The archive's root folder.
            at = data_at.saturating_add(blobs);
            continue;
        }
        if let Some((offset, n)) = data
            && wanted(&e)
        {
            stored.push((e.path.clone(), data_at + offset, n));
        }
        inv.push(e);
        at = data_at.saturating_add(blobs);
    }
    inv.report(cx, len);
    super::stored_children(src, cx, stored)
}

// --- Android backup -----------------------------------------------------------------

fn android_backup(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    let head = src.read_vec(0, usize::try_from(len.min(4096)).unwrap_or(0))?;
    let mut lines = head.split(|&b| b == b'\n');
    lines.next();
    let mut header_len = 15usize;
    let mut next = || -> Option<String> {
        let l = lines.next()?;
        header_len += l.len() + 1;
        Some(latin1_or_utf8(l))
    };
    let version = next().unwrap_or_default();
    let compressed = next().unwrap_or_default() == "1";
    let encryption = next().unwrap_or_default();
    cx.format_set("backup_version", version);
    cx.format_set("compressed", compressed);
    cx.format_set("encryption", encryption.clone());
    if encryption != "none" {
        cx.security().encrypted(true);
        // Salts, the PBKDF2 round count, the IV and the wrapped master key.
        let (_salt, _ck_salt, rounds) = (next(), next(), next());
        if let Some(n) = rounds.and_then(|r| r.parse::<u64>().ok()) {
            cx.format_set("pbkdf2_rounds", n);
        }
        return Ok(());
    }
    let n = len.saturating_sub(header_len as u64).min(cx.parse_limit() as u64);
    let body = src.read_vec(header_len as u64, usize::try_from(n).unwrap_or(0))?;
    let tar = if compressed { cx.inflate(&body, Compression::Zlib, cx.parse_limit())? } else { body };
    cx.format_set("tar_bytes", tar.len());
    child(cx, "backup.tar", tar, true).map(|_| ())
}

// --- dump ------------------------------------------------------------------------

fn unix_dump(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 1024)?;
    let big = h[24..28] == [0, 0, 0xea, 0x6c];
    let int = |at: usize| {
        let b = [h[at], h[at + 1], h[at + 2], h[at + 3]];
        if big { i32::from_be_bytes(b) } else { i32::from_le_bytes(b) }
    };
    let text = |at: usize, n: usize| latin1_or_utf8(h[at..at + n].split(|&b| b == 0).next().unwrap_or(&[]));
    if int(0) != 1 {
        cx.warn("the first record is not a TS_TAPE header");
    }
    if let Some(t) = unix_time(i64::from(int(4))) {
        cx.format_set("dump_date", t.clone());
        cx.temporal().content_date(DateField::Created, t, true);
    }
    if let Some(t) = unix_time(i64::from(int(8))) {
        cx.format_set("previous_dump_date", t);
    }
    cx.format_set("volume", int(12));
    cx.format_set("level", int(692));
    let label = text(676, 16);
    if !label.is_empty() && label != "none" {
        cx.format_set("label", label);
    }
    cx.format_set("file_system", text(696, 64));
    cx.format_set("device", text(760, 64));
    let host = text(824, 64);
    if !host.is_empty() && !cx.privacy_strict() {
        cx.format_set("host", host);
    }
    let flags = int(888);
    for (bit, name) in [
        (0x0001, "new_header"),
        (0x0002, "new_inode_format"),
        (0x0004, "full_inode_list"),
        (0x0008, "metadata_only"),
        (0x0080, "compressed"),
    ] {
        if flags & bit != 0 {
            cx.format_set(name, true);
        }
    }
    cx.format_set("records_per_block", int(896));
    Ok(())
}

// --- Borg ------------------------------------------------------------------------

fn borg(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let text = src.read_vec(0, usize::try_from(src.len().min(1 << 20)).unwrap_or(0))?;
    let text = String::from_utf8_lossy(&text);
    if text.starts_with("This is a Borg Backup repository.") {
        cx.format_set("file", "README");
        return Ok(());
    }
    cx.format_set("file", "config");
    let mut section = String::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            section = t.trim_matches(['[', ']']).to_string();
            continue;
        }
        let Some((k, v)) = t.split_once('=') else { continue };
        if section != "repository" {
            continue;
        }
        let (k, v) = (k.trim(), v.trim());
        match k {
            "version" | "segments_per_dir" | "max_segment_size" | "storage_quota" | "additional_free_space" => {
                if let Ok(n) = v.parse::<u64>() {
                    cx.format_set(k, n);
                }
            }
            "append_only" => cx.format_set("append_only", v == "1"),
            "id" => cx.format_set("repository_id", v),
            // A repokey repository keeps its (passphrase-protected) key
            // here: say so, never copy it.
            "key" => {
                cx.format_set("key_in_config", true);
                cx.security().encrypted(true);
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("apple_archive", "android_backup", "unix_dump", "borg_repository");

    #[test]
    fn aa_field_types() {
        let mut h = b"TYP1D".to_vec();
        h.extend(b"PATP\x05\x00notes");
        h.extend(b"MTMS");
        h.extend(1_756_728_000u64.to_le_bytes());
        h.extend(b"DATA\x10\x00");
        let f = aa_fields(&h).unwrap();
        assert_eq!(f.len(), 4);
        assert!(matches!(&f[1].1, AaValue::Text(p) if p == "notes"));
        assert!(matches!(f[3].1, AaValue::Blob(16)));
        // An unknown subtype ends the walk without an error.
        assert_eq!(aa_fields(b"SH2Hxxxx").unwrap().len(), 0);
    }
}
