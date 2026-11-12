//! What a disk holds, read without mounting it: the partition table (MBR
//! with its extended partitions, GPT, the Apple Partition Map) and, for the
//! whole disk or each partition, the file system's superblock (ext2 / 3 /
//! 4, FAT12 / 16 / 32, exFAT, NTFS, HFS / HFS+ / HFSX, APFS with its
//! volumes, btrfs, XFS, ISO 9660, UDF, squashfs, swap, LVM2, LUKS,
//! BitLocker, ReFS).
//!
//! Readers go through a [`Source`], so every read is charged to the budget;
//! a disk image's virtual disk is a `Source` too, so the same code reads
//! raw images, VM disks and the partitions inside them. Only a few small,
//! fixed structures are read per volume.

mod fs;
mod partition;

use std::fmt::Write as _;

use serde_json::{Map, Value, json};

use crate::io::Source;

pub use fs::{FileSystem, filesystem, identify};
// Used by the disk extractors (feature `forensics`) and squashfs.
#[allow(unused_imports)]
pub(crate) use fs::{FatGeometry, fat_geometry, squashfs_compression};
pub use partition::{is_mbr, table};

/// Partitions described at most.
pub const MAX_PARTITIONS: usize = 128;

/// Describe a disk: its partition table and each partition's file system,
/// or the file system that fills it. Returns the facts as a JSON object
/// (`partition_table`, `disk_guid`, `partitions`, or `filesystem`); empty
/// when nothing is recognised.
pub fn describe(src: &mut dyn Source) -> Map<String, Value> {
    let mut out = Map::new();
    let len = src.len();
    if let Some(fs) = filesystem(src, 0, len)
        && fs.whole_disk()
    {
        out.insert("filesystem".into(), Value::Object(fs.facts));
        return out;
    }
    if let Some(t) = table(src) {
        out.insert("partition_table".into(), json!(t.scheme));
        if t.sector_size != 512 {
            out.insert("sector_size".into(), json!(t.sector_size));
        }
        if let Some(g) = &t.disk_id {
            let key = if t.scheme == "gpt" { "disk_guid" } else { "disk_signature" };
            out.insert(key.into(), json!(g));
        }
        if !t.notes.is_empty() {
            out.insert("partition_table_notes".into(), json!(t.notes));
        }
        let mut parts = Vec::new();
        for p in t.partitions.iter().take(MAX_PARTITIONS) {
            let mut m = p.facts();
            if p.size > 0
                && p.start < len
                && !p.container
                && let Some(fs) = filesystem(src, p.start, p.size.min(len - p.start))
            {
                m.insert("filesystem".into(), Value::Object(fs.facts));
            }
            parts.push(Value::Object(m));
        }
        out.insert("partitions".into(), Value::Array(parts));
        return out;
    }
    if let Some(fs) = filesystem(src, 0, len) {
        out.insert("filesystem".into(), Value::Object(fs.facts));
    }
    out
}

/// Little-endian and big-endian integers at fixed offsets (`None` past the end).
pub(crate) mod num {
    macro_rules! int {
        ($($name:ident, $ty:ty, $from:ident;)*) => {$(
            pub fn $name(b: &[u8], at: usize) -> Option<$ty> {
                Some(<$ty>::$from(b.get(at..at + size_of::<$ty>())?.try_into().ok()?))
            }
        )*};
    }
    int! {
        le16, u16, from_le_bytes;
        le32, u32, from_le_bytes;
        le64, u64, from_le_bytes;
        be16, u16, from_be_bytes;
        be32, u32, from_be_bytes;
        be64, u64, from_be_bytes;
    }
}

/// A fixed-size text field: up to the first NUL, trailing spaces dropped,
/// `None` when blank.
pub(crate) fn text_field(b: &[u8]) -> Option<String> {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    let s = String::from_utf8_lossy(&b[..end]);
    let s = s.trim_end_matches([' ', '\u{0}']).trim_start();
    (!s.is_empty() && !s.chars().all(|c| c == '\u{fffd}')).then(|| s.to_string())
}

/// UTF-16 (little-endian when `le`) text up to the first NUL, `None` when blank.
pub(crate) fn utf16_field(b: &[u8], le: bool) -> Option<String> {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| if le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) })
        .take_while(|&u| u != 0)
        .collect();
    let s = String::from_utf16_lossy(&units);
    let s = s.trim_end();
    (!s.is_empty()).then(|| s.to_string())
}

/// A big-endian (RFC 4122 byte order) UUID, `None` when all zero.
pub(crate) fn uuid_be(b: &[u8]) -> Option<String> {
    let b: &[u8; 16] = b.get(..16)?.try_into().ok()?;
    if b.iter().all(|&x| x == 0) {
        return None;
    }
    let h = |r: std::ops::Range<usize>| {
        b[r].iter().fold(String::new(), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
    };
    Some(format!("{}-{}-{}-{}-{}", h(0..4), h(4..6), h(6..8), h(8..10), h(10..16)))
}

/// A mixed-endian GUID (Microsoft / EFI byte order), lowercase.
pub(crate) fn guid_le(b: &[u8]) -> Option<String> {
    let b: &[u8; 16] = b.get(..16)?.try_into().ok()?;
    crate::container::cfb::guid(b).map(|g| g.to_ascii_lowercase())
}

/// Unix seconds as RFC 3339 UTC (`None` for 0 and out-of-range values).
pub(crate) fn unix_time(secs: i64) -> Option<String> {
    if secs <= 0 {
        return None;
    }
    let ts = jiff::Timestamp::from_second(secs).ok()?;
    Some(ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Seconds since 1904-01-01 (HFS) as RFC 3339 UTC.
pub(crate) fn mac_time(secs: u32) -> Option<String> {
    unix_time(i64::from(secs) - 2_082_844_800)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(text_field(b"LABEL   \0\0"), Some("LABEL".into()));
        assert_eq!(text_field(b"    "), None);
        assert_eq!(utf16_field(b"A\0B\0\0\0C\0", true), Some("AB".into()));
        assert_eq!(uuid_be(&[0; 16]), None);
        assert_eq!(
            uuid_be(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 1, 2, 3, 4, 5, 6, 7, 8]).as_deref(),
            Some("12345678-9abc-def0-0102-030405060708")
        );
        assert_eq!(num::le32(&[1, 0, 0, 0], 0), Some(1));
        assert_eq!(num::be16(&[1], 0), None);
        assert_eq!(mac_time(2_082_844_800 + 86_400).as_deref(), Some("1970-01-02T00:00:00Z"));
    }
}
