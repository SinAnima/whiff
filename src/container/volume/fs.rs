//! File-system superblocks: what kind of file system a volume holds, its
//! label, UUID, block size, size and free space, and the times it records
//! (created, written, mounted, checked). Only fixed structures are read;
//! where the label lives outside the superblock (NTFS `$Volume`, the HFS+
//! catalog's root folder, APFS volume superblocks found through the
//! object map, the FAT / exFAT root directory) that one record is read too.
//!
//! Specifications: the ext4 disk layout (kernel.org wiki); Microsoft FAT
//! specification (2005) and exFAT specification; NTFS documentation from
//! the Linux-NTFS project; Apple TN1150 (HFS+) and the Apple File System
//! Reference (2020); btrfs on-disk format (btrfs wiki); XFS algorithms &
//! data structures; ECMA-119 / ECMA-167; squashfs-tools `squashfs_fs.h`;
//! LUKS1 / LUKS2 on-disk format specifications; LVM2 `label.h` and
//! `format_text/layout.h`.

use serde_json::{Map, Value, json};

use super::num::{be16, be32, be64, le16, le32, le64};
use super::{mac_time, text_field, unix_time, utf16_field, uuid_be};
use crate::io::Source;

/// Bytes read from the start of a volume to identify it (btrfs keeps its
/// superblock at 64 KiB).
const PROBE: u64 = 0x11000;

/// A recognised file system.
#[derive(Debug, Clone)]
pub struct FileSystem {
    /// `ext4`, `fat32`, `ntfs`, `apfs` …
    pub kind: &'static str,
    /// The facts, `type` first.
    pub facts: Map<String, Value>,
}

impl FileSystem {
    /// Whether finding this file system at the start of a disk means the
    /// disk is just this volume (ISO 9660 and UDF images often carry a
    /// partition table too, for USB booting).
    pub fn whole_disk(&self) -> bool {
        !matches!(self.kind, "iso9660" | "udf")
    }
}

/// Recognise the file system at `offset` (a volume of `len` bytes).
pub fn filesystem(src: &mut dyn Source, offset: u64, len: u64) -> Option<FileSystem> {
    let n = usize::try_from(len.min(PROBE)).ok()?;
    let buf = src.read_vec(offset, n).ok()?;
    let kind = identify(&buf).or_else(|| (buf.get(0x10040..0x10048) == Some(b"_BHRfS_M")).then_some("btrfs"))?;
    let mut f = Facts::new(kind);
    let v = Volume { src, offset, len, buf: &buf };
    match kind {
        "ext2" | "ext3" | "ext4" => ext(&v, &mut f),
        "fat12" | "fat16" | "fat32" => fat(v, &mut f),
        "exfat" => exfat(v, &mut f),
        "ntfs" => ntfs(v, &mut f),
        "hfs" | "hfs_plus" | "hfsx" => hfs(v, &mut f),
        "apfs" => apfs(v, &mut f),
        "btrfs" => btrfs(&buf, &mut f),
        "xfs" => xfs(&buf, &mut f),
        "iso9660" => iso9660(&buf, &mut f),
        "squashfs" => squashfs(&buf, &mut f),
        "swap" => swap(&buf, &mut f),
        "lvm2" => lvm2(v, &mut f),
        "luks" => luks(&buf, &mut f),
        "bitlocker" => {
            f.set("encrypted", true);
            Some(())
        }
        _ => Some(()),
    };
    Some(FileSystem { kind, facts: f.0 })
}

/// Name the file system whose first bytes are `b` (at least 64 KiB for
/// the ones identified further in).
pub fn identify(b: &[u8]) -> Option<&'static str> {
    let at = |o: usize, sig: &[u8]| b.get(o..o + sig.len()) == Some(sig);
    if at(0, b"LUKS\xba\xbe") {
        return Some("luks");
    }
    if at(3, b"-FVE-FS-") {
        return Some("bitlocker");
    }
    if at(3, b"NTFS    ") && le16(b, 11).is_some_and(|s| s.is_power_of_two() && s >= 256) {
        return Some("ntfs");
    }
    if at(3, b"EXFAT   ") {
        return Some("exfat");
    }
    if at(3, b"ReFS\0\0\0\0") {
        return Some("refs");
    }
    if at(0, b"XFSB") && be32(b, 4).is_some_and(|s| s.is_power_of_two() && (512..=65536).contains(&s)) {
        return Some("xfs");
    }
    if at(0, b"hsqs") && le16(b, 28) == Some(4) {
        return Some("squashfs");
    }
    if at(32, b"NXSB") {
        return Some("apfs");
    }
    if let Some(kind) = ext_kind(b) {
        return Some(kind);
    }
    match b.get(1024..1026) {
        Some(b"H+") if be16(b, 1026) == Some(4) => return Some("hfs_plus"),
        Some(b"HX") if be16(b, 1026) == Some(5) => return Some("hfsx"),
        Some(b"BD") if be32(b, 1024 + 20).is_some_and(|s| s > 0 && s % 512 == 0) => return Some("hfs"),
        _ => {}
    }
    if at(32769, b"CD001") {
        return Some("iso9660");
    }
    if at(32769, b"BEA01") || at(32769, b"NSR02") || at(32769, b"NSR03") {
        return Some("udf");
    }
    if at(512, b"LABELONE") && at(512 + 24, b"LVM2 001") {
        return Some("lvm2");
    }
    for page in [4096usize, 8192, 16384, 65536] {
        if at(page - 10, b"SWAPSPACE2") || at(page - 10, b"SWAP-SPACE") {
            return Some("swap");
        }
    }
    fat_geometry(b).map(|g| g.kind)
}

/// The volume being read: the source, where the volume starts, its length,
/// and its first bytes.
struct Volume<'v, 's> {
    src: &'v mut (dyn Source + 's),
    offset: u64,
    len: u64,
    buf: &'v [u8],
}

impl Volume<'_, '_> {
    /// Read `n` bytes at `at` within the volume.
    fn read(&mut self, at: u64, n: usize) -> Option<Vec<u8>> {
        if at.checked_add(n as u64)? > self.len {
            return None;
        }
        self.src.read_vec(self.offset + at, n).ok()
    }
}

/// The facts being collected.
struct Facts(Map<String, Value>);

impl Facts {
    fn new(kind: &str) -> Self {
        let mut m = Map::new();
        m.insert("type".into(), json!(kind));
        Self(m)
    }

    fn set(&mut self, key: &str, v: impl Into<Value>) {
        self.0.insert(key.into(), v.into());
    }

    fn opt(&mut self, key: &str, v: Option<impl Into<Value>>) {
        if let Some(v) = v {
            self.set(key, v);
        }
    }

    fn sizes(&mut self, block: u64, blocks: u64, free: Option<u64>) {
        self.set("block_size", block);
        self.set("size_bytes", block.saturating_mul(blocks));
        if let Some(free) = free.filter(|&f| f <= blocks) {
            self.set("free_bytes", block.saturating_mul(free));
        }
    }
}

fn unix32(b: &[u8], at: usize) -> Option<String> {
    unix_time(i64::from(le32(b, at)?))
}

// ---------------------------------------------------------------- ext2/3/4

fn ext_kind(b: &[u8]) -> Option<&'static str> {
    let s = b.get(1024..2048)?;
    if le16(s, 56)? != 0xEF53 || le32(s, 24)? > 6 || le32(s, 0)? == 0 || le32(s, 4)? == 0 || le32(s, 76)? > 1 {
        return None;
    }
    let (compat, incompat) = (le32(s, 92)?, le32(s, 96)?);
    // extents, 64bit, flex_bg, inline data, meta_bg-free ext4 features.
    Some(if incompat & (0x40 | 0x80 | 0x200 | 0x8000) != 0 {
        "ext4"
    } else if compat & 0x4 != 0 {
        "ext3"
    } else {
        "ext2"
    })
}

fn ext(v: &Volume<'_, '_>, f: &mut Facts) -> Option<()> {
    let s = v.buf.get(1024..2048)?;
    let incompat = le32(s, 96)?;
    let wide = incompat & 0x80 != 0 && le16(s, 0xFE).unwrap_or(0) >= 64;
    let hi = |at: usize| if wide { u64::from(le32(s, at).unwrap_or(0)) << 32 } else { 0 };
    let blocks = u64::from(le32(s, 4)?) | hi(0x150);
    let free = u64::from(le32(s, 12)?) | hi(0x158);
    f.opt("label", text_field(&s[120..136]));
    f.opt("uuid", uuid_be(&s[104..120]));
    f.sizes(1024 << le32(s, 24)?, blocks, Some(free));
    f.set("inodes", le32(s, 0)?);
    f.set("free_inodes", le32(s, 16)?);
    f.opt("created", unix32(s, 0x108));
    f.opt("written", unix32(s, 48));
    f.opt("mounted", unix32(s, 44));
    f.opt("checked", unix32(s, 64));
    f.opt("last_mount_point", text_field(&s[136..200]));
    f.set("mount_count", le16(s, 52)?);
    f.set(
        "state",
        match le16(s, 58)? {
            1 => "clean",
            2 => "errors",
            _ => "not clean",
        },
    );
    let os = match le32(s, 72)? {
        0 => "Linux",
        1 => "Hurd",
        2 => "Masix",
        3 => "FreeBSD",
        4 => "Lites",
        _ => "other",
    };
    f.set("creator_os", os);
    let (compat, ro) = (le32(s, 92)?, le32(s, 100)?);
    let mut features = Vec::new();
    for (flags, bit, name) in [
        (compat, 0x4, "has_journal"),
        (compat, 0x20, "dir_index"),
        (incompat, 0x2, "filetype"),
        (incompat, 0x40, "extents"),
        (incompat, 0x80, "64bit"),
        (incompat, 0x200, "flex_bg"),
        (incompat, 0x8000, "inline_data"),
        (incompat, 0x1_0000, "encrypt"),
        (incompat, 0x2_0000, "casefold"),
        (ro, 0x1, "sparse_super"),
        (ro, 0x8, "huge_file"),
        (ro, 0x400, "metadata_csum"),
        (ro, 0x2000, "project"),
        (ro, 0x8000, "verity"),
    ] {
        if flags & bit != 0 {
            features.push(name);
        }
    }
    f.set("features", features);
    if incompat & 0x4 != 0 {
        f.set("needs_recovery", true);
    }
    if incompat & 0x1_0000 != 0 {
        f.set("encryption_enabled", true);
    }
    Some(())
}

// ---------------------------------------------------------------- FAT

/// FAT boot-sector geometry, in sectors.
pub(crate) struct FatGeometry {
    pub kind: &'static str,
    pub sector: u32,
    pub cluster_sectors: u32,
    pub reserved: u32,
    pub fats: u32,
    pub fat_sectors: u32,
    pub root_entries: u32,
    pub total: u32,
    pub clusters: u32,
    /// FAT32: the root directory's first cluster.
    pub root_cluster: u32,
}

impl FatGeometry {
    /// Byte offset of the root directory (FAT12 / 16) or the data area.
    pub fn root_dir(&self) -> u64 {
        (u64::from(self.reserved) + u64::from(self.fats) * u64::from(self.fat_sectors)) * u64::from(self.sector)
    }

    /// Byte offset of the data area (cluster 2).
    pub fn data(&self) -> u64 {
        self.root_dir() + u64::from((self.root_entries * 32).div_ceil(self.sector) * self.sector)
    }

    pub fn cluster_bytes(&self) -> u64 {
        u64::from(self.cluster_sectors) * u64::from(self.sector)
    }
}

/// The geometry of a FAT boot sector, if `b` starts with a valid one.
pub(crate) fn fat_geometry(b: &[u8]) -> Option<FatGeometry> {
    let jump = matches!(b.first()?, 0xEB | 0xE9) || (b[0] == 0x60 && b.get(1).is_some());
    if !jump || &b.get(3..11)? == b"NTFS    " || &b[3..11] == b"EXFAT   " {
        return None;
    }
    let sector = u32::from(le16(b, 11)?);
    let cluster_sectors = u32::from(*b.get(13)?);
    let reserved = u32::from(le16(b, 14)?);
    let fats = u32::from(*b.get(16)?);
    let root_entries = u32::from(le16(b, 17)?);
    let media = *b.get(21)?;
    if !matches!(sector, 512 | 1024 | 2048 | 4096)
        || !cluster_sectors.is_power_of_two()
        || reserved == 0
        || !(1..=2).contains(&fats)
        || !(media == 0xF0 || media >= 0xF8)
    {
        return None;
    }
    let fat_sectors = match le16(b, 22)? {
        0 => le32(b, 36)?,
        n => u32::from(n),
    };
    let total = match le16(b, 19)? {
        0 => le32(b, 32)?,
        n => u32::from(n),
    };
    // In u64: a damaged FAT size would overflow the u32 sum.
    let meta = u64::from(reserved)
        + u64::from(fats) * u64::from(fat_sectors)
        + u64::from((root_entries * 32).div_ceil(sector));
    if fat_sectors == 0 || u64::from(total) <= meta {
        return None;
    }
    let clusters = u32::try_from((u64::from(total) - meta) / u64::from(cluster_sectors)).ok()?;
    let kind = if clusters < 4085 {
        "fat12"
    } else if clusters < 65525 {
        "fat16"
    } else {
        "fat32"
    };
    let root_cluster = if kind == "fat32" { le32(b, 44)? } else { 0 };
    Some(FatGeometry {
        kind,
        sector,
        cluster_sectors,
        reserved,
        fats,
        fat_sectors,
        root_entries,
        total,
        clusters,
        root_cluster,
    })
}

fn fat(mut v: Volume<'_, '_>, f: &mut Facts) -> Option<()> {
    let g = fat_geometry(v.buf)?;
    let ext = if g.kind == "fat32" { 64 } else { 36 };
    f.set("block_size", g.cluster_bytes());
    f.set("size_bytes", u64::from(g.total) * u64::from(g.sector));
    f.set("clusters", g.clusters);
    f.opt("oem_name", text_field(&v.buf[3..11]));
    if v.buf.get(ext + 2) == Some(&0x29) {
        let serial = le32(v.buf, ext + 3)?;
        f.set("serial", format!("{:04X}-{:04X}", serial >> 16, serial & 0xFFFF));
        f.opt("boot_sector_label", text_field(&v.buf[ext + 7..ext + 18]).filter(|l| l != "NO NAME"));
    }
    // The volume label proper is a root-directory entry.
    let root = if g.kind == "fat32" {
        g.data() + u64::from(g.root_cluster.saturating_sub(2)) * g.cluster_bytes()
    } else {
        g.root_dir()
    };
    let n = usize::try_from(g.cluster_bytes().max(u64::from(g.root_entries) * 32).min(64 << 10)).ok()?;
    if let Some(dir) = v.read(root, n) {
        for e in dir.as_chunks::<32>().0 {
            if e[0] == 0 {
                break;
            }
            if e[0] != 0xE5 && e[11] & 0x08 != 0 && e[11] & 0x0F != 0x0F {
                f.opt("label", text_field(&e[..11]));
                break;
            }
        }
    }
    Some(())
}

fn exfat(mut v: Volume<'_, '_>, f: &mut Facts) -> Option<()> {
    let b = v.buf;
    let sector = 1u64 << b.get(108).copied().filter(|&s| (9..=12).contains(&s))?;
    let cluster = sector << b.get(109).copied().filter(|&s| s <= 25)?;
    let clusters = le32(b, 92)?;
    f.set("block_size", cluster);
    f.set("size_bytes", le64(b, 72)?.saturating_mul(sector));
    f.set("clusters", clusters);
    let serial = le32(b, 100)?;
    f.set("serial", format!("{:04X}-{:04X}", serial >> 16, serial & 0xFFFF));
    f.set("version", format!("{}.{:02}", b[105], b[104]));
    if b[112] <= 100 {
        f.set("percent_used", b[112]);
    }
    let heap = u64::from(le32(b, 88)?) * sector;
    let root = heap + u64::from(le32(b, 96)?.saturating_sub(2)) * cluster;
    if let Some(dir) = v.read(root, usize::try_from(cluster.min(64 << 10)).ok()?) {
        for e in dir.as_chunks::<32>().0 {
            if e[0] == 0 {
                break;
            }
            if e[0] == 0x83 {
                let chars = usize::from(e[1].min(11));
                f.opt("label", utf16_field(&e[2..2 + 2 * chars], true));
                break;
            }
        }
    }
    Some(())
}

// ---------------------------------------------------------------- NTFS

fn ntfs(mut v: Volume<'_, '_>, f: &mut Facts) -> Option<()> {
    let b = v.buf;
    let sector = u64::from(le16(b, 11)?);
    let spc = match b[13] {
        n @ 0..=0x80 => u64::from(n),
        n => 1 << (256 - u32::from(n)).min(31),
    };
    let cluster = sector * spc.max(1);
    let total = le64(b, 40)?;
    f.set("block_size", cluster);
    f.set("size_bytes", total.saturating_mul(sector));
    let serial = le64(b, 72)?;
    f.set("serial", format!("{serial:016X}"));
    let rec = match b[64].cast_signed() {
        n @ 1..=127 => u64::from(n.unsigned_abs()) * cluster,
        n @ -31..=-1 => 1 << n.unsigned_abs(),
        _ => 1024,
    };
    let mft = le64(b, 48)?.saturating_mul(cluster);
    // $Volume is MFT record 3: its name and version attributes.
    let mut r = v.read(mft.saturating_add(3 * rec), usize::try_from(rec.min(4096)).ok()?)?;
    if !r.starts_with(b"FILE") || !fixup(&mut r, usize::try_from(sector).ok()?) {
        return Some(());
    }
    let mut at = usize::from(le16(&r, 20)?);
    while let (Some(ty), Some(len)) = (le32(&r, at), le32(&r, at + 4)) {
        if ty == 0xFFFF_FFFF || len < 24 {
            break;
        }
        // Resident attributes only: their value follows the header.
        if r.get(at + 8) == Some(&0) {
            let vlen = le32(&r, at + 16)? as usize;
            let voff = at + usize::from(le16(&r, at + 20)?);
            let val = r.get(voff..voff + vlen)?;
            match ty {
                0x10 => f.opt("created", crate::container::cfb::filetime(le64(val, 0)?)),
                0x60 => f.opt("label", utf16_field(val, true)),
                0x70 if val.len() >= 12 => {
                    f.set("version", format!("{}.{}", val[8], val[9]));
                    if le16(val, 10)? & 1 != 0 {
                        f.set("dirty", true);
                    }
                }
                _ => {}
            }
        }
        at += len as usize;
    }
    Some(())
}

/// Apply an NTFS update sequence array (restores each sector's last two
/// bytes); `false` when the record is torn.
fn fixup(r: &mut [u8], sector: usize) -> bool {
    let (Some(off), Some(count)) = (le16(r, 4), le16(r, 6)) else { return false };
    let (off, count) = (usize::from(off), usize::from(count));
    let Some(usa) = r.get(off..off + 2 * count).map(<[u8]>::to_vec) else { return false };
    for i in 1..count {
        let end = i * sector;
        if end > r.len() {
            break;
        }
        if r[end - 2..end] != usa[..2] {
            return false;
        }
        r[end - 2..end].copy_from_slice(&usa[2 * i..2 * i + 2]);
    }
    true
}

// ---------------------------------------------------------------- HFS / HFS+

fn hfs(mut v: Volume<'_, '_>, f: &mut Facts) -> Option<()> {
    let h = v.buf.get(1024..1536)?.to_vec();
    if &h[..2] == b"BD" {
        // HFS (standard): a Pascal-string name in the master directory block.
        let n = usize::from(h[36].min(27));
        f.opt("label", text_field(&h[37..37 + n]));
        f.opt("created", mac_time(be32(&h, 2)?));
        f.opt("modified", mac_time(be32(&h, 6)?));
        f.sizes(u64::from(be32(&h, 20)?), u64::from(be16(&h, 18)?), Some(u64::from(be16(&h, 34)?)));
        if &h[124..126] == b"H+" {
            f.set("embedded_hfs_plus", true);
        }
        return Some(());
    }
    f.set("version", be16(&h, 2)?);
    let attributes = be32(&h, 4)?;
    if attributes & (1 << 13) != 0 {
        f.set("journaled", true);
    }
    if attributes & (1 << 8) == 0 {
        f.set("cleanly_unmounted", false);
    }
    f.opt("last_mounted_by", text_field(&h[8..12]));
    f.opt("created", mac_time(be32(&h, 16)?));
    f.opt("modified", mac_time(be32(&h, 20)?));
    f.opt("backed_up", mac_time(be32(&h, 24)?));
    f.opt("checked", mac_time(be32(&h, 28)?));
    f.set("files", be32(&h, 32)?);
    f.set("folders", be32(&h, 36)?);
    let block = u64::from(be32(&h, 40)?);
    f.sizes(block, u64::from(be32(&h, 44)?), Some(u64::from(be32(&h, 48)?)));
    if let Some(id) = be64(&h, 80 + 24).filter(|&id| id != 0) {
        f.set("volume_id", format!("{id:016X}"));
    }
    // The volume name is the root folder's name: the catalog record whose
    // parent is 1, at the start of the first leaf node.
    let first_extent = u64::from(be32(&h, 0x110 + 16)?) * block;
    let node0 = v.read(first_extent, 512)?;
    let node_size = u64::from(be16(&node0, 32)?);
    let leaf = u64::from(be32(&node0, 24)?);
    if !(512..=32768).contains(&node_size) || leaf == 0 {
        return Some(());
    }
    let node = v.read(first_extent + leaf * node_size, usize::try_from(node_size).ok()?)?;
    let records = usize::from(be16(&node, 10)?).min(64);
    for i in 0..records {
        let at = usize::from(be16(&node, node.len() - 2 * (i + 1))?);
        if be32(&node, at + 2)? == 1 {
            let n = usize::from(be16(&node, at + 6)?);
            f.opt("label", utf16_field(node.get(at + 8..at + 8 + 2 * n)?, false));
            break;
        }
    }
    Some(())
}

// ---------------------------------------------------------------- APFS

/// Volumes described at most.
const MAX_VOLUMES: usize = 16;

fn apfs(mut v: Volume<'_, '_>, f: &mut Facts) -> Option<()> {
    let b = v.buf;
    let block = u64::from(le32(b, 0x24)?);
    if !block.is_power_of_two() || !(4096..=65536).contains(&block) {
        return None;
    }
    let bs = usize::try_from(block).ok()?;
    // The newest container superblock is in the checkpoint descriptor area.
    let mut nx = b.get(..bs)?.to_vec();
    let (base, blocks) = (le64(b, 0x70)?, le32(b, 0x68)? & 0x7FFF_FFFF);
    for i in 0..u64::from(blocks.min(256)) {
        let Some(c) = v.read((base + i) * block, bs) else { break };
        if c.get(32..36) == Some(b"NXSB") && le64(&c, 16)? > le64(&nx, 16)? && le64(&c, 0x28) == le64(&nx, 0x28) {
            nx = c;
        }
    }
    f.opt("uuid", uuid_be(&nx[0x48..0x58]));
    f.sizes(block, le64(&nx, 0x28)?, None);
    let max = le32(&nx, 0xB4)? as usize;
    let fs_oids: Vec<u64> = (0..max.min(100)).filter_map(|i| le64(&nx, 0xB8 + 8 * i)).filter(|&o| o != 0).collect();
    f.set("volume_count", fs_oids.len());
    // Virtual object ids resolve through the container's object map.
    let Some(omap) = v.read(le64(&nx, 0xA0)? * block, bs) else { return Some(()) };
    let tree = le64(&omap, 0x30)?;
    let mut map = Vec::new();
    omap_leaves(&mut v, block, tree, 0, &mut map);
    let mut volumes = Vec::new();
    for oid in fs_oids.into_iter().take(MAX_VOLUMES) {
        let Some(&(_, _, paddr)) = map.iter().filter(|(o, _, _)| *o == oid).max_by_key(|(_, xid, _)| *xid) else {
            continue;
        };
        let Some(s) = v.read(paddr * block, 1024) else { continue };
        if s.get(32..36) != Some(b"APSB") {
            continue;
        }
        volumes.push(Value::Object(apfs_volume(&s)?));
    }
    if !volumes.is_empty() {
        if volumes.iter().any(|v| v["encrypted"] == json!(true)) {
            f.set("encrypted", true);
        }
        f.set("volumes", volumes);
    }
    Some(())
}

/// Collect `(oid, xid, physical address)` from an object-map B-tree.
fn omap_leaves(v: &mut Volume<'_, '_>, block: u64, node: u64, depth: u32, out: &mut Vec<(u64, u64, u64)>) {
    let Ok(bs) = usize::try_from(block) else { return };
    if depth > 4 || out.len() > 4096 {
        return;
    }
    let Some(n) = v.read(node.saturating_mul(block), bs) else { return };
    let (Some(flags), Some(level), Some(keys), Some(toc_off), Some(toc_len)) =
        (le16(&n, 0x20), le16(&n, 0x22), le32(&n, 0x24), le16(&n, 0x28), le16(&n, 0x2A))
    else {
        return;
    };
    let toc = 0x38 + usize::from(toc_off);
    let key_start = toc + usize::from(toc_len);
    let val_end = if flags & 1 != 0 { bs - 40 } else { bs };
    for i in 0..(keys as usize).min(512) {
        // Object-map nodes use fixed-size entries: (key offset, value offset).
        let (Some(k), Some(val)) = (le16(&n, toc + 4 * i), le16(&n, toc + 4 * i + 2)) else { break };
        let ka = key_start + usize::from(k);
        let Some(va) = val_end.checked_sub(usize::from(val)) else { break };
        let (Some(oid), Some(xid)) = (le64(&n, ka), le64(&n, ka + 8)) else { break };
        if level == 0 {
            if let Some(paddr) = le64(&n, va + 8) {
                out.push((oid, xid, paddr));
            }
        } else if let Some(child) = le64(&n, va) {
            omap_leaves(v, block, child, depth + 1, out);
        }
    }
}

fn apfs_volume(s: &[u8]) -> Option<Map<String, Value>> {
    let mut f = Facts(Map::new());
    f.opt("name", text_field(&s[0x2C0..0x3C0]));
    let role = le16(s, 0x3C4)?;
    let role = match role {
        0 => None,
        1 => Some("system"),
        2 => Some("user"),
        4 => Some("recovery"),
        8 => Some("vm"),
        0x10 => Some("preboot"),
        0x20 => Some("installer"),
        0x40 => Some("data"),
        0x80 => Some("baseband"),
        0xC0 => Some("update"),
        0x100 => Some("xart"),
        0x140 => Some("hardware"),
        0x180 => Some("backup"),
        0x200 => Some("enterprise"),
        0x280 => Some("prelogin"),
        _ => Some("other"),
    };
    f.opt("role", role);
    f.opt("uuid", uuid_be(&s[0xF0..0x100]));
    let incompat = le64(s, 0x38)?;
    f.set("case_sensitive", incompat & 1 == 0);
    if incompat & 0x20 != 0 {
        f.set("sealed", true);
    }
    f.set("encrypted", le64(s, 0x108)? & 1 == 0);
    f.set("files", le64(s, 0xB8)?);
    f.set("directories", le64(s, 0xC0)?);
    f.set("symlinks", le64(s, 0xC8)?);
    f.set("snapshots", le64(s, 0xD8)?);
    f.set("used_blocks", le64(s, 0x58)?);
    f.opt("formatted_by", text_field(&s[0x110..0x130]));
    let ns = |at: usize| le64(s, at).and_then(|t| unix_time(i64::try_from(t / 1_000_000_000).ok()?));
    f.opt("created", ns(0x130));
    f.opt("modified", ns(0x100));
    Some(f.0)
}

// ---------------------------------------------------------------- others

fn btrfs(b: &[u8], f: &mut Facts) -> Option<()> {
    let s = b.get(0x10000..0x11000)?;
    f.opt("label", text_field(&s[0x12B..0x22B]));
    f.opt("uuid", uuid_be(&s[0x20..0x30]));
    let sector = u64::from(le32(s, 0x90)?);
    f.set("block_size", sector);
    f.set("node_size", le32(s, 0x94)?);
    f.set("size_bytes", le64(s, 0x70)?);
    f.set("used_bytes", le64(s, 0x78)?);
    f.set("devices", le64(s, 0x88)?);
    f.set("generation", le64(s, 0x48)?);
    let csum = match le16(s, 0xC4)? {
        0 => "crc32c",
        1 => "xxhash64",
        2 => "sha256",
        3 => "blake2b",
        _ => "other",
    };
    f.set("checksum", csum);
    Some(())
}

fn xfs(b: &[u8], f: &mut Facts) -> Option<()> {
    f.opt("label", text_field(b.get(108..120)?));
    f.opt("uuid", uuid_be(&b[32..48]));
    let block = u64::from(be32(b, 4)?);
    f.sizes(block, be64(b, 8)?, Some(be64(b, 144)?));
    f.set("version", be16(b, 100)? & 0xF);
    f.set("allocation_groups", be32(b, 88)?);
    f.set("inodes", be64(b, 128)?);
    Some(())
}

fn iso9660(b: &[u8], f: &mut Facts) -> Option<()> {
    let p = b.get(32768..32768 + 2048)?;
    f.opt("label", text_field(&p[40..72]));
    let block = u64::from(le16(p, 128)?);
    f.sizes(block, u64::from(le32(p, 80)?), None);
    Some(())
}

fn squashfs(b: &[u8], f: &mut Facts) -> Option<()> {
    f.set("version", format!("{}.{}", le16(b, 28)?, le16(b, 30)?));
    f.opt("compression", squashfs_compression(le16(b, 20)?));
    f.set("block_size", le32(b, 12)?);
    f.set("size_bytes", le64(b, 40)?);
    f.set("inodes", le32(b, 4)?);
    f.opt("created", unix32(b, 8));
    Some(())
}

/// Name of a squashfs compression id.
pub(crate) fn squashfs_compression(id: u16) -> Option<&'static str> {
    Some(match id {
        1 => "gzip",
        2 => "lzma",
        3 => "lzo",
        4 => "xz",
        5 => "lz4",
        6 => "zstd",
        _ => return None,
    })
}

fn swap(b: &[u8], f: &mut Facts) -> Option<()> {
    f.set("version", le32(b, 1024)?);
    f.set("pages", le32(b, 1028)?);
    f.opt("uuid", uuid_be(&b[1036..1052]));
    f.opt("label", text_field(&b[1052..1068]));
    Some(())
}

fn lvm2(mut v: Volume<'_, '_>, f: &mut Facts) -> Option<()> {
    let label = v.buf.get(512..1024)?;
    let pv = 512 + le32(label, 20)? as usize;
    let id = v.buf.get(pv..pv + 32)?;
    if id.iter().all(u8::is_ascii_alphanumeric) {
        let s = std::str::from_utf8(id).ok()?;
        let parts = [&s[..6], &s[6..10], &s[10..14], &s[14..18], &s[18..22], &s[22..26], &s[26..]];
        f.set("uuid", parts.join("-"));
    }
    f.set("size_bytes", le64(v.buf, pv + 32)?);
    // Data areas then metadata areas, each list ending in a zero entry;
    // the first metadata area's text starts with the volume group name.
    let mut at = pv + 40;
    while le64(v.buf, at)? != 0 {
        at += 16;
    }
    at += 16;
    let mda = le64(v.buf, at)?;
    if mda == 0 {
        return Some(());
    }
    let hdr = v.read(mda, 512)?;
    let (off, size) = (le64(&hdr, 40)?, le64(&hdr, 48)?);
    if size == 0 {
        return Some(());
    }
    let text = v.read(mda + off, usize::try_from(size.min(256)).ok()?)?;
    let name: String =
        text.iter().take_while(|c| c.is_ascii_alphanumeric() || b"._+-".contains(c)).map(|&c| char::from(c)).collect();
    if !name.is_empty() {
        f.set("volume_group", name);
    }
    Some(())
}

fn luks(b: &[u8], f: &mut Facts) -> Option<()> {
    f.set("encrypted", true);
    // A header cut short by the end of the input leaves its fields blank.
    let field = |r: std::ops::Range<usize>| b.get(r).and_then(text_field);
    let version = be16(b, 6)?;
    f.set("version", version);
    f.opt("uuid", field(168..208));
    if version == 1 {
        let cipher = [field(8..40), field(40..72)].into_iter().flatten().collect::<Vec<_>>();
        if !cipher.is_empty() {
            f.set("cipher", cipher.join("-"));
        }
        f.opt("hash", field(72..104));
        f.set("key_bits", u64::from(be32(b, 108)?) * 8);
        let slots = (0..8).filter(|i| be32(b, 208 + 48 * i) == Some(0x00AC_71F3)).count();
        f.set("key_slots", slots);
        return Some(());
    }
    f.opt("label", field(24..72));
    f.opt("subsystem", field(208..256));
    // LUKS2 keeps its parameters in JSON after the binary header.
    let hdr = usize::try_from(be64(b, 8)?).ok()?;
    if let Some(json) = b.get(4096..hdr.min(b.len()))
        && let Ok(Value::Object(m)) =
            serde_json::from_slice::<Value>(&json[..json.iter().position(|&c| c == 0).unwrap_or(json.len())])
    {
        if let Some(Value::Object(seg)) = m.get("segments")
            && let Some(c) = seg.values().find_map(|s| s.get("encryption")?.as_str())
        {
            f.set("cipher", c);
        }
        if let Some(Value::Object(k)) = m.get("keyslots") {
            f.set("key_slots", k.len());
            if let Some(kdf) = k.values().find_map(|s| s.get("kdf")?.get("type")?.as_str()) {
                f.set("kdf", kdf);
            }
        }
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::{Budget, BytesSource};

    #[test]
    fn identifies_superblocks() {
        let mut ext = vec![0u8; 4096];
        ext[1024 + 56..1024 + 58].copy_from_slice(&0xEF53u16.to_le_bytes());
        ext[1024] = 16;
        ext[1028] = 64;
        assert_eq!(identify(&ext), Some("ext2"));
        ext[1024 + 92] = 4;
        assert_eq!(identify(&ext), Some("ext3"));
        ext[1024 + 96] = 0x40;
        assert_eq!(identify(&ext), Some("ext4"));
        let mut luks = vec![0u8; 1024];
        luks[..6].copy_from_slice(b"LUKS\xba\xbe");
        luks[7] = 1;
        assert_eq!(identify(&luks), Some("luks"));
        let fs = filesystem(&mut BytesSource::new(None, luks, Budget::unlimited()), 0, 1024).unwrap();
        assert_eq!(fs.facts["encrypted"], json!(true));
        assert_eq!(identify(&[0u8; 4096]), None);
    }

    #[test]
    fn short_luks_headers() {
        // Fuzz regression: a LUKS header cut short by the end of the input.
        for (version, n) in [(1u8, 100usize), (2, 200), (2, 247)] {
            let mut luks = vec![0u8; n];
            luks[..6].copy_from_slice(b"LUKS\xba\xbe");
            luks[7] = version;
            let fs = filesystem(&mut BytesSource::new(None, luks, Budget::unlimited()), 0, n as u64).unwrap();
            assert_eq!(fs.facts["encrypted"], json!(true));
        }
    }

    #[test]
    fn apfs_volume_through_object_map() {
        // Block 0: container superblock; 1: object map; 2: its B-tree (one
        // leaf entry: oid 0x402 → block 3); 3: the volume superblock.
        let bs = 4096usize;
        let mut d = vec![0u8; 4 * bs];
        let put = |d: &mut [u8], at: usize, v: &[u8]| d[at..at + v.len()].copy_from_slice(v);
        put(&mut d, 32, b"NXSB");
        put(&mut d, 0x24, &4096u32.to_le_bytes());
        put(&mut d, 0x28, &4u64.to_le_bytes());
        put(&mut d, 0xA0, &1u64.to_le_bytes());
        put(&mut d, 0xB4, &1u32.to_le_bytes());
        put(&mut d, 0xB8, &0x402u64.to_le_bytes());
        put(&mut d, bs + 0x30, &2u64.to_le_bytes());
        let node = 2 * bs;
        put(&mut d, node + 0x20, &7u16.to_le_bytes());
        put(&mut d, node + 0x24, &1u32.to_le_bytes());
        put(&mut d, node + 0x2A, &4u16.to_le_bytes());
        put(&mut d, node + 0x38, &[0, 0, 16, 0]);
        put(&mut d, node + 0x3C, &0x402u64.to_le_bytes());
        put(&mut d, node + 0x44, &1u64.to_le_bytes());
        put(&mut d, node + bs - 40 - 16 + 8, &3u64.to_le_bytes());
        put(&mut d, 3 * bs + 32, b"APSB");
        put(&mut d, 3 * bs + 0x2C0, b"Tides");
        put(&mut d, 3 * bs + 0x3C4, &2u16.to_le_bytes());
        put(&mut d, 3 * bs + 0x108, &1u64.to_le_bytes());
        let len = d.len() as u64;
        let fs = filesystem(&mut BytesSource::new(None, d, Budget::unlimited()), 0, len).unwrap();
        let v = &fs.facts["volumes"][0];
        assert_eq!(
            (v["name"].as_str(), v["role"].as_str(), v["encrypted"].as_bool()),
            (Some("Tides"), Some("user"), Some(false))
        );
    }

    #[test]
    fn fat_boot_sector() {
        let mut b = vec![0u8; 512];
        b[..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        b[11..13].copy_from_slice(&512u16.to_le_bytes());
        b[13] = 1;
        b[14] = 1;
        b[16] = 2;
        b[17..19].copy_from_slice(&224u16.to_le_bytes());
        b[19..21].copy_from_slice(&2880u16.to_le_bytes());
        b[21] = 0xF0;
        b[22] = 9;
        let g = fat_geometry(&b).unwrap();
        assert_eq!((g.kind, g.root_dir(), g.data()), ("fat12", 19 * 512, 33 * 512));
        b[16] = 3;
        assert!(fat_geometry(&b).is_none());
    }

    #[test]
    fn ntfs_fixups() {
        let mut r = vec![0u8; 1024];
        r[4..6].copy_from_slice(&48u16.to_le_bytes());
        r[6..8].copy_from_slice(&3u16.to_le_bytes());
        r[48..54].copy_from_slice(&[7, 7, 1, 2, 3, 4]);
        r[510..512].copy_from_slice(&[7, 7]);
        r[1022..1024].copy_from_slice(&[7, 7]);
        assert!(fixup(&mut r, 512));
        assert_eq!((&r[510..512], &r[1022..1024]), (&[1u8, 2][..], &[3u8, 4][..]));
        assert!(!fixup(&mut r, 512), "a torn record");
    }
}
