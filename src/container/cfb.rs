//! OLE2 compound files (Microsoft Compound File Binary, MS-CFB): legacy
//! Word / Excel / PowerPoint, Outlook `.msg`, MSI, Visio, Publisher,
//! encrypted OOXML (`EncryptionInfo` + `EncryptedPackage`), Thumbs.db.
//!
//! The reader loads the FAT, the mini FAT and the directory, then reads
//! streams on demand. Every sector chain is checked for cycles and bounded
//! by the FAT size, so a hostile file cannot loop or claim more than it holds.

use crate::io::{ByteReader, Source};
use crate::plugin::ExtractError;

/// The compound-file signature.
pub const SIGNATURE: &[u8; 8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
const END_OF_CHAIN: u32 = 0xFFFF_FFFE;
const NO_STREAM: u32 = 0xFFFF_FFFF;
/// Directory entries listed at most.
const MAX_DIRECTORY: usize = 100_000;

/// Kind of a directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfbKind {
    /// The root storage.
    Root,
    /// A storage (folder).
    Storage,
    /// A stream (file).
    Stream,
}

/// One directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfbEntry {
    /// Entry name (control characters such as the `\x05` of
    /// `\x05SummaryInformation` are kept).
    pub name: String,
    /// Path from the root, `/`-separated, without the root's name.
    pub path: String,
    /// Kind.
    pub kind: CfbKind,
    /// Stream size in bytes.
    pub size: u64,
    /// Class id of a storage, as a GUID string (`None` when all zero).
    pub clsid: Option<String>,
    /// Creation time (storages), RFC 3339.
    pub created: Option<String>,
    /// Modification time (storages), RFC 3339.
    pub modified: Option<String>,
    /// Index of the parent storage in [`Cfb::entries`].
    pub parent: Option<usize>,
    start: u32,
}

/// A compound file's allocation tables and directory.
#[derive(Debug, Clone)]
pub struct Cfb {
    /// Directory entries; index 0 is the root.
    pub entries: Vec<CfbEntry>,
    /// Major version (3: 512-byte sectors, 4: 4096-byte sectors).
    pub version: u16,
    /// Whether the directory listing was cut.
    pub truncated: bool,
    sector_size: usize,
    fat: Vec<u32>,
    minifat: Vec<u32>,
    mini_cutoff: u64,
    /// Regular sectors holding the mini stream, in order.
    mini_sectors: Vec<u32>,
}

/// A GUID in its registry form, from its little-endian byte layout.
pub fn guid(b: &[u8; 16]) -> Option<String> {
    if b.iter().all(|&x| x == 0) {
        return None;
    }
    Some(format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    ))
}

/// A Windows FILETIME (100 ns ticks since 1601) as RFC 3339 UTC, or `None`
/// for zero and out-of-range values.
pub fn filetime(ticks: u64) -> Option<String> {
    if ticks == 0 {
        return None;
    }
    let secs = i64::try_from(ticks / 10_000_000).ok()? - 11_644_473_600;
    // Before 1980 or after 2200: zero-ish or garbage.
    if !(315_532_800..7_258_118_400).contains(&secs) {
        return None;
    }
    let ts = jiff::Timestamp::from_second(secs).ok()?;
    Some(ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string())
}

impl Cfb {
    /// Whether `head` starts with the compound-file signature.
    pub fn is_cfb(head: &[u8]) -> bool {
        head.starts_with(SIGNATURE)
    }

    /// Read the header, the allocation tables and the directory.
    pub fn open(src: &mut dyn Source) -> Result<Self, ExtractError> {
        let header = src.read_vec(0, 512)?;
        if !header.starts_with(SIGNATURE) {
            return Err(ExtractError::Unsupported("compound file".into()));
        }
        let mut h = ByteReader::new(&header).skip(24)?;
        let _minor = h.le_u16()?;
        let version = h.le_u16()?;
        let _order = h.le_u16()?;
        let shift = h.le_u16()?;
        let mini_shift = h.le_u16()?;
        if !(7..=16).contains(&shift) || mini_shift > shift {
            return Err(ExtractError::malformed(format!("sector shift {shift}")));
        }
        h.advance(6)?;
        let _dir_sectors = h.le_u32()?;
        let fat_sectors = h.le_u32()?;
        let first_dir = h.le_u32()?;
        let _transaction = h.le_u32()?;
        let mini_cutoff = u64::from(h.le_u32()?);
        let first_minifat = h.le_u32()?;
        let minifat_sectors = h.le_u32()?;
        let first_difat = h.le_u32()?;
        let difat_sectors = h.le_u32()?;
        let sector_size = 1usize << shift;
        let total_sectors = usize::try_from(src.len().saturating_sub(512) / sector_size as u64 + 1).unwrap_or(0);

        // DIFAT: 109 entries in the header, then a chain of DIFAT sectors.
        let mut difat: Vec<u32> = (0..109).filter_map(|_| h.le_u32().ok()).filter(|&s| s < 0xFFFF_FFFA).collect();
        let mut next = first_difat;
        let per = sector_size / 4 - 1;
        let mut seen = 0u32;
        while next < 0xFFFF_FFFA && seen < difat_sectors.min(u32::try_from(total_sectors).unwrap_or(u32::MAX)) {
            let s = read_sector(src, next, sector_size)?;
            let mut r = ByteReader::new(&s);
            for _ in 0..per {
                let v = r.le_u32()?;
                if v < 0xFFFF_FFFA {
                    difat.push(v);
                }
            }
            next = r.le_u32()?;
            seen += 1;
        }
        difat.truncate(fat_sectors as usize);
        if difat.len() > total_sectors {
            return Err(ExtractError::malformed("FAT larger than the file"));
        }
        let mut fat = Vec::with_capacity(difat.len() * sector_size / 4);
        for s in difat {
            let data = read_sector(src, s, sector_size)?;
            fat.extend(data.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)));
        }
        let mut cfb = Cfb {
            entries: Vec::new(),
            version,
            truncated: false,
            sector_size,
            fat,
            minifat: Vec::new(),
            mini_cutoff,
            mini_sectors: Vec::new(),
        };
        let minifat_bytes = cfb.read_chain(src, first_minifat, u64::from(minifat_sectors) * sector_size as u64)?;
        cfb.minifat = minifat_bytes.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)).collect();
        let dir = cfb.read_chain(src, first_dir, (MAX_DIRECTORY * 128) as u64)?;
        cfb.parse_directory(&dir)?;
        if let Some(root) = cfb.entries.first() {
            cfb.mini_sectors = cfb.chain(root.start)?;
        }
        Ok(cfb)
    }

    #[allow(clippy::too_many_lines)] // records, then the tree walk
    fn parse_directory(&mut self, dir: &[u8]) -> Result<(), ExtractError> {
        struct Raw {
            name: String,
            kind: u8,
            left: u32,
            right: u32,
            child: u32,
            clsid: [u8; 16],
            created: u64,
            modified: u64,
            start: u32,
            size: u64,
        }
        let mut raw = Vec::new();
        for rec in dir.as_chunks::<128>().0 {
            let mut r = ByteReader::new(rec);
            let name_bytes = r.bytes(64)?;
            let n = usize::from(r.le_u16()?).min(64);
            let units: Vec<u16> = name_bytes[..n]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .take_while(|&u| u != 0)
                .collect();
            let kind = r.u8()?;
            let _color = r.u8()?;
            let (left, right, child) = (r.le_u32()?, r.le_u32()?, r.le_u32()?);
            let clsid = r.array::<16>()?;
            let _state = r.le_u32()?;
            let (created, modified) = (r.le_u64()?, r.le_u64()?);
            let start = r.le_u32()?;
            let size = r.le_u64()?;
            let size = if self.version == 3 { size & 0xFFFF_FFFF } else { size };
            raw.push(Raw {
                name: String::from_utf16_lossy(&units),
                kind,
                left,
                right,
                child,
                clsid,
                created,
                modified,
                start,
                size,
            });
        }
        if raw.first().is_none_or(|r| r.kind != 5) {
            return Err(ExtractError::malformed("no root entry"));
        }
        // Walk the red-black trees from the root, iteratively, visiting each
        // entry once (a cycle or shared node is ignored).
        let mut visited = vec![false; raw.len()];
        let mut stack: Vec<(u32, Option<usize>, String)> = vec![(0, None, String::new())];
        while let Some((id, parent, prefix)) = stack.pop() {
            let i = id as usize;
            if i >= raw.len() || visited[i] {
                continue;
            }
            visited[i] = true;
            let e = &raw[i];
            if !matches!(e.kind, 1 | 2 | 5) {
                continue;
            }
            if self.entries.len() >= MAX_DIRECTORY {
                self.truncated = true;
                break;
            }
            let kind = match e.kind {
                5 => CfbKind::Root,
                1 => CfbKind::Storage,
                _ => CfbKind::Stream,
            };
            let path = match kind {
                CfbKind::Root => String::new(),
                _ if prefix.is_empty() => e.name.clone(),
                _ => format!("{prefix}/{}", e.name),
            };
            let index = self.entries.len();
            self.entries.push(CfbEntry {
                name: e.name.clone(),
                path: path.clone(),
                kind,
                size: e.size,
                clsid: guid(&e.clsid),
                created: filetime(e.created),
                modified: filetime(e.modified),
                parent,
                start: e.start,
            });
            for sib in [e.left, e.right] {
                if sib != NO_STREAM {
                    stack.push((sib, parent, prefix.clone()));
                }
            }
            if e.child != NO_STREAM && kind != CfbKind::Stream {
                stack.push((e.child, Some(index), path));
            }
        }
        // Siblings were pushed in tree order; present each storage's
        // children sorted by name for stable output.
        let root = self.entries.remove(0);
        self.entries.sort_by_key(|e| e.path.to_lowercase());
        self.entries.insert(0, root);
        let index: std::collections::HashMap<String, usize> =
            self.entries.iter().enumerate().map(|(i, e)| (e.path.clone(), i)).collect();
        for e in &mut self.entries[1..] {
            e.parent = Some(e.path.rsplit_once('/').map_or(0, |(p, _)| index.get(p).copied().unwrap_or(0)));
        }
        Ok(())
    }

    /// The sectors of the chain starting at `start` (cycle-checked).
    fn chain(&self, start: u32) -> Result<Vec<u32>, ExtractError> {
        let mut out = Vec::new();
        let mut s = start;
        while s != END_OF_CHAIN && s < 0xFFFF_FFFA {
            if out.len() > self.fat.len() {
                return Err(ExtractError::malformed("sector chain loops"));
            }
            out.push(s);
            s = *self.fat.get(s as usize).ok_or_else(|| ExtractError::malformed("sector beyond the FAT"))?;
        }
        Ok(out)
    }

    fn read_chain(&self, src: &mut dyn Source, start: u32, max: u64) -> Result<Vec<u8>, ExtractError> {
        let mut out = Vec::new();
        if start == END_OF_CHAIN || start >= 0xFFFF_FFFA {
            return Ok(out);
        }
        let sectors = self.chain(start)?;
        let mut i = 0;
        while i < sectors.len() && (out.len() as u64) < max {
            // Coalesce runs of consecutive sectors into one read.
            let mut j = i + 1;
            while j < sectors.len() && sectors[j] == sectors[j - 1] + 1 && j - i < 256 {
                j += 1;
            }
            let at = (u64::from(sectors[i]) + 1) * self.sector_size as u64;
            let want = ((j - i) * self.sector_size).min(usize::try_from(src.len().saturating_sub(at)).unwrap_or(0));
            out.extend_from_slice(&src.read_vec(at, want)?);
            i = j;
        }
        out.truncate(usize::try_from(max).unwrap_or(usize::MAX));
        Ok(out)
    }

    /// The entry at `path` (case-insensitive, as Windows treats names).
    pub fn find(&self, path: &str) -> Option<&CfbEntry> {
        self.entries.iter().find(|e| e.path.eq_ignore_ascii_case(path))
    }

    /// Direct children of the entry at index `parent`.
    pub fn children(&self, parent: usize) -> impl Iterator<Item = &CfbEntry> {
        self.entries.iter().filter(move |e| e.parent == Some(parent))
    }

    #[cfg(test)]
    /// Index of `entry` in [`entries`](Self::entries).
    pub fn index_of(&self, entry: &CfbEntry) -> Option<usize> {
        self.entries.iter().position(|e| e.path == entry.path)
    }

    /// The first `max` bytes of the stream `entry`.
    pub fn read(&self, src: &mut dyn Source, entry: &CfbEntry, max: usize) -> Result<Vec<u8>, ExtractError> {
        if entry.kind != CfbKind::Stream {
            return Err(ExtractError::malformed(format!("{} is not a stream", entry.path)));
        }
        let want = entry.size.min(max as u64);
        if entry.size < self.mini_cutoff {
            return self.read_mini(src, entry.start, want);
        }
        let mut data = self.read_chain(src, entry.start, want)?;
        data.truncate(usize::try_from(want).unwrap_or(usize::MAX));
        Ok(data)
    }

    /// [`read`](Self::read) of the stream at `path`, if present.
    pub fn read_path(&self, src: &mut dyn Source, path: &str, max: usize) -> Option<Result<Vec<u8>, ExtractError>> {
        let e = self.find(path)?.clone();
        (e.kind == CfbKind::Stream).then(|| self.read(src, &e, max))
    }

    fn read_mini(&self, src: &mut dyn Source, start: u32, want: u64) -> Result<Vec<u8>, ExtractError> {
        let mini = 64usize;
        let mut out = Vec::new();
        let mut s = start;
        let mut steps = 0usize;
        while s != END_OF_CHAIN && s < 0xFFFF_FFFA && (out.len() as u64) < want {
            steps += 1;
            if steps > self.minifat.len() + 1 {
                return Err(ExtractError::malformed("mini chain loops"));
            }
            let pos = s as usize * mini;
            let sector = *self
                .mini_sectors
                .get(pos / self.sector_size)
                .ok_or_else(|| ExtractError::malformed("mini sector beyond the mini stream"))?;
            let at = (u64::from(sector) + 1) * self.sector_size as u64 + (pos % self.sector_size) as u64;
            out.extend_from_slice(&src.read_vec(at, mini)?);
            s = *self.minifat.get(s as usize).ok_or_else(|| ExtractError::malformed("mini sector beyond the FAT"))?;
        }
        out.truncate(usize::try_from(want).unwrap_or(usize::MAX));
        Ok(out)
    }

    /// The root storage's class id.
    pub fn root_clsid(&self) -> Option<&str> {
        self.entries.first().and_then(|e| e.clsid.as_deref())
    }
}

fn read_sector(src: &mut dyn Source, n: u32, size: usize) -> Result<Vec<u8>, ExtractError> {
    Ok(src.read_vec((u64::from(n) + 1) * size as u64, size)?)
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // test files are small
pub(crate) mod tests {
    use super::*;
    use crate::io::{Budget, BytesSource};

    /// A version-3 compound file holding `streams` (path, data) at the root or
    /// one storage deep (`Storage/Stream`). Streams are stored in regular
    /// sectors when ≥ 4096 bytes, in the mini stream otherwise.
    #[allow(clippy::too_many_lines)] // test writer
    pub(crate) fn build(streams: &[(&str, &[u8])]) -> Vec<u8> {
        const SS: usize = 512;
        // Directory entries: root, storages, streams.
        struct Node {
            name: String,
            kind: u8,
            data: Vec<u8>,
            children: Vec<usize>,
            start: u32,
        }
        let mut nodes = vec![Node { name: "Root Entry".into(), kind: 5, data: Vec::new(), children: vec![], start: 0 }];
        for (path, data) in streams {
            let mut parent = 0;
            let parts: Vec<&str> = path.split('/').collect();
            for (k, part) in parts.iter().enumerate() {
                let last = k == parts.len() - 1;
                let found = nodes[parent].children.iter().copied().find(|&c| nodes[c].name == *part);
                parent = if let Some(c) = found {
                    c
                } else {
                    nodes.push(Node {
                        name: (*part).into(),
                        kind: if last { 2 } else { 1 },
                        data: if last { data.to_vec() } else { Vec::new() },
                        children: vec![],
                        start: END_OF_CHAIN,
                    });
                    let id = nodes.len() - 1;
                    nodes[parent].children.push(id);
                    id
                };
            }
        }
        // Layout: sector 0 = FAT, then directory, then minifat, then mini stream, then big streams.
        let mut sectors: Vec<Vec<u8>> = vec![vec![0; SS]]; // FAT placeholder
        let mut fat: Vec<u32> = vec![0xFFFF_FFFD];
        let alloc = |data: &[u8], sectors: &mut Vec<Vec<u8>>, fat: &mut Vec<u32>| -> u32 {
            if data.is_empty() {
                return END_OF_CHAIN;
            }
            let first = sectors.len() as u32;
            let n = data.len().div_ceil(SS);
            for (k, chunk) in data.chunks(SS).enumerate() {
                let mut s = chunk.to_vec();
                s.resize(SS, 0);
                sectors.push(s);
                fat.push(if k + 1 == n { END_OF_CHAIN } else { first + k as u32 + 1 });
            }
            first
        };
        let mut mini_stream = Vec::new();
        let mut minifat: Vec<u32> = Vec::new();
        for node in nodes.iter_mut().skip(1).filter(|n| n.kind == 2 && n.data.len() < 4096 && !n.data.is_empty()) {
            let first = (mini_stream.len() / 64) as u32;
            let n = node.data.len().div_ceil(64);
            for k in 0..n {
                minifat.push(if k + 1 == n { END_OF_CHAIN } else { first + k as u32 + 1 });
            }
            mini_stream.extend_from_slice(&node.data);
            mini_stream.resize(mini_stream.len().div_ceil(64) * 64, 0);
            node.start = first;
        }
        let mut dir = Vec::new();
        let count = nodes.len();
        // Children as a right-leaning chain of siblings.
        let mut child = vec![NO_STREAM; count];
        let mut right = vec![NO_STREAM; count];
        for i in 0..count {
            let ch = &nodes[i].children;
            if let Some(&f) = ch.first() {
                child[i] = f as u32;
            }
            for w in ch.windows(2) {
                right[w[0]] = w[1] as u32;
            }
        }
        let big: Vec<(usize, Vec<u8>)> = nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.kind == 2 && n.data.len() >= 4096)
            .map(|(i, n)| (i, n.data.clone()))
            .collect();
        let minifat_bytes: Vec<u8> = minifat.iter().flat_map(|v| v.to_le_bytes()).collect();
        // Directory is allocated after we know the start sectors; reserve sectors.
        let dir_len = count * 128;
        let dir_start = alloc(&vec![0; dir_len], &mut sectors, &mut fat);
        let minifat_start = alloc(&minifat_bytes, &mut sectors, &mut fat);
        let mini_start = alloc(&mini_stream, &mut sectors, &mut fat);
        nodes[0].start = mini_start;
        for (i, data) in big {
            nodes[i].start = alloc(&data, &mut sectors, &mut fat);
        }
        for (i, n) in nodes.iter().enumerate() {
            let mut rec = vec![0u8; 128];
            let units: Vec<u16> = n.name.encode_utf16().chain([0]).collect();
            for (k, u) in units.iter().enumerate().take(32) {
                rec[k * 2..k * 2 + 2].copy_from_slice(&u.to_le_bytes());
            }
            rec[64..66].copy_from_slice(&((units.len() * 2) as u16).to_le_bytes());
            rec[66] = n.kind;
            rec[67] = 1;
            rec[68..72].copy_from_slice(&NO_STREAM.to_le_bytes());
            rec[72..76].copy_from_slice(&right[i].to_le_bytes());
            rec[76..80].copy_from_slice(&child[i].to_le_bytes());
            rec[116..120].copy_from_slice(&n.start.to_le_bytes());
            let size = if n.kind == 5 { mini_stream.len() } else { n.data.len() };
            rec[120..124].copy_from_slice(&(size as u32).to_le_bytes());
            dir.extend_from_slice(&rec);
        }
        for (k, chunk) in dir.chunks(SS).enumerate() {
            let s = &mut sectors[dir_start as usize + k];
            s[..chunk.len()].copy_from_slice(chunk);
        }
        assert!(fat.len() <= 128, "test builder: one FAT sector only");
        fat.resize(128, NO_STREAM);
        sectors[0] = fat.iter().flat_map(|v| v.to_le_bytes()).collect();
        let mut out = Vec::new();
        out.extend_from_slice(SIGNATURE);
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(&0x3Eu16.to_le_bytes());
        out.extend_from_slice(&3u16.to_le_bytes());
        out.extend_from_slice(&0xFFFEu16.to_le_bytes());
        out.extend_from_slice(&9u16.to_le_bytes());
        out.extend_from_slice(&6u16.to_le_bytes());
        out.extend_from_slice(&[0; 6]);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // FAT sectors
        out.extend_from_slice(&dir_start.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&4096u32.to_le_bytes());
        out.extend_from_slice(&minifat_start.to_le_bytes());
        out.extend_from_slice(&(minifat_bytes.len().div_ceil(SS) as u32).to_le_bytes());
        out.extend_from_slice(&END_OF_CHAIN.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // DIFAT[0] = sector 0
        for _ in 1..109 {
            out.extend_from_slice(&NO_STREAM.to_le_bytes());
        }
        for s in sectors {
            out.extend_from_slice(&s);
        }
        out
    }

    #[test]
    fn reads_mini_and_regular_streams() {
        let big: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let file = build(&[("WordDocument", &big), ("\u{5}SummaryInformation", b"props"), ("Macros/VBA/dir", b"x")]);
        let mut src = BytesSource::new(None, file, Budget::unlimited());
        let cfb = Cfb::open(&mut src).unwrap();
        let paths: Vec<&str> = cfb.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["", "\u{5}SummaryInformation", "Macros", "Macros/VBA", "Macros/VBA/dir", "WordDocument"]);
        assert_eq!(cfb.read_path(&mut src, "worddocument", usize::MAX).unwrap().unwrap(), big);
        assert_eq!(cfb.read_path(&mut src, "\u{5}SummaryInformation", 100).unwrap().unwrap(), b"props");
        assert_eq!(cfb.read_path(&mut src, "Macros/VBA/dir", 100).unwrap().unwrap(), b"x");
        let macros = cfb.index_of(cfb.find("Macros").unwrap()).unwrap();
        assert_eq!(cfb.children(macros).map(|e| e.name.as_str()).collect::<Vec<_>>(), ["VBA"]);
    }

    #[test]
    fn rejects_loops_and_garbage() {
        let mut file = build(&[("A", &[1u8; 5000])]);
        // Point the FAT entry of A's first sector at itself.
        let mut src = BytesSource::new(None, file.clone(), Budget::unlimited());
        let cfb = Cfb::open(&mut src).unwrap();
        let a = cfb.find("A").unwrap().start as usize;
        file[512 + a * 4..512 + a * 4 + 4].copy_from_slice(&(a as u32).to_le_bytes());
        let mut src = BytesSource::new(None, file, Budget::unlimited());
        let cfb = Cfb::open(&mut src).unwrap();
        assert!(cfb.read_path(&mut src, "A", usize::MAX).unwrap().is_err());
        let mut src = BytesSource::new(None, b"nope".to_vec(), Budget::unlimited());
        assert!(Cfb::open(&mut src).is_err());
    }

    #[test]
    fn guids_and_filetimes() {
        let b = [0x06, 0x09, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];
        assert_eq!(guid(&b).as_deref(), Some("00020906-0000-0000-C000-000000000046"));
        assert_eq!(guid(&[0; 16]), None);
        assert_eq!(filetime(133_000_000_000_000_000).as_deref(), Some("2022-06-18T04:26:40Z"));
        assert_eq!(filetime(0), None);
    }
}
