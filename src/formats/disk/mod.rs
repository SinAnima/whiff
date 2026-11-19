//! `disk` extractors (feature `forensics`): disk and volume images. Each
//! reports its container's own facts (image type and version, virtual
//! size, how blocks are allocated, backing files, snapshots, case
//! metadata, boot images …) and then what is on the disk, read without
//! mounting it: the partition table and each partition's file system
//! (type, label, UUID, size and free space, times), through
//! [`volume`](crate::plugin::volume).
//!
//! VM and forensic images are read through a [`Virtual`] source that maps
//! the virtual disk's blocks onto the image file (decompressing blocks
//! where the format compresses them), so the same partition and file
//! system code reads raw images, VM disks and evidence files. ISO 9660,
//! UDF, FAT and ext2 / 3 / 4 volumes are also listed, with the archive
//! [`Inventory`](super::archive::Inventory), and their files handed on as
//! children within the limits.

pub(crate) mod android;
pub(crate) mod cd;
pub(crate) mod ewf;
pub(crate) mod ext;
pub(crate) mod fat;
pub(crate) mod firmware;
pub(crate) mod floppy;
pub(crate) mod iso;
pub(crate) mod ovf;
pub(crate) mod raw;
pub(crate) mod vm;

use serde_json::Value;

// Readers shared with the archive, document and package extractors.
use super::archive;
use super::doc::xml;
use crate::plugin::{Budget, Codec, Context, ExtractError, Source, SourceError, codec, volume};

/// The head and tail windows a source pre-reads.
const WINDOW: u64 = 64 << 10;

/// Where one block of a virtual disk is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Block {
    /// Not allocated (or allocated in a backing image whiff cannot see):
    /// reads as zeros.
    Zero,
    /// Stored as is at this offset of the image.
    At(u64),
    /// Every 4 bytes the same value (Android sparse fill chunks).
    Fill(u32),
    /// Compressed; decoding gives the whole block.
    Compressed { at: u64, len: usize, codec: Codec },
}

/// `base + add` as an image offset. An overflow means the image is damaged:
/// fail the read rather than wrap onto another part of the image.
pub(crate) fn offset(base: u64, add: u64) -> Result<u64, SourceError> {
    base.checked_add(add).ok_or_else(|| SourceError::Io("block offset out of range".into()))
}

/// `a * b` as an image offset (see [`offset`]).
pub(crate) fn scaled(a: u64, b: u64) -> Result<u64, SourceError> {
    a.checked_mul(b).ok_or_else(|| SourceError::Io("block offset out of range".into()))
}

/// How a virtual disk's blocks map onto its image file.
pub(crate) trait BlockMap: Send {
    /// Bytes per block.
    fn block_size(&self) -> u64;
    /// Where block `n` is.
    fn locate(&mut self, image: &mut dyn Source, n: u64) -> Result<Block, SourceError>;
}

/// The virtual disk inside an image, readable like any other source.
pub(crate) struct Virtual<'p, 's, M: BlockMap> {
    image: &'p mut (dyn Source + 's),
    map: M,
    len: u64,
    head: Vec<u8>,
    tail: Vec<u8>,
    budget: Budget,
    /// The last decompressed block.
    cache: Option<(u64, Vec<u8>)>,
}

impl<'p, 's, M: BlockMap> Virtual<'p, 's, M> {
    /// The `len`-byte virtual disk `map` describes inside `image`.
    pub fn new(image: &'p mut (dyn Source + 's), map: M, len: u64) -> Result<Self, SourceError> {
        let budget = image.budget().clone();
        let mut v = Self { image, map, len, head: Vec::new(), tail: Vec::new(), budget, cache: None };
        let head = usize::try_from(len.min(WINDOW)).unwrap_or(0);
        v.head = (&mut v as &mut dyn Source).read_vec(0, head)?;
        if len > WINDOW {
            v.tail = (&mut v as &mut dyn Source).read_vec(len - WINDOW, usize::try_from(WINDOW).unwrap_or(0))?;
        }
        Ok(v)
    }
}

impl<M: BlockMap> Source for Virtual<'_, '_, M> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let bs = self.map.block_size().max(1);
        let want = usize::try_from((self.len - offset).min(buf.len() as u64)).unwrap_or(buf.len());
        let mut done = 0;
        while done < want {
            let pos = offset + done as u64;
            let (n, within) = (pos / bs, pos % bs);
            let take = usize::try_from((bs - within).min((want - done) as u64)).unwrap_or(0);
            let out = &mut buf[done..done + take];
            match self.map.locate(self.image, n)? {
                Block::Zero => {
                    self.budget.charge_read(take as u64)?;
                    out.fill(0);
                }
                Block::Fill(v) => {
                    self.budget.charge_read(take as u64)?;
                    let pattern = v.to_le_bytes();
                    let within = usize::try_from(within % 4).unwrap_or(0);
                    for (i, b) in out.iter_mut().enumerate() {
                        *b = pattern[(within + i) % 4];
                    }
                }
                Block::At(at) => (self.image as &mut dyn Source).read_exact_at(self::offset(at, within)?, out)?,
                Block::Compressed { at, len, codec } => {
                    if self.cache.as_ref().is_none_or(|(c, _)| *c != n) {
                        let data = (self.image as &mut dyn Source).read_vec(at, len)?;
                        let max = usize::try_from(bs).unwrap_or(0);
                        let decoded = codec::decode(&data, codec, max, &self.budget)
                            .map_err(|e| SourceError::Io(e.to_string()))?;
                        // A full block, or a stream that ended normally. Anything
                        // else would read as zeros, so it fails and is not cached.
                        if decoded.data.len() < max && decoded.end != codec::End::Complete {
                            self.cache = None;
                            return Err(match decoded.end {
                                codec::End::Limit => SourceError::LimitExceeded("decompressed_bytes"),
                                _ => SourceError::Io(format!("compressed block {n} does not decode")),
                            });
                        }
                        self.cache = Some((n, decoded.data));
                    }
                    let block = self.cache.as_ref().map_or(&[][..], |(_, d)| d.as_slice());
                    let within = usize::try_from(within).unwrap_or(usize::MAX);
                    for (i, b) in out.iter_mut().enumerate() {
                        *b = block.get(within.saturating_add(i)).copied().unwrap_or(0);
                    }
                }
            }
            done += take;
        }
        Ok(done)
    }

    fn head(&self) -> &[u8] {
        &self.head
    }

    fn tail(&self) -> &[u8] {
        if self.tail.is_empty() { &self.head } else { &self.tail }
    }

    fn name_hint(&self) -> Option<&str> {
        self.image.name_hint()
    }

    fn budget(&self) -> &Budget {
        &self.budget
    }
}

/// Write what is on a disk (partition table, file systems) into the
/// report, and list the FAT volumes on it. A read failure (an image cut
/// short, a block that does not decode) is a warning, not an error: the
/// container's own facts are already written.
pub(crate) fn report_contents(src: &mut dyn Source, cx: &mut Context<'_>) {
    let facts = volume::describe(src);
    for (k, v) in &facts {
        cx.format_set(k, v.clone());
    }
    // An encrypted volume anywhere on the disk (LUKS, BitLocker, APFS).
    let encrypted = |f: Option<&Value>| f.is_some_and(|f| f["encrypted"] == Value::Bool(true));
    let partitions = facts.get("partitions").and_then(Value::as_array).into_iter().flatten();
    if encrypted(facts.get("filesystem")) || partitions.into_iter().any(|p| encrypted(p.get("filesystem"))) {
        cx.security().encrypted(true);
    }
    if let Err(e) = list_volumes(src, cx, &facts) {
        cx.warn(format!("file listing: {e}"));
    }
}

/// A volume whose directory tree whiff reads.
enum Listable {
    Fat(fat::Fat),
    Ext(ext::Ext),
}

/// List the FAT and ext volumes `facts` (from `volume::describe`) found on
/// the disk into one inventory (paths prefixed `p<n>/` when there are
/// several), and hand their files on.
fn list_volumes(
    src: &mut dyn Source,
    cx: &mut Context<'_>,
    facts: &serde_json::Map<String, Value>,
) -> Result<(), ExtractError> {
    let kind = |f: Option<&Value>| {
        f.and_then(|f| f["type"].as_str()).filter(|t| t.starts_with("fat") || t.starts_with("ext")).map(str::to_string)
    };
    let mut volumes = Vec::new();
    if let Some(k) = kind(facts.get("filesystem")) {
        volumes.push((String::new(), 0, src.len(), k));
    }
    for p in facts.get("partitions").and_then(Value::as_array).into_iter().flatten() {
        if let Some(k) = kind(p.get("filesystem"))
            && let (Some(i), Some(start), Some(size)) =
                (p["index"].as_u64(), p["start_bytes"].as_u64(), p["size_bytes"].as_u64())
        {
            volumes.push((format!("p{i}/"), start, size, k));
        }
    }
    if volumes.is_empty() {
        return Ok(());
    }
    if volumes.len() == 1 {
        volumes[0].0.clear();
    }
    let mut inv = archive::Inventory::new();
    let mut opened: Vec<Listable> = Vec::new();
    // `(path, volume, file handle, size)`.
    let mut files: Vec<(String, usize, u64, u64)> = Vec::new();
    for (prefix, offset, len, kind) in volumes {
        let mut found = Vec::new();
        let volume = if kind.starts_with("fat") {
            fat::Fat::open(src, offset, len)?.map(|f| {
                let r = fat::walk(&f, src, cx, &prefix, &mut inv, &mut found);
                (Listable::Fat(f), r)
            })
        } else {
            ext::Ext::open(src, offset, len)?.map(|e| {
                let r = e.walk(src, cx, &prefix, &mut inv, &mut found);
                (Listable::Ext(e), r)
            })
        };
        let Some((v, result)) = volume else { continue };
        result?;
        let i = opened.len();
        opened.push(v);
        files.extend(found.into_iter().map(|(p, h, n)| (p, i, h, n)));
    }
    inv.report(cx, src.len());
    let limit = cx.parse_limit() as u64;
    for (path, i, handle, size) in files {
        let data = match &opened[i] {
            Listable::Fat(f) => f.read(src, u32::try_from(handle).unwrap_or(0), size.min(limit))?,
            Listable::Ext(e) => e.read(src, cx, handle, size.min(limit))?,
        };
        let complete = data.len() as u64 == size;
        if !archive::child(cx, &path, data, complete)? {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::BytesSource;

    /// Blocks 0 and 2 are stored (reversed), block 1 is a hole.
    struct Swap;

    impl BlockMap for Swap {
        fn block_size(&self) -> u64 {
            4
        }

        fn locate(&mut self, _: &mut dyn Source, n: u64) -> Result<Block, SourceError> {
            Ok(match n {
                0 => Block::At(4),
                2 => Block::At(0),
                3 => Block::Fill(0x0403_0201),
                _ => Block::Zero,
            })
        }
    }

    #[test]
    fn virtual_blocks() {
        let mut image = BytesSource::new(None, b"abcdEFGH".to_vec(), Budget::unlimited());
        let mut v = Virtual::new(&mut image, Swap, 15).unwrap();
        let src: &mut dyn Source = &mut v;
        assert_eq!(src.read_vec(0, 15).unwrap(), b"EFGH\0\0\0\0abcd\x01\x02\x03");
        assert_eq!(src.read_vec(2, 4).unwrap(), b"GH\0\0");
    }

    /// One 512-byte block, wherever `block` says.
    struct One(Block);

    impl BlockMap for One {
        fn block_size(&self) -> u64 {
            512
        }

        fn locate(&mut self, _: &mut dyn Source, _: u64) -> Result<Block, SourceError> {
            Ok(self.0)
        }
    }

    #[test]
    fn an_offset_past_u64_fails_instead_of_wrapping() {
        // Wrapped, `u64::MAX - 8 + 100` would land on the planted sector at 91.
        let mut data = vec![0u8; 1024];
        data[91..99].copy_from_slice(b"PLANTED!");
        let mut image = BytesSource::new(None, data, Budget::unlimited());
        let mut v = Virtual::new(&mut image, One(Block::Zero), 512).unwrap();
        v.map = One(Block::At(u64::MAX - 8));
        let err = (&mut v as &mut dyn Source).read_vec(100, 8).err();
        assert!(matches!(err, Some(SourceError::Io(_))), "{err:?}");
    }

    #[test]
    fn a_compressed_block_cut_short_fails_instead_of_reading_zeros() {
        let block = miniz_oxide::deflate::compress_to_vec_zlib(&[0xAB; 512], 6);
        let len = block.len();
        let at = |budget| BytesSource::new(None, block.clone(), budget);
        let zlib = Block::Compressed { at: 0, len, codec: Codec::Zlib };
        // Whole: every byte is the data, none zero.
        let mut image = at(Budget::unlimited());
        let mut v = Virtual::new(&mut image, One(zlib), 512).unwrap();
        assert_eq!((&mut v as &mut dyn Source).read_vec(500, 12).unwrap(), [0xAB; 12]);
        // A 16-byte decompression budget.
        let mut image = at(Budget::new(u64::MAX, 16, None));
        let err = Virtual::new(&mut image, One(zlib), 512).err();
        assert!(matches!(err, Some(SourceError::LimitExceeded("decompressed_bytes"))), "{err:?}");
        // The stream cut in half.
        let mut image = at(Budget::unlimited());
        let half = Block::Compressed { at: 0, len: len / 2, codec: Codec::Zlib };
        let err = Virtual::new(&mut image, One(half), 512).err();
        assert!(matches!(err, Some(SourceError::Io(_))), "{err:?}");
    }
}
