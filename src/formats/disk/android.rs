//! Android images: sparse images (`simg`, as fastboot flashes them) and
//! boot images (`boot.img`, `recovery.img`, `vendor_boot.img`). A sparse
//! image reports its block size and the raw / fill / don't-care chunk
//! counts, and the file system it expands to is described through its
//! chunk map. A boot image reports its header version, board name, kernel
//! command line, OS version and security patch level, page size and the
//! sizes and load addresses of the kernel, ramdisk, second-stage loader
//! and device tree, the kernel's format and version string; the parts are
//! handed on (the ramdisk is a compressed cpio archive).
//!
//! Specifications: AOSP `system/core/libsparse/sparse_format.h` and
//! `system/tools/mkbootimg/include/bootimg/bootimg.h` (boot image header
//! versions 0–4, vendor boot versions 3–4).

use super::archive::{Stored, stored_children};
use super::{Block, BlockMap, Virtual, report_contents};
use crate::plugin::volume::num::{le16, le32};
use crate::plugin::volume::text_field;
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, SourceError};

/// Extractor for Android sparse and boot images.
pub struct AndroidImage;

static META: ExtractorMeta = ExtractorMeta {
    id: "disk.android",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "android_sparse",
            name: "Android sparse image",
            family: "disk",
            mimes: &["application/x-android-sparse"],
            extensions: &["simg"],
            magic: &[Magic::prefix(b"\x3a\xff\x26\xed")],
            parent: None,
        },
        FormatSpec {
            id: "android_boot",
            name: "Android boot image",
            family: "disk",
            mimes: &["application/x-android-boot-image"],
            extensions: &[],
            magic: &[Magic::prefix(b"ANDROID!"), Magic::prefix(b"VNDRBOOT")],
            parent: None,
        },
    ],
};

/// Sparse chunks walked at most.
const MAX_CHUNKS: usize = 1 << 20;

impl Extractor for AndroidImage {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "android_sparse" { sparse(src, cx) } else { boot(src, cx) }
    }
}

crate::register_extractor!(AndroidImage);

// ---------------------------------------------------------------- sparse

/// A run of blocks: `(first block, blocks, what)`.
struct SparseMap {
    block: u64,
    runs: Vec<(u64, u64, Block)>,
}

impl BlockMap for SparseMap {
    fn block_size(&self) -> u64 {
        self.block
    }

    fn locate(&mut self, _: &mut dyn Source, n: u64) -> Result<Block, SourceError> {
        let i = self.runs.partition_point(|r| r.0 + r.1 <= n);
        Ok(match self.runs.get(i) {
            Some(&(first, count, Block::At(at))) if n >= first && n < first + count => {
                Block::At(super::offset(at, super::scaled(n - first, self.block)?)?)
            }
            Some(&(first, _, b)) if n >= first => b,
            _ => Block::Zero,
        })
    }
}

fn sparse(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 28)?;
    let bad = || ExtractError::malformed("short sparse header");
    cx.format_set("version", format!("{}.{}", le16(&h, 4).ok_or_else(bad)?, le16(&h, 6).ok_or_else(bad)?));
    let header_len = u64::from(le16(&h, 8).ok_or_else(bad)?);
    let chunk_header = u64::from(le16(&h, 10).ok_or_else(bad)?);
    let block = u64::from(le32(&h, 12).ok_or_else(bad)?);
    let blocks = u64::from(le32(&h, 16).ok_or_else(bad)?);
    let chunks = le32(&h, 20).ok_or_else(bad)?;
    let size = block.saturating_mul(blocks);
    cx.format_set("block_size", block);
    cx.format_set("blocks", blocks);
    cx.format_set("chunks", chunks);
    cx.format_set("expanded_bytes", size);
    cx.physical().uncompressed_bytes(size);
    let mut runs = Vec::new();
    let (mut at, mut next) = (header_len, 0u64);
    let mut kinds = [0u64; 4];
    for _ in 0..(chunks as usize).min(MAX_CHUNKS) {
        cx.checkpoint()?;
        let Ok(c) = src.read_vec(at, usize::try_from(chunk_header.max(12)).unwrap_or(12)) else { break };
        let (ty, count, total) =
            (le16(&c, 0).unwrap_or(0), u64::from(le32(&c, 4).unwrap_or(0)), u64::from(le32(&c, 8).unwrap_or(0)));
        let data = at + chunk_header;
        let what = match ty {
            0xCAC1 => Block::At(data),
            0xCAC2 => {
                let v = src.read_vec(data, 4)?;
                Block::Fill(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
            }
            0xCAC3 => Block::Zero,
            0xCAC4 => {
                kinds[3] += 1;
                at += total.max(chunk_header);
                continue;
            }
            _ => {
                cx.warn(format!("unknown chunk type {ty:#x}"));
                break;
            }
        };
        kinds[usize::from(ty - 0xCAC1)] += 1;
        runs.push((next, count, what));
        next += count;
        at += total.max(chunk_header);
    }
    for (i, name) in ["raw_chunks", "fill_chunks", "dont_care_chunks", "crc_chunks"].iter().enumerate() {
        if kinds[i] > 0 {
            cx.format_set(name, kinds[i]);
        }
    }
    if block.is_power_of_two() && block >= 512 && size > 0 {
        match Virtual::new(src, SparseMap { block, runs }, size) {
            Ok(mut v) => report_contents(&mut v, cx),
            Err(e) => cx.warn(format!("expanded image unreadable: {e}")),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- boot

/// `A.B.C` and the `YYYY-MM` patch level packed into `os_version`.
fn os_version(v: u32) -> (Option<String>, Option<String>) {
    let (a, b, c) = (v >> 25, (v >> 18) & 0x7F, (v >> 11) & 0x7F);
    let level = v & 0x7FF;
    let version = (v >> 11 != 0).then(|| format!("{a}.{b}.{c}"));
    let patch = (level != 0).then(|| format!("{:04}-{:02}", (level >> 4) + 2000, level & 0xF));
    (version, patch)
}

/// What a kernel image is, from its first bytes.
fn kernel_format(k: &[u8]) -> &'static str {
    if k.starts_with(&[0x1F, 0x8B]) {
        "gzip"
    } else if k.starts_with(&[0x02, 0x21, 0x4C, 0x18]) || k.starts_with(&[0x04, 0x22, 0x4D, 0x18]) {
        "lz4"
    } else if k.get(56..60) == Some(b"ARMd") {
        "arm64_image"
    } else if le32(k, 36) == Some(0x016F_2818) {
        "arm_zimage"
    } else if k.starts_with(b"\x7fELF") {
        "elf"
    } else if k.get(0x202..0x206) == Some(b"HdrS") {
        "x86_bzimage"
    } else {
        "other"
    }
}

/// The `Linux version …` banner of an uncompressed kernel.
fn kernel_version(k: &[u8]) -> Option<String> {
    let at = k.windows(14).position(|w| w == b"Linux version ")?;
    let end = k[at..].iter().position(|&b| b == 0 || b == b'\n').map_or(k.len(), |e| at + e);
    let s = String::from_utf8_lossy(&k[at + 14..end.min(at + 200)]).trim().to_string();
    (!s.is_empty()).then_some(s)
}

#[allow(clippy::too_many_lines)] // header versions 0–4 and vendor boot
fn boot(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 4096.min(usize::try_from(src.len()).unwrap_or(0)))?;
    let bad = || ExtractError::malformed("short boot image header");
    let pages = |n: u64, page: u64| n.div_ceil(page) * page;
    let mut parts: Vec<(&str, u64, u64)> = Vec::new();
    if h.starts_with(b"VNDRBOOT") {
        let version = le32(&h, 8).ok_or_else(bad)?;
        let page = u64::from(le32(&h, 12).ok_or_else(bad)?);
        cx.format_set("image", "vendor_boot");
        cx.format_set("header_version", version);
        cx.format_set("page_size", page);
        if let Some(c) = h.get(28..2076).and_then(text_field) {
            cx.format_set("cmdline", c);
        }
        if let Some(n) = h.get(2080..2096).and_then(text_field) {
            cx.format_set("board", n);
        }
        let ramdisk = u64::from(le32(&h, 24).ok_or_else(bad)?);
        let header = u64::from(le32(&h, 2096).ok_or_else(bad)?);
        let dtb = u64::from(le32(&h, 2100).ok_or_else(bad)?);
        if !page.is_power_of_two() || page < 2048 {
            return Ok(());
        }
        let mut at = pages(header, page);
        parts.push(("vendor_ramdisk", at, ramdisk));
        at += pages(ramdisk, page);
        parts.push(("dtb", at, dtb));
    } else {
        let version = le32(&h, 40).ok_or_else(bad)?;
        cx.format_set("image", "boot");
        cx.format_set("header_version", version);
        let (kernel, ramdisk, os, page);
        if version >= 3 {
            kernel = u64::from(le32(&h, 8).ok_or_else(bad)?);
            ramdisk = u64::from(le32(&h, 12).ok_or_else(bad)?);
            os = le32(&h, 16).ok_or_else(bad)?;
            page = 4096;
            if let Some(c) = h.get(44..1580).and_then(text_field) {
                cx.format_set("cmdline", c);
            }
        } else {
            kernel = u64::from(le32(&h, 8).ok_or_else(bad)?);
            ramdisk = u64::from(le32(&h, 16).ok_or_else(bad)?);
            os = le32(&h, 44).ok_or_else(bad)?;
            page = u64::from(le32(&h, 36).ok_or_else(bad)?);
            cx.format_set("kernel_address", format!("{:#x}", le32(&h, 12).ok_or_else(bad)?));
            cx.format_set("ramdisk_address", format!("{:#x}", le32(&h, 20).ok_or_else(bad)?));
            if let Some(n) = h.get(48..64).and_then(text_field) {
                cx.format_set("board", n);
            }
            let mut cmdline = h.get(64..576).and_then(text_field).unwrap_or_default();
            if let Some(extra) = h.get(608..1632).and_then(text_field) {
                cmdline.push_str(&extra);
            }
            if !cmdline.is_empty() {
                cx.format_set("cmdline", cmdline);
            }
        }
        cx.format_set("page_size", page);
        let (v, patch) = os_version(os);
        if let Some(v) = v {
            cx.format_set("os_version", v);
        }
        if let Some(p) = patch {
            cx.format_set("security_patch", p);
        }
        if !page.is_power_of_two() || page < 2048 {
            return Ok(());
        }
        let mut at = page;
        parts.push(("kernel", at, kernel));
        at += pages(kernel, page);
        parts.push(("ramdisk", at, ramdisk));
        at += pages(ramdisk, page);
        if version < 3 {
            let second = u64::from(le32(&h, 24).ok_or_else(bad)?);
            parts.push(("second", at, second));
            at += pages(second, page);
            if version >= 1 {
                let dtbo = u64::from(le32(&h, 1632).ok_or_else(bad)?);
                parts.push(("recovery_dtbo", at, dtbo));
                at += pages(dtbo, page);
            }
            if version == 2 {
                parts.push(("dtb", at, u64::from(le32(&h, 1648).ok_or_else(bad)?)));
            }
        }
    }
    let len = src.len();
    let mut sizes = serde_json::Map::new();
    let mut stored: Vec<Stored> = Vec::new();
    for &(name, at, n) in &parts {
        if n == 0 {
            continue;
        }
        sizes.insert(format!("{name}_bytes"), n.into());
        if at.saturating_add(n) > len {
            cx.warn(format!("{name} runs past the end of the image"));
            continue;
        }
        stored.push((format!("{name}.img"), at, n));
    }
    if let Some(&(_, at, n)) = parts.iter().find(|p| p.0 == "kernel").filter(|p| p.2 > 0 && p.1 + p.2 <= len) {
        let k = src.read_vec(at, usize::try_from(n.min(cx.parse_limit() as u64)).unwrap_or(0))?;
        cx.format_set("kernel_format", kernel_format(&k));
        if let Some(v) = kernel_version(&k) {
            cx.format_set("kernel_version", v);
        }
    }
    for (k, v) in sizes {
        cx.format_set(&k, v);
    }
    stored_children(src, cx, stored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        // Android 14.0.0, patch level 2025-09.
        let v = (14 << 25) | ((25 << 4) | 9);
        assert_eq!(os_version(v), (Some("14.0.0".into()), Some("2025-09".into())));
        assert_eq!(os_version(0), (None, None));
        assert_eq!(kernel_format(&[0x1F, 0x8B, 8]), "gzip");
        assert_eq!(
            kernel_version(b"xx\0Linux version 6.1.0-tides (b@h) #1\n").as_deref(),
            Some("6.1.0-tides (b@h) #1")
        );
    }

    crate::fixture_tests!("android_sparse", "android_boot");
}
