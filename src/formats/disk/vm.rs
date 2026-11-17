//! Virtual machine disk images: VirtualBox VDI, VMware VMDK (sparse,
//! stream-optimised and descriptor files), Microsoft VHD (fixed, dynamic,
//! differencing) and VHDX, QEMU QCOW / QCOW2 and QED, and Apple
//! `.sparseimage`. Each reports its header: format version, virtual size,
//! block or cluster size and how many are allocated, creator, UUIDs,
//! parent / backing file (a differencing image is incomplete on its own),
//! snapshots (QCOW2), encryption, compression, adapter and geometry
//! (VMDK). The virtual disk is then read through its block map, so the
//! partition table and file systems inside are described too.
//!
//! Specifications: VirtualBox `VDICore.h`; VMware "Virtual Disk Format
//! 5.0"; Microsoft "Virtual Hard Disk Image Format Specification" 1.0 and
//! [MS-VHDX] 2.0; QEMU `docs/interop/qcow2.txt`, `block/qcow.c` and
//! `docs/interop/qed_spec.txt`; Apple sparse image layout as read by
//! `hdiutil` (header, band table, bands from 4 KiB).

use serde_json::{Map, Value, json};

use super::{Block, BlockMap, Virtual, report_contents};
use crate::plugin::volume::num::{be16, be32, be64, le16, le32, le64};
use crate::plugin::volume::{guid_le, text_field, unix_time, utf16_field, uuid_be};
use crate::plugin::{
    Codec, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, SourceError,
};

/// Extractor for VM disk images.
pub struct VmDisk;

static META: ExtractorMeta = ExtractorMeta {
    id: "disk.vm",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "vdi",
            name: "VirtualBox disk image",
            family: "disk",
            mimes: &["application/x-virtualbox-vdi"],
            extensions: &["vdi"],
            magic: &[Magic::at(64, b"\x7f\x10\xda\xbe")],
            parent: None,
        },
        FormatSpec {
            id: "vmdk",
            name: "VMware virtual disk",
            family: "disk",
            mimes: &["application/x-vmdk"],
            extensions: &["vmdk"],
            magic: &[Magic::prefix(b"KDMV"), Magic::prefix(b"# Disk DescriptorFile")],
            parent: None,
        },
        FormatSpec {
            id: "vhd",
            name: "Microsoft virtual hard disk",
            family: "disk",
            mimes: &["application/x-vhd"],
            extensions: &["vhd", "vpc"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "vhdx",
            name: "Microsoft VHDX virtual hard disk",
            family: "disk",
            mimes: &["application/x-vhdx"],
            extensions: &["vhdx", "avhdx"],
            magic: &[Magic::prefix(b"vhdxfile")],
            parent: None,
        },
        FormatSpec {
            id: "qcow2",
            name: "QEMU copy-on-write disk",
            family: "disk",
            mimes: &["application/x-qemu-disk"],
            extensions: &["qcow2", "qcow"],
            magic: &[Magic::prefix(b"QFI\xfb")],
            parent: None,
        },
        FormatSpec {
            id: "qed",
            name: "QEMU enhanced disk",
            family: "disk",
            mimes: &["application/x-qemu-disk"],
            extensions: &["qed"],
            magic: &[Magic::prefix(b"QED\0")],
            parent: None,
        },
        FormatSpec {
            id: "sparseimage",
            name: "Apple sparse disk image",
            family: "disk",
            mimes: &["application/x-apple-diskimage"],
            extensions: &["sparseimage"],
            magic: &[Magic::prefix(b"sprs")],
            parent: None,
        },
    ],
};

/// Virtual disks larger than this are described by header only (an 8 EiB
/// size is a damaged header).
const MAX_VIRTUAL: u64 = 1 << 50;

impl Extractor for VmDisk {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let footer = probe.tail.len() >= 512 && probe.tail[probe.tail.len() - 512..].starts_with(b"conectix");
        if probe.head.starts_with(b"conectix") || footer {
            return Some(Sniff { format: "vhd", confidence: 0.97 });
        }
        // A VMDK descriptor file (text).
        (probe.head.starts_with(b"# Disk DescriptorFile")).then_some(Sniff { format: "vmdk", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.head().to_vec();
        match cx.format_id() {
            "vdi" => vdi(src, cx, &head),
            "vmdk" => vmdk(src, cx, &head),
            "vhd" => vhd(src, cx),
            "vhdx" => vhdx(src, cx, &head),
            "qcow2" => qcow(src, cx, &head),
            "qed" => qed(src, cx, &head),
            _ => sparseimage(src, cx, &head),
        }
    }
}

crate::register_extractor!(VmDisk);

/// Read the virtual disk and describe what is on it.
fn contents<M: BlockMap>(src: &mut dyn Source, cx: &mut Context<'_>, map: M, size: u64) {
    if size == 0 || size > MAX_VIRTUAL {
        return;
    }
    match Virtual::new(src, map, size) {
        Ok(mut v) => report_contents(&mut v, cx),
        Err(e) => cx.warn(format!("virtual disk unreadable: {e}")),
    }
}

/// Read a big- or little-endian integer from the image (a block-map entry).
fn entry(src: &mut dyn Source, at: u64, n: usize) -> Result<Vec<u8>, SourceError> {
    src.read_vec(at, n)
}

// ---------------------------------------------------------------- VDI

struct VdiMap {
    block: u64,
    map: u64,
    data: u64,
    extra: u64,
    blocks: u64,
}

impl BlockMap for VdiMap {
    fn block_size(&self) -> u64 {
        self.block
    }

    fn locate(&mut self, src: &mut dyn Source, n: u64) -> Result<Block, SourceError> {
        if n >= self.blocks {
            return Ok(Block::Zero);
        }
        let e = entry(src, self.map + 4 * n, 4)?;
        let i = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
        Ok(if i >= 0xFFFF_FFFE {
            Block::Zero
        } else {
            Block::At(super::offset(
                super::offset(self.data, super::scaled(u64::from(i), super::offset(self.block, self.extra)?)?)?,
                self.extra,
            )?)
        })
    }
}

fn vdi(src: &mut dyn Source, cx: &mut Context<'_>, h: &[u8]) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("short VDI header");
    let version = le32(h, 68).ok_or_else(bad)?;
    cx.format_set("version", format!("{}.{}", version >> 16, version & 0xFFFF));
    if let Some(t) = text_field(&h[..64]) {
        cx.format_set("creator", t.trim_start_matches("<<< ").trim_end_matches(" >>>").to_string());
    }
    if version >> 16 != 1 {
        return Ok(());
    }
    let ty = le32(h, 76).ok_or_else(bad)?;
    let kind = match ty {
        1 => "dynamic",
        2 => "fixed",
        3 => "undo",
        4 => "differencing",
        _ => "other",
    };
    cx.format_set("image_type", kind);
    if let Some(d) = text_field(h.get(84..340).ok_or_else(bad)?) {
        cx.format_set("description", d);
    }
    let size = le64(h, 368).ok_or_else(bad)?;
    let block = u64::from(le32(h, 376).ok_or_else(bad)?);
    let blocks = le32(h, 384).ok_or_else(bad)?;
    cx.format_set("virtual_bytes", size);
    cx.format_set("block_size", block);
    cx.format_set("blocks", blocks);
    cx.format_set("allocated_blocks", le32(h, 388).ok_or_else(bad)?);
    if let Some(u) = h.get(392..408).and_then(guid_le) {
        cx.format_set("uuid", u);
    }
    if let Some(u) = h.get(424..440).and_then(guid_le) {
        cx.format_set("parent_uuid", u);
    }
    cx.physical().uncompressed_bytes(size);
    if !block.is_power_of_two() {
        return Ok(());
    }
    let map = VdiMap {
        block,
        map: u64::from(le32(h, 340).ok_or_else(bad)?),
        data: u64::from(le32(h, 344).ok_or_else(bad)?),
        extra: u64::from(le32(h, 380).ok_or_else(bad)?),
        blocks: u64::from(blocks),
    };
    contents(src, cx, map, size);
    Ok(())
}

// ---------------------------------------------------------------- VMDK

struct VmdkMap {
    grain: u64,
    gtes: u64,
    gd: u64,
    compressed: bool,
    capacity: u64,
}

impl BlockMap for VmdkMap {
    fn block_size(&self) -> u64 {
        self.grain
    }

    fn locate(&mut self, src: &mut dyn Source, n: u64) -> Result<Block, SourceError> {
        if n.saturating_mul(self.grain) >= self.capacity {
            return Ok(Block::Zero);
        }
        let gde = entry(src, self.gd * 512 + 4 * (n / self.gtes), 4)?;
        let gt = u64::from(u32::from_le_bytes([gde[0], gde[1], gde[2], gde[3]]));
        if gt == 0 {
            return Ok(Block::Zero);
        }
        let gte = entry(src, gt * 512 + 4 * (n % self.gtes), 4)?;
        let sector = u64::from(u32::from_le_bytes([gte[0], gte[1], gte[2], gte[3]]));
        if sector <= 1 {
            return Ok(Block::Zero);
        }
        if self.compressed {
            // A grain marker: LBA (8), compressed size (4), zlib data.
            let m = entry(src, sector * 512, 12)?;
            let len = u32::from_le_bytes([m[8], m[9], m[10], m[11]]) as usize;
            return Ok(Block::Compressed { at: sector * 512 + 12, len, codec: Codec::Zlib });
        }
        Ok(Block::At(sector * 512))
    }
}

/// The facts of a VMDK descriptor (`key = "value"` lines and extent lines).
fn descriptor(text: &str, cx: &mut Context<'_>) {
    let mut extents = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let (k, v) = (k.trim(), v.trim().trim_matches('"'));
            let key = match k {
                "createType" => "create_type",
                "CID" => "content_id",
                "parentCID" if v != "ffffffff" => "parent_content_id",
                "parentFileNameHint" => "parent_file",
                "ddb.adapterType" => "adapter_type",
                "ddb.virtualHWVersion" => "virtual_hardware_version",
                "ddb.toolsVersion" if v != "0" => "tools_version",
                "ddb.uuid" => "uuid",
                "ddb.longContentID" => "long_content_id",
                "encoding" => "encoding",
                _ => continue,
            };
            cx.format_set(key, v.to_string());
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, ' ').collect();
        if parts.len() >= 3 && matches!(parts[0], "RW" | "RDONLY" | "NOACCESS") {
            let mut e = Map::new();
            e.insert("access".into(), json!(parts[0]));
            e.insert("sectors".into(), json!(parts[1].parse::<u64>().unwrap_or(0)));
            e.insert("type".into(), json!(parts[2]));
            if let Some(f) = parts.get(3) {
                let file = f.split('"').nth(1).unwrap_or(f);
                e.insert("file".into(), json!(file));
            }
            if extents.len() < 64 {
                extents.push(Value::Object(e));
            }
        }
    }
    if !extents.is_empty() {
        cx.format_set("extents", extents);
    }
}

fn vmdk(src: &mut dyn Source, cx: &mut Context<'_>, head: &[u8]) -> Result<(), ExtractError> {
    if !head.starts_with(b"KDMV") {
        let (text, _) = cx.read_bytes(src)?;
        cx.format_set("variant", "descriptor");
        descriptor(&String::from_utf8_lossy(&text), cx);
        return Ok(());
    }
    let mut h = head.get(..512).ok_or_else(|| ExtractError::malformed("short VMDK header"))?.to_vec();
    let bad = || ExtractError::malformed("short VMDK header");
    // Stream-optimised images put the grain directory after the data and
    // repeat the header, with its offset, in a footer.
    if le64(&h, 56) == Some(u64::MAX) && src.len() >= 1024 {
        let footer = src.read_vec(src.len() - 1024, 512)?;
        if footer.starts_with(b"KDMV") {
            h = footer;
        }
    }
    let flags = le32(&h, 8).ok_or_else(bad)?;
    let capacity = le64(&h, 12).ok_or_else(bad)?.saturating_mul(512);
    let grain = le64(&h, 20).ok_or_else(bad)?.saturating_mul(512);
    cx.format_set("version", le32(&h, 4).ok_or_else(bad)?);
    cx.format_set("virtual_bytes", capacity);
    cx.format_set("grain_size", grain);
    let compressed = flags & 0x1_0000 != 0;
    if compressed {
        cx.format_set("compression", if le16(&h, 77) == Some(1) { "deflate" } else { "other" });
    }
    if h.get(72) == Some(&1) {
        cx.format_set("unclean_shutdown", true);
    }
    cx.physical().uncompressed_bytes(capacity);
    let (desc_at, desc_len) = (le64(&h, 28).ok_or_else(bad)?, le64(&h, 36).ok_or_else(bad)?);
    if desc_at > 0 && desc_len > 0 && desc_len <= 2048 {
        let text = src.read_vec(desc_at * 512, usize::try_from(desc_len * 512).unwrap_or(0))?;
        let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
        descriptor(&String::from_utf8_lossy(&text[..end]), cx);
    }
    let gtes = u64::from(le32(&h, 44).ok_or_else(bad)?);
    let gd = le64(&h, 56).ok_or_else(bad)?;
    if grain.is_power_of_two() && grain >= 512 && gtes > 0 && gd != u64::MAX {
        contents(src, cx, VmdkMap { grain, gtes, gd, compressed, capacity }, capacity);
    }
    Ok(())
}

// ---------------------------------------------------------------- VHD

struct VhdMap {
    block: u64,
    bat: u64,
    entries: u64,
    bitmap: u64,
}

impl BlockMap for VhdMap {
    fn block_size(&self) -> u64 {
        self.block
    }

    fn locate(&mut self, src: &mut dyn Source, n: u64) -> Result<Block, SourceError> {
        if n >= self.entries {
            return Ok(Block::Zero);
        }
        let e = entry(src, self.bat + 4 * n, 4)?;
        let sector = u32::from_be_bytes([e[0], e[1], e[2], e[3]]);
        Ok(if sector == u32::MAX {
            Block::Zero
        } else {
            Block::At(super::offset(u64::from(sector) * 512, self.bitmap)?)
        })
    }
}

/// Seconds since 2000-01-01 (VHD time stamps).
fn vhd_time(secs: u32) -> Option<String> {
    unix_time(i64::from(secs) + 946_684_800)
}

#[allow(clippy::too_many_lines)] // footer, dynamic header, parent locators, map
fn vhd(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    let mut f = if len >= 512 { src.read_vec(len - 512, 512)? } else { Vec::new() };
    let mut footer_ok = f.starts_with(b"conectix");
    if !footer_ok {
        // Dynamic disks keep a copy of the footer at the start.
        f = src.read_vec(0, 512.min(usize::try_from(len).unwrap_or(0)))?;
        footer_ok = f.starts_with(b"conectix");
        if footer_ok {
            cx.warn("the footer at the end of the file is missing; using the copy at the start");
        }
    }
    if !footer_ok {
        return Err(ExtractError::malformed("no VHD footer"));
    }
    // A footer copy at the start of a file shorter than 512 bytes: read
    // the missing fields as zero.
    f.resize(512, 0);
    let bad = || ExtractError::malformed("short VHD footer");
    let version = be32(&f, 12).ok_or_else(bad)?;
    cx.format_set("version", format!("{}.{}", version >> 16, version & 0xFFFF));
    let kind = be32(&f, 60).ok_or_else(bad)?;
    cx.format_set(
        "disk_type",
        match kind {
            2 => "fixed",
            3 => "dynamic",
            4 => "differencing",
            _ => "other",
        },
    );
    if let Some(t) = vhd_time(be32(&f, 24).ok_or_else(bad)?) {
        cx.format_set("created", t.clone());
        cx.temporal().content_date(crate::plugin::DateField::Created, t, true);
    }
    let app = text_field(&f[28..32]).unwrap_or_default();
    let creator = match app.as_str() {
        "vpc" => "Virtual PC",
        "vs" => "Virtual Server",
        "win" => "Windows",
        "qemu" => "QEMU",
        "vbox" => "VirtualBox",
        "d2v" => "Disk2vhd",
        "tap" => "Xen",
        _ => app.as_str(),
    };
    let cv = be32(&f, 32).ok_or_else(bad)?;
    cx.format_set("creator", format!("{creator} {}.{}", cv >> 16, cv & 0xFFFF));
    let host = text_field(&f[36..40]).unwrap_or_default();
    cx.format_set(
        "creator_host",
        match host.as_str() {
            "Wi2k" => "Windows",
            "Mac" => "macOS",
            _ => host.as_str(),
        },
    );
    let size = be64(&f, 48).ok_or_else(bad)?;
    cx.format_set("virtual_bytes", size);
    cx.format_set("geometry", format!("{}/{}/{}", be16(&f, 56).unwrap_or(0), f[58], f[59]));
    if let Some(u) = uuid_be(&f[68..84]) {
        cx.format_set("uuid", u);
    }
    if f[84] != 0 {
        cx.format_set("saved_state", true);
    }
    cx.physical().uncompressed_bytes(size);
    if kind == 2 {
        if size <= len {
            let mut disk = src.slice(0, size)?;
            report_contents(&mut disk, cx);
        }
        return Ok(());
    }
    let dyn_at = be64(&f, 16).ok_or_else(bad)?;
    let Ok(d) = src.read_vec(dyn_at, 1024) else { return Ok(()) };
    if !d.starts_with(b"cxsparse") {
        return Ok(());
    }
    let block = u64::from(be32(&d, 32).ok_or_else(bad)?);
    let entries = u64::from(be32(&d, 28).ok_or_else(bad)?);
    cx.format_set("block_size", block);
    if kind == 4 {
        if let Some(n) = utf16_field(&d[64..576], false) {
            cx.format_set("parent_name", n);
        }
        if let Some(u) = uuid_be(&d[40..56]) {
            cx.format_set("parent_uuid", u);
        }
        let mut locators = Vec::new();
        for i in 0..8 {
            let l = &d[576 + 24 * i..600 + 24 * i];
            let code = &l[..4];
            let (n, at) = (be32(l, 8).unwrap_or(0), be64(l, 16).unwrap_or(0));
            if code == [0; 4] || n == 0 || n > 4096 {
                continue;
            }
            let Ok(data) = src.read_vec(at, n as usize) else { continue };
            let path = match code {
                b"W2ku" | b"W2ru" => utf16_field(&data, true),
                _ => text_field(&data),
            };
            if let Some(p) = path {
                locators.push(json!(p));
            }
        }
        if !locators.is_empty() {
            cx.format_set("parent_locators", locators);
        }
        cx.warn("a differencing disk: blocks not stored here come from the parent");
    }
    if block.is_power_of_two() && block >= 512 {
        let bitmap = (block / 512).div_ceil(8).div_ceil(512) * 512;
        contents(src, cx, VhdMap { block, bat: be64(&d, 16).ok_or_else(bad)?, entries, bitmap }, size);
    }
    Ok(())
}

// ---------------------------------------------------------------- VHDX

const VHDX_BAT: &str = "2dc27766-f623-4200-9d64-115e9bfd4a08";
const VHDX_METADATA: &str = "8b7ca206-4790-4b9a-b8fe-575f050f886e";

struct VhdxMap {
    block: u64,
    bat: u64,
    ratio: u64,
}

impl BlockMap for VhdxMap {
    fn block_size(&self) -> u64 {
        self.block
    }

    fn locate(&mut self, src: &mut dyn Source, n: u64) -> Result<Block, SourceError> {
        // A sector-bitmap entry follows every `ratio` payload entries.
        let i = n + n / self.ratio;
        let e = entry(src, self.bat + 8 * i, 8)?;
        let e = u64::from_le_bytes(e.try_into().unwrap_or([0; 8]));
        Ok(match e & 7 {
            6 | 7 => Block::At(e >> 20 << 20),
            _ => Block::Zero,
        })
    }
}

fn vhdx(src: &mut dyn Source, cx: &mut Context<'_>, head: &[u8]) -> Result<(), ExtractError> {
    if let Some(c) = head.get(8..520).and_then(|b| utf16_field(b, true)) {
        cx.format_set("creator", c);
    }
    // Two headers; the one with the higher sequence number is current.
    let mut header: Option<Vec<u8>> = None;
    for at in [64u64 << 10, 128 << 10] {
        let Ok(h) = src.read_vec(at, 4096) else { continue };
        if h.starts_with(b"head") && header.as_ref().is_none_or(|c| le64(&h, 8) > le64(c, 8)) {
            header = Some(h);
        }
    }
    let Some(h) = header else { return Err(ExtractError::malformed("no VHDX header")) };
    cx.format_set("version", le16(&h, 66).unwrap_or(0));
    if guid_le(&h[48..64]).is_some() {
        cx.format_set("log_pending", true);
    }
    let Ok(rt) = src.read_vec(192 << 10, 4096) else {
        cx.warn("region table unreadable");
        return Ok(());
    };
    if !rt.starts_with(b"regi") {
        return Ok(());
    }
    let (mut bat, mut meta) = (None, None);
    for i in 0..usize::try_from(le32(&rt, 8).unwrap_or(0).min(64)).unwrap_or(0) {
        let e = &rt[16 + 32 * i..48 + 32 * i];
        let (at, n) = (le64(e, 16).unwrap_or(0), le32(e, 24).unwrap_or(0));
        match guid_le(&e[..16]).as_deref() {
            Some(VHDX_BAT) => bat = Some(at),
            Some(VHDX_METADATA) => meta = Some((at, n)),
            _ => {}
        }
    }
    let Some((meta_at, meta_len)) = meta else { return Ok(()) };
    // Item data follows the table, usually 64 KiB in.
    let n = u64::from(meta_len).clamp(64 << 10, 1 << 20).min(src.len().saturating_sub(meta_at));
    let m = match src.read_vec(meta_at, usize::try_from(n).unwrap_or(0)) {
        Ok(m) if m.len() >= 64 => m,
        _ => {
            cx.warn("metadata region past the end of the file");
            return Ok(());
        }
    };
    if !m.starts_with(b"metadata") {
        return Ok(());
    }
    let (mut block, mut size, mut sector, mut has_parent) = (0u64, 0u64, 512u64, false);
    for i in 0..usize::from(le16(&m, 10).unwrap_or(0).min(64)) {
        let Some(e) = m.get(32 + 32 * i..64 + 32 * i) else { break };
        let at = le32(e, 16).unwrap_or(0) as usize;
        let item = |n: usize| m.get(at..at + n);
        match guid_le(&e[..16]).as_deref() {
            Some("caa16737-fa36-4d43-b3b6-33f0aa44e76b") => {
                if let Some(v) = item(8) {
                    block = u64::from(le32(v, 0).unwrap_or(0));
                    has_parent = le32(v, 4).unwrap_or(0) & 2 != 0;
                }
            }
            Some("2fa54224-cd1b-4876-b211-5dbed83bf4b8") => size = item(8).and_then(|v| le64(v, 0)).unwrap_or(0),
            Some("8141bf1d-a96f-4709-ba47-f233a8faab5f") => {
                sector = u64::from(item(4).and_then(|v| le32(v, 0)).unwrap_or(512));
            }
            Some("cda348c7-445d-4471-9cc9-e9885251c556") => {
                cx.format_set("physical_sector_size", item(4).and_then(|v| le32(v, 0)).unwrap_or(0));
            }
            Some("beca12ab-b2e6-4523-93ef-c309e000c746") => {
                if let Some(g) = item(16).and_then(guid_le) {
                    cx.format_set("disk_id", g);
                }
            }
            Some("a8d35f2d-b30b-454d-abf7-d3d84834ab0c") => {
                let n = le32(e, 20).unwrap_or(0) as usize;
                if let Some(p) = m.get(at..at + n) {
                    parent_locator(p, cx);
                }
            }
            _ => {}
        }
    }
    cx.format_set("virtual_bytes", size);
    cx.format_set("block_size", block);
    cx.format_set("logical_sector_size", sector);
    cx.physical().uncompressed_bytes(size);
    if has_parent {
        cx.warn("a differencing disk: blocks not stored here come from the parent");
    }
    if let Some(bat) = bat
        && block.is_power_of_two()
        && block >= 1 << 20
        && sector.is_power_of_two()
    {
        let ratio = ((1u64 << 23) * sector / block).max(1);
        contents(src, cx, VhdxMap { block, bat, ratio }, size);
    }
    Ok(())
}

/// VHDX parent locator: UTF-16 key / value pairs.
fn parent_locator(p: &[u8], cx: &mut Context<'_>) {
    let count = usize::from(le16(p, 18).unwrap_or(0).min(32));
    for i in 0..count {
        let e = 20 + 12 * i;
        let (ko, vo) = (le32(p, e).unwrap_or(0) as usize, le32(p, e + 4).unwrap_or(0) as usize);
        let (kl, vl) = (usize::from(le16(p, e + 8).unwrap_or(0)), usize::from(le16(p, e + 10).unwrap_or(0)));
        let (Some(k), Some(v)) = (
            p.get(ko..ko + kl).and_then(|b| utf16_field(b, true)),
            p.get(vo..vo + vl).and_then(|b| utf16_field(b, true)),
        ) else {
            continue;
        };
        let key = match k.as_str() {
            "relative_path" => "parent_relative_path",
            "absolute_win32_path" => "parent_absolute_path",
            "volume_path" => "parent_volume_path",
            "parent_linkage" => "parent_linkage",
            _ => continue,
        };
        cx.format_set(key, v);
    }
}

// ---------------------------------------------------------------- QCOW / QCOW2

struct QcowMap {
    cluster_bits: u32,
    l1: u64,
    l1_size: u64,
    /// L2 entries per table, and bytes per entry.
    l2_entries: u64,
    l2_entry: u64,
    version: u32,
    codec: Codec,
}

impl BlockMap for QcowMap {
    fn block_size(&self) -> u64 {
        1 << self.cluster_bits
    }

    fn locate(&mut self, src: &mut dyn Source, n: u64) -> Result<Block, SourceError> {
        let (i1, i2) = (n / self.l2_entries, n % self.l2_entries);
        if i1 >= self.l1_size {
            return Ok(Block::Zero);
        }
        let l1e = u64::from_be_bytes(entry(src, self.l1 + 8 * i1, 8)?.try_into().unwrap_or([0; 8]));
        let l2 = l1e & 0x00FF_FFFF_FFFF_FE00;
        if l2 == 0 {
            return Ok(Block::Zero);
        }
        let e = u64::from_be_bytes(entry(src, l2 + self.l2_entry * i2, 8)?.try_into().unwrap_or([0; 8]));
        if self.version == 1 {
            // QCOW 1: bit 63 marks a compressed cluster, its size above the offset.
            let shift = 63 - self.cluster_bits;
            if e >> 63 == 1 {
                let at = e & ((1 << shift) - 1);
                let len = (e >> shift) & ((1 << self.cluster_bits) - 1);
                return Ok(Block::Compressed { at, len: usize::try_from(len).unwrap_or(0), codec: Codec::Deflate });
            }
            return Ok(if e == 0 { Block::Zero } else { Block::At(e) });
        }
        if e >> 62 & 1 == 1 {
            let x = 62 - (self.cluster_bits - 8);
            let at = e & ((1 << x) - 1);
            let sectors = ((e >> x) & ((1 << (self.cluster_bits - 8)) - 1)) + 1;
            let len = sectors * 512 - (at & 511);
            return Ok(Block::Compressed { at, len: usize::try_from(len).unwrap_or(0), codec: self.codec });
        }
        let at = e & 0x00FF_FFFF_FFFF_FE00;
        Ok(if e & 1 == 1 || at == 0 { Block::Zero } else { Block::At(at) })
    }
}

#[allow(clippy::too_many_lines)] // header, extensions, snapshots, map
fn qcow(src: &mut dyn Source, cx: &mut Context<'_>, h: &[u8]) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("short QCOW header");
    let version = be32(h, 4).ok_or_else(bad)?;
    cx.format_set("version", version);
    let backing = |src: &mut dyn Source, at: u64, n: u32| -> Option<String> {
        if at == 0 || n == 0 || n > 1023 {
            return None;
        }
        text_field(&src.read_vec(at, n as usize).ok()?)
    };
    if version == 1 {
        let size = be64(h, 24).ok_or_else(bad)?;
        let (cb, l2b) = (u32::from(*h.get(32).ok_or_else(bad)?), u32::from(h[33]));
        cx.format_set("virtual_bytes", size);
        cx.format_set("cluster_size", 1u64 << cb.min(31));
        if let Some(b) = backing(src, be64(h, 8).ok_or_else(bad)?, be32(h, 16).ok_or_else(bad)?) {
            cx.format_set("backing_file", b);
        }
        if let Some(t) = unix_time(i64::from(be32(h, 20).ok_or_else(bad)?)) {
            cx.format_set("modified", t);
        }
        let crypt = be32(h, 36).ok_or_else(bad)?;
        cx.physical().uncompressed_bytes(size);
        if crypt != 0 {
            cx.format_set("encryption", "aes");
            cx.security().encrypted(true);
            return Ok(());
        }
        if (9..=16).contains(&cb) && (9..=16).contains(&l2b) {
            let span = 1u64 << (cb + l2b);
            let map = QcowMap {
                cluster_bits: cb,
                l1: be64(h, 40).ok_or_else(bad)?,
                l1_size: size.div_ceil(span),
                l2_entries: 1 << l2b,
                l2_entry: 8,
                version,
                codec: Codec::Deflate,
            };
            contents(src, cx, map, size);
        }
        return Ok(());
    }
    let size = be64(h, 24).ok_or_else(bad)?;
    let cb = be32(h, 20).ok_or_else(bad)?;
    cx.format_set("virtual_bytes", size);
    cx.format_set("cluster_size", 1u64 << cb.min(31));
    cx.physical().uncompressed_bytes(size);
    if let Some(b) = backing(src, be64(h, 8).ok_or_else(bad)?, be32(h, 16).ok_or_else(bad)?) {
        cx.format_set("backing_file", b);
        cx.warn("an overlay: clusters not stored here come from the backing file");
    }
    let crypt = be32(h, 32).ok_or_else(bad)?;
    let (mut incompat, mut compat, mut header_len, mut codec) = (0, 0, 72usize, Codec::Deflate);
    if version >= 3 {
        incompat = be64(h, 72).ok_or_else(bad)?;
        compat = be64(h, 80).ok_or_else(bad)?;
        header_len = be32(h, 100).ok_or_else(bad)? as usize;
        if incompat & 8 != 0 && h.get(104) == Some(&1) {
            codec = Codec::Zstd;
            cx.format_set("compression_type", "zstd");
        }
    }
    let mut flags = Vec::new();
    for (bit, name) in [(0, "dirty"), (1, "corrupt"), (2, "external_data_file"), (4, "extended_l2")] {
        if incompat >> bit & 1 == 1 {
            flags.push(name);
        }
    }
    if compat & 1 != 0 {
        flags.push("lazy_refcounts");
    }
    if !flags.is_empty() {
        cx.format_set("flags", flags);
    }
    // Header extensions: backing format, data file, feature names, encryption.
    let mut at = header_len.max(72);
    for _ in 0..32 {
        let (Some(ty), Some(n)) = (be32(h, at), be32(h, at + 4)) else { break };
        if ty == 0 {
            break;
        }
        let data = h.get(at + 8..at + 8 + n as usize).unwrap_or(&[]);
        match ty {
            0xE279_2ACA => {
                if let Some(t) = text_field(data) {
                    cx.format_set("backing_format", t);
                }
            }
            0x4441_5441 => {
                if let Some(t) = text_field(data) {
                    cx.format_set("data_file", t);
                }
            }
            0x2385_2875 => cx.format_set("bitmaps", true),
            _ => {}
        }
        at += 8 + (n as usize).div_ceil(8) * 8;
    }
    let snapshots = be32(h, 60).ok_or_else(bad)?;
    if snapshots > 0 {
        cx.format_set("snapshots", qcow_snapshots(src, be64(h, 64).ok_or_else(bad)?, snapshots));
    }
    if crypt != 0 {
        cx.format_set("encryption", if crypt == 2 { "luks" } else { "aes" });
        cx.security().encrypted(true);
        return Ok(());
    }
    if incompat & 4 != 0 {
        cx.warn("data is in an external file");
        return Ok(());
    }
    if (9..=21).contains(&cb) {
        let l2_entry = if incompat & 16 != 0 { 16 } else { 8 };
        let map = QcowMap {
            cluster_bits: cb,
            l1: be64(h, 40).ok_or_else(bad)?,
            l1_size: u64::from(be32(h, 36).ok_or_else(bad)?),
            l2_entries: (1u64 << cb) / l2_entry,
            l2_entry,
            version,
            codec,
        };
        contents(src, cx, map, size);
    }
    Ok(())
}

/// QCOW2 snapshot table: id, name, date, VM state size.
fn qcow_snapshots(src: &mut dyn Source, mut at: u64, count: u32) -> Vec<Value> {
    let mut out = Vec::new();
    for _ in 0..count.min(64) {
        let Ok(s) = src.read_vec(at, 40) else { break };
        let (Some(id_len), Some(name_len), Some(secs), Some(state), Some(extra)) =
            (be16(&s, 12), be16(&s, 14), be32(&s, 16), be32(&s, 32), be32(&s, 36))
        else {
            break;
        };
        let (id_len, name_len) = (usize::from(id_len), usize::from(name_len));
        let Ok(names) = src.read_vec(at + 40 + u64::from(extra), id_len + name_len) else { break };
        let mut m = Map::new();
        m.insert("id".into(), json!(String::from_utf8_lossy(&names[..id_len])));
        m.insert("name".into(), json!(String::from_utf8_lossy(&names[id_len..])));
        if let Some(t) = unix_time(i64::from(secs)) {
            m.insert("date".into(), json!(t));
        }
        if state > 0 {
            m.insert("vm_state_bytes".into(), json!(state));
        }
        out.push(Value::Object(m));
        at += (40 + u64::from(extra) + (id_len + name_len) as u64).div_ceil(8) * 8;
    }
    out
}

// ---------------------------------------------------------------- QED

struct QedMap {
    cluster: u64,
    entries: u64,
    l1: u64,
}

impl BlockMap for QedMap {
    fn block_size(&self) -> u64 {
        self.cluster
    }

    fn locate(&mut self, src: &mut dyn Source, n: u64) -> Result<Block, SourceError> {
        let (i1, i2) = (n / self.entries, n % self.entries);
        if i1 >= self.entries {
            return Ok(Block::Zero);
        }
        let l2 = u64::from_le_bytes(entry(src, self.l1 + 8 * i1, 8)?.try_into().unwrap_or([0; 8]));
        if l2 == 0 {
            return Ok(Block::Zero);
        }
        let at = u64::from_le_bytes(entry(src, l2 + 8 * i2, 8)?.try_into().unwrap_or([0; 8]));
        Ok(if at <= 1 { Block::Zero } else { Block::At(at) })
    }
}

fn qed(src: &mut dyn Source, cx: &mut Context<'_>, h: &[u8]) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("short QED header");
    let cluster = u64::from(le32(h, 4).ok_or_else(bad)?);
    let table = u64::from(le32(h, 8).ok_or_else(bad)?);
    let features = le64(h, 16).ok_or_else(bad)?;
    let size = le64(h, 48).ok_or_else(bad)?;
    cx.format_set("virtual_bytes", size);
    cx.format_set("cluster_size", cluster);
    cx.format_set("table_size", table);
    cx.physical().uncompressed_bytes(size);
    if features & 2 != 0 {
        cx.format_set("needs_check", true);
    }
    if features & 1 != 0 {
        let (at, n) = (le32(h, 56).ok_or_else(bad)?, le32(h, 60).ok_or_else(bad)?);
        if n > 0
            && n < 1024
            && let Some(b) = text_field(&src.read_vec(u64::from(at), n as usize)?)
        {
            cx.format_set("backing_file", b);
        }
    }
    if cluster.is_power_of_two() && (4096..=1 << 26).contains(&cluster) && (1..=16).contains(&table) {
        let map = QedMap { cluster, entries: table * cluster / 8, l1: le64(h, 40).ok_or_else(bad)? };
        contents(src, cx, map, size);
    }
    Ok(())
}

// ---------------------------------------------------------------- Apple sparse image

struct SparseMap {
    band: u64,
    /// Virtual band → slot in the file.
    slots: Vec<Option<u32>>,
}

impl BlockMap for SparseMap {
    fn block_size(&self) -> u64 {
        self.band
    }

    fn locate(&mut self, _: &mut dyn Source, n: u64) -> Result<Block, SourceError> {
        Ok(match self.slots.get(usize::try_from(n).unwrap_or(usize::MAX)).copied().flatten() {
            Some(slot) => u64::from(slot).checked_mul(self.band).map_or(Block::Zero, |o| Block::At(4096 + o)),
            None => Block::Zero,
        })
    }
}

fn sparseimage(src: &mut dyn Source, cx: &mut Context<'_>, h: &[u8]) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("short sparse image header");
    cx.format_set("version", be32(h, 4).ok_or_else(bad)?);
    let band_bytes = u64::from(be32(h, 8).ok_or_else(bad)?) * 512;
    let sectors = u64::from(be32(h, 16).ok_or_else(bad)?);
    let size = sectors * 512;
    cx.format_set("virtual_bytes", size);
    cx.format_set("band_size", band_bytes);
    cx.physical().uncompressed_bytes(size);
    if band_bytes == 0 {
        return Ok(());
    }
    // The band_bytes table in the header: slot i holds band_bytes table[i] (1-based).
    let bands = size.div_ceil(band_bytes);
    let mut slots = vec![None; usize::try_from(bands.min(1 << 20)).unwrap_or(0)];
    let mut stored = 0u64;
    for (slot, e) in (0u32..).zip(h.get(64..4096).unwrap_or(&[]).as_chunks::<4>().0.iter()) {
        let b = u32::from_be_bytes([e[0], e[1], e[2], e[3]]);
        if b == 0 {
            continue;
        }
        if let Some(s) = slots.get_mut(b as usize - 1) {
            *s = Some(slot);
            stored += 1;
        }
    }
    cx.format_set("bands", bands);
    cx.format_set("allocated_bands", stored);
    if bands > 1008 {
        cx.warn("band_bytes table continues past the first header; later bands read as empty");
    }
    contents(src, cx, SparseMap { band: band_bytes, slots }, size);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vhd_times() {
        assert_eq!(vhd_time(0).as_deref(), Some("2000-01-01T00:00:00Z"));
    }

    #[test]
    fn short_vhd_footer() {
        // Fuzz regression: a footer copy at the start of a 64-byte file.
        let mut d = b"conectix".to_vec();
        d.resize(64, 0);
        let r = crate::plugin::testing::report_for("disk.vhd", &d);
        assert_eq!(r.identification.format, "vhd");
    }

    crate::fixture_tests!("vdi", "vmdk", "vhd", "vhdx", "qcow2", "qed", "sparseimage");
}
